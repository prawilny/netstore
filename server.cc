#include "netstore.h"

static constexpr int DEFAULT_FREE = 52428800;

enum class req_type {
    hello,
    list,
    upload,
    download,
    remove,
    invalid
};

struct server_config {
    std::string server_address;
    int server_port;
    std::string shared_folder;
    uint64_t free_space;
    int timeout;
};

// global variables:
struct server_config config;
struct sockaddr_in local_address;
struct sockaddr_in client_address;

bool parse_commandline_args(int argc, char **argv) {
    try {
        namespace po = boost::program_options;

        po::options_description desc(std::string(argv[0]).append(" options"));
        desc.add_options()
                ("help,h", "help message")
                (",g", po::value<std::string>(&config.server_address)->required(), "multicast address")
                (",p", po::value<int>(&config.server_port)->required(), "udp port")
                (",f", po::value<std::string>(&config.shared_folder)->required(), "shared folder")
                (",t", po::value<int>(&config.timeout)->default_value(DEFAULT_TIMEOUT),
                 "timeout for client connections")
                (",b", po::value<uint64_t>(&config.free_space)->default_value(DEFAULT_FREE), "shared folder max size");

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc)
                          .style(po::command_line_style::unix_style | po::command_line_style::allow_long_disguise)
                          .run(), vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            exit(0);
        }
        po::notify(vm);

        if (!(std::regex_match(config.server_address, std::regex(IPV4_REGEXP)))) {
            throw std::invalid_argument("Server address is not a valid ipv4 address");
        }
        if (config.server_port < 0 || MAX_PORT < config.server_port) {
            throw std::invalid_argument("Server port is not valid");
        }
        if (config.timeout <= 0 || MAX_TIMEOUT < config.timeout) {
            throw std::invalid_argument("Timeout is not valid");
        }
    }
    catch (std::exception &e) {
        std::cerr << "error: " << e.what() << "\n";
        return false;
    }
    return true;
}

bool index_files(std::vector<std::string> &names) {
    namespace stdfs = std::filesystem;
    std::filesystem::path path(config.shared_folder);

    const stdfs::directory_iterator end{};
    try {
        for (stdfs::directory_iterator iter{path}; iter != end; ++iter) {
            if (stdfs::is_regular_file(*iter)) {
                names.push_back(iter->path().string());
                uint64_t fSize = iter->file_size();
                if (fSize > config.free_space) {
                    std::cerr << "Shared folder's size exceeds limit\n";
                    return false;
                }
                config.free_space -= fSize;
            }
        }
    }
    catch (std::exception &e) {
        std::cerr << "filesystem error while indexing: " << e.what() << "\n";
        return false;
    }
    return true;
}

int create_socket() {
    int sock;
    struct ip_mreq ip_mreq;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        std::cerr << "socket\n";
        perror(NULL);
        return -1;
    }

    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(config.server_address.c_str(), &ip_mreq.imr_multiaddr) == 0) {
        std::cerr << "inet_aton\n";
        perror(NULL);
        close(sock);
        return -1;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *) &ip_mreq, sizeof(ip_mreq)) == -1) {
        std::cerr << "setsockopt\n";
        perror(NULL);
        close(sock);
        return -1;
    }

    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(config.server_port);
    if (bind(sock, (struct sockaddr *) &local_address, sizeof(local_address)) < 0) {
        std::cerr << "bind\n";
        perror(NULL);
        close(sock);
        return -1;
    }

    return sock;
}

bool do_hello(int sock, struct SIMPL_CMD * request){
    struct CMPLX_CMD reply;

    reply.cmd_seq = request->cmd_seq;
    snprintf(reply.cmd, CMD_LEN, "%s", MSG_HEADER_GOOD_DAY);

    return cmd_send(sock, &reply, &client_address);
}

req_type parse_req_type(struct BUF_CMD *buf) {
    if (strncmp(buf->cmd, MSG_HEADER_HELLO, CMD_LEN) == 0) {
        return req_type::hello;
    }
    /*if (strncmp(buf->cmd, ..., CMD_LEN) == 0) {
        return req_type::hello;
    }*/
    return req_type::invalid;
}

int main(int argc, char *argv[]) {
    int sock;
    std::vector<std::string> filenames;
    struct BUF_CMD buffer;
    struct SIMPL_CMD *buffer_simpl = (struct SIMPL_CMD *) &buffer;
    struct CMPLX_CMD *buffer_cmplx = (struct CMPLX_CMD *) &buffer;

    if (!parse_commandline_args(argc, argv)) {
        return 1;
    }

    if (!index_files(filenames)) {
        return 2;
    }

    if ((sock = create_socket()) == -1) {
        return 1;
    }

    for (;;) {
        if (!cmd_recvfrom(sock, &buffer, &client_address)) {
            std::cerr << "Partial read\n";
            continue;
        }
        std::cout << "msg received\n";
        switch(parse_req_type(&buffer)){
            case req_type::hello:
                if(!do_hello(sock, buffer_simpl)){
                    std::cerr << "Error replying to hello\n";
                }
                break;
            default:
                pckg_error(&client_address);
                break;
        }
    }
}
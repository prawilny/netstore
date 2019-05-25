#include "netstore.h"

#include <sstream>
#include <unordered_map>
#include <cstdlib> // rand()

static constexpr int MULTICAST_UDP_TTL_VALUE = 4;

enum class cmd_type {
    discover,
    search,
    search_all,
    search_exp,
    fetch,
    upload,
    remove,
    exit,
    invalid
};

static std::unordered_map<std::string, cmd_type> command_types = {
        {"discover", cmd_type::discover},
        {"search",   cmd_type::search},
        {"fetch",    cmd_type::fetch},
        {"upload",   cmd_type::upload},
        {"remove",   cmd_type::remove},
        {"exit",     cmd_type::exit},
};

struct client_config {
    std::string server_address;
    int server_port;
    std::string download_folder;
    int timeout;
};

struct command {
    cmd_type type;
    std::string arg;
};

// global variables:
struct client_config config;
struct sockaddr_in local_address;
struct sockaddr_in remote_multicast_address;


bool parse_commandline_args(int argc, char **argv) {
    try {
        namespace po = boost::program_options;

        po::options_description desc(std::string(argv[0]).append(" options"));
        desc.add_options()
                ("help,h", "help message")
                (",g", po::value<std::string>(&config.server_address)->required(), "multicast address of servers")
                (",p", po::value<int>(&config.server_port)->required(), "server port")
                (",o", po::value<std::string>(&config.download_folder)->required(), "download folder")
                (",t", po::value<int>(&config.timeout)->default_value(DEFAULT_TIMEOUT), "timeout for server replies");

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

bool parse_command(struct command *c) {
    std::string line, token;

    if (!getline(std::cin, line)) {
        std::cerr << "Error reading line\n";
        return false;
    }
    std::istringstream linestream(line);

    if (!(linestream >> token)) {
        return false;
    }
    std::transform(token.begin(), token.end(), token.begin(), ::tolower);

    c->type = cmd_type::invalid;
    for (auto it = command_types.begin(); it != command_types.end(); it++) {
        if (token.compare(it->first) == 0) {
            c->type = it->second;
            break;
        }
    }

    //todo whitespace as first argument...

    int args = 0;
    if (!linestream.eof()) {
        args++;
        linestream >> c->arg;
        if (!linestream.eof()) {
            args++;
        }
    }

    switch (c->type) {
        case cmd_type::discover:
        case cmd_type::exit:
            return args == 0;
        case cmd_type::fetch:
        case cmd_type::upload:
        case cmd_type::remove:
            return args == 1;
        case cmd_type::search:
            switch (args) {
                case 0:
                    c->type = cmd_type::search_all;
                    return true;
                case 1:
                    c->type = cmd_type::search_exp;
                    return true;
                default:
                    return false;
            }
        default:
            return false;
    }
}

int create_socket() {
    int sock;

    int broadcast_flag = 1;
    int ttl_val = MULTICAST_UDP_TTL_VALUE;
    int mcast_loop_flag = 0;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        std::cerr << "socket\n";
        perror(NULL);
        return -1;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void *) &ttl_val, sizeof(ttl_val)) == -1
        || setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &broadcast_flag, sizeof(broadcast_flag)) == -1
        || setsockopt(sock, SOL_IP, IP_MULTICAST_LOOP, (void *) &mcast_loop_flag, sizeof mcast_loop_flag) < 0) {
        std::cerr << "setsockopt\n";
        perror(NULL);
        close(sock);
        return -1;
    }

    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(0);
    if (bind(sock, (struct sockaddr *) &local_address, sizeof(local_address)) == -1) {
        std::cerr << "bind\n";
        perror(NULL);
        close(sock);
        return -1;
    }

    remote_multicast_address.sin_family = AF_INET;
    remote_multicast_address.sin_port = htons(config.server_port);
    if (inet_aton(config.server_address.c_str(), &remote_multicast_address.sin_addr) == 0) {
        std::cerr << "inet_aton\n";
        perror(NULL);
        close(sock);
        return -1;
    }

    return sock;
}

void do_exit() {
    exit(0);
}

void do_discover(int socket) {
    uint64_t seq;
    struct SIMPL_CMD simple;
    struct CMPLX_CMD complex;
    struct sockaddr_in server_address;
    struct timeval timeout;

    seq = (uint64_t) rand();
    timeout.tv_sec = config.timeout;
    timeout.tv_usec = 0;

    snprintf(simple.cmd, CMD_LEN, "%s", MSG_HEADER_HELLO);
    simple.cmd_seq = htobe64(seq);
    memset(simple.data, '\0', SIMPL_CMD_DATA_SIZE);

    if (cmd_send(socket, &simple, &remote_multicast_address)) {
        std::cerr << "Couldn't send HELLO message\n";
        return;
    }

    while (cmd_recvfrom_timed(socket, &complex, &server_address, &timeout)) {
        if (be64toh(complex.cmd_seq) != seq || strncmp(MSG_HEADER_GOOD_DAY, complex.cmd, CMD_LEN) != 0) {
            std::cerr << "[PCKG ERROR]  Skipping invalid package from {" << server_address.sin_addr.s_addr << "}:{"
                      << server_address.sin_port << "}." << std::endl;
            continue;
        }
        std::cout << "Found " << server_address.sin_addr.s_addr << "(" << config.server_port << ") with free space "
                  << be64toh(complex.param) << std::endl;
    }
}

void execute_command(struct command *cmd, int socket) {
    switch (cmd->type) {
        case cmd_type::exit:
            do_exit();
            break;
        case cmd_type::discover:
            do_discover(socket);
        default:
            return;
    }
}

int main(int argc, char *argv[]) {
    int sock;
    struct command cmd;
    std::vector<std::string> filenames;

    srand(time(NULL));

    if (!parse_commandline_args(argc, argv)) {
        return 1;
    }

    if ((sock = create_socket()) == -1) {
        return 1;
    }

    for (;;) {
        if (parse_command(&cmd)) {
            execute_command(&cmd, sock);
        }
    }
}
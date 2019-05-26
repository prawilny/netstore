#include "netstore.h"
#include "netstore-boost.h"

enum class req_type {
    hello,
    list,
    upload,
    download,
    remove,
    invalid
};

// global variables:
extern struct server_config s_config;
struct sockaddr_in local_address;
struct sockaddr_in client_address;

bool index_files(std::vector<std::string> &names) {
    namespace stdfs = std::filesystem;
    std::filesystem::path path(s_config.shared_folder);

    const stdfs::directory_iterator end{};
    try {
        for (stdfs::directory_iterator iter{path}; iter != end; ++iter) {
            if (stdfs::is_regular_file(*iter)) {
                names.push_back(iter->path().string());
                uint64_t fSize = iter->file_size();
                if (fSize > s_config.free_space) {
                    std::cerr << "Shared folder's size exceeds limit\n";
                    return false;
                }
                s_config.free_space -= fSize;
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
    if (inet_aton(s_config.server_address.c_str(), &ip_mreq.imr_multiaddr) == 0) {
        std::cerr << "inet_aton\n";
        perror(NULL);
        close(sock);
        return -1;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &ip_mreq, sizeof(ip_mreq)) == -1) {
        std::cerr << "setsockopt\n";
        perror(NULL);
        close(sock);
        return -1;
    }

    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons((uint16_t) s_config.server_port);
    if (bind(sock, (struct sockaddr *) &local_address, sizeof(local_address)) < 0) {
        std::cerr << "bind\n";
        perror(NULL);
        close(sock);
        return -1;
    }

    return sock;
}

bool do_hello(int sock, struct SIMPL_CMD *request) {
    struct CMPLX_CMD reply;

    reply.cmd_seq = request->cmd_seq;
    snprintf(reply.cmd, CMD_LEN, "%s", MSG_HEADER_GOOD_DAY);
    reply.param = htobe64(s_config.free_space);

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

    if (!parse_server_args(argc, argv)) {
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
        switch (parse_req_type(&buffer)) {
            case req_type::hello:
                if (!do_hello(sock, buffer_simpl)) {
                    std::cerr << "Error replying to hello\n";
                }
                break;
            default:
                pckg_error(&client_address);
                break;
        }
    }
}
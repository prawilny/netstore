#include "netstore.h"
#include "netstore-boost.h"

#include <sstream>
#include <unordered_map>
#include <cstdlib>
#include <netdb.h>

//todo make cmd_seq sequential (static counter and so on)

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

struct command {
    cmd_type type;
    std::string arg;
};

// global variables:
extern struct client_config c_config;
struct sockaddr_in local_address;
struct sockaddr_in remote_multicast_address;

//todo check again (esp. no argument situation)
//checked
bool parse_command(struct command *c) {
    std::string line, token;

    c->arg = "";

    if (!getline(std::cin, line)) {
        perror("Error reading line");
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

    getline(linestream, c->arg);
    bool arg_present = false;
    for (int i = 0; i < c->arg.length(); i++) {
        if (c->arg[i] != ' ') {
            arg_present = true;
            c->arg = c->arg.substr(i, c->arg.length());
            break;
        }
    }

    switch (c->type) {
        case cmd_type::discover:
        case cmd_type::exit:
            return !arg_present;
        case cmd_type::fetch:
        case cmd_type::upload:
        case cmd_type::remove:
            return arg_present;
        case cmd_type::search:
            switch (arg_present) {
                case false:
                    c->type = cmd_type::search_all;
                    return true;
                case true:
                    c->type = cmd_type::search_exp;
                    return true;
            }
        default:
            return false;
    }
}

//checked
int tcp_socket(std::string host, int port) {
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;

    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &addr_hints, &addr_result) != 0) {
        perror("getaddrinfo");
        return -1;
    }

    for (struct addrinfo *rp = addr_result; rp != NULL; rp = rp->ai_next) {
        int sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            perror("socket (nonfatal)");
            continue;
        }
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            freeaddrinfo(addr_result);
            return sfd;
        }
        perror("connect");
        close(sfd);
    }
    freeaddrinfo(addr_result);
    return -1;
}

//checked
int udp_socket() {
    int sock;

    int broadcast_flag = 1;
    int ttl_val = MULTICAST_UDP_TTL_VALUE;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_val, sizeof(ttl_val)) == -1
        || setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast_flag, sizeof(broadcast_flag)) == -1) {
        perror("setsockopt");
        close(sock);
        return -1;
    }

    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons(0);
    if (bind(sock, (struct sockaddr *) &local_address, sizeof(local_address)) == -1) {
        perror("bind");
        close(sock);
        return -1;
    }

    remote_multicast_address.sin_family = AF_INET;
    remote_multicast_address.sin_port = htons((uint16_t) c_config.server_port);
    if (inet_aton(c_config.server_address.c_str(), &remote_multicast_address.sin_addr) == 0) {
        perror("inet_aton");
        close(sock);
        return -1;
    }

    return sock;
}

//checked
void do_exit() {
    quick_exit(0);
}

//checked
void work_download(int sfd, int fd, std::filesystem::path file_node, std::string server_ip, int server_port) {
    std::error_code ec;
    std::string filename = file_node.filename();

    char buffer[TCP_BUFFER_SIZE];
    ssize_t rcvd;
    while ((rcvd = readn(sfd, buffer, TCP_BUFFER_SIZE)) > 0) {
        if (writen(fd, buffer, rcvd) != rcvd) {
            std::cerr << "File {" << filename << "} downloading failed ({" << server_ip << "}:{" << server_port
                      << "}) {" << "couldn't write to file.}";
            std::filesystem::remove(file_node, ec);
            close(fd);
            close(sfd);
            return;
        }
    }
    close(fd);
    close(sfd);

    if (rcvd == -1) {
        std::cerr << "File {" << filename << "} downloading failed ({" << server_ip << "}:{" << server_port
                  << "}) {" << "couldn't read from socket.}";
        std::filesystem::remove(file_node, ec);
        return;
    }

    std::cout << "File {" << filename << "} downloaded ({" << server_ip << "}:{" << server_port << "})";
    return;
}

//checked
void work_upload(int sfd, int fd, size_t filesize, std::string fname, std::string server_ip, int server_port) {
    std::error_code ec;
    char buffer[TCP_BUFFER_SIZE];

    int result = fdncpy(sfd, fd, filesize, buffer, TCP_BUFFER_SIZE);

    close(sfd);
    close(fd);

    if (result == -1) {
        std::cout << "File {" << fname << "} uploading failed ({" << server_ip << "}:{" << server_port << "})"
                  << "Couldn't write  to socket.";
    } else {
        std::cout << "File {" << fname << "} uploaded ({" << server_ip << "}:{" << server_port << "})";
    }
}

//checked
void do_discover(int socket, std::vector<std::pair<struct sockaddr_in, uint64_t>> &servers_available) {
    uint64_t seq = (uint64_t) rand();
    struct SIMPL_CMD simple;
    struct CMPLX_CMD complex;
    struct sockaddr_in server_address;
    struct timeval timeout;
    ssize_t rcvd;

    servers_available.clear();

    timeout.tv_sec = c_config.timeout;
    timeout.tv_usec = 0;

    memcpy(simple.cmd, MSG_HEADER_HELLO, CMD_LEN);
    simple.cmd_seq = htobe64(seq);

    std::cout << "do_discover()\n";
    if (!cmd_send(socket, &simple, (size_t) EMPTY_SIMPL_CMD_SIZE, &remote_multicast_address)) {
        perror("Couldn't send HELLO message");
        return;
    }
    std::cout << "HELLO sent\n";

    while ((rcvd = cmd_recvfrom_timed(socket, &complex, &server_address, &timeout)) != -1) {
        if (be64toh(complex.cmd_seq) != seq || memcmp(MSG_HEADER_GOOD_DAY, complex.cmd, CMD_LEN) != 0) {
            pckg_error("wrong message metadata (discovering)", &server_address);
            continue;
        }
        std::string server_ip(inet_ntoa(server_address.sin_addr));
        uint64_t server_space = be64toh(complex.param);
        servers_available.push_back(std::make_pair(server_address, server_space));
        std::cout << "Found " << server_ip << "(" << c_config.server_address << ") with free space " << server_space
                  << std::endl;
    }
    std::cout << "do_discover() returns\n";
}

//checked
void do_remove(int socket, struct command *cmd) {
    struct SIMPL_CMD simple;

    memcpy(simple.cmd, MSG_HEADER_DEL, CMD_LEN);
    simple.cmd_seq = htobe64((uint64_t) rand());
    snprintf(simple.data, SIMPL_CMD_DATA_SIZE, cmd->arg.c_str());

    if (!cmd_send(socket, &simple,
                  (size_t) EMPTY_SIMPL_CMD_SIZE + std::min(cmd->arg.length(), (size_t) SIMPL_CMD_DATA_SIZE),
                  &remote_multicast_address)) {
        perror("Couldn't send DEL message");
    }
}

//checked
void
do_search(int socket, struct command *cmd, std::unordered_map<std::string, struct sockaddr_in> &files_available) {
    uint64_t seq = (uint64_t) rand();
    struct SIMPL_CMD simple;
    struct sockaddr_in server_address;
    struct timeval timeout;
    int msg_size = EMPTY_SIMPL_CMD_SIZE;
    ssize_t rcvd;

    files_available.clear();

    timeout.tv_sec = c_config.timeout;
    timeout.tv_usec = 0;

    memcpy(simple.cmd, MSG_HEADER_LIST, CMD_LEN);
    simple.cmd_seq = htobe64(seq);

    if (cmd->type == cmd_type::search_exp) {
        snprintf(simple.data, SIMPL_CMD_DATA_SIZE, "%s", cmd->arg.c_str());
        msg_size += std::min(SIMPL_CMD_DATA_SIZE, (int) cmd->arg.length());
    }

    std::cout << "do_search()\n";
    if (!cmd_send(socket, &simple, msg_size, &remote_multicast_address)) {
        perror("Couldn't send LIST message");
        return;
    }
    std::cout << "LIST sent\n";

    while ((rcvd = cmd_recvfrom_timed(socket, &simple, &server_address, &timeout)) != -1) {
        if (rcvd <= EMPTY_SIMPL_CMD_SIZE || be64toh(simple.cmd_seq) != seq
            || memcmp(MSG_HEADER_MY_LIST, simple.cmd, CMD_LEN) != 0) {
            pckg_error("wrong message metadata (searching)", &server_address);
            continue;
        }

        simple.data[rcvd - EMPTY_SIMPL_CMD_SIZE] = '\0';
        for (char *token = strtok(simple.data, "\n"); token != NULL; token = strtok(NULL, "\n")) {
            std::cout << "{" << token << "}" << "{" << inet_ntoa(server_address.sin_addr) << "}\n";
            files_available.insert(std::make_pair(token, server_address));
        }
    }
    std::cout << "do_search() returns\n";
}

//checked
void do_fetch(int socket, struct command *cmd, std::unordered_map<std::string, struct sockaddr_in> &files_available) {
    struct SIMPL_CMD req;
    struct CMPLX_CMD res;
    struct timeval timeout;

    uint64_t seq;
    int fd = -1;
    int sfd = -1;
    std::error_code ec;
    std::string filepath(c_config.download_folder + "/" + cmd->arg);
    std::filesystem::path file_node(filepath);
    ssize_t rcvd;

    if (files_available.find(cmd->arg) == files_available.end()) {
        std::cerr << "File not among last search results.\n";
        return;
    }
    if ((fd = open(filepath.c_str(), O_CREAT | O_EXCL | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO)) == -1) {
        std::cerr << "Couldn't open file.\n";
        return;
    }

    bool connected = false;
    struct sockaddr_in sockaddr;
    for (auto it = files_available.equal_range(cmd->arg).first;
         !connected && it != files_available.equal_range(cmd->arg).second;
         it++) {
        seq = (uint64_t) rand();
        sockaddr = it->second;

        memcpy(req.cmd, MSG_HEADER_GET, CMD_LEN);
        req.cmd_seq = htobe64(seq);
        snprintf(req.data, CMPLX_CMD_DATA_SIZE, "%s", cmd->arg.c_str());

        if (!cmd_send(socket, &req,
                      (size_t) EMPTY_SIMPL_CMD_SIZE + std::min(cmd->arg.length(), (size_t) SIMPL_CMD_DATA_SIZE),
                      &sockaddr)) {
            continue;
        }

        timeout.tv_sec = c_config.timeout;
        timeout.tv_usec = 0;
        rcvd = cmd_recvfrom_timed(socket, &res, &sockaddr, &timeout);
        if (rcvd <= EMPTY_CMPLX_CMD_SIZE || be64toh(res.cmd_seq) != seq
            || memcmp(res.cmd, MSG_HEADER_CONNECT_ME, CMD_LEN) != 0
            || memcmp(cmd->arg.c_str(), res.data, rcvd - EMPTY_CMPLX_CMD_SIZE) != 0) {
            if (rcvd != -1) {
                pckg_error("Wrong message metadata", &sockaddr);
            }
            continue;
        }

        sfd = tcp_socket(inet_ntoa(sockaddr.sin_addr), be64toh(res.param));
        if (sfd == -1) {
            continue;
        }
        connected = true;
    }

    if (connected) {
        std::thread worker(work_download, sfd, fd, file_node, std::string(inet_ntoa(sockaddr.sin_addr)),
                           sockaddr.sin_port);
        worker.detach();
    } else {
        std::cerr << "Couldn't reach any server hosting file " << cmd->arg << ".\n";
        std::filesystem::remove(file_node, ec);
        close(sfd);
        close(fd);
    }
}

//checked
void do_upload(int sock, command *cmd, std::vector<std::pair<struct sockaddr_in, uint64_t>> &servers_available) {
    std::sort(servers_available.begin(), servers_available.end(), [](auto &left, auto &right) {
        return left.second < right.second;
    });

    uint64_t seq;
    int fd;
    int sfd = -1;
    ssize_t rcvd;

    //todo fix relative path open()
    if ((fd = open(cmd->arg.c_str(), O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO)) == -1) {
        std::cerr << "Couldn't open file.\n";
        return;
    }

    std::error_code ec;
    std::filesystem::path file_node(cmd->arg);
    uint64_t filesize = std::filesystem::file_size(file_node, ec);
    std::string filename = file_node.filename();

    bool connected = false;
    struct sockaddr_in sockaddr;
    for (auto it = servers_available.begin(); !connected && it != servers_available.end(); it++) {
        struct CMPLX_CMD msg;
        struct timeval timeout;

        seq = (uint64_t) rand();
        struct sockaddr_in sockaddr = it->first;

        memcpy(msg.cmd, MSG_HEADER_ADD, CMD_LEN);
        msg.cmd_seq = htobe64(seq);
        msg.param = htobe64(filesize);
        snprintf(msg.data, CMPLX_CMD_DATA_SIZE, "%s", filename.c_str());

        if (!cmd_send(sock, &msg,
                      (size_t) EMPTY_CMPLX_CMD_SIZE + std::min(filename.length(), (size_t) CMPLX_CMD_DATA_SIZE),
                      &sockaddr)) {
            continue;
        }

        timeout.tv_usec = 0;
        timeout.tv_sec = c_config.timeout;
        rcvd = cmd_recvfrom_timed(sock, &msg, &sockaddr, &timeout);

        if (rcvd <= EMPTY_CMPLX_CMD_SIZE || be64toh(msg.cmd_seq) != seq
            || memcmp(msg.cmd, MSG_HEADER_CAN_ADD, CMD_LEN) != 0
            || strncmp(cmd->arg.c_str(), msg.data, rcvd - EMPTY_CMPLX_CMD_SIZE) != 0) {
            if (rcvd != -1
                && !(rcvd == EMPTY_SIMPL_CMD_SIZE
                     && msg.cmd_seq == seq
                     && memcmp(msg.cmd, MSG_HEADER_NO_WAY, CMD_LEN) == 0)) {
                pckg_error("Wrong message format", &sockaddr);
            }
            continue;
        }

        sfd = tcp_socket(inet_ntoa(sockaddr.sin_addr), be64toh(msg.param));
        if (sfd == -1) {
            continue;
        }
        connected = true;
    }

    if (connected) {
        std::thread worker(work_upload, sfd, fd, filesize, filename, std::string(inet_ntoa(sockaddr.sin_addr)),
                           sockaddr.sin_port);
        worker.detach();
    } else {
        std::cerr << "File " << cmd->arg << " too big\n";
        close(sfd);
        close(fd);
    }
}

//checked
int main(int argc, char *argv[]) {
    int sock;
    struct command cmd;

    std::unordered_map<std::string, struct sockaddr_in> files_available;
    std::vector<std::pair<struct sockaddr_in, uint64_t>> servers_available;

    srand(time(NULL));

    if (!parse_client_args(argc, argv)) {
        return 1;
    }

    if ((sock = udp_socket()) == -1) {
        return 1;
    }

    for (;;) {
        if (parse_command(&cmd)) {
            switch (cmd.type) {
                case cmd_type::exit:
                    do_exit();
                    break;
                case cmd_type::discover:
                    do_discover(sock, servers_available);
                    break;
                case cmd_type::remove:
                    do_remove(sock, &cmd);
                    break;
                case cmd_type::search_all:
                case cmd_type::search_exp:
                    do_search(sock, &cmd, files_available);
                    break;
                case cmd_type::fetch:
                    do_fetch(sock, &cmd, files_available);
                    break;
                case cmd_type::upload:
                    do_upload(sock, &cmd, servers_available);
                    break;
                default:
                    break;
            }
        }
    }
}
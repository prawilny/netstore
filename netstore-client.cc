#include "netstore.h"
#include "netstore-boost.h"

#include <sstream>
#include <unordered_map>
#include <cstdlib>
#include <netdb.h>

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

struct download_worker_arg{

};

// global variables:
extern struct client_config c_config;
struct sockaddr_in local_address;
struct sockaddr_in remote_multicast_address;
pthread_attr_t attr;

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

    //todo whitespacce in filename

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

int tcp_socket(std::string host, int port) {
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;

    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &addr_hints, &addr_result) != 0) {
        return -1;
    }

    for (struct addrinfo *rp = addr_result; rp != NULL; rp = rp->ai_next) {
        int sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            freeaddrinfo(addr_result);
            return sfd;
        }
        close(sfd);
    }
    return -1;
}

int udp_socket() {
    int sock;

    int broadcast_flag = 1;
    int ttl_val = MULTICAST_UDP_TTL_VALUE;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        std::cerr << "socket\n";
        perror(NULL);
        return -1;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_val, sizeof(ttl_val)) == -1
        || setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast_flag, sizeof(broadcast_flag)) == -1) {
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
    remote_multicast_address.sin_port = htons((uint16_t) c_config.server_port);
    if (inet_aton(c_config.server_address.c_str(), &remote_multicast_address.sin_addr) == 0) {
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

void do_discover(int socket, std::vector<std::pair<std::string, uint64_t>> &servers_available) {
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
    memset(simple.data, '\0', SIMPL_CMD_DATA_SIZE);

    std::cout << "do_discover()\n";
    if (!cmd_send(socket, &simple, EMPTY_SIMPL_CMD_SIZE, &remote_multicast_address)) {
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
        servers_available.push_back(std::pair<std::string, uint64_t>());
        std::cout << "Found " << server_ip << "(" << c_config.server_address << ") with free space " << server_space
                  << std::endl;
    }
    std::cout << "do_discover() returns\n";
}

void do_remove(int socket, struct command *cmd) {
    struct SIMPL_CMD simple;

    memcpy(simple.cmd, MSG_HEADER_DEL, CMD_LEN);
    simple.cmd_seq = htobe64((uint64_t) rand());
    snprintf(simple.data, SIMPL_CMD_DATA_SIZE, cmd->arg.c_str());

    if (!cmd_send(socket, &simple, EMPTY_SIMPL_CMD_SIZE + std::min(cmd->arg.length(), SIMPL_CMD_DATA_SIZE),
                  &remote_multicast_address)) {
        perror("Couldn't send DEL message");
    }
}

void
do_search(int socket, struct command *cmd, std::unordered_map<std::string, std::string> &files_available) {
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
    memset(simple.data, '\0', SIMPL_CMD_DATA_SIZE);

    if (cmd->type == cmd_type::search_exp) {
        snprintf(simple.data, SIMPL_CMD_DATA_SIZE, "%s", cmd->arg.c_str());
        msg_size += std::min(SIMPL_CMD_DATA_SIZE, (int) cmd->arg.length());
    }

    std::cout << "do_search()\n";
    if (!cmd_send(socket, &simple, EMPTY_SIMPL_CMD_SIZE, &remote_multicast_address)) {
        perror("Couldn't send LIST message");
        return;
    }
    std::cout << "LIST sent\n";

    while ((rcvd = cmd_recvfrom_timed(socket, &simple, &server_address, &timeout)) != -1) {
        if (be64toh(simple.cmd_seq) != seq || strncmp(MSG_HEADER_MY_LIST, simple.cmd, CMD_LEN) != 0) {
            pckg_error("wrong message metadata (searching)", &server_address);
            continue;
        }

        simple.data[rcvd - CMD_LEN - sizeof(simple.cmd_seq)] = '\0';
        for (char *token = strtok(simple.data, "\n"); token != NULL; token = strtok(NULL, "\n")) {
            std::cout << "{" << filename << "}" << "{" << inet_ntoa(server_address.sin_addr << "}\n";
            files_available.insert({token, server_address});
        }
    }
    std::cout << "do_search() returns\n";
}

void do_fetch(int socket, struct command *cmd, std::unordered_map<std::string, struct sockaddr_in> &files_available) {
    struct SIMPL_CMD req;
    struct CMPLX_CMD res;
    struct timeval timeout;

    uint64_t seq = (uint64_t) rand();
    int fd;
    int sfd;
    std::error_code ec;
    std::string filepath(c_config.download_folder + "/" + cmd->arg);
    auto fileservers = files_available.find(cmd->arg);
    struct sockaddr_in sockaddr;
    std::string server_ip;
    pthread_t pt;

    if (fileservers == files_available.end()) {
        std::cerr << "File not among last search results.\n";
        return;
    }
    if (access(filepath.c_str(), F_OK) == 0) {
        std::cerr << "File already exists.\n";
        return;
    }
    if ((fd = open(filepath.c_str(), O_CREAT | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO)) == -1) {
        std::cerr << "Couldn't open file.\n";
        return;
    }
    std::filesystem::path file_node(filepath);

    memcpy(req.cmd, MSG_HEADER_GET, CMD_LEN);
    req.cmd_seq = htobe64(seq);
    snprintf("%s", SIMPL_CMD_DATA_SIZE, cmd->arg.c_str());

    sockaddr = fileservers->second;

    //for (auto it = fileservers; it != files_available.end(); it++)...
    if (!cmd_send(socket, &req, std::min(cmd->arg.length(), SIMPL_CMD_DATA_SIZE), &sockaddr)) {
        close(fd);
        std::filesystem::remove(file_node, ec);
        std::cerr << "Couldn't send request to server.\n";
        return;
    }

    timeout.tv_sec = c_config.timeout;
    timeout.tv_usec = 0;
    rcvd = cmd_recvfrom_timed(socket, &res, &server_address, &timeout);
    if (rcvd <= EMPTY_CMPLX_CMD_SIZE || be64toh(res.cmd_seq) != seq
        || memcmp(res.cmd, MSG_HEADER_CONNECT_ME, CMD_LEN) != 0
        || strncmp(cmd->arg.c_str(), res.data, SIMPL_CMD_DATA_SIZE) != 0) {
        close(fd);
        std::filesystem::remove(file_node, ec);
        std::cerr << "Wrong format of server's reply.\n";
        pckg_error("", &sockaddr);
        return;
    }

    if ((sfd = tcp_socket(inet_ntoa(sockaddr.sin_addr), be64toh(res.param))) == -1) {
        close(fd);
        std::filesystem::remove(file_node, ec);
        std::cerr << "Couldn't connect TCP socket.\n";
        return;
    }



    if (pthread_create(&pt, &thread_attr/* global SETDETACHEDSTATE */, work_send, &worker_arg) == 0) {
        std::filesystem::remove(file_node, ec);
        std::cerr << "Couldn't start worker.\n";
    }

    close(sfd);
    close(fd);
    //remove if something went wrong...

    return;
}

int main(int argc, char *argv[]) {
    int sock;
    struct command cmd;

    std::unordered_map<std::string, struct sockaddr_in> files_available;
    std::vector<std::pair<std::string, uint64_t>> servers_available;

    /*
     *  std::sort(v.begin(), v.end(), [](auto &left, auto &right) {
     *      return left.second < right.second;
     *  });
     */

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
                    break;
                case cmd_type::upload:
                    break;
                default:
                    break;
            }
        }
    }
}
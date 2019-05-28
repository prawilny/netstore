#include "netstore.h"
#include "netstore-boost.h"

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

struct command {
    cmd_type type;
    std::string arg;
};

// global variables:
extern struct client_config c_config;
struct sockaddr_in local_address;
struct sockaddr_in remote_multicast_address;

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

void do_discover(int socket) {
    uint64_t seq = (uint64_t) rand();
    struct SIMPL_CMD simple;
    struct CMPLX_CMD complex;
    struct sockaddr_in server_address;
    struct timeval timeout;
    ssize_t rcvd;

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
        std::cout << "Found " << inet_ntoa(server_address.sin_addr) << "(" << c_config.server_address
                  << ") with free space "
                  << be64toh(complex.param) << std::endl;
    }
    std::cout << "do_discover() returns\n";
}

void do_remove(int socket, struct command *cmd) {
    struct SIMPL_CMD simple;

    memcpy(simple.cmd, MSG_HEADER_DEL, CMD_LEN);
    simple.cmd_seq = htobe64((uint64_t) rand());
    snprintf(simple.data, SIMPL_CMD_DATA_SIZE, cmd->arg.c_str());

    if (!cmd_send(socket, &simple, EMPTY_SIMPL_CMD_SIZE + cmd->arg.length() , &remote_multicast_address)) {
        perror("Couldn't send DEL message");
    }
}

void do_search(int socket, struct command *cmd) {
    uint64_t seq = (uint64_t) rand();
    struct SIMPL_CMD simple;
    struct sockaddr_in server_address;
    struct timeval timeout;
    int msg_size = EMPTY_SIMPL_CMD_SIZE;
    ssize_t rcvd;

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
        for (char * token = strtok(simple.data, "\n"); token != NULL; token = strtok(NULL, "\n")) {
            std::cout << "{" << token << "}" << "{" << inet_ntoa(server_address.sin_addr) << "}\n";
        }
    }
    std::cout << "do_search() returns\n";
}

void execute_command(struct command *cmd, int socket) {
    switch (cmd->type) {
        case cmd_type::exit:
            do_exit();
            break;
        case cmd_type::discover:
            do_discover(socket);
            break;
        case cmd_type::remove:
            do_remove(socket, cmd);
            break;
        case cmd_type::search_all:
        case cmd_type::search_exp:
            do_search(socket, cmd);
            break;
        default:
            return;
    }
}

int main(int argc, char *argv[]) {
    int sock;
    struct command cmd;
    std::vector<std::string> filenames;

    srand(time(NULL));

    if (!parse_client_args(argc, argv)) {
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
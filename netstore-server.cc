#include "netstore.h"
#include "netstore-boost.h"
#include <regex>
#include <csignal>

static std::string ANYTHING_REGEXP = ".*";

enum class req_type {
    hello,
    remove,
    list_all,
    list_exp,
    upload,
    download,
    invalid
};

struct worker_sender_data {
    int sock;
    int fd;
    size_t file_size;
};

// global variables:
extern struct server_config s_config;
struct sockaddr_in local_address;
struct sockaddr_in client_address;
pthread_attr_t thread_attr;
sigset_t blockSIGINT;

void *work_send(void *ptr) {
    struct worker_sender_data *data = (struct worker_sender_data *) ptr;
    char buffer[TCP_BUFFER_SIZE];
    struct timeval timeout;
    int sock_fd;
    fd_set rfds;
    bool error = false;

    timeout.tv_usec = 0;
    timeout.tv_sec = s_config.timeout;

    error = error || pthread_sigmask(SIG_BLOCK, &blockSIGINT, NULL) == -1;

    //todo accept
    FD_ZERO(&rfds);
    FD_SET(data->sock, &rfds);

    error = error || select(data->sock + 1, &rfds, NULL, NULL, &timeout) != 1;

    error = error || (sock_fd = accept(data->sock, NULL, NULL)) == -1;

    std::cout << (error ? "Worker failed before transmission" : "Started file transmission") << '\n';
    error = error || fdncpy(sock_fd, data->fd, data->file_size, buffer, TCP_BUFFER_SIZE) != 0;
    std::cout << "File transfer " << (error ? "failed" : "successful") << ".\n";

    close(data->sock);
    close(data->fd);
    close(sock_fd);

    return NULL;
}

bool index_files(std::vector<std::string> &names) {
    std::filesystem::path dir(s_config.shared_folder);

    if (!std::filesystem::is_directory(dir)) {
        return false;
    }

    const std::filesystem::directory_iterator end{};
    try {
        for (std::filesystem::directory_iterator iter{dir}; iter != end; ++iter) {
            if (std::filesystem::is_regular_file(*iter)
                && iter->path().filename().string().length() < CMPLX_CMD_DATA_SIZE) {
                names.push_back(iter->path().filename());
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

    memcpy(reply.cmd, MSG_HEADER_GOOD_DAY, CMD_LEN);
    reply.cmd_seq = request->cmd_seq;
    reply.param = htobe64(s_config.free_space);

    return cmd_send(sock, &reply, EMPTY_SIMPL_CMD_SIZE, &client_address);
}

bool do_remove(struct SIMPL_CMD *request, size_t req_len, std::vector<std::string> &filenames) {
    std::error_code ec;

    char buffer[SIMPL_CMD_DATA_SIZE];
    memcpy(buffer, request->data, req_len - EMPTY_SIMPL_CMD_SIZE);
    std::string filename(buffer);
    std::filesystem::path file(s_config.shared_folder + '/' + filename);
    auto file_pos = std::find(filenames.begin(), filenames.end(), filename);

    if (filename.find('/') != std::string::npos || file_pos == filenames.end()
        || !std::filesystem::is_regular_file(file)) {
        return false;
    }

    filenames.erase(file_pos);
    //todo check error_code...
    s_config.free_space += std::filesystem::file_size(file, ec);
    std::filesystem::remove(file, ec);
    return true;
}

bool do_list(int sock, struct SIMPL_CMD *request, size_t req_len, std::vector<std::string> filenames, bool filtered) {
    struct SIMPL_CMD reply;
    memcpy(reply.cmd, MSG_HEADER_MY_LIST, CMD_LEN);
    reply.cmd_seq = request->cmd_seq;

    if (filtered) {
        char buffer[SIMPL_CMD_DATA_SIZE];
        memcpy(buffer, request->data, req_len - EMPTY_SIMPL_CMD_SIZE);

        std::regex pattern(ANYTHING_REGEXP + std::string(buffer) + ANYTHING_REGEXP);
        for (auto it = filenames.begin(); it != filenames.end(); it++) {
            if (!std::regex_match(*it, pattern)) {
                filenames.erase(it);
            }
        }
    }

    std::sort(filenames.begin(), filenames.end());

    for (auto it = filenames.begin(); it != filenames.end();) {
        memset(reply.data, '\0', SIMPL_CMD_DATA_SIZE);
        int left_space = SIMPL_CMD_DATA_SIZE;

        for (; it != filenames.end(); it++) {
            int filename_len = it->length() + 1;
            if (left_space < filename_len) {
                if (!cmd_send(sock, &reply, UDP_DATA_SIZE - left_space, &client_address)) {
                    return false;
                }
                break;
            }

            snprintf(reply.data + (SIMPL_CMD_DATA_SIZE - left_space), filename_len, "%s", it->c_str());
            left_space -= filename_len;
            reply.data[SIMPL_CMD_DATA_SIZE - left_space - 1] = '\n';
        }
        return cmd_send(sock, &reply, UDP_DATA_SIZE - left_space, &client_address); //added last filename to reply
    }

    return true; //filenames.size() == 0
}

bool do_send(int sock, struct SIMPL_CMD *request, size_t req_len, std::vector<std::string> &filenames) {
    struct CMPLX_CMD res;
    int fd;
    int tcp_sock;
    int tcp_port;
    struct sockaddr_in tcp_address;
    pthread_t thread_work;
    char buffer[SIMPL_CMD_DATA_SIZE];
    struct worker_sender_data worker_arg;
    socklen_t sockaddr_size;

    memcpy(buffer, request->data, req_len - EMPTY_SIMPL_CMD_SIZE);
    std::string filename(buffer);
    std::string filepath(s_config.shared_folder + '/' + filename);

    std::error_code ec;
    std::filesystem::path file_path(filepath);

    //filenames lock
    if (std::find(filenames.begin(), filenames.end(), filename) == filenames.end()
        || (fd = open(filepath.c_str(), O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO) == -1)) {
        std::cerr << "File not found\n";
        return false;
    }

    //socket
    tcp_address.sin_addr.s_addr = INADDR_ANY;
    tcp_address.sin_family = AF_INET;
    sockaddr_size = sizeof(tcp_address);

    if ((tcp_sock = socket(PF_INET, SOCK_STREAM, 0)) == -1
        || bind(tcp_sock, (sockaddr *) &tcp_address, sizeof(tcp_address)) == -1
        || listen(tcp_sock, 1)
        || getsockname(tcp_sock, (sockaddr *) &tcp_address, &sockaddr_size) == -1) {
        std::cerr << "Couldn't create socket\n";
        close(fd);
        close(tcp_sock);
        return false;
    }
    tcp_port = tcp_address.sin_port;

    memcpy(res.cmd, MSG_HEADER_CONNECT_ME, CMD_LEN);
    res.cmd_seq = request->cmd_seq;
    res.param = htobe64((uint64_t) tcp_port);
    memcpy(res.data, request->data, req_len - EMPTY_SIMPL_CMD_SIZE);

    bool op_success = cmd_send(sock, &res, EMPTY_CMPLX_CMD_SIZE + (req_len - EMPTY_SIMPL_CMD_SIZE), &client_address);

    worker_arg.file_size = std::filesystem::file_size(file_path, ec);
    worker_arg.fd = fd;
    worker_arg.sock = tcp_sock;
    //todo move worker_arg to heap and add free() in worker
    //!!!!

    op_success = op_success && pthread_create(&thread_work, &thread_attr, work_send, &worker_arg) == 0;

    close(fd);
    close(tcp_port);
    return op_success;
}

bool do_receive() {
    return false;
}

req_type parse_req_type(struct BUF_CMD *buf, ssize_t msg_len) {
    if (memcmp(buf->cmd, MSG_HEADER_HELLO, CMD_LEN) == 0
        && msg_len == EMPTY_SIMPL_CMD_SIZE) {
        return req_type::hello;
    }
    if (memcmp(buf->cmd, MSG_HEADER_DEL, CMD_LEN) == 0
        && msg_len > EMPTY_SIMPL_CMD_SIZE) {
        return req_type::remove;
    }
    if (memcmp(buf->cmd, MSG_HEADER_LIST, CMD_LEN) == 0
        && msg_len >= EMPTY_SIMPL_CMD_SIZE) {
        return (msg_len == EMPTY_SIMPL_CMD_SIZE ? req_type::list_all : req_type::list_exp);
    }
    if (memcmp(buf->cmd, MSG_HEADER_GET, CMD_LEN) == 0
        && msg_len > EMPTY_SIMPL_CMD_SIZE) {
        return req_type::download;
    }
    if (memcmp(buf->cmd, MSG_HEADER_ADD, CMD_LEN) == 0
        && msg_len > EMPTY_CMPLX_CMD_SIZE) {
        return req_type::upload;
    }
    return req_type::invalid;
}

int main(int argc, char *argv[]) {
    int sock;
    std::vector<std::string> filenames;
    struct BUF_CMD buffer;
    struct SIMPL_CMD *buffer_simpl = (struct SIMPL_CMD *) &buffer;
    struct CMPLX_CMD *buffer_cmplx = (struct CMPLX_CMD *) &buffer;
    ssize_t msg_len;

    if (pthread_attr_init(&thread_attr) != 0
        || pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED) != 0
        || sigemptyset(&blockSIGINT) != 0
        || sigaddset(&blockSIGINT, SIGINT) != 0) {
        return 42;
    }

    if (!parse_server_args(argc, argv)) {
        return 1;
    }

    if (!index_files(filenames)) {
        return 2;
    }

    if ((sock = create_socket()) == -1) {
        return 3;
    }

    for (;;) {
        msg_len = cmd_recvfrom(sock, &buffer, &client_address);
        if (msg_len == -1) {
            perror("Recvfrom error\n");
            continue;
        }
        std::cout << "msg received\n";
        switch (parse_req_type(&buffer, msg_len)) {
            case req_type::hello:
                if (!do_hello(sock, buffer_simpl)) {
                    std::cerr << "Error replying to hello\n";
                }
                break;
            case req_type::remove:
                if (!do_remove(buffer_simpl, msg_len, filenames)) {
                    std::cerr << "Error removing file\n";
                }
                break;
            case req_type::list_all:
                if (!do_list(sock, buffer_simpl, msg_len, filenames, false)) {
                    std::cerr << "Error sending list\n";
                }
                break;
            case req_type::list_exp:
                if (!do_list(sock, buffer_simpl, msg_len, filenames, true)) {
                    std::cerr << "Error sending list\n";
                }
                break;
            case req_type::download:
                if (!do_send(sock, buffer_simpl, msg_len, filenames)) {
                    std::cerr << "Error starting file transmission to client\n";
                }
                break;
            case req_type::upload:
                if (!do_receive()) {
                    std::cerr << "Error starting file transmission from client\n";
                }
                break;
            case req_type::invalid:
                pckg_error("", &client_address);
                break;
        }
    }
}
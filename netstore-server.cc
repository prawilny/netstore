#include "netstore.h"
#include "netstore-boost.h"
#include <csignal>

enum class req_type {
    hello,
    remove,
    list_all,
    list_exp,
    upload,
    download,
    invalid
};

static int MAX_FDS_OPEN = 10000;

// global variables:
extern struct server_config s_config;
struct sockaddr_in local_address;
struct sockaddr_in client_address;
std::mutex mutex_space;
std::mutex mutex_files;
std::vector<std::string> filenames;

void work_send(int tcp_sock, int fd, size_t file_size) {
    char buffer[TCP_BUFFER_SIZE];
    struct timeval timeout;
    int sock_fd = -1;
    fd_set rfds;

    timeout.tv_sec = s_config.timeout;
    timeout.tv_usec = 0;

    FD_ZERO(&rfds);
    FD_SET(tcp_sock, &rfds);

    if (select(tcp_sock + 1, &rfds, NULL, NULL, &timeout) != 1
        || (sock_fd = accept(tcp_sock, NULL, NULL)) == -1
        || fdncpy(sock_fd, fd, file_size, buffer, TCP_BUFFER_SIZE) == -1){
        ;
    }

    close(tcp_sock);
    close(fd);
    close(sock_fd);
    return;
}

void work_receive(int tcp_sock, int fd, size_t file_size, const char *filename) {
    char buffer[TCP_BUFFER_SIZE];
    struct timeval timeout;
    int sock_fd = -1;
    fd_set rfds;
    std::filesystem::path file_node = s_config.shared_folder + '/' + filename;

    timeout.tv_usec = 0;
    timeout.tv_sec = s_config.timeout;

    FD_ZERO(&rfds);
    FD_SET(tcp_sock, &rfds);

    if (select(tcp_sock + 1, &rfds, NULL, NULL, &timeout) != 1
        || (sock_fd = accept(tcp_sock, NULL, NULL)) == -1
        || fdncpy(fd, sock_fd, file_size, buffer, TCP_BUFFER_SIZE) == -1) {
        unlink(file_node.c_str());
        {
            mutex_space.lock();
            s_config.free_space += (int64_t) file_size;
            mutex_space.unlock();
        }
    } else {
        {
            mutex_files.lock();
            filenames.push_back(filename);
            mutex_files.unlock();
        }
    }

    close(sock_fd);
    close(fd);
    close(tcp_sock);
    return;
}

bool index_files(std::vector<std::string> &names) {
    std::filesystem::path dir(s_config.shared_folder);
    std::error_code ec;

    if (!std::filesystem::is_directory(dir, ec) || ec) {
        return false;
    }

    const std::filesystem::directory_iterator end{};
    try {
        for (std::filesystem::directory_iterator iter{dir}; iter != end; ++iter) {
            if (std::filesystem::is_regular_file(*iter, ec) && !ec
                && iter->path().filename().string().length() < CMPLX_CMD_DATA_SIZE) {
                names.push_back(iter->path().filename());
                uint64_t f_size = iter->file_size(ec);
                if (!ec) {
                    s_config.free_space -= (int64_t) f_size;
                }
            }
        }
    }
    catch (std::exception &e) {
        return false;
    }
    return true;
}

int udp_multicast_socket() {
    int sock = -1;
    struct ip_mreq ip_mreq;
    int enable_flag = 1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return -1;
    }

    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(s_config.server_address.c_str(), &ip_mreq.imr_multiaddr) == 0) {
        close(sock);
        return -1;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &ip_mreq, sizeof(ip_mreq)) == -1
        || setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &enable_flag, sizeof(enable_flag)) == -1
        || setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable_flag, sizeof(enable_flag)) == -1) {
        close(sock);
        return -1;
    }

    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons((uint16_t) s_config.server_port);
    if (bind(sock, (struct sockaddr *) &local_address, sizeof(local_address)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

int tcp_socket(struct sockaddr_in *tcp_address) {
    int tcp_sock = -1;

    tcp_address->sin_addr.s_addr = INADDR_ANY;
    tcp_address->sin_family = AF_INET;
    tcp_address->sin_port = 0;
    socklen_t sockaddr_size = sizeof(tcp_address);

    if ((tcp_sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        return -1;
    }
    if (bind(tcp_sock, (sockaddr *) tcp_address, sizeof(*tcp_address)) == -1) {
        close(tcp_sock);
        return -1;
    }
    if (listen(tcp_sock, 1) == -1) {
        close(tcp_sock);
        return -1;
    }
    if (getsockname(tcp_sock, (sockaddr *) tcp_address, &sockaddr_size) == -1) {
        close(tcp_sock);
        return -1;
    }
    return tcp_sock;
}

bool do_hello(int sock, struct SIMPL_CMD *request) {
    struct CMPLX_CMD reply;

    memcpy(reply.cmd, MSG_HEADER_GOOD_DAY, CMD_LEN);
    reply.cmd_seq = request->cmd_seq;
    reply.param = htobe64(s_config.free_space < 0 ? 0 : s_config.free_space);
    sprintf(reply.data, "%s", s_config.server_address.c_str());

    return cmd_send(sock, &reply, EMPTY_CMPLX_CMD_SIZE + s_config.server_address.length(), &client_address);
}

bool do_remove(struct SIMPL_CMD *request, size_t req_len) {
    std::error_code ec;
    int data_len = req_len = EMPTY_SIMPL_CMD_SIZE;
    size_t f_size;

    char buffer[SIMPL_CMD_DATA_SIZE + 1];
    memcpy(buffer, request->data, data_len);
    buffer[data_len] = '\0';

    std::string filename = std::string(buffer);
    std::filesystem::path file(s_config.shared_folder + '/' + filename);
    {
        mutex_files.lock();
        auto file_pos = std::find(filenames.begin(), filenames.end(), filename);
        bool file_to_delete = (filename.find('/') == std::string::npos
                               && std::filesystem::is_regular_file(file, ec) && !ec
                               && file_pos != filenames.end());
        if (file_to_delete) {
            filenames.erase(file_pos);
        }
        mutex_files.unlock();

        if (!file_to_delete) {
            return false;
        }
    }

    f_size = std::filesystem::file_size(file, ec);
    if (!ec) {
        {
            mutex_space.lock();
            s_config.free_space += f_size;
            mutex_space.unlock();
        }
    }
    unlink(file.c_str());
    return true;
}

bool do_list(int sock, struct SIMPL_CMD *request, size_t req_len, bool filtered) {
    struct SIMPL_CMD reply;
    std::vector<std::string> filenames_local;
    int data_len = req_len - EMPTY_SIMPL_CMD_SIZE;

    memcpy(reply.cmd, MSG_HEADER_MY_LIST, CMD_LEN);
    reply.cmd_seq = request->cmd_seq;

    {
        mutex_files.lock();
        filenames_local = filenames;
        mutex_files.unlock();
    }

    if (filtered) {
        char buffer[SIMPL_CMD_DATA_SIZE + 1];
        memcpy(buffer, request->data, data_len);
        buffer[data_len] = '\0';

        for (auto it = filenames_local.begin(); it != filenames_local.end();) {
            if (strstr((*it).c_str(), buffer) == NULL) {
                it = filenames_local.erase(it);
            } else {
                it++;
            }
        }
    }

    std::sort(filenames_local.begin(), filenames_local.end());

    int left_space = SIMPL_CMD_DATA_SIZE;
    memset(reply.data, '\n', SIMPL_CMD_DATA_SIZE);

    for (auto it = filenames_local.begin(); it != filenames_local.end();) {
        int filename_len = it->length();
        if (SIMPL_CMD_DATA_SIZE <= filename_len) {
            return false;
        }

        if (left_space <= filename_len) {
            if (!cmd_send(sock, &reply, UDP_DATA_SIZE - left_space - 1, &client_address)) {
                return false;
            }
            left_space = SIMPL_CMD_DATA_SIZE;
            memset(reply.data, '\n', SIMPL_CMD_DATA_SIZE);
            continue;
        } else {
            snprintf(reply.data + (SIMPL_CMD_DATA_SIZE - left_space), filename_len + 1, "%s", it->c_str());
            reply.data[SIMPL_CMD_DATA_SIZE - left_space + filename_len] = '\n';
            left_space -= (filename_len + 1);
            it++;
        }
        if (it == filenames_local.end()) {
            return cmd_send(sock, &reply, UDP_DATA_SIZE - left_space - 1, &client_address);
        }
    }

    return true;
}

bool do_send(int sock, struct SIMPL_CMD *request, size_t req_len) {
    struct CMPLX_CMD res;
    int fd = -1;
    int tcp_sock = -1;
    int tcp_port;
    struct sockaddr_in tcp_address;
    char buffer[SIMPL_CMD_DATA_SIZE];
    int data_len = req_len - EMPTY_SIMPL_CMD_SIZE;

    memcpy(buffer, request->data, data_len);
    buffer[data_len] = '\0';
    std::string filename(buffer);
    std::string filepath(s_config.shared_folder + '/' + filename);

    std::error_code ec;
    std::filesystem::path file_node(filepath);

    {
        mutex_files.lock();
        auto file_pos = std::find(filenames.begin(), filenames.end(), filename);
        auto filenames_end = filenames.end();
        mutex_files.unlock();
        if (file_pos == filenames_end) {
            return false;
        }
    }

    if ((fd = open(filepath.c_str(), O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO)) == -1) {
        return false;
    }

    size_t file_size = std::filesystem::file_size(file_node, ec);
    if (ec) {
        close(fd);
        return false;
    }

    if ((tcp_sock = tcp_socket(&tcp_address)) == -1) {
        close(fd);
        return false;
    }
    tcp_port = ntohs(tcp_address.sin_port);

    memcpy(res.cmd, MSG_HEADER_CONNECT_ME, CMD_LEN);
    res.cmd_seq = request->cmd_seq;
    res.param = htobe64((uint64_t) tcp_port);
    memcpy(res.data, request->data, data_len);

    bool msg_sent = cmd_send(sock, &res, EMPTY_CMPLX_CMD_SIZE + data_len, &client_address);

    std::thread worker(work_send, tcp_sock, fd, file_size);
    worker.detach();

    return msg_sent;
}

bool do_receive(int sock, struct CMPLX_CMD *request, size_t req_len, std::vector<std::string> &filenames) {
    struct CMPLX_CMD response;
    struct SIMPL_CMD no_way;
    int fd = -1;
    int tcp_sock = -1;
    int tcp_port;
    uint64_t file_size;
    struct sockaddr_in tcp_address;
    char buffer[SIMPL_CMD_DATA_SIZE];
    int data_len = req_len - EMPTY_SIMPL_CMD_SIZE;

    memcpy(buffer, request->data, data_len);
    buffer[data_len] = '\0';
    std::string filename(buffer);
    std::string filepath(s_config.shared_folder + '/' + filename);
    file_size = be64toh(request->param);

    if ((int64_t) file_size > s_config.free_space || filename.find('/') != std::string::npos
        || filename.length() == 0) {
        memcpy(no_way.cmd, MSG_HEADER_NO_WAY, CMD_LEN);
        no_way.cmd_seq = request->cmd_seq;
        return cmd_send(sock, &no_way, EMPTY_SIMPL_CMD_SIZE, &client_address);
    }

    {
        mutex_files.lock();
        auto file_pos = std::find(filenames.begin(), filenames.end(), filename);
        auto filenames_end = filenames.end();
        mutex_files.unlock();
        if (file_pos != filenames_end) {
            return false;
        }
    }

    if ((fd = open(filepath.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRWXU | S_IRWXG | S_IRWXO)) == -1) {
        return false;
    }

    if ((tcp_sock = tcp_socket(&tcp_address)) == -1) {
        close(fd);
        unlink(filepath.c_str());
        return false;
    }
    tcp_port = ntohs(tcp_address.sin_port);

    memcpy(response.cmd, MSG_HEADER_CAN_ADD, CMD_LEN);
    response.param = htobe64((uint64_t) tcp_port);
    response.cmd_seq = request->cmd_seq;
    memcpy(response.data, request->data, CMPLX_CMD_DATA_SIZE);

    {
        mutex_space.lock();
        s_config.free_space -= (int64_t) file_size;
        mutex_space.unlock();
    }
    bool msg_sent = cmd_send(sock, &response, req_len, &client_address);

    std::thread worker(work_receive, tcp_sock, fd, file_size, filename.c_str());
    worker.detach();

    return msg_sent;
}

req_type parse_req_type(struct BUF_CMD *buf, ssize_t msg_len) {
    if (msg_len == EMPTY_SIMPL_CMD_SIZE
        && memcmp(buf->cmd, MSG_HEADER_HELLO, CMD_LEN) == 0) {
        return req_type::hello;
    }
    if (msg_len > EMPTY_SIMPL_CMD_SIZE
        && memcmp(buf->cmd, MSG_HEADER_DEL, CMD_LEN) == 0) {
        return req_type::remove;
    }
    if (msg_len >= EMPTY_SIMPL_CMD_SIZE
        && memcmp(buf->cmd, MSG_HEADER_LIST, CMD_LEN) == 0) {
        return (msg_len == EMPTY_SIMPL_CMD_SIZE ? req_type::list_all : req_type::list_exp);
    }
    if (msg_len > EMPTY_SIMPL_CMD_SIZE
        && memcmp(buf->cmd, MSG_HEADER_GET, CMD_LEN) == 0) {
        return req_type::download;
    }
    if (msg_len > EMPTY_CMPLX_CMD_SIZE
        && memcmp(buf->cmd, MSG_HEADER_ADD, CMD_LEN) == 0) {
        return req_type::upload;
    }
    return req_type::invalid;
}

void sigint_handler(int signal) {
    (void) signal;

    for (int i = 3; i <= MAX_FDS_OPEN; i++) {
        close(i);
    }
    quick_exit(0);
}

int main(int argc, char *argv[]) {
    int sock;
    struct BUF_CMD buffer;
    ssize_t msg_len;

    if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        return 9;
    }

    if (!parse_server_args(argc, argv)) {
        return 1;
    }

    if (!index_files(filenames)) {
        return 2;
    }

    if ((sock = udp_multicast_socket()) == -1) {
        return 3;
    }

    for (;;) {
        msg_len = cmd_recvfrom(sock, &buffer, &client_address);
        if (msg_len == -1) {
            continue;
        }
        switch (parse_req_type(&buffer, msg_len)) {
            case req_type::hello:
                do_hello(sock, (struct SIMPL_CMD *) &buffer);
                break;
            case req_type::remove:
                do_remove((struct SIMPL_CMD *) &buffer, msg_len);
                break;
            case req_type::list_all:
                do_list(sock, (struct SIMPL_CMD *) &buffer, msg_len, false);
                break;
            case req_type::list_exp:
                do_list(sock, (struct SIMPL_CMD *) &buffer, msg_len, true);
                break;
            case req_type::download:
                do_send(sock, (struct SIMPL_CMD *) &buffer, msg_len);
                break;
            case req_type::upload:
                do_receive(sock, (struct CMPLX_CMD *) &buffer, msg_len, filenames);
                break;
            case req_type::invalid:
                printf(msg_pckg_error, inet_ntoa(client_address.sin_addr), (int) ntohs(client_address.sin_port),
                       "Command not recognized");
                break;
        }
    }
}
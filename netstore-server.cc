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

// global variables:
extern struct server_config s_config;
struct sockaddr_in local_address;
struct sockaddr_in client_address;

//checked
void work_send(int tcp_sock, int fd, size_t file_size) {
    char buffer[TCP_BUFFER_SIZE];
    struct timeval timeout;
    int sock_fd;
    fd_set rfds;

    timeout.tv_usec = 0;
    timeout.tv_sec = s_config.timeout;

    FD_ZERO(&rfds);
    FD_SET(tcp_sock, &rfds);

    if (select(tcp_sock + 1, &rfds, NULL, NULL, &timeout) != 1
        || (sock_fd = accept(tcp_sock, NULL, NULL)) == -1
        || fdncpy(sock_fd, fd, file_size, buffer, TCP_BUFFER_SIZE) == -1) {
        std::cerr << "Something went wrong receiving\n";
    }

    //todo edit filelist

    close(tcp_sock);
    close(fd);
    close(sock_fd);
    return;
}

//checked
void work_receive(int tcp_sock, int fd, size_t file_size, const char *filename) {
    char buffer[TCP_BUFFER_SIZE];
    struct timeval timeout;
    int sock_fd;
    fd_set rfds;

    timeout.tv_usec = 0;
    timeout.tv_sec = s_config.timeout;

    FD_ZERO(&rfds);
    FD_SET(tcp_sock, &rfds);

    if (select(tcp_sock + 1, &rfds, NULL, NULL, &timeout) != 1
        || (sock_fd = accept(tcp_sock, NULL, NULL)) == -1
        || fdncpy(fd, sock_fd, file_size, buffer, TCP_BUFFER_SIZE) == -1) {
        std::cerr << "Something went wrong receiving\n";
        remove(filename);
    } else {
        std::cout << "Upload succesful.\n";
    }

    close(sock_fd);
    close(fd);
    close(tcp_sock);
    return;
}

//checked
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
                uint64_t f_size = iter->file_size();
                if (f_size > s_config.free_space) {
                    std::cerr << "Shared folder's size exceeds limit\n";
                    return false;
                }
                s_config.free_space -= f_size;
            }
        }
    }
    catch (std::exception &e) {
        std::cerr << "filesystem error while indexing: " << e.what() << "\n";
        return false;
    }
    return true;
}

//checked
int udp_multicast_socket() {
    int sock;
    struct ip_mreq ip_mreq;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(s_config.server_address.c_str(), &ip_mreq.imr_multiaddr) == 0) {
        perror("inet_aton");
        close(sock);
        return -1;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &ip_mreq, sizeof(ip_mreq)) == -1) {
        perror("setsockopt");
        close(sock);
        return -1;
    }

    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_ANY);
    local_address.sin_port = htons((uint16_t) s_config.server_port);
    if (bind(sock, (struct sockaddr *) &local_address, sizeof(local_address)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

//checked
int tcp_socket(struct sockaddr_in *tcp_address) {
    int tcp_sock;

    tcp_address->sin_addr.s_addr = INADDR_ANY;
    tcp_address->sin_family = AF_INET;
    socklen_t sockaddr_size = sizeof(tcp_address);

    if ((tcp_sock = socket(PF_INET, SOCK_STREAM, 0)) == -1
        || bind(tcp_sock, (sockaddr *) tcp_address, sizeof(tcp_address)) == -1
        || listen(tcp_sock, 1)
        || getsockname(tcp_sock, (sockaddr *) tcp_address, &sockaddr_size) == -1) {
        return -1;
    }

    return tcp_sock;
}

//checked
bool do_hello(int sock, struct SIMPL_CMD *request) {
    struct CMPLX_CMD reply;

    memcpy(reply.cmd, MSG_HEADER_GOOD_DAY, CMD_LEN);
    reply.cmd_seq = request->cmd_seq;
    reply.param = htobe64(s_config.free_space);

    return cmd_send(sock, &reply, EMPTY_CMPLX_CMD_SIZE, &client_address);
}

//checked
bool do_remove(struct SIMPL_CMD *request, size_t req_len, std::vector<std::string> &filenames) {
    std::error_code ec;
    int data_len = req_len = EMPTY_SIMPL_CMD_SIZE;
    size_t f_size;

    char buffer[SIMPL_CMD_DATA_SIZE + 1];
    memcpy(buffer, request->data, data_len);
    buffer[data_len] = '\0';

    std::string filename = std::string(buffer);
    std::filesystem::path file(s_config.shared_folder + '/' + filename);
    auto file_pos = std::find(filenames.begin(), filenames.end(), filename);

    if (filename.find('/') != std::string::npos || file_pos == filenames.end()
        || !std::filesystem::is_regular_file(file)) {
        return false;
    }
    filenames.erase(file_pos);

    f_size = std::filesystem::file_size(file, ec);
    if (ec) {
        s_config.free_space += f_size;
    }
    std::filesystem::remove(file, ec);
    return true;
}

//checked
bool do_list(int sock, struct SIMPL_CMD *request, size_t req_len, std::vector<std::string> filenames, bool filtered) {
    struct SIMPL_CMD reply;
    int data_len = req_len - EMPTY_SIMPL_CMD_SIZE;

    memcpy(reply.cmd, MSG_HEADER_MY_LIST, CMD_LEN);
    reply.cmd_seq = request->cmd_seq;

    if (filtered) {
        char buffer[SIMPL_CMD_DATA_SIZE + 1];
        memcpy(buffer, request->data, data_len);
        buffer[data_len] = '\0';

        for (auto it = filenames.begin(); it != filenames.end();) {
            if (strstr((*it).c_str(), buffer) == NULL) {
                it = filenames.erase(it);
            } else {
                it++;
            }
        }
    }

    std::sort(filenames.begin(), filenames.end());

    int left_space = SIMPL_CMD_DATA_SIZE;
    memset(reply.data, '\0', SIMPL_CMD_DATA_SIZE);

    for (auto it = filenames.begin(); it != filenames.end();) {
        int filename_len = it->length();
        if (filename_len >= SIMPL_CMD_DATA_SIZE){
            return false;
        }

        if (left_space <= filename_len) {
            if (!cmd_send(sock, &reply, UDP_DATA_SIZE - left_space, &client_address)) {
                return false;
            }
            left_space = SIMPL_CMD_DATA_SIZE;
            memset(reply.data, '\0', SIMPL_CMD_DATA_SIZE);
        } else {
            snprintf(reply.data + (SIMPL_CMD_DATA_SIZE - left_space), filename_len, "%s", it->c_str());
            reply.data[SIMPL_CMD_DATA_SIZE - left_space + filename_len] = '\n';
            left_space -= (filename_len + 1);
            it++;
        }
        if (it == filenames.end()) {
            return cmd_send(sock, &reply, UDP_DATA_SIZE - left_space, &client_address);
        }
    }

    return true;
}

//checked
bool do_send(int sock, struct SIMPL_CMD *request, size_t req_len, std::vector<std::string> &filenames) {
    struct CMPLX_CMD res;
    int fd;
    int tcp_sock;
    int tcp_port;
    struct sockaddr_in tcp_address;
    char buffer[SIMPL_CMD_DATA_SIZE];
    int data_len = req_len - EMPTY_SIMPL_CMD_SIZE;

    memcpy(buffer, request->data, data_len);
    buffer[data_len] = '\0';
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

    if ((tcp_sock = tcp_socket(&tcp_address)) == -1) {
        std::cerr << "Couldn't create socket\n";
        close(fd);
        return false;
    }
    tcp_port = tcp_address.sin_port;

    memcpy(res.cmd, MSG_HEADER_CONNECT_ME, CMD_LEN);
    res.cmd_seq = request->cmd_seq;
    res.param = htobe64((uint64_t) tcp_port);
    memcpy(res.data, request->data, data_len);

    bool msg_sent = cmd_send(sock, &res, EMPTY_CMPLX_CMD_SIZE + data_len, &client_address);

    size_t file_size = std::filesystem::file_size(file_path, ec);
    std::thread worker(work_send, tcp_sock, fd, file_size);
    worker.detach();

    close(fd);
    close(tcp_port);
    return msg_sent;
}

//checked
bool do_receive(int sock, struct CMPLX_CMD *request, size_t req_len, std::vector<std::string> &filenames) {
    struct CMPLX_CMD msg;
    int fd;
    int tcp_sock;
    int tcp_port;
    size_t file_size;
    struct sockaddr_in tcp_address;
    char buffer[SIMPL_CMD_DATA_SIZE];
    int data_len = req_len - EMPTY_SIMPL_CMD_SIZE;

    memcpy(buffer, request->data, data_len);
    buffer[data_len] = '\0';
    std::string filename(buffer);
    std::string filepath(s_config.shared_folder + '/' + filename);
    file_size = be64toh(msg.param);

    if (file_size > s_config.free_space || filename.find('/') != std::string::npos || filename.length() == 0) {
        memcpy(msg.cmd, MSG_HEADER_NO_WAY, CMD_LEN);
        return cmd_send(sock, &msg, EMPTY_SIMPL_CMD_SIZE, &client_address);
    }

    if (std::find(filenames.begin(), filenames.end(), filename) != filenames.end()
        || (fd = open(filepath.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRWXU | S_IRWXG | S_IRWXO) == -1)) {
        std::cerr << "File already present\n";
        return false;
    }

    if ((tcp_sock = tcp_socket(&tcp_address)) == -1) {
        std::cerr << "Couldn't create socket\n";
        close(fd);
        return false;
    }
    tcp_port = tcp_address.sin_port;

    memcpy(msg.cmd, MSG_HEADER_CONNECT_ME, CMD_LEN);
    msg.param = htobe64((uint64_t) tcp_port);

    s_config.free_space -= file_size;
    bool msg_sent = cmd_send(sock, &msg, req_len, &client_address);

    std::thread worker(work_receive, tcp_sock, fd, file_size, filename.c_str());
    worker.detach();

    close(fd);
    close(tcp_port);
    return msg_sent;
}

//checked
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
    quick_exit(0);
}

//checked
int main(int argc, char *argv[]) {
    int sock;
    std::vector<std::string> filenames;
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
            perror("Recvfrom error\n");
            continue;
        }
        std::cout << "Message received\n";
        switch (parse_req_type(&buffer, msg_len)) {
            case req_type::hello:
                if (!do_hello(sock, (struct SIMPL_CMD *) &buffer)) {
                    perror("Error replying to hello\n");
                }
                break;
            case req_type::remove:
                if (!do_remove((struct SIMPL_CMD *) &buffer, msg_len, filenames)) {
                    perror("Error removing file\n");
                }
                break;
            case req_type::list_all:
                if (!do_list(sock, (struct SIMPL_CMD *) &buffer, msg_len, filenames, false)) {
                    perror("Error sending list\n");
                }
                break;
            case req_type::list_exp:
                if (!do_list(sock, (struct SIMPL_CMD *) &buffer, msg_len, filenames, true)) {
                    perror("Error sending list\n");
                }
                break;
            case req_type::download:
                if (!do_send(sock, (struct SIMPL_CMD *) &buffer, msg_len, filenames)) {
                    perror("Error starting file transmission to client\n");
                }
                break;
            case req_type::upload:
                if (!do_receive(sock, (struct CMPLX_CMD *) &buffer, msg_len, filenames)) {
                    perror("Error starting file transmission from client\n");
                }
                break;
            case req_type::invalid:
                pckg_error("Invalid message metadata", &client_address);
                break;
        }
    }
}
#include "netstore.h"
#include "netstore-boost.h"
#include <regex>

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

// global variables:
extern struct server_config s_config;
struct sockaddr_in local_address;
struct sockaddr_in client_address;

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

    reply.cmd_seq = request->cmd_seq;
    memcpy(reply.cmd, MSG_HEADER_GOOD_DAY, CMD_LEN);
    reply.param = htobe64(s_config.free_space);

    return cmd_send(sock, &reply, EMPTY_SIMPL_CMD_SIZE, &client_address);
}

bool do_remove(struct SIMPL_CMD *request, std::vector<std::string> &filenames) {
    std::error_code ec;
    std::string filename(request->data);
    std::filesystem::path file(s_config.shared_folder + '/' + filename);
    auto file_pos = std::find(filenames.begin(), filenames.end(), filename);

    if (filename.find('/') != std::string::npos || file_pos == filenames.end()
        || !std::filesystem::is_regular_file(file)) {
        return false;
    }

    filenames.erase(file_pos);
    s_config.free_space += std::filesystem::file_size(file);
    std::filesystem::remove(file, ec);
    return true;
}

bool do_list(int sock, struct SIMPL_CMD *request, std::vector<std::string> filenames, bool filtered) {
    struct SIMPL_CMD reply;
    memcpy(reply.cmd, MSG_HEADER_MY_LIST, CMD_LEN);
    reply.cmd_seq = request->cmd_seq;

    if (filtered) {
        std::regex pattern(ANYTHING_REGEXP + std::string(request->data) + ANYTHING_REGEXP);
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

req_type parse_req_type(struct BUF_CMD *buf, ssize_t msg_len) {
    if (memcmp(buf->cmd, MSG_HEADER_HELLO, CMD_LEN) == 0
        && msg_len == EMPTY_SIMPL_CMD_SIZE) {
        return req_type::hello;
    }
    if (memcmp(buf->cmd, MSG_HEADER_DEL, CMD_LEN) == 0
        && msg_len != EMPTY_SIMPL_CMD_SIZE) {
        return req_type::remove;
    }
    if (memcmp(buf->cmd, MSG_HEADER_LIST, CMD_LEN) == 0) {
        return (msg_len == EMPTY_SIMPL_CMD_SIZE ? req_type::list_all : req_type::list_exp);
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
                if (!do_remove(buffer_simpl, filenames)) {
                    std::cerr << "Error removing file\n";
                }
                break;
            case req_type::list_all:
                if (!do_list(sock, buffer_simpl, filenames, false)) {
                    std::cerr << "Error sending list\n";
                }
                break;
            case req_type::list_exp:
                if (!do_list(sock, buffer_simpl, filenames, true)) {
                    std::cerr << "Error sending list\n";
                }
                break;
            default:
                pckg_error(&client_address);
                break;
        }
    }
}
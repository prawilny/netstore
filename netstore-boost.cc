#include "netstore-boost.h"
#include <filesystem>

static constexpr int DEFAULT_TIMEOUT = 5;
static constexpr int MAX_TIMEOUT = 300;
static constexpr int MAX_PORT = 65535;
static std::string IPV4_REGEXP = "^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\\.(?!$)|$)){4}$";

static constexpr int DEFAULT_SERVER_FREE = 52428800;

struct server_config s_config;
struct client_config c_config;

bool parse_client_args(int argc, char **argv) {
    try {
        namespace po = boost::program_options;

        po::options_description desc("options");
        desc.add_options()
                ("help,h", "help message")
                (",g", po::value<std::string>(&c_config.server_address)->required(), "multicast address of servers")
                (",p", po::value<int>(&c_config.server_port)->required(), "server port")
                (",o", po::value<std::string>(&c_config.download_folder)->required(), "download folder")
                (",t", po::value<int>(&c_config.timeout)->default_value(DEFAULT_TIMEOUT), "timeout for server replies");

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc)
                          .style(po::command_line_style::unix_style | po::command_line_style::allow_long_disguise)
                          .run(), vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            exit(0);
        }
        po::notify(vm);

        if (!(std::regex_match(c_config.server_address, std::regex(IPV4_REGEXP)))) {
            throw std::invalid_argument("Server address is not a valid ipv4 address");
        }
        if (c_config.server_port < 0 || MAX_PORT < c_config.server_port) {
            throw std::invalid_argument("Server port is not valid");
        }
        if (c_config.timeout <= 0 || MAX_TIMEOUT < c_config.timeout) {
            throw std::invalid_argument("Timeout is not valid");
        }
        if (!std::filesystem::is_directory(std::filesystem::path(c_config.download_folder))) {
            throw std::invalid_argument("Download folder does not exist");
        }
    }
    catch (std::exception &e) {
        std::cerr << "error: " << e.what() << "\n";
        return false;
    }
    return true;
}

bool parse_server_args(int argc, char **argv) {
    try {
        namespace po = boost::program_options;

        po::options_description desc("options");
        desc.add_options()
                ("help,h", "help message")
                (",g", po::value<std::string>(&s_config.server_address)->required(), "multicast address")
                (",p", po::value<int>(&s_config.server_port)->required(), "udp port")
                (",f", po::value<std::string>(&s_config.shared_folder)->required(), "shared folder")
                (",t", po::value<int>(&s_config.timeout)->default_value(DEFAULT_TIMEOUT),
                 "timeout for client connections")
                (",b", po::value<int64_t>(&s_config.free_space)->default_value(DEFAULT_SERVER_FREE),
                 "shared folder max size");

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc)
                          .style(po::command_line_style::unix_style | po::command_line_style::allow_long_disguise)
                          .run(), vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            exit(0);
        }
        po::notify(vm);

        if (!(std::regex_match(s_config.server_address, std::regex(IPV4_REGEXP)))) {
            throw std::invalid_argument("Server address is not a valid ipv4 address");
        }
        if (s_config.server_port < 0 || MAX_PORT < s_config.server_port) {
            throw std::invalid_argument("Server port is not valid");
        }
        if (s_config.timeout <= 0 || MAX_TIMEOUT < s_config.timeout) {
            throw std::invalid_argument("Timeout is not valid");
        }
        if (!std::filesystem::is_directory(std::filesystem::path(s_config.shared_folder))) {
            throw std::invalid_argument("Shared folder does not exist");
        }
    }
    catch (std::exception &e) {
        std::cerr << "error: " << e.what() << "\n";
        return false;
    }
    return true;
}
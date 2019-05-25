#include "netstore.h"

static constexpr int DEFAULT_FREE = 52428800;

struct server_config {
    std::string server_address;
    int server_port;
    std::string shared_folder;
    uint64_t free_space;
    int timeout;
};

bool parse_commandline_args(struct server_config *config, int argc, char **argv) {
    try {
        namespace po = boost::program_options;

        po::options_description desc(std::string(argv[0]).append(" options"));
        desc.add_options()
                ("help,h", "help message")
                (",g", po::value<std::string>(&config->server_address)->required(), "multicast address")
                (",p", po::value<int>(&config->server_port)->required(), "udp port")
                (",f", po::value<std::string>(&config->shared_folder)->required(), "shared folder")
                (",t", po::value<int>(&config->timeout)->default_value(DEFAULT_TIMEOUT),
                 "timeout for client connections")
                (",b", po::value<uint64_t>(&config->free_space)->default_value(DEFAULT_FREE), "shared folder max size");

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc)
                          .style(po::command_line_style::unix_style | po::command_line_style::allow_long_disguise)
                          .run(), vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return true;
        }
        po::notify(vm);

        if (!(std::regex_match(config->server_address, std::regex(IPV4_REGEXP)))) {
            throw std::invalid_argument("Server address is not a valid ipv4 address");
        }
        if (config->server_port < 0 || MAX_PORT < config->server_port) {
            throw std::invalid_argument("Server port is not valid");
        }
        if (config->timeout <= 0 || MAX_TIMEOUT < config->timeout) {
            throw std::invalid_argument("Timeout is not valid");
        }
    }
    catch (std::exception &e) {
        std::cerr << "error: " << e.what() << "\n";
        return false;
    }
    return true;
}

bool index_files(std::vector<std::string> &names, std::filesystem::path path, uint64_t *free_space) {
    namespace stdfs = std::filesystem;

    const stdfs::directory_iterator end{};
    try {
        for (stdfs::directory_iterator iter{path}; iter != end; ++iter) {
            if (stdfs::is_regular_file(*iter)) {
                names.push_back(iter->path().string());
                uint64_t fSize = iter->file_size();
                if (fSize > *free_space) {
                    std::cerr << "Shared folder's size exceeds limit\n";
                    return false;
                }
                *free_space -= fSize;
            }
        }
    }
    catch (std::exception &e) {
        std::cerr << "filesystem error while indexing: " << e.what() << "\n";
        return false;
    }
    return true;
}

int main(int argc, char *argv[]) {
    struct server_config config;

    std::vector<std::string> filenames;

    if (!parse_commandline_args(&config, argc, argv)) {
        return 1;
    }

    if (!index_files(filenames, config.shared_folder, &config.free_space)) {
        return 2;
    }

    return 0;
}
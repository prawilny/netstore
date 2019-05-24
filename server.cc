#include "netstore.h"

static constexpr int DEFAULT_FREE = 52428800;

int get_filenames(std::vector<std::string> &names, std::filesystem::path path, uint64_t *freeSpace) {
    namespace stdfs = std::filesystem;

    const stdfs::directory_iterator end{};
    try {
        for (stdfs::directory_iterator iter{path}; iter != end; ++iter) {
            if (stdfs::is_regular_file(*iter)) {
                names.push_back(iter->path().string());
                uint64_t fSize = iter->file_size();
                if (fSize > *freeSpace) {
                    return 1;
                }
                *freeSpace -= fSize;
            }
        }
    }
    catch (std::exception &e){
        std::cerr << "filesystem error while indexing: " << e.what() << "\n";
        return 2;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    std::string serverAddress, sharedFolder;
    int serverPort, timeout;
    uint64_t freeSpace;
    std::vector<std::string> filenames;

    try {
        namespace po = boost::program_options;

        po::options_description desc(std::string(argv[0]).append(" options"));
        desc.add_options()
                ("help,h", "help message")
                (",g", po::value<std::string>(&serverAddress)->required(), "multicast address")
                (",p", po::value<int>(&serverPort)->required(), "udp port")
                (",f", po::value<std::string>(&sharedFolder)->required(), "shared folder")
                (",t", po::value<int>(&timeout)->default_value(DEFAULT_TIMEOUT), "timeout for client connections")
                (",b", po::value<uint64_t>(&freeSpace)->default_value(DEFAULT_FREE), "shared folder max size");

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc)
                          .style(po::command_line_style::unix_style | po::command_line_style::allow_long_disguise)
                          .run(), vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return 0;
        }
        po::notify(vm);

        if (!(std::regex_match(serverAddress, std::regex(IPV4_REGEXP)))) {
            throw std::invalid_argument("Server address is not a valid ipv4 address");
        }
        if (serverPort < 0 || MAX_PORT < serverPort) {
            throw std::invalid_argument("Server port is not valid");
        }
        if (timeout <= 0 || MAX_TIMEOUT < timeout) {
            throw std::invalid_argument("Timeout is not valid");
        }
    }
    catch (std::exception &e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }

    if (get_filenames(filenames, sharedFolder, &freeSpace) != 0){
        return 2;
    }

    return 0;
}
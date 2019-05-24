#include "netstore.h"

using namespace std;

static constexpr int DEFAULT_FREE = 52428800;

int main(int argc, char *argv[]) {
    std::string serverAddress, downloadFolder;
    int serverPort, timeout;
    uint64_t freeSpace;

    try {
        po::options_description desc(string(argv[0]).append(" options"));
        desc.add_options()
                ("help,h", "help message")
                (",g", po::value<std::string>(&serverAddress)->required(), "multicast address")
                (",p", po::value<int>(&serverPort)->required(), "udp port")
                (",f", po::value<std::string>(&downloadFolder)->required(), "shared folder")
                (",t", po::value<int>(&timeout)->default_value(DEFAULT_TIMEOUT), "timeout for client connections");
        (",b", po::value<uint64_t>(&freeSpace)->default_value(DEFAULT_FREE), "shared folder max size");

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc)
                          .style(po::command_line_style::unix_style | po::command_line_style::allow_long_disguise)
                          .run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            cout << desc << "\n";
            return 0;
        }

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
    catch (exception &e) {
        cerr << "error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
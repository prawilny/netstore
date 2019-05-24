#include "netstore.h"

int main(int argc, char *argv[]) {
    std::string serverAddress, downloadFolder;
    int serverPort, timeout;

    try {
        namespace po = boost::program_options;

        po::options_description desc(std::string(argv[0]).append(" options"));
        desc.add_options()
                ("help,h", "help message")
                (",g", po::value<std::string>(&serverAddress)->required(), "multicast address of servers")
                (",p", po::value<int>(&serverPort)->required(), "server port")
                (",o", po::value<std::string>(&downloadFolder)->required(), "download folder")
                (",t", po::value<int>(&timeout)->default_value(DEFAULT_TIMEOUT), "timeout for server replies");

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

    return 0;
}
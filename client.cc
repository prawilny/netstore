#include "netstore.h"

struct client_config{
    std::string server_address;
    int server_port;
    std::string download_folder;
    int timeout;
};

bool parse_commandline(struct client_config * config, int argc, char ** argv) {
    try {
        namespace po = boost::program_options;

        po::options_description desc(std::string(argv[0]).append(" options"));
        desc.add_options()
                ("help,h", "help message")
                (",g", po::value<std::string>(&config->server_address)->required(), "multicast address of servers")
                (",p", po::value<int>(&config->server_port)->required(), "server port")
                (",o", po::value<std::string>(&config->download_folder)->required(), "download folder")
                (",t", po::value<int>(&config->timeout)->default_value(DEFAULT_TIMEOUT), "timeout for server replies");

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

int main(int argc, char *argv[]) {
    struct client_config config;

    if (!parse_commandline(&config, argc, argv)){
         return 1;
    }

    return 0;
}
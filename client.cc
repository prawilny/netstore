#include "netstore.h"

#include <sstream> //?
#include <unordered_map>

enum class cmd_type {
    discover,
    search,
    search_all,
    search_regex,
    fetch,
    upload,
    remove,
    exit,
    invalid
};

static std::unordered_map<std::string, cmd_type> command_types = {
        {"discover", cmd_type::discover},
        {"search",   cmd_type::search},
        {"fetch",    cmd_type::fetch},
        {"upload",   cmd_type::upload},
        {"remove",   cmd_type::remove},
        {"exit",     cmd_type::exit},
};

struct client_config {
    std::string server_address;
    int server_port;
    std::string download_folder;
    int timeout;
};

struct command {
    cmd_type type;
    std::string arg;
};

bool parse_commandline_args(struct client_config *config, int argc, char **argv) {
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

bool parse_command(struct command *c) {
    std::string line, token;

    if (!getline(std::cin, line)) {
        std::cerr << "Error reading line\n";
        return false;
    }
    std::istringstream linestream(line);

    if (!(linestream >> token)) {
        return false;
    }
    std::transform(token.begin(), token.end(), token.begin(), ::tolower);

    c->type = cmd_type::invalid;
    for (auto it = command_types.begin(); it != command_types.end(); it++) {
        if (token.compare(it->first) == 0) {
            c->type = it->second;
            break;
        }
    }

    int args = 0;
    if (!linestream.eof()){
        args++;
        linestream >> c->arg;
        if (!linestream.eof()){
            args++;
        }
    }

    switch (c->type) {
        case cmd_type::discover:
        case cmd_type::exit:
            return (args == 0 ? true : false);
        case cmd_type::fetch:
        case cmd_type::upload:
        case cmd_type::remove:
            return (args == 1 ? true : false);
        case cmd_type::search:
            switch (args) {
                case 0:
                    c->type = cmd_type::search_all;
                    return true;
                case 1:
                    c->type = cmd_type::search_regex;
                    return true;
                default:
                    return false;
            }
        default:
            return false;
    }
}

int main(int argc, char *argv[]) {
    struct client_config config;
    struct command cmd;
    std::vector<std::string> filenames;

    if (!parse_commandline_args(&config, argc, argv)) {
        return 1;
    }

    for (;;){
        parse_command(&cmd);
    }

    return 0;
}
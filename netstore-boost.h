#ifndef NETSTORE_NETSTORE_BOOST_H
#define NETSTORE_NETSTORE_BOOST_H

#include <boost/program_options.hpp>
#include <regex>
#include <iostream>
#include <string>

struct server_config {
    std::string server_address;
    int server_port;
    std::string shared_folder;
    int64_t free_space;
    int timeout;
};

struct client_config {
    std::string server_address;
    int server_port;
    std::string download_folder;
    int timeout;
};

extern struct server_config s_config;
extern struct client_config c_config;

bool parse_client_args(int argc, char **argv);

bool parse_server_args(int argc, char **argv);

#endif //NETSTORE_NETSTORE_BOOST_H

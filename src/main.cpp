#include <iostream>
#include <string>
#include <exception>
#include <cstring>
#include <cstdlib>
#include "getopt.h"

#include "../include/network_utils.h"
#include "../include/icmp.h"



using namespace std;

// Config of parameters
class Config {
    private:
    string protocol = "ICMP";
    string dst;
    string type_addr;
    bool is_fqdn;
    bool bandwidth = false;
    int port = 0;
    int max_hops = 64;
    
    

    public:
    void print_data() {
        cout << "Protocol: " << protocol << "\n";
        if (port != 0) 
            cout << "Port: " << port << "\n";
        cout << "Maximum hops: " << max_hops << "\n\n";
    }


    // Setters
    void set_protocol(string protocol) {
        this->protocol = protocol;
    }

    void set_dst(string dst) {
        this->dst = dst;
    }

    void set_type_addr(string type_addr) {
        this->type_addr = type_addr;
    }

    void set_fqdn(bool is_fqdn) {
        this->is_fqdn = is_fqdn;
    }

    void set_bandwidth(bool bandwidth) {
        this->bandwidth = bandwidth;
    }

    void set_port(int port) {
        this->port = port;
    }

    void set_max_hops(int max_hops) {
        this->max_hops = max_hops;
    }


    // Getters
    string get_protocol() {
        return protocol;
    }

    string get_dst() {
        return dst;
    }

    string get_type_addr() {
        return type_addr;
    }

    bool get_fqdn() {
        return is_fqdn;
    }

    bool get_bandwidth() {
        return bandwidth;
    }

    int get_port() {
        return port;
    }

    int get_max_hops() {
        return max_hops;
    }
    

    
};

// Manual of usage
void print_manual() {
    cout << "\nUsing netxplorer: ./netxplorer [options]\n\n";
    cout << "\n";
    cout << "Options:\n";
    cout << "   -t <protocol>       Which protocol will be used: ICMP, UDP, TCP or all [default: ICMP]\n";
    cout << "   -d <destination>    Target IP/FQDN. It can be IPv4 or FQDN [necessary]\n";
    cout << "   -p <port>           Target port for using TCP, UDP, all mode [unnecessary for ICMP mode]\n";
    cout << "   -m <max_hops>       Maximum number of hops (TTL) [default: 64]\n\n";
    cout << "   --bandwidth         Enable a mode that shows a estimated bandwidth [default: false]\n\n\n";
    
}

// Parsing parameters
Config parse_args(int argc, char* argv[]) {
    Config config;
    int opt;

    struct option long_options[] = {
        {"bandwidth", no_argument,       0, 'b'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}  
    };

    while ((opt = getopt_long(argc, argv, "bh:t:d:p:m:", long_options, NULL)) != -1) {
        switch ((opt))
        {
            // Protocol
            case 't': {
                string protocol = optarg;
                if (protocol != "icmp" && protocol != "tcp" && protocol != "udp" && protocol != "all") {
                    cerr << "Failure: Unknown method " << protocol << "\n";
                    print_manual();
                    exit(EXIT_FAILURE);
                }
                config.set_protocol(protocol);
                break;
            }

            // Destination    
            case 'd': {
                string dst = optarg;
                string type_addr = check_type(dst.c_str());
                if (type_addr == "None") {
                    cerr << "Failure: Invalid destination " << dst << "\n";
                    print_manual();
                    exit(EXIT_FAILURE);;
                }
                else if (type_addr == "FQDN") {
                    config.set_type_addr(type_addr);
                    config.set_fqdn(true);
                }
                else {
                    config.set_type_addr(type_addr);
                    config.set_fqdn(false);
                }
                config.set_dst(dst);
                break;
            }

            // Port
            case 'p': {
                try {
                    int port = stoi(optarg);
                    // 65535 - max port
                    if (port > 65535) {
                        cerr << "Failure: Maximum port value exceeded " << port << "\n";
                        print_manual();
                        exit(EXIT_FAILURE);
                    }
                    config.set_port(port);
                } 
                catch (const invalid_argument& e) {
                    cerr << "Failure: Invalid port " << optarg << "\n";
                    print_manual();
                    exit(EXIT_FAILURE);
                }
                break;
            }

            // Max hops
            case 'm': {
                try {
                    int max_hops = stoi(optarg);
                    config.set_max_hops(max_hops);
                } 
                catch (const invalid_argument& e) {
                    cerr << "Failure: Invalid maximum hops number " << optarg << "\n";
                    exit(EXIT_FAILURE);
                }
                break;
            }

            // Bandwidth
            case 'b': {
                config.set_bandwidth(true);
                break;
            }

            // Help
            case 'h': {
                print_manual();
                exit(EXIT_SUCCESS);
            }

            default: {
                print_manual();
                exit(EXIT_FAILURE);
            }

        }


    }   

    if (optind < argc) {
        print_manual();
        exit(EXIT_FAILURE);
    }

    return config;    

}

// Main function
int main(int argc, char *argv[]) {
    Config config = parse_args(argc, argv);
    char *dst_ip = strdup(config.get_dst().c_str());
    char *type_addr = strdup(config.get_type_addr().c_str());
    int max_hops = config.get_max_hops();
    bool is_fqdn = config.get_fqdn();
    bool bandwidth_mode = config.get_bandwidth();
    if (is_fqdn) {
        char *ip_from_fqdn = get_ip_from_fqdn(dst_ip);      
        cout << "\nStarting traceroute to " << dst_ip << " (" << ip_from_fqdn << ")" << "\n";
    }
    else {
        cout << "\nStarting traceroute to " << dst_ip << "(" << dst_ip << ")" << "\n";
    }
    config.print_data();
    
    


    if(icmp_trace(dst_ip, is_fqdn, max_hops, bandwidth_mode) == -1) {
        free(dst_ip);
        free(type_addr);
        exit(EXIT_FAILURE);
    }
    
    
    free(dst_ip);
    free(type_addr);    

    return 0;
}


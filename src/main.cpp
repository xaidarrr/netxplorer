#include <iostream>
#include <string>
#include <exception>
#include <cstring>
#include <iomanip>
#include "getopt.h"

#include "../include/network_utils.h"
#include "../include/icmp.h"
#include "../include/tcp.h"

using namespace std;

// Configuration of parameters 
class Config {
private:
    string protocol = "icmp";  // Default protocol
    string dst;                // Target address
    string type_addr;          // Address type (IPv4/FQDN)
    char *interface = NULL;    // Network interface
    int is_fqdn;              // Flag indicating if the address is FQDN
    unsigned short port = 80;        // Port
    int max_hops = 64;         // Maximum number hops (TTL)

public:
    // Displays configuration data
    void print_data() {
        cout << "Protocol: " << protocol << "\n";
        if (protocol != "icmp")
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

    void set_iface(char *interface) {
        this->interface = interface;
    }

    void set_type_addr(string type_addr) {
        this->type_addr = type_addr;
    }

    void set_fqdn(bool is_fqdn) {
        this->is_fqdn = is_fqdn;
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

    char* get_iface() {
        return interface;
    }

    int get_fqdn() {
        return is_fqdn;
    }

    int get_port() {
        return port;
    }

    int get_max_hops() {
        return max_hops;
    }
};

// Manual user guide
void print_manual() {
    cout << "Usage: netxplorer <destination> [options]\n\n";
    cout << "    <destination>"
         << setw(37) << " "
         << "Target IP address or Fully Qualified Domain Name (FQDN).\n"
         << setw(54) << " " 
         << "It can be an IPv4 address or a valid FQDN. [required]\n\n";
    cout << "Options:\n\n";
    cout << "-t <protocol>, --protocol=<protocol>" 
         << setw(18) << " "
         << "Specifies which protocol to use for the test.\n" 
         << setw(54) << " " 
         << "Options:\n"
         << setw(54) << " " 
         << "ICMP or TCP.\n"
         << setw(54) << " " 
         << "Example: -t tcp  \n"
         << setw(54) << " " 
         << "[default: ICMP]\n\n";
    cout << "-p <port>, --port=<port>" 
         << setw(30) << " "
         << "Specifies the target port for TCP.\n"
         << setw(54) << " " 
         << "Example: -p 443\n"
         << setw(54) << " " 
         << "[default: 80]\n\n";
    cout << "-m <max-hops>, --max-hops=<max-hops>" 
         << setw(18) << " "
         << "Specifies the maximum number of hops (TTL) to trace. \n"
         << setw(54) << " " 
         << "Example: -m 30\n"
         << setw(54) << " " 
         << "[default: 64]\n\n";
    cout << "-i <interface>, --iface=<interface>" 
         << setw(19) << " "
         << "Select the network interface to use for the trace.\n"
         << setw(54) << " " 
         << "Example: -i eth0\n"
         << setw(54) << " " 
         << "[optional]\n\n";
    cout << "-h, --help" 
         << setw(44) << " " 
         << "Show this help message and exit.\n\n";
    
    
}

// Command-line arguments parsing
Config parse_args(int argc, char* argv[]) {
    Config config;
    int opt;

    struct option long_options[] = {
        {"protocol", required_argument, 0, 't'},
        {"port", required_argument, 0, 'p'},
        {"max-hops", required_argument, 0, 'm'},
        {"help", no_argument, 0, 'h'},
        {"iface", required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };

    // Processing command-line arguments
    while ((opt = getopt_long(argc, argv, "t:p:m:i:h", long_options, NULL)) != -1) {
        switch (opt) {
            // Protocol
            case 't': {
                string protocol = optarg;
                // Convert the string to lowercase if the user entered it in uppercase
                for (auto& c : protocol) {
                    c = tolower(c);
                }
                if (protocol != "icmp" && protocol != "tcp") {
                    cerr << "Failure: Unknown method " << protocol << "\n";
                    print_manual();
                    exit(EXIT_FAILURE);
                }
                config.set_protocol(protocol);
                break;
            }

            // Port
            case 'p': {
                try {
                    int port = stoi(optarg);
                    // Check to ensure the port does not exceed the maximum allowed
                    if (port > 65535) {
                        cerr << "Failure: Maximum port value exceeded " << port << "\n";
                        print_manual();
                        exit(EXIT_FAILURE);
                    }
                    config.set_port(port);
                } catch (const invalid_argument& e) {
                    cerr << "Failure: Invalid port " << optarg << "\n";
                    print_manual();
                    exit(EXIT_FAILURE);
                }
                break;
            }

            // Maximum number of hops
            case 'm': {
                try {
                    int max_hops = stoi(optarg);
                    config.set_max_hops(max_hops);
                } catch (const invalid_argument& e) {
                    cerr << "Failure: Invalid maximum hops number " << optarg << "\n";
                    exit(EXIT_FAILURE);
                }
                break;
            }

            // Help
            case 'h': {
                print_manual();
                exit(EXIT_SUCCESS);
            }

            // Network interface
            case 'i': {
                config.set_iface(optarg);
                break;
            }

            // Unknown argument
            default: {
                print_manual();
                exit(EXIT_FAILURE);
            }
        }
    }

    // Processing additional parameters for the presence of destination
    if (optind < argc) {
        string dst = argv[optind];
        string type_addr = check_type(dst.c_str());
        if (type_addr == "None") {
            cerr << "Failure: Invalid destination " << dst << "\n";
            print_manual();
            exit(EXIT_FAILURE);
        } else if (type_addr == "FQDN") {
            config.set_type_addr(type_addr);
            config.set_fqdn(1);
        } else {
            config.set_type_addr(type_addr);
            config.set_fqdn(0);
        }
        config.set_dst(dst);
    }

    return config;
}

// Main function
int main(int argc, char *argv[]) {
    // Parsing arguments
    Config config = parse_args(argc, argv);
    char *dst_ip = strdup(config.get_dst().c_str());
    char *type_addr = strdup(config.get_type_addr().c_str());
    char *iface = config.get_iface();
    int max_hops = config.get_max_hops();
    int is_fqdn = config.get_fqdn();
    string protocol = config.get_protocol();
    unsigned short port = config.get_port();

    // Displaying information about the target host
    if (is_fqdn == 1) {
        char *ip_from_fqdn = get_ip_from_fqdn(dst_ip);
        if ( ip_from_fqdn == NULL) {
            free(dst_ip);
            free(type_addr);
            exit(EXIT_FAILURE);
        }
        cout << "\nStarting traceroute to " << dst_ip << " (" << ip_from_fqdn << ")" << "\n";
    } else {
        cout << "\nStarting traceroute to " << dst_ip << " (" << dst_ip << ")" << "\n";
    }

    // Displaying the configuration
    config.print_data();
    
    printf("%-8s %-20s %s\n", "Hop", "RTT(ms)", "FQDN / Address");
    printf("--------------------------------------------------------------------------------\n");

    // Choosing the protocol for tracing
    if (protocol == "tcp") {
        if (tcp_trace(dst_ip, port, is_fqdn, max_hops, iface) == -1) {
            free(dst_ip);
            free(type_addr);
            exit(EXIT_FAILURE);
        }
    } else if (protocol == "icmp") {
        if (icmp_trace(dst_ip, is_fqdn, max_hops, iface) == -1) {
            free(dst_ip);
            free(type_addr);
            exit(EXIT_FAILURE);
        }
    }

    // Freeing allocated memory
    free(dst_ip);
    free(type_addr);

    return 0;
}
#include<iostream>
#include<unistd.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<cstring>
#include<cerrno>

using namespace std;

int main(int argc, char *argv[])
{
    int opt;
    string bind_address = "0.0.0.0"; // Default: listen on all addresses
    int port = 0;                   // Default: any available port
    string peer_address = "";       // Default: no peer address
    int peer_port = 0;              // Default: no peer port
    
    while((opt = getopt(argc, argv, "b:p:a:r"))){
        switch (opt){
            case 'b':
                bind_address = optarg;
                break;
            case 'p':
                port = std::stoi(optarg);
                break;
            case 'a':
                peer_address = optarg;
                break;  
            case 'r':
                peer_port = std::stoi(optarg);
                break;
        }
    }

    // Optional: Print the parsed values for debugging
    cout << "Bind Address: " << bind_address << endl;
    cout << "Port: " << port << endl;
    cout << "Peer Address: " << peer_address << endl;
    cout << "Peer Port: " << peer_port << endl;

    // Initialize socket for binding (UDP and IPv4)
    int server_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_socket < 0) {
        cerr << "Error creating socket: " << strerror(errno) << endl;
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(bind_address.c_str());

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Error binding socket: " << strerror(errno) << endl;
        return 1;
    }

    cout << "Server socket initialized and bound to " << bind_address << ":" << port << endl;

    // Initialize socket for peer connection if peer_address and peer_port are provided
    if (!peer_address.empty() && peer_port > 0) {
        sockaddr_in peer_addr{};
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(peer_port);
        peer_addr.sin_addr.s_addr = inet_addr(peer_address.c_str());

        // Example: Send a test message to the peer
        string message = "Hello, peer!";
        if (sendto(server_socket, message.c_str(), message.size(), 0, 
                   (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
            cerr << "Error sending message to peer: " << strerror(errno) << endl;
            return 1;
        }

        cout << "Message sent to peer at " << peer_address << ":" << peer_port << endl;
    }
}
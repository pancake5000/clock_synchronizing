#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>
#include <endian.h> // Use endian.h for htonll and ntohll
#include <set>

#include "komunikaty.h"
#include "err.h"

#define MAX_DATAGRAM_SIZE 65507 // Maximum size of a UDP datagram
#define IP_ADDRESS_LENGTH 4
#define PEER_DESCRIPTION_SIZE 7 // 1 byte for length + 4 bytes for IP + 2 bytes for port
using namespace std;

int read_from_argv(int argc, char *argv[], string &bind_address, int &port, string &peer_address, int &peer_port)
{
    int opt;
    bool got_peer = 0;
    bool got_peer_port = 0;
    while ((opt = getopt(argc, argv, "b:p:a:r:")) != -1)
    {
        switch (opt)
        {
        case 'b':
        {
            if (optarg == nullptr)
            {
                cerr << "Error: Bind address is required." << endl;
                return 1;
            }
            bind_address = optarg;
            // Validate the bind address format (IPv4)
            struct sockaddr_in sa;
            if (inet_pton(AF_INET, bind_address.c_str(), &(sa.sin_addr)) == 0)
            {
                cerr << "Error: Invalid bind address format. Must be a valid IPv4 address." << endl;
                return 1;
            }
            break;
        }
        case 'p':
        {
            if (optarg == nullptr)
            {
                cerr << "Error: Port is required." << endl;
                return 1;
            }
            int tmp_port = 0;
            try
            {
                tmp_port = std::stoi(optarg);
            }
            catch (const std::invalid_argument &e)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            catch (const std::out_of_range &e)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            port = tmp_port;
            if (port < 0 || port > 65535)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            break;
        }
        case 'a':
        {
            if (optarg == nullptr)
            {
                cerr << "Error: No peer adsress" << endl;
                return 1;
            }
            got_peer = 1;
            peer_address = optarg;
            struct sockaddr_in sa;
            if (inet_pton(AF_INET, peer_address.c_str(), &(sa.sin_addr)) == 0)
            {
                cerr << "Error: Invalid bind address format. Must be a valid IPv4 address." << endl;
                return 1;
            }
            break;
        }
        case 'r':
        {
            if (optarg == nullptr)
            {
                cerr << "Error: Peer port is required." << endl;
                return 1;
            }
            got_peer_port = 1;
            int tmp_port = 0;
            try
            {
                tmp_port = std::stoi(optarg);
            }
            catch (const std::invalid_argument &e)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            catch (const std::out_of_range &e)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            peer_port = tmp_port;
            if (peer_port < 0 || peer_port > 65535)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            break;
        }
        default:
        {
            cerr << "Error: Invalid option: " << (char)opt << endl;
            return 1;
        }
        }
    }
    if (got_peer != got_peer_port)
    {
        cerr << "Error: Peer address and port must be provided together." << endl;
        return 1;
    }
    // Optional: Print the parsed values for debugging
    cout << "Bind Address: " << bind_address << endl;
    cout << "Port: " << port << endl;
    cout << "Peer Address: " << peer_address << endl;
    cout << "Peer Port: " << peer_port << endl;
    return 0;
}
int initialize_socket(int &server_socket, sockaddr_in &server_addr, string bind_address, int port)
{
    server_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_socket < 0)
    {
        cerr << "Error creating socket: " << strerror(errno) << endl;
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(bind_address.c_str());

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        cerr << "Error binding socket: " << strerror(errno) << endl;
        return 1;
    }

    cout << "Server socket initialized and bound to " << bind_address << ":" << port << endl;
    return 0;
}
message_t new_message(int message_type)
{
    message_t message;
    message.message = message_type;
    message.count = 0;
    message.timestamp = 0;
    message.synchronized = 255;
    return message;
}
int serialize(message_t message, char *buf)
{
    int size = 1;
    buf[0] = message.message;
    switch (message.message)
    {
    case HELLO_REPLY:
    {
        unsigned short value = htons(message.count);     // Convert to network byte order
        memcpy(buf + 1, &value, sizeof(unsigned short)); // Copy to buffer starting at position 1
        size += sizeof(unsigned short);                  // Update size
        for (int i = 0; i < message.count; i++)
        {
            buf[size] = message.peers[i].peer_address_length;
            size++;
            memcpy(buf + size, message.peers[i].peer_address.c_str(), message.peers[i].peer_address_length); // Copy address
            size += message.peers[i].peer_address_length;                                                    // Update size
            unsigned short port_value = htons(message.peers[i].port);                                        // Convert to network byte order
            memcpy(buf + size, &port_value, sizeof(unsigned short));                                         // Copy to buffer starting at position size
            size += sizeof(unsigned short);                                                                  // Update size
        }
        break;
    }
    case SYNC_START:
    case DELAY_RESPONSE:
    case TIME:
    {
        unsigned long long value = htobe64(message.timestamp);   // Convert to network byte order
        memcpy(buf + size, &value, sizeof(unsigned long long));  // Copy to buffer starting at position size
        size += sizeof(unsigned long long);                      // Update size
        memcpy(buf + size, &message.synchronized, sizeof(char)); // Copy synchronized flag
        size += sizeof(char);                                    // Update size
    }
    }
    return size;
}
int deserialize(message_t &message, char *buf, int size)
{
    if (size < 1)
    {
        cerr << "Error: Buffer size is too small to deserialize message." << endl;
        return -1;
    }
    message.message = buf[0];
    int pos = 1;
    switch (message.message)
    {
    case HELLO_REPLY:
    {
        if (size - pos < (int)sizeof(unsigned short))
        {
            cerr << "Error: Buffer size is too small to deserialize message." << endl;
            return -1;
        }
        message.count = ntohs(*(unsigned short *)(buf + pos)); // Convert from network byte order
        pos += sizeof(unsigned short);                         // Update position
        if (size - pos < (int)message.count * (PEER_DESCRIPTION_SIZE))
        {
            cerr << "Error: Buffer size is too small to deserialize message." << endl;
            return -1;
        }
        // Resize vector to hold peers
        for (int i = 0; i < message.count; i++)
        {
            message.peers[i].peer_address_length = buf[pos]; // Read address length
            pos++;
            if (message.peers[i].peer_address_length != IP_ADDRESS_LENGTH)
            {
                cerr << "Error: Invalid peer address length." << endl;
                return -1;
            }
            message.peers[i].peer_address = string(buf + pos, message.peers[i].peer_address_length); // Read address
            pos += message.peers[i].peer_address_length;                                             // Update position
            message.peers[i].port = ntohs(*(unsigned short *)(buf + pos));                           // Convert from network byte order
            pos += sizeof(unsigned short);                                                           // Update position
        }
        break;
    }
    case SYNC_START:
    case DELAY_RESPONSE:
    case TIME:
    {
        if (size - pos < (int)sizeof(unsigned long long) + (int)sizeof(char))
        {
            cerr << "Error: Buffer size is too small to deserialize message." << endl;
            return -1;
        }
        message.timestamp = be64toh(*(unsigned long long *)(buf + pos)); // Convert from network byte order
        pos += sizeof(unsigned long long);                               // Update position
        message.synchronized = *(char *)(buf + pos);                     // Read synchronized flag
        pos += sizeof(char);                                             // Update position
    }
    }
    return size;
}

int send_message(message_t message, int socket, string peer_address, int peer_port, char *buf)
{
    int size = serialize(message, buf);
    sockaddr_in peer_addr{};
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    peer_addr.sin_addr.s_addr = inet_addr(peer_address.c_str());

    if (sendto(socket, buf, size, 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0)
    {
        cerr << "Error sending message to peer: " << strerror(errno) << endl;
        return -1;
    }
    return 0;
}
int receive_message(message_t &message, int socket, char *buf)
{
    sockaddr_in peer_addr{};
    socklen_t addr_len = sizeof(peer_addr);
    ssize_t bytes_received = recvfrom(socket, buf, MAX_DATAGRAM_SIZE, 0, (struct sockaddr *)&peer_addr, &addr_len);
    if (bytes_received < 0)
    {
        cerr << "Error receiving message: " << strerror(errno) << endl;
        return -1;
    }
    return deserialize(message, buf, bytes_received);
}

int say_hello(int socket, string peer_address, int peer_port, char *buf)
{
    message_t message = new_message(HELLO);
    if(send_message(message, socket, peer_address, peer_port, buf)<0){
        return -1;
    }
    return 0;
}
int main(int argc, char *argv[])
{

    string bind_address = "0.0.0.0"; // Default: listen on all addresses
    int port = 0;                    // Default: any available port
    string peer_address = "";        // Default: no peer address
    int peer_port = 0;               // Default: no peer port

    // Parsing command line arguments
    if (read_from_argv(argc, argv, bind_address, port, peer_address, peer_port) != 0)
    {
        return 1;
    }

    int server_socket = -1;
    sockaddr_in server_addr{};
    if (initialize_socket(server_socket, server_addr, bind_address, port) != 0)
    {
        return 1;
    }
    set<peer> known_vertices;
    char *buffer = new char[MAX_DATAGRAM_SIZE];
    // Say Hello
   

    // Initialize socket for peer connection if peer_address and peer_port are provided
    if (!peer_address.empty() && peer_port > 0)
    {
        known_vertices.insert({0, peer_address, (unsigned short)peer_port});
        if (say_hello(server_socket, peer_address, peer_port, buffer) < 0)
        {
            err_msg("Error sending hello message");
        }
        cout << "Hello message sent to peer at " << peer_address << ":" << peer_port << endl;
    }
    // Wait for hello_reply
    // connect to all the peers
    /*
        while(true){
            czytaj z socketu
            responduj
        }
    */
}
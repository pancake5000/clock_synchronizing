#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>
#include <endian.h> // Use endian.h for htonll and ntohll
#include <set>
#include <chrono>

#include "komunikaty.h"
#include "err.h"

#define MAX_DATAGRAM_SIZE 65507 // Maximum size of a UDP datagram
#define IP_ADDRESS_LENGTH 4
#define PEER_DESCRIPTION_SIZE 7 // 1 byte for length + 4 bytes for IP + 2 bytes for port
using namespace std;

chrono::time_point<chrono::high_resolution_clock> time0;
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

unsigned long long time()
{
    auto now = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(now - time0);
    return duration.count();
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
    return 0;
}

int send_message(message_t message, int socket, string receiver_address, int receiver_port, char *buf)
{
    int size = serialize(message, buf);
    sockaddr_in peer_addr{};
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(receiver_port);
    peer_addr.sin_addr.s_addr = inet_addr(receiver_address.c_str());

    if (sendto(socket, buf, size, 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0)
    {
        cerr << "Error sending message to peer: " << strerror(errno) << endl;
        return -1;
    }
    return 0;
}
int receive_message(message_t &message, sockaddr *sender_address, int socket, char *buf)
{
    socklen_t addr_len = sizeof(sender_address);
    ssize_t bytes_received = recvfrom(socket, buf, MAX_DATAGRAM_SIZE, 0, (struct sockaddr *)sender_address, &addr_len);
    if (bytes_received < 0)
    {
        cerr << "Error receiving message: " << strerror(errno) << endl;
        return -1;
    }
    if (deserialize(message, buf, bytes_received) < 0)
    {
        return -1;
    }
    return 0;
}

int say_hello(int socket, string receiver_address, int receiver_port, char *buf)
{
    message_t message = new_message(HELLO);
    if (send_message(message, socket, receiver_address, receiver_port, buf) < 0)
    {
        return -1;
    }
    return 0;
}

// int handle_next_message(int socket, char *buf)
// {
//     sockaddr_in sender_addr{};
//     message_t message;
//     if(receive_message(message, (struct sockaddr *)&sender_addr, socket, buf)<0){
//         return -1;
//     }
//     cout << "Received message from " << inet_ntoa(sender_addr.sin_addr) << ":" << ntohs(sender_addr.sin_port) << endl;
//     cout << "Message type: " << (int)message.message << endl;
//     switch (message.message)
//         {
//         case HELLO:
//             cout << "Received HELLO message" << endl;
//             send_hello_reply()
//             break;
//         case HELLO_REPLY:
//             cout << "Received HELLO_REPLY message" << endl;
//             break;
//         case CONNECT:
//             cout << "Received CONNECT message" << endl;
//             break;
//         case ACK_CONNECT:
//             cout << "Received ACK_CONNECT message" << endl;
//             break;
//         case SYNC_START:
//             cout << "Received SYNC_START message" << endl;
//             break;
//         case DELAY_REQUEST:
//             cout << "Received DELAY_REQUEST message" << endl;
//             break;
//         case DELAY_RESPONSE:
//             cout << "Received DELAY_RESPONSE message" << endl;
//             break;
//         case LEADER:
//             cout << "Received LEADER message" << endl;
//             break;
//         case GET_TIME:
//             cout << "Received GET_TIME message" << endl;
//             break;
//         case TIME:
//             cout << "Received TIME message" << endl;
//             break;
//         default:
//             err_msg("Unknown message type: %d", message.message);
//             break;
//         }
//     return 0;
// }
void handle_hello(const message_t &message, const sockaddr_in &sender_addr, set<peer> &known_vertices, int socket, char *buf)
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if (known_vertices.find(sender) != known_vertices.end())
    {
        known_vertices.erase(sender);
    }
    message_t hello_reply = new_message(HELLO_REPLY);
    hello_reply.count = known_vertices.size();
    hello_reply.peers = vector<peer>(known_vertices.begin(), known_vertices.end());
    if (send_message(hello_reply, socket, sender.peer_address, sender.port, buf) < 0)
    {
        err_msg("Error sending hello reply");
    }
    known_vertices.insert(sender);
}

void handle_hello_reply(const message_t &message, const sockaddr_in &sender_addr, set<peer> &known_vertices, string bind_address, int my_port, int socket, char *buf)
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if (known_vertices.find(sender) != known_vertices.end())
    {
        err_msg("Sender in list of known vertices");
        return;
    }
    peer me = {IP_ADDRESS_LENGTH, bind_address, my_port};
    if(known_vertices.find(me)!=known_vertices.end()){
        err_msg("I am in list of known vertices");
        return;
    }
    for (int i = 0; i < message.count; i++)
    {
        peer new_peer = message.peers[i];
        new_peer.port = ntohs(new_peer.port);
        known_vertices.insert(new_peer);
        message_t connect_message = new_message(CONNECT);
        if(send_message(connect_message, socket, new_peer.peer_address, new_peer.port, buf) < 0)
        {
            err_msg("Error sending connect message");
        }
    }
    known_vertices.insert(sender);
}

void handle_connect(const message_t &message, const sockaddr_in &sender_addr, set<peer> &known_vertices, int socket, char *buf) 
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if (known_vertices.find(sender) != known_vertices.end())
    {
        err_msg("Sender in list of known vertices");
        return;
    }
    known_vertices.insert(sender);
    message_t ack_connect = new_message(ACK_CONNECT);
    if (send_message(ack_connect, socket, sender.peer_address, sender.port, buf) < 0)
    {
        err_msg("Error sending ACK_CONNECT message");
    }
}

void handle_ack_connect(const message_t &message, const sockaddr_in &sender_addr, set<peer> &known_vertices)
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if(known_vertices.find(sender) != known_vertices.end())
    {
        err_msg("Sender in list of known vertices");
        return;
    }
    known_vertices.insert(sender);
}

void handle_sync_start(const message_t &message, const sockaddr_in &sender_addr)
{
    // TODO: Implement handle_sync_start logic
}

void handle_delay_request(const message_t &message, const sockaddr_in &sender_addr)
{
    // TODO: Implement handle_delay_request logic
}

void handle_delay_response(const message_t &message, const sockaddr_in &sender_addr)
{
    // TODO: Implement handle_delay_response logic
}

void handle_leader(const message_t &message, const sockaddr_in &sender_addr, set<peer> &known_vertices)
{
    // TODO: Implement handle_leader logic
}

void handle_get_time(const message_t &message, const sockaddr_in &sender_addr)
{
    // TODO: Implement handle_get_time logic
}

void handle_time(const message_t &message, const sockaddr_in &sender_addr)
{
    // TODO: Implement handle_time logic
}
int handle_messages(int socket, char *buf, string bind_address, int my_port)
{

    set<peer> known_vertices;
    vector<pair<sockaddr_in, message_t>> to_send;
    while (true)
    {
        sockaddr_in sender_addr{};
        message_t message;
        if (receive_message(message, (struct sockaddr *)&sender_addr, socket, buf) < 0)
        {
            return -1;
        }
        cout << "Received message from " << inet_ntoa(sender_addr.sin_addr) << ":" << ntohs(sender_addr.sin_port) << endl;
        cout << "Message type: " << (int)message.message << endl;
        switch (message.message)
        {
        case HELLO:
            cout << "Received HELLO message" << endl;
            handle_hello(message, sender_addr, known_vertices, socket, buf);
            break;
        case HELLO_REPLY:
            cout << "Received HELLO_REPLY message" << endl;
            handle_hello_reply(message, sender_addr, known_vertices, bind_address, my_port, socket, buf);
            break;
        case CONNECT:
            cout << "Received CONNECT message" << endl;
            handle_connect(message, sender_addr, known_vertices, socket, buf);
            break;
        case ACK_CONNECT:
            cout << "Received ACK_CONNECT message" << endl;
            handle_ack_connect(message, sender_addr, known_vertices);
            break;
        case SYNC_START:
            cout << "Received SYNC_START message" << endl;
            handle_sync_start(message, sender_addr);
            break;
        case DELAY_REQUEST:
            cout << "Received DELAY_REQUEST message" << endl;
            handle_delay_request(message, sender_addr);
            break;
        case DELAY_RESPONSE:
            cout << "Received DELAY_RESPONSE message" << endl;
            handle_delay_response(message, sender_addr);
            break;
        case LEADER:
            cout << "Received LEADER message" << endl;
            handle_leader(message, sender_addr, known_vertices);
            break;
        case GET_TIME:
            cout << "Received GET_TIME message" << endl;
            handle_get_time(message, sender_addr);
            break;
        case TIME:
            handle_time(message, sender_addr);
            cout << "Received TIME message" << endl;
            break;
        default:
            err_msg("Unknown message type: %d", message.message);
            break;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    time0 = chrono::high_resolution_clock::now();

    string bind_address = "0.0.0.0"; // Default: listen on all addresses
    int port = 0;             // Default: any available port
    string peer_address = ""; // Default: no peer address
    int peer_port = 0;        // Default: no peer port

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

    char *buffer = new char[MAX_DATAGRAM_SIZE];
    // Say Hello

    // Initialize socket for peer connection if peer_address and peer_port are provided
    if (!peer_address.empty() && peer_port > 0)
    {
        if (say_hello(server_socket, peer_address, peer_port, buffer) < 0)
        {
            err_msg("Error sending hello message");
        }
        cout << "Hello message sent to peer at " << peer_address << ":" << peer_port << endl;
    }
    handle_messages(server_socket, buffer, bind_address, port);

    // Wait for hello_reply
    // connect to all the peers
    /*
        while(true){
            czytaj z socketu
            responduj
        }
    */
}
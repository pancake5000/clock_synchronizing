#include<iostream>
#include<unistd.h>
using namespace std;

int main(int argc, char *argv[])
{
    int opt;
    string bind_address = 0;
    int port = 0;
    string peer_address = 0;
    int peer_port = 0;
    
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
}
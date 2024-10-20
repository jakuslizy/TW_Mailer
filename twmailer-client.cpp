#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <algorithm>

class TwMailerClient {
private:
    int sock;
    struct sockaddr_in server;

public:
    TwMailerClient(const char* ip, int port) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            throw std::runtime_error("Socket creation failed");
        }

        server.sin_addr.s_addr = inet_addr(ip);
        server.sin_family = AF_INET;
        server.sin_port = htons(port);

        if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
            throw std::runtime_error("Connection error");
        }
    }

    ~TwMailerClient() {
        close(sock);
    }

    void run() {
        std::string command;
        while (true) {
            std::cout << "Please enter a command (SEND, LIST, READ, DEL, QUIT): ";
            std::getline(std::cin, command);

            if (command == "QUIT") {
                sendCommand(command);
                break;
            } else if (command == "SEND") {
                handleSend();
            } else if (command == "LIST") {
                handleList();
            } else if (command == "READ") {
                handleRead();
            } else if (command == "DEL") {
                handleDel();
            } else {
                std::cout << "Invalid command" << std::endl;
            }
        }
    }

private:
    void sendCommand(const std::string& command) {
        if (send(sock, command.c_str(), command.length(), 0) < 0) {
            throw std::runtime_error("Sending failed");
        }
    }

    std::string receiveResponse() {
        char buffer[1024] = {0};
        int valread = recv(sock, buffer, 1024, 0);
        if (valread < 0) {
            throw std::runtime_error("Receiving response failed");
        }
        return std::string(buffer);
    }

    void handleSend() {
        std::string sender, receiver, subject, message, line;

        std::cout << "Sender: ";
        std::getline(std::cin, sender);
        if (!isValidUsername(sender)) {
            std::cout << "Invalid sender name. Please use a maximum of 8 characters (a-z, 0-9)." << std::endl;
            return;
        }
        std::cout << "Receiver: ";
        std::getline(std::cin, receiver);
        if (!isValidUsername(receiver)) {
            std::cout << "Invalid receiver name. Please use a maximum of 8 characters (a-z, 0-9)." << std::endl;
            return;
        }
        std::cout << "Subject (max 80 characters): ";
        std::getline(std::cin, subject);
        if (subject.empty()) {
            std::cout << "Subject cannot be empty." << std::endl;
            return;
        }
        if (subject.length() > 80) {
            std::cout << "Subject is too long. Maximum length is 80 characters." << std::endl;
            return;
        }
        std::cout << "Message (end with a line containing only a dot):" << std::endl;

        std::stringstream ss;
        ss << "SEND\n" << sender << "\n" << receiver << "\n" << subject << "\n";

        bool hasContent = false;
        while (std::getline(std::cin, line) && line != ".") {
            ss << line << "\n";
            hasContent = true;
        }
        if (!hasContent) {
            std::cout << "Message body cannot be empty." << std::endl;
            return;
        }
        ss << ".\n";

        sendCommand(ss.str());
        std::string response = receiveResponse();
        std::cout << response;
    }

    void handleList() {
        std::string username;
        std::cout << "Username: ";
        std::getline(std::cin, username);
        
        if (!isValidUsername(username)) {
            std::cout << "Invalid username. Please use a maximum of 8 characters (a-z, 0-9)." << std::endl;
            return;
        }
        
        sendCommand("LIST\n" + username + "\n");
        std::string response = receiveResponse();
        
        if (response.substr(0, 3) == "OK\n") {
            std::cout << "Received message list:" << std::endl;
            std::cout << response.substr(3) << std::endl;
        } else if (response.substr(0, 4) == "ERR\n") {
            std::cout << "Error: " << response.substr(4);
        } else {
            std::cout << "Unexpected response from server." << std::endl;
        }
    }

    void handleRead() {
        std::string username, messageNumber;
        std::cout << "Username: ";
        std::getline(std::cin, username);
        
        if (!isValidUsername(username)) {
            std::cout << "Invalid username. Please use a maximum of 8 characters (a-z, 0-9)." << std::endl;
            return;
        }
        
        std::cout << "Message number: ";
        std::getline(std::cin, messageNumber);
        
        sendCommand("READ\n" + username + "\n" + messageNumber + "\n");
        std::cout << receiveResponse() << std::endl;
    }

    void handleDel() {
        std::string username, messageNumber;
        std::cout << "Username: ";
        std::getline(std::cin, username);
        
        if (!isValidUsername(username)) {
            std::cout << "Invalid username. Please use a maximum of 8 characters (a-z, 0-9)." << std::endl;
            return;
        }
        
        std::cout << "Message number: ";
        std::getline(std::cin, messageNumber);
        
        sendCommand("DEL\n" + username + "\n" + messageNumber + "\n");
        std::cout << receiveResponse() << std::endl;
    }

    bool isValidUsername(const std::string& username) {
        if (username.length() > 8) return false;
        return std::all_of(username.begin(), username.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        });
    }
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <ip> <port>" << std::endl;
        return 1;
    }

    TwMailerClient client(argv[1], std::stoi(argv[2]));
    client.run();

    return 0;
}

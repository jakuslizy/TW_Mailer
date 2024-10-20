#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <algorithm>

// Class for the client
// It handles the connection to the server and the communication with the server
class TwMailerClient {
private:
    int sock; // Socket for the connection
    struct sockaddr_in server; // Server address

public:
    // Constructor for the client
    // It creates the socket and connects to the server
    TwMailerClient(const char* ip, int port) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            throw std::runtime_error("Socket creation failed");
        }

        // Set the server address
        server.sin_addr.s_addr = inet_addr(ip);
        server.sin_family = AF_INET;
        server.sin_port = htons(port);

        // Connect to the server
        if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
            throw std::runtime_error("Connection error");
        }
    }

    // Destructor for the client
    // It closes the socket
    ~TwMailerClient() {
        close(sock);
    }

    // Main loop for the client
    // It reads the commands from the user and sends them to the server
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
    // Function to send a command to the server
    void sendCommand(const std::string& command) {
        // Send the command to the server
        if (send(sock, command.c_str(), command.length(), 0) < 0) {
            throw std::runtime_error("Sending failed");
        }
    }

    // Function to receive a response from the server
    std::string receiveResponse() {
        char buffer[1024] = {0}; // Buffer to store the response
        int valread = recv(sock, buffer, 1024, 0); // Receive the response
        if (valread < 0) {
            throw std::runtime_error("Receiving response failed");
        }
        return std::string(buffer);
    }

    // Function to handle the SEND command
    void handleSend() {
        std::string sender, receiver, subject, message, line;

        std::cout << "Sender: ";
        std::getline(std::cin, sender); // Read the sender
        if (!isValidUsername(sender)) {
            std::cout << "Invalid sender name. Please use a maximum of 8 characters (a-z, 0-9)." << std::endl;
            return;
        }
        std::cout << "Receiver: ";
        std::getline(std::cin, receiver); // Read the receiver
        if (!isValidUsername(receiver)) {
            std::cout << "Invalid receiver name. Please use a maximum of 8 characters (a-z, 0-9)." << std::endl;
            return;
        }
        std::cout << "Subject (max 80 characters): ";
        std::getline(std::cin, subject); // Read the subject
        if (subject.empty()) {
            std::cout << "Subject cannot be empty." << std::endl;
            return;
        }
        if (subject.length() > 80) {
            std::cout << "Subject is too long. Maximum length is 80 characters." << std::endl;
            return;
        }
        std::cout << "Message (end with a line containing only a dot):" << std::endl;

        std::stringstream ss; // String stream to store the message
        ss << "SEND\n" << sender << "\n" << receiver << "\n" << subject << "\n";

        bool hasContent = false; // Flag to check if the message has content
        while (std::getline(std::cin, line) && line != ".") {
            ss << line << "\n";
            hasContent = true;
        }
        if (!hasContent) {
            std::cout << "Message body cannot be empty." << std::endl;
            return;
        }
        ss << ".\n";

        sendCommand(ss.str()); // Send the command to the server
        std::string response = receiveResponse(); // Receive the response
        std::cout << response;
    }

    // Function to handle the LIST command
    void handleList() {
        std::string username;
        std::cout << "Username: ";
        std::getline(std::cin, username); // Read the username
        
        if (!isValidUsername(username)) {
            std::cout << "Invalid username. Please use a maximum of 8 characters (a-z, 0-9)." << std::endl;
            return;
        }
        
        sendCommand("LIST\n" + username + "\n"); // Send the command to the server
        std::string response = receiveResponse(); // Receive the response
        
        // Check the response
        if (response.substr(0, 3) == "OK\n") {
            std::cout << "Received message list:" << std::endl;
            std::cout << response.substr(3) << std::endl; // Print the response
        } else if (response.substr(0, 4) == "ERR\n") {
            std::cout << "Error: " << response.substr(4);
        } else {
            std::cout << "Unexpected response from server." << std::endl;
        }
    }

    // Function to handle the READ command
    void handleRead() {
        std::string username, messageNumber;
        std::cout << "Username: ";
        std::getline(std::cin, username);
        
        if (!isValidUsername(username)) {
            std::cout << "Invalid username. Please use a maximum of 8 characters (a-z, 0-9)." << std::endl;
            return;
        }
        
        std::cout << "Message number: ";
        std::getline(std::cin, messageNumber); // Read the message number
        
        sendCommand("READ\n" + username + "\n" + messageNumber + "\n"); // Send the command to the server
        std::cout << receiveResponse() << std::endl; // Print the response
    }

    // Function to handle the DEL command
    void handleDel() {
        std::string username, messageNumber;
        std::cout << "Username: ";
        std::getline(std::cin, username); // Read the username
        
        if (!isValidUsername(username)) {
            std::cout << "Invalid username. Please use a maximum of 8 characters (a-z, 0-9)." << std::endl;
            return;
        }
        
        std::cout << "Message number: ";
        std::getline(std::cin, messageNumber);
        
        sendCommand("DEL\n" + username + "\n" + messageNumber + "\n"); // Send the command to the server
        std::cout << receiveResponse() << std::endl; // Print the response
    }

    // Function to check if the username is valid
    bool isValidUsername(const std::string& username) {
        // Check if the username is longer than 8 characters
        if (username.length() > 8) return false;

        // Check if all characters in the username are lowercase letters or digits
        return std::all_of(username.begin(), username.end(), [](char c) {
            // 'c' represents each character of the username in turn
            // Return true if 'c' is a lowercase letter (a-z) or a digit (0-9)
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        });
    }
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <ip> <port>" << std::endl;
        return 1;
    }

    // Create the client
    TwMailerClient client(argv[1], std::stoi(argv[2]));
    // Run the client
    client.run();

    return 0;
}

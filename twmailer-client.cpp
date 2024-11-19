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
    int sock;
    bool is_logged_in;
    std::string username;

    // Function to safely read from the socket
    std::string safeRead() {
        std::string result;
        const size_t chunk_size = 1024; // Size of the chunk to read from the socket
        char chunk[chunk_size];

        // Read the message from the socket
        while (true) {
            memset(chunk, 0, chunk_size);
            ssize_t bytes = read(sock, chunk, chunk_size - 1);

            if (bytes <= 0) break;

            result.append(chunk, bytes);

            // Check if the message is complete
            if (result.find("OK\n") != std::string::npos ||
                result.find("ERR\n") != std::string::npos) {
                break;
            }
        }
        return result;
    }

    // Function to safely send a message to the server
    void safeSend(const std::string &message) {
        size_t total_sent = 0;
        while (total_sent < message.length()) {
            ssize_t sent = send(sock,
                                message.c_str() + total_sent,
                                message.length() - total_sent,
                                0);
            if (sent <= 0) {
                throw std::runtime_error("Connection interrupted");
            }
            total_sent += sent;
        }
    }

public:
    // Constructor
    TwMailerClient() : sock(0), is_logged_in(false) {}

    // Function to connect to the server
    bool connect(const char *address, int port) {
        struct sockaddr_in serv_addr;

        // Create the socket
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            std::cout << "Socket creation failed" << std::endl;
            return false;
        }
        // Set up the server address
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        // Convert the address to a network address
        if (inet_pton(AF_INET, address, &serv_addr.sin_addr) <= 0) {
            std::cout << "Invalid address" << std::endl;
            return false;
        }

        // Connect to the server
        if (::connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
            std::cout << "Connection failed" << std::endl;
            return false;
        }

        return true;
    }

    // Function to login to the server
    bool login() {
        // If the user is already logged in, return true
        if (is_logged_in) {
            std::cout << "Already logged in as: " << username << std::endl;
            return true;
        }

        // Read the username and password from the console
        std::string password;
        std::cout << "Username: ";
        std::getline(std::cin, username);

        // Disable echo for password input
        struct termios old, new_term;
        tcgetattr(STDIN_FILENO, &old);
        new_term = old;
        new_term.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

        std::cout << "Password: ";
        std::getline(std::cin, password);
        std::cout << "\n";

        / Restore terminal settings
        tcsetattr(STDIN_FILENO, TCSANOW, &old);

        try {
            // Create the message to send to the server
            std::string message = "LOGIN\n" + username + "\n" + password + "\n.\n";
            safeSend(message);
            // Read the response from the server
            std::string response = safeRead();

            // Check if the login was successful
            if (response.find("OK\n") != std::string::npos) {
                is_logged_in = true;
                std::cout << "Login successful!" << std::endl;
                return true;
            } else {
                std::cout << "Login failed: " << response << std::endl;
                return false;
            }
        } catch (const std::exception &e) {
            std::cerr << "Login error: " << e.what() << std::endl;
            return false;
        }
    }

    // Function to send a mail
    void sendMail() {
        if (!checkLogin()) return;

        try {
            // Read the receiver and subject from the console
            std::string receiver, subject;
            std::cout << "Receiver: ";
            std::getline(std::cin, receiver);

            // Read the subject from the console
            std::cout << "Subject (max 80 characters): ";
            std::getline(std::cin, subject);
            if (subject.length() > 80) {
                std::cout << "Subject too long!" << std::endl;
                return;
            }

            // Create the message to send to the server
            std::string message = "SEND\n" + receiver + "\n" + subject + "\n";
            std::cout << "Message (end with a single '.' in a new line):\n";

            // Read the message from the console
            std::string line;
            while (std::getline(std::cin, line)) {
                if (line == ".") break;
                message += line + "\n";
            }
            message += ".\n";

            // Send the message to the server
            safeSend(message);
            // Read the response from the server
            std::string response = safeRead();
            std::cout << "Server response: " << response;
        } catch (const std::exception &e) {
            std::cerr << "Sending error: " << e.what() << std::endl;
        }
    }

    // Function to list all mails
    void listMails() {
        if (!checkLogin()) return;

        try {
            // Create the message to send to the server
            safeSend("LIST\n.\n");
            // Read the response from the server
            std::string response = safeRead();
            std::cout << "Your messages:\n" << response;
        } catch (const std::exception &e) {
            std::cerr << "Listing error: " << e.what() << std::endl;
        }
    }

    // Function to read a mail
    void readMail() {
        if (!checkLogin()) return;

        try {
            // Read the message number from the console
            std::string number;
            std::cout << "Message number: ";
            std::getline(std::cin, number);

            try {
                // Convert the message number to an integer
                int msg_num = std::stoi(number);
                if (msg_num <= 0) {
                    std::cout << "Invalid message number" << std::endl;
                    return;
                }
            } catch (...) {
                std::cout << "Please enter a valid number" << std::endl;
                return;
            }

            // Create the message to send to the server
            safeSend("READ\n" + number + "\n.\n");

            // Read the response from the server
            std::string response;
            // Size of the chunk to read from the socket
            const size_t chunk_size = 1024;
            char chunk[chunk_size];
            // Flag to check if the message has started
            bool messageStarted = false;
            // String stream to store the full message
            std::stringstream fullMessage;

            while (true) {
                memset(chunk, 0, chunk_size);
                // Read the message from the socket
                ssize_t bytes = read(sock, chunk, chunk_size - 1);

                if (bytes <= 0) break;
                // Append the message to the response
                response.append(chunk, bytes);

                if (!messageStarted) {
                    // Check if the message has started
                    if (response.find("OK\n") != std::string::npos) {
                        messageStarted = true;
                        size_t start = response.find("OK\n") + 3;
                        fullMessage << response.substr(start);
                    } else if (response.find("ERR\n") != std::string::npos) {
                        std::cout << "Error: " << response;
                        return;
                    }
                } else {
                    // Append the message to the full message
                    fullMessage << chunk;
                }

                // Check if the message has ended
                if (response.find("\n.\n") != std::string::npos) {
                    break;
                }
            }

            // Get the final message
            std::string finalMessage = fullMessage.str();
            size_t endPos = finalMessage.find("\n.\n");
            if (endPos != std::string::npos) {
                finalMessage = finalMessage.substr(0, endPos);
            }

            // Print the final message
            std::cout << finalMessage << std::endl;

        } catch (const std::exception &e) {
            std::cerr << "Reading error: " << e.what() << std::endl;
        }
    }

    // Function to delete a mail
    void deleteMail() {
        if (!checkLogin()) return;

        try {
            std::string number;
            std::cout << "Message number to delete: ";
            std::getline(std::cin, number);

            // Validate input
            try {
                int msg_num = std::stoi(number);
                if (msg_num <= 0) {
                    std::cout << "Invalid message number" << std::endl;
                    return;
                }
            } catch (...) {
                std::cout << "Please enter a valid number" << std::endl;
                return;
            }

            // Create the message to send to the server
            safeSend("DEL\n" + number + "\n.\n");
            // Read the response from the server
            std::string response = safeRead();

            if (response.find("OK\n") != std::string::npos) {
                std::cout << "Message deleted successfully" << std::endl;
            } else {
                std::string error = response.substr(4);
                std::cout << "Deletion error: " << error;
            }
        } catch (const std::exception &e) {
            std::cerr << "Deletion error: " << e.what() << std::endl;
        }
    }

private:
    // Function to check if the user is logged in
    bool checkLogin() {
        if (!is_logged_in) {
            std::cout << "Please login first!" << std::endl;
            return false;
        }
        return true;
    }
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <ip> <port>" << std::endl;
        return 1;
    }

    // Create a client object
    TwMailerClient client;
    // Connect to the server
    if (!client.connect(argv[1], std::stoi(argv[2]))) {
        return 1;
    }

    std::string input;
    std::cout << "Commands: LOGIN, SEND, LIST, READ, DEL, QUIT" << std::endl;

    while (true) {
        std::cout << "> ";
        std::getline(std::cin, input);

        if (input == "LOGIN") {
            client.login();
        } else if (input == "SEND") {
            client.sendMail();
        } else if (input == "LIST") {
            client.listMails();
        } else if (input == "READ") {
            client.readMail();
        } else if (input == "DEL") {
            client.deleteMail();
        } else if (input == "QUIT") {
            break;
        } else {
            std::cout << "Unknown command" << std::endl;
        }
    }

    return 0;
}


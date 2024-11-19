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
        const size_t chunk_size = 1024;
        char chunk[chunk_size];

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
    TwMailerClient() : sock(0), is_logged_in(false) {}

    // Function to connect to the server
    bool connect(const char *address, int port) {
        struct sockaddr_in serv_addr;

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
        if (is_logged_in) {
            std::cout << "Already logged in as: " << username << std::endl;
            return true;
        }

        std::string password;
        std::cout << "Username: ";
        std::getline(std::cin, username);
        std::cout << "Password: ";
        std::getline(std::cin, password);

        try {
            std::string message = "LOGIN\n" + username + "\n" + password + "\n.\n";
            safeSend(message);
            std::string response = safeRead();

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
            std::string receiver, subject;
            std::cout << "Receiver: ";
            std::getline(std::cin, receiver);

            std::cout << "Subject (max 80 characters): ";
            std::getline(std::cin, subject);
            if (subject.length() > 80) {
                std::cout << "Subject too long!" << std::endl;
                return;
            }

            safeSend("SEND\n" + receiver + "\n" + subject + "\n");

            std::cout << "Message (end with a single '.' in a new line):\n";
            std::string line;
            while (std::getline(std::cin, line)) {
                safeSend(line + "\n");
                if (line == ".") {
                    break;
                }
            }

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
            safeSend("LIST\n.\n");
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
            std::string number;
            std::cout << "Message number: ";
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

            safeSend("READ\n" + number + "\n");

            // Erst OK/ERR lesen
            std::string response = safeRead();
            if (response != "OK\n") {
                std::cout << "Error: " << response;
                return;
            }

            std::cout << "Message:\n";
            std::string buffer;
            const size_t chunk_size = 1024;
            char chunk[chunk_size];

            while (true) {
                memset(chunk, 0, chunk_size);
                ssize_t bytes = read(sock, chunk, chunk_size - 1);

                if (bytes <= 0) break;

                buffer.append(chunk, bytes);

                size_t pos;
                while ((pos = buffer.find('\n')) != std::string::npos) {
                    std::string line = buffer.substr(0, pos);
                    buffer = buffer.substr(pos + 1);

                    if (line == ".") {
                        return;
                    }
                    std::cout << line << std::endl;
                }
            }
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

            safeSend("DEL\n" + number + "\n.\n");
            std::string response = safeRead();

            if (response.find("OK\n") != std::string::npos) {
                std::cout << "Message deleted successfully" << std::endl;
            } else {
                std::string error = response.substr(4); // Remove "ERR\n"
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

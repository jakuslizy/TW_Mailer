#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

class TwMailerServer {
private:
    int server_fd, client_sock;
    struct sockaddr_in address;
    std::string mail_spool_dir;

public:
    TwMailerServer(int port, const std::string& mail_dir) : mail_spool_dir(mail_dir) {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == 0) {
            throw std::runtime_error("Socket creation failed");
        }

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            throw std::runtime_error("Bind failed");
        }

        if (listen(server_fd, 3) < 0) {
            throw std::runtime_error("Listen failed");
        }

        fs::create_directories(mail_spool_dir);
    }

    ~TwMailerServer() {
        close(server_fd);
    }

    void run() {
        int addrlen = sizeof(address);
        std::cout << "Server is running..." << std::endl;

        while (true) {
            client_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
            if (client_sock < 0) {
                std::cerr << "Accept failed" << std::endl;
                continue;
            }

            handleClient();
        }
    }

private:
    void handleClient() {
        char buffer[1024] = {0};
        std::string command;

        std::cout << "New client connection accepted." << std::endl;

        while (true) {
            memset(buffer, 0, sizeof(buffer));
            int valread = read(client_sock, buffer, 1024);
            if (valread <= 0) {
                std::cout << "Client disconnected." << std::endl;
                break;
            }

            std::istringstream iss(buffer);
            std::getline(iss, command);

            std::cout << "Received command: " << command << std::endl;

            if (command == "SEND") {
                std::cout << "Processing SEND command..." << std::endl;
                handleSend(iss);
            } else if (command == "LIST") {
                std::cout << "Processing LIST command..." << std::endl;
                handleList(iss);
            } else if (command == "READ") {
                std::cout << "Processing READ command..." << std::endl;
                handleRead(iss);
            } else if (command == "DEL") {
                std::cout << "Processing DEL command..." << std::endl;
                handleDel(iss);
            } else if (command == "QUIT") {
                std::cout << "Client terminates the connection." << std::endl;
                break;
            } else {
                std::cout << "Invalid command received." << std::endl;
                send(client_sock, "ERR\n", 4, 0);
            }
        }

        close(client_sock);
        std::cout << "Client connection closed." << std::endl;
    }

    void handleSend(std::istringstream& iss) {
        std::string sender, receiver, subject, line;
        std::getline(iss, sender);
        std::getline(iss, receiver);
        std::getline(iss, subject);

        std::cout << "Sending message from " << sender << " to " << receiver << std::endl;
        std::cout << "Subject: " << subject << std::endl;

        fs::path inbox_path = fs::path(mail_spool_dir) / receiver;
        fs::create_directories(inbox_path);

        int message_number = 1;
        while (fs::exists(inbox_path / (std::to_string(message_number) + ".txt"))) {
            message_number++;
        }

        std::ofstream outfile(inbox_path / (std::to_string(message_number) + ".txt"));
        if (!outfile) {
            std::cout << "Error creating message file." << std::endl;
            send(client_sock, "ERR\n", 4, 0);
            return;
        }

        outfile << "From: " << sender << std::endl;
        outfile << "To: " << receiver << std::endl;
        outfile << "Subject: " << subject << std::endl << std::endl;

        while (std::getline(iss, line) && line != ".") {
            outfile << line << std::endl;
        }

        outfile.close();

        std::cout << "Message successfully saved." << std::endl;
        send(client_sock, "OK\n", 3, 0);
        std::cout << "Response 'OK' sent to client." << std::endl;
    }

    void handleList(std::istringstream& iss) {
        std::string username;
        std::getline(iss, username);

        fs::path inbox_path = fs::path(mail_spool_dir) / username;
        if (!fs::exists(inbox_path)) {
            std::string error_msg = "ERR\nUser " + username + " has no messages.\n";
            send(client_sock, error_msg.c_str(), error_msg.length(), 0);
            std::cout << "Error: Empty list sent for user " << username << std::endl;
            return;
        }

        std::vector<std::string> subjects;
        for (const auto& entry : fs::directory_iterator(inbox_path)) {
            std::ifstream infile(entry.path());
            std::string line;
            while (std::getline(infile, line)) {
                if (line.find("Subject: ") == 0) {
                    subjects.push_back(line.substr(9));
                    break;
                }
            }
        }

        std::stringstream ss;
        ss << "OK\n" << subjects.size() << "\n";
        for (const auto& subject : subjects) {
            ss << subject << "\n";
        }

        send(client_sock, ss.str().c_str(), ss.str().length(), 0);
        std::cout << "OK: List of messages for user " << username << " sent." << std::endl;
    }

    void handleRead(std::istringstream& iss) {
        std::string username, message_number;
        std::getline(iss, username);
        std::getline(iss, message_number);

        fs::path message_path = fs::path(mail_spool_dir) / username / (message_number + ".txt");
        if (!fs::exists(message_path)) {
            send(client_sock, "ERR\n", 4, 0);
            std::cout << "Error: Message not found." << std::endl;
            return;
        }

        std::ifstream infile(message_path);
        std::stringstream ss;
        ss << "OK\n" << infile.rdbuf();

        send(client_sock, ss.str().c_str(), ss.str().length(), 0);
        std::cout << "OK: Message " << message_number << " for user " << username << " sent." << std::endl;
    }

    void handleDel(std::istringstream& iss) {
        std::string username, message_number;
        std::getline(iss, username);
        std::getline(iss, message_number);

        fs::path message_path = fs::path(mail_spool_dir) / username / (message_number + ".txt");
        if (!fs::exists(message_path)) {
            send(client_sock, "ERR\n", 4, 0);
            std::cout << "Error: Message not found." << std::endl;
            return;
        }

        fs::remove(message_path);
        send(client_sock, "OK\n", 3, 0);
        std::cout << "OK: Message " << message_number << " for user " << username << " deleted." << std::endl;
    }
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <port> <mail-spool-directoryname>" << std::endl;
        return 1;
    }

    TwMailerServer server(std::stoi(argv[1]), argv[2]);
    server.run();

    return 0;
}

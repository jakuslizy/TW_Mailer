#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

// Namespace for the filesystem
namespace fs = std::filesystem;

class TwMailerServer {
private:
    int server_fd, client_sock; // Socket for the server and the client
    struct sockaddr_in address; // Address for the server
    std::string mail_spool_dir; // Directory for the mail spool

public:
    // Constructor for the server
    // It creates the socket and binds it to the address
    TwMailerServer(int port, const std::string& mail_dir) : mail_spool_dir(mail_dir) {
        server_fd = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
        if (server_fd == 0) {
            throw std::runtime_error("Socket creation failed");
        }

        address.sin_family = AF_INET; // Set the address family to IPv4
        address.sin_addr.s_addr = INADDR_ANY; // Set the address to any
        address.sin_port = htons(port); // Set the port to the given port

        // If the bind fails, throw an error
        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            throw std::runtime_error("Bind failed");
        }

        // If the listen fails, throw an error
        if (listen(server_fd, 3) < 0) {
            throw std::runtime_error("Listen failed");
        }

        // Create the mail spool directory
        fs::create_directories(mail_spool_dir);
    }

    // Destructor for the server
    // It closes the socket
    ~TwMailerServer() {
        close(server_fd);
    }

    // Main loop for the server
    // It accepts connections from clients and handles them
    void run() {

        int addrlen = sizeof(address);
        std::cout << "Server is running..." << std::endl;

        while (true) {
            // Accept a connection from a client
            client_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
            // Check if the connection was successful
            if (client_sock < 0) {
                std::cerr << "Accept failed" << std::endl;
                continue;
            }

            // Handle the client
            handleClient();
        }
    }

private:
    // Function to handle a client
    // It reads the commands from the client and handles them
    void handleClient() {
        char buffer[1024] = {0}; // Buffer to store the command
        std::string command; // Command to be executed

        std::cout << "New client connection accepted." << std::endl;

        while (true) {
            memset(buffer, 0, sizeof(buffer)); // Clear the buffer
            int valread = read(client_sock, buffer, 1024); // Read the command from the client
            if (valread <= 0) {
                std::cout << "Client disconnected." << std::endl;
                break;
            }

            std::istringstream iss(buffer); // String stream to store the command
            std::getline(iss, command); // Get the command

            std::cout << "Received command: " << command << std::endl; // Print the command

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

    // Function to handle the SEND command
    // It reads the sender, receiver, subject, and content from the client
    void handleSend(std::istringstream& iss) {
        std::string sender, receiver, subject, line; // Variables to store the sender, receiver, subject, and content
        std::getline(iss, sender); // Get the sender
        std::getline(iss, receiver); // Get the receiver
        std::getline(iss, subject); // Get the subject

        std::cout << "Sending message from " << sender << " to " << receiver << std::endl; // Print the sender and receiver
        std::cout << "Subject: " << subject << std::endl; // Print the subject

        fs::path inbox_path = fs::path(mail_spool_dir) / receiver; // Path to the receiver's inbox
        fs::create_directories(inbox_path); // Create the inbox directory if it doesn't exist

        int message_number = 1; // Message number
        while (fs::exists(inbox_path / (std::to_string(message_number) + ".txt"))) {
            message_number++;
        }

        std::ofstream outfile(inbox_path / (std::to_string(message_number) + ".txt")); // Open the message file
        if (!outfile) {
            std::cout << "Error creating message file." << std::endl;
            send(client_sock, "ERR\n", 4, 0);
            return;
        }

        outfile << "From: " << sender << std::endl;
        outfile << "To: " << receiver << std::endl; 
        outfile << "Subject: " << subject << std::endl << std::endl; 

        // Write the content 
        while (std::getline(iss, line) && line != ".") {
            outfile << line << std::endl; 
        }

        outfile.close(); // Close the message file

        std::cout << "Message successfully saved." << std::endl;
        send(client_sock, "OK\n", 3, 0);
        std::cout << "Response 'OK' sent to client." << std::endl;
    }

    // Function to handle the LIST command
    // It reads the username from the client and sends the list of messages to the client
    void handleList(std::istringstream& iss) {
        std::string username;
        std::getline(iss, username); // Get the username

        fs::path inbox_path = fs::path(mail_spool_dir) / username; // Path to the user's inbox
        if (!fs::exists(inbox_path)) {
            std::string error_msg = "ERR\nUser " + username + " has no messages.\n"; // Error message
            send(client_sock, error_msg.c_str(), error_msg.length(), 0); // Send the error message to the client
            std::cout << "Error: Empty list sent for user " << username << std::endl;
            return;
        }

        std::vector<std::string> subjects;
        for (const auto& entry : fs::directory_iterator(inbox_path)) {
            std::ifstream infile(entry.path()); // Open the message file
            std::string line;
            while (std::getline(infile, line)) {
                if (line.find("Subject: ") == 0) {
                    subjects.push_back(line.substr(9)); // Add the subject to the vector
                    break;
                }
            }
        }

        std::stringstream ss;
        ss << "OK\n" << subjects.size() << "\n"; // Write the number of messages
        for (const auto& subject : subjects) {
            ss << subject << "\n"; // Write the subjects
        }

        send(client_sock, ss.str().c_str(), ss.str().length(), 0); // Send the list of messages to the client
        std::cout << "OK: List of messages for user " << username << " sent." << std::endl;
    }

    // Function to handle the READ command
    // It reads the username and message number from the client and sends the message to the client
    void handleRead(std::istringstream& iss) {
        std::string username, message_number;
        std::getline(iss, username); // Get the username
        std::getline(iss, message_number); // Get the message number

        fs::path message_path = fs::path(mail_spool_dir) / username / (message_number + ".txt");
        if (!fs::exists(message_path)) {
            send(client_sock, "ERR\n", 4, 0); // Send the error message to the client
            std::cout << "Error: Message not found." << std::endl;
            return;
        }

        std::ifstream infile(message_path);
        std::stringstream ss;
        ss << "OK\n" << infile.rdbuf(); // Write the message to the stringstream

        send(client_sock, ss.str().c_str(), ss.str().length(), 0); // Send the message to the client
        std::cout << "OK: Message " << message_number << " for user " << username << " sent." << std::endl;
    }

    // Function to handle the DEL command
    // It reads the username and message number from the client and deletes the message
    void handleDel(std::istringstream& iss) {
        std::string username, message_number;
        std::getline(iss, username); // Get the username
        std::getline(iss, message_number); // Get the message number

        fs::path message_path = fs::path(mail_spool_dir) / username / (message_number + ".txt"); // Path to the message
        if (!fs::exists(message_path)) {
            send(client_sock, "ERR\n", 4, 0); // Send the error message to the client
            std::cout << "Error: Message not found." << std::endl;
            return;
        }

        fs::remove(message_path); // Delete the message
        send(client_sock, "OK\n", 3, 0); // Send the OK message to the client
        std::cout << "OK: Message " << message_number << " for user " << username << " deleted." << std::endl;
    }
};

int main(int argc, char *argv[]) {
    // Check if the number of arguments is correct
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <port> <mail-spool-directoryname>" << std::endl;
        return 1;
    }

    // Create the server
    TwMailerServer server(std::stoi(argv[1]), argv[2]); 
    // Run the server
    server.run();

    return 0;
}

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <ldap.h>
#include <sys/wait.h>
#include <map>
#include <chrono>
#include <mutex>
#include <algorithm>


namespace fs = std::filesystem;

// LDAP Configuration for Technikum Wien
#define LDAP_URI "ldap://ldap.technikum-wien.at:389"
#define LDAP_PORT 389
#define LDAP_BASEDN "ou=people,dc=technikum-wien,dc=at"

class TwMailerServer {
private:
    int server_fd, client_sock; // Socket for the server and the client
    struct sockaddr_in address; // Address for the server
    std::string mail_spool_dir; // Directory for the mail spool

    std::map<std::string, int> login_attempts; // IP -> Number of attempts
    std::map <std::string, std::chrono::system_clock::time_point> blacklist; // IP -> Timestamp
    std::mutex login_mutex;

    // Session information
    std::string current_user;
    bool is_authenticated;

    // LDAP connection
    LDAP *ldap;

    // Blacklist file for IP addresses
    const std::string blacklist_file = "blacklist.dat";

    void loadBlacklist() {
        //std::lock_guard <std::mutex> lock(login_mutex); // Lock the mutex
        std::ifstream file(blacklist_file, std::ios::binary); // Open the blacklist file
        if (!file) return; // If the file is not found, return

        size_t size;
        file.read(reinterpret_cast<char *>(&size), sizeof(size)); // Read the size of the blacklist

        // Iterate over the blacklist
        for (size_t i = 0; i < size; ++i) {
            std::string ip;
            std::chrono::system_clock::time_point timestamp;

            // Read the length of the IP address
            size_t ip_length;
            file.read(reinterpret_cast<char *>(&ip_length), sizeof(ip_length)); // Read the length of the IP address
            ip.resize(ip_length);
            file.read(&ip[0], ip_length); // Read the IP address

            file.read(reinterpret_cast<char *>(&timestamp), sizeof(timestamp)); // Read the timestamp

            // If the timestamp is within the last minute, add the IP to the blacklist
            auto now = std::chrono::system_clock::now();
            if (now - timestamp < std::chrono::minutes(1)) {
                blacklist[ip] = timestamp;
            }
        }
        file.close();
    }

    // Save the blacklist to the file
    void saveBlacklist() {
        std::lock_guard <std::mutex> lock(login_mutex);
        std::ofstream file(blacklist_file, std::ios::binary); // Open the blacklist file
        if (!file) return; // If the file is not found, return

        size_t size = blacklist.size();
        file.write(reinterpret_cast<const char *>(&size), sizeof(size)); // Write the size of the blacklist

        // Iterate over the blacklist
        for (const auto &[ip, timestamp]: blacklist) {
            size_t ip_length = ip.length();
            file.write(reinterpret_cast<const char *>(&ip_length),
                       sizeof(ip_length)); // Write the length of the IP address
            file.write(ip.c_str(), ip_length); // Write the IP address
            file.write(reinterpret_cast<const char *>(&timestamp), sizeof(timestamp)); // Write the timestamp
        }
        file.close();
    }

    // Read a message from the client safely
    std::string safeRead() {
        std::string result;
        const size_t chunk_size = 1024; // Size of the chunk to read from the socket
        char chunk[chunk_size];

        while (true) {
            memset(chunk, 0, chunk_size);
            ssize_t bytes = read(client_sock, chunk, chunk_size - 1);

            if (bytes <= 0) break;

            result.append(chunk, bytes);

            // Check if the message has ended with a point
            if (result.find(".\n") != std::string::npos) {
                break;
            }
        }
        return result;
    }


public:
    // Constructor for the server
    // It creates the socket and binds it to the address
    TwMailerServer(int port, const std::string &mail_dir)
            : mail_spool_dir(mail_dir), is_authenticated(false) {
        server_fd = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
        if (server_fd == 0) {
            throw std::runtime_error("Socket creation failed");
        }

        address.sin_family = AF_INET; // Set the address family to IPv4
        address.sin_addr.s_addr = INADDR_ANY; // Set the address to any
        address.sin_port = htons(port); // Set the port to the given port

        // If the bind fails, throw an error
        if (bind(server_fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
            throw std::runtime_error("Bind failed");
        }

        // If the listen fails, throw an error
        if (listen(server_fd, 3) < 0) {
            throw std::runtime_error("Listen failed");
        }

        // Create the mail spool directory
        fs::create_directories(mail_spool_dir);

        loadBlacklist();
    }

    // Destructor for the server
    // It closes the socket
    ~TwMailerServer() {
        saveBlacklist();
        close(server_fd);
    }

    // Main loop for the server
    // It accepts connections from clients and handles them
    void run() {
        int addrlen = sizeof(address);
        std::cout << "Server is running..." << std::endl;

        while (true) {
            client_sock = accept(server_fd, (struct sockaddr *) &address, (socklen_t * ) & addrlen);
            if (client_sock < 0) {
                std::cerr << "Accept failed" << std::endl;
                continue;
            }

            pid_t pid = fork();
            if (pid == 0) {  // Child process
                close(server_fd);  // Child closes the server socket
                handleClient();
                exit(0);
            } else if (pid > 0) {  // Parent-Prozess
                close(client_sock);  // Parent closes the client socket
                // Prevent zombie processes
                signal(SIGCHLD, SIG_IGN);
            } else {
                std::cerr << "Fork failed" << std::endl;
            }
        }
    }

private:
    // Function to handle a client
    // It reads the commands from the client and handles them
    void handleClient() {
        try {
            while (true) {
                std::string input = safeRead();
                if (input.empty()) {
                    std::cout << "Client disconnected." << std::endl;
                    break;
                }

                // Read the command from the client
                std::istringstream iss(input);
                std::string command;
                std::getline(iss, command);

                if (command == "LOGIN") {
                    handleLogin(iss);
                } else if (!is_authenticated && command != "QUIT") {
                    send(client_sock, "ERR\nNot logged in\n", 21, 0);
                } else if (command == "SEND") {
                    handleSend(iss);
                } else if (command == "LIST") {
                    handleList();
                } else if (command == "READ") {
                    handleRead(iss);
                } else if (command == "DEL") {
                    handleDel(iss);
                } else if (command == "QUIT") {
                    break;
                } else {
                    send(client_sock, "ERR\nUnknown command\n", 23, 0);
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "Error handling client: " << e.what() << std::endl;
        }

        close(client_sock);
    }

    // Function to handle the SEND command
    // It reads the sender, receiver, subject, and content from the client
    void handleSend(std::istringstream &iss) {
        if (!is_authenticated) {
            send(client_sock, "ERR\nNot logged in\n", 21, 0);
            return;
        }

        try {
            std::string receiver, subject;
            std::getline(iss, receiver);
            std::getline(iss, subject);

            // Check if the subject is too long
            if (subject.length() > 80) {
                send(client_sock, "ERR\nSubject too long\n", 20, 0);
                return;
            }

            // Create the inbox directory for the receiver
            fs::path inbox_path = fs::path(mail_spool_dir) / receiver;
            fs::create_directories(inbox_path);

            int message_number = 1;
            // Find the next available message number
            while (fs::exists(inbox_path / (std::to_string(message_number) + ".txt"))) {
                message_number++;
            }

            // Create the message file
            std::ofstream outfile(inbox_path / (std::to_string(message_number) + ".txt"));
            if (!outfile) {
                send(client_sock, "ERR\nCannot create message file\n", 30, 0);
                return;
            }

            // Write the message to the file
            outfile << "From: " << current_user << std::endl;
            outfile << "To: " << receiver << std::endl;
            outfile << "Subject: " << subject << std::endl << std::endl;

            // Read the message from the client
            std::string line;
            while (std::getline(iss, line)) {
                if (line == ".") break;
                outfile << line << std::endl;
            }

            // Close the message file
            outfile.close();

            // Send the OK message to the client
            send(client_sock, "OK\n", 3, 0);
            std::cout << "OK: Message sent to user " << receiver << std::endl;
        } catch (const std::exception &e) {
            send(client_sock, "ERR\nInternal server error\n", 25, 0);
            std::cerr << "Error handling send: " << e.what() << std::endl;
        }
    }

    // Function to handle the LIST command
    // It reads the username from the client and sends the list of messages to the client
    void handleList() {
        if (!is_authenticated) {
            send(client_sock, "ERR\nNot logged in\n", 21, 0);
            return;
        }

        // Create the inbox directory for the current user
        fs::path inbox_path = fs::path(mail_spool_dir) / current_user;
        if (!fs::exists(inbox_path) || fs::is_empty(inbox_path)) {
            std::string error_msg = "OK\n0\n.\n";
            send(client_sock, error_msg.c_str(), error_msg.length(), 0);
            return;
        }

        // Vector to store the messages with their numbers and subjects
        std::vector <std::pair<int, std::string>> messages;
        // Collect all messages with their numbers and subjects
        for (const auto &entry: fs::directory_iterator(inbox_path)) {
            std::ifstream infile(entry.path());
            std::string line;
            // Get the filename of the message
            std::string filename = entry.path().filename().string();
            // Get the message number from the filename
            int msg_num = std::stoi(filename.substr(0, filename.find(".txt")));

            // Read the message from the file
            while (std::getline(infile, line)) {
                if (line.find("Subject: ") == 0) {
                    messages.push_back({msg_num, line.substr(9)});
                    break;
                }
            }
        }

        // Sort messages by their number
        std::sort(messages.begin(), messages.end());

        // Create response with sequential message numbering
        std::stringstream ss;
        ss << "OK\n" << messages.size() << "\n";
        for (size_t i = 0; i < messages.size(); i++) {
            ss << (i + 1) << ". " << messages[i].second << "\n";  // Index + Subject
        }
        ss << ".\n";

        // Send the response to the client
        send(client_sock, ss.str().c_str(), ss.str().length(), 0);
        std::cout << "OK: " << messages.size() << " messages listed for user " << current_user << std::endl;
    }

    // Function to handle the READ command
    // It reads the username and message number from the client and sends the message to the client
    void handleRead(std::istringstream &iss) {
        if (!is_authenticated) {
            send(client_sock, "ERR\nNot logged in\n", 21, 0);
            return;
        }

        // Read the message number from the client
        std::string message_number;
        std::getline(iss, message_number);

        try {
            int msg_num = std::stoi(message_number);
            if (msg_num <= 0) {
                send(client_sock, "ERR\nInvalid message number\n", 31, 0);
                return;
            }

            // Create the inbox directory for the current user
            fs::path inbox_path = fs::path(mail_spool_dir) / current_user;
            // Vector to store the messages with their numbers and paths
            std::vector <std::pair<int, fs::path>> messages;

            // Collect all messages with their numbers and paths
            for (const auto &entry: fs::directory_iterator(inbox_path)) {
                std::string filename = entry.path().filename().string();
                int file_num = std::stoi(filename.substr(0, filename.find(".txt")));
                messages.push_back({file_num, entry.path()});
            }

            // Sort the messages by their number
            std::sort(messages.begin(), messages.end());

            // Check if the message number is valid
            if (msg_num > static_cast<int>(messages.size())) {
                send(client_sock, "ERR\nMessage not found\n", 28, 0);
                return;
            }

            // Open and read the message
            std::ifstream infile(messages[msg_num - 1].second);
            if (!infile) {
                send(client_sock, "ERR\nCannot read message\n", 30, 0);
                return;
            }

            // Read the entire message into a string
            std::stringstream buffer;
            buffer << infile.rdbuf();
            std::string message = buffer.str();

            // Send the OK message to the client
            send(client_sock, "OK\n", 3, 0);
            // Send the message to the client
            send(client_sock, message.c_str(), message.length(), 0);
            // Send the message end marker to the client
            send(client_sock, "\n.\n", 3, 0);

            std::cout << "OK: Message " << message_number << " sent to user " << current_user << std::endl;

        } catch (const std::exception &e) {
            send(client_sock, "ERR\nInvalid message number\n", 31, 0);
            std::cerr << "Error handling read: " << e.what() << std::endl;
        }
    }

    // Function to handle the DEL command
    // It reads the username and message number from the client and deletes the message
    void handleDel(std::istringstream &iss) {
        if (!is_authenticated) {
            send(client_sock, "ERR\nNot logged in\n", 21, 0);
            return;
        }

        // Read the message number from the client
        std::string message_number;
        std::getline(iss, message_number);

        try {
            int requested_msg_num = std::stoi(message_number);
            if (requested_msg_num <= 0) {
                throw std::out_of_range("Negative message number");
            }

            // Create the inbox directory for the current user
            fs::path inbox_path = fs::path(mail_spool_dir) / current_user;
            // Vector to store the messages with their numbers and paths
            std::vector <std::pair<int, fs::path>> messages;

            // Collect all messages with their file paths
            for (const auto &entry: fs::directory_iterator(inbox_path)) {
                std::string filename = entry.path().filename().string();
                int msg_num = std::stoi(filename.substr(0, filename.find(".txt")));
                messages.push_back({msg_num, entry.path()});
            }

            // Sort messages by their number
            std::sort(messages.begin(), messages.end());

            // Check if the requested message number is valid
            if (requested_msg_num > static_cast<int>(messages.size())) {
                send(client_sock, "ERR\nMessage not found\n", 28, 0);
                return;
            }

            // Delete the requested message
            if (fs::remove(messages[requested_msg_num - 1].second)) {
                // Rename subsequent messages to maintain sequential numbering
                for (size_t i = requested_msg_num; i < messages.size(); i++) {
                    fs::path old_path = messages[i].second;
                    fs::path new_path = old_path.parent_path() / (std::to_string(i) + ".txt");
                    fs::rename(old_path, new_path);
                }

                // Send the OK message to the client
                send(client_sock, "OK\n", 3, 0);
                std::cout << "OK: Message " << message_number << " deleted for user " << current_user << std::endl;
            } else {
                send(client_sock, "ERR\nCould not delete message\n", 34, 0);
            }
        } catch (const std::exception &e) {
            send(client_sock, "ERR\nInvalid message number\n", 31, 0);
            std::cerr << "Error handling delete: " << e.what() << std::endl;
        }
    }

    // Function to check the LDAP credentials
    // It checks if the username and password are correct
    bool checkLDAPCredentials(const std::string &username, const std::string &password) {
        LDAP *ld;
        int rc;

        std::cout << "Trying to connect to LDAP: " << LDAP_URI << std::endl;
        // Initialize the LDAP connection
        rc = ldap_initialize(&ld, LDAP_URI);
        if (rc != LDAP_SUCCESS) {
            std::cerr << "LDAP init failed: " << ldap_err2string(rc) << std::endl;
            return false;
        }

        std::cout << "LDAP initialized" << std::endl;

        // Set the LDAP protocol version to 3
        int version = LDAP_VERSION3;
        ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

        // Create a berval structure for the password
        struct berval cred;
        cred.bv_val = (char *) password.c_str();
        cred.bv_len = password.length();

        // Create the user DN
        std::string userdn = "uid=" + username + ",ou=people,dc=technikum-wien,dc=at";
        std::cout << "Trying to bind with DN: " << userdn << std::endl;

        rc = ldap_sasl_bind_s(ld, userdn.c_str(), LDAP_SASL_SIMPLE, &cred,
                              nullptr, nullptr, nullptr);

        // Check if the bind failed
        if (rc != LDAP_SUCCESS) {
            std::cerr << "LDAP bind failed: " << ldap_err2string(rc) << std::endl;
        }

        bool success = (rc == LDAP_SUCCESS);
        // Unbind from the LDAP server
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return success;
    }

    // Function to handle the LOGIN command
    // It reads the username and password from the client and checks if they are correct
    void handleLogin(std::istringstream &iss) {
        std::string username, password;
        std::getline(iss, username);
        std::getline(iss, password);

        // Get the client IP address
        std::string client_ip = inet_ntoa(address.sin_addr);


        std::lock_guard <std::mutex> lock(login_mutex);
        loadBlacklist();

        // Check if the IP is blacklisted
        auto it = blacklist.find(client_ip);
        if (it != blacklist.end()) {
            auto now = std::chrono::system_clock::now();
            // Check if the IP is blocked
            if (now - it->second < std::chrono::minutes(1)) {
                send(client_sock, "ERR\nIP is blocked\n", 20, 0);
                return;
            }
            blacklist.erase(it); // Remove the IP from the blacklist
        }

        // Check login attempts
        if (login_attempts[client_ip] >= 2) {
            blacklist[client_ip] = std::chrono::system_clock::now();
            login_attempts[client_ip] = 0;

            std::ofstream file(blacklist_file, std::ios::binary);
            if (file) {
                size_t size = blacklist.size();
                file.write(reinterpret_cast<const char *>(&size), sizeof(size));
                for (const auto &[ip, time]: blacklist) {
                    size_t ip_length = ip.length();
                    file.write(reinterpret_cast<const char *>(&ip_length), sizeof(ip_length));
                    file.write(ip.c_str(), ip_length);
                    file.write(reinterpret_cast<const char *>(&time), sizeof(time));
                }
            }

            send(client_sock, "ERR\nToo many attempts\n", 22, 0);
            return;
        }

        // Check the LDAP credentials
        if (checkLDAPCredentials(username, password)) {
            current_user = username;
            is_authenticated = true;
            login_attempts[client_ip] = 0;
            // Send the OK message to the client
            send(client_sock, "OK\n", 3, 0);
        } else {
            login_attempts[client_ip]++;
            send(client_sock, "ERR\n", 4, 0);
        }
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

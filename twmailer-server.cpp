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

// Namespace for the filesystem
namespace fs = std::filesystem;

class TwMailerServer {
private:
    int server_fd, client_sock; // Socket for the server and the client
    struct sockaddr_in address; // Address for the server
    std::string mail_spool_dir; // Directory for the mail spool

    std::map<std::string, int> login_attempts; // IP -> Anzahl der Versuche
    std::map<std::string, std::chrono::system_clock::time_point> blacklist; // IP -> Zeitpunkt
    std::mutex login_mutex;
    
    // Session-Informationen
    std::string current_user;
    bool is_authenticated;
    
    // LDAP-Verbindung
    LDAP* ldap;

    const std::string blacklist_file = "blacklist.dat";
    
    void loadBlacklist() {
        std::lock_guard<std::mutex> lock(login_mutex);
        std::ifstream file(blacklist_file, std::ios::binary);
        if (!file) return;
        
        size_t size;
        file.read(reinterpret_cast<char*>(&size), sizeof(size));
        
        for (size_t i = 0; i < size; ++i) {
            std::string ip;
            std::chrono::system_clock::time_point timestamp;
            
            size_t ip_length;
            file.read(reinterpret_cast<char*>(&ip_length), sizeof(ip_length));
            ip.resize(ip_length);
            file.read(&ip[0], ip_length);
            
            file.read(reinterpret_cast<char*>(&timestamp), sizeof(timestamp));
            
            auto now = std::chrono::system_clock::now();
            if (now - timestamp < std::chrono::minutes(1)) {
                blacklist[ip] = timestamp;
            }
        }
        file.close();
    }
    
    void saveBlacklist() {
        std::lock_guard<std::mutex> lock(login_mutex);
        std::ofstream file(blacklist_file, std::ios::binary);
        if (!file) return;
        
        size_t size = blacklist.size();
        file.write(reinterpret_cast<const char*>(&size), sizeof(size));
        
        for (const auto& [ip, timestamp] : blacklist) {
            size_t ip_length = ip.length();
            file.write(reinterpret_cast<const char*>(&ip_length), sizeof(ip_length));
            file.write(ip.c_str(), ip_length);
            file.write(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));
        }
        file.close();
    }

    std::string safeRead() {
        std::string result;
        const size_t chunk_size = 1024;
        char chunk[chunk_size];
        size_t total_bytes = 0;
        const size_t max_size = 100 * 1024 * 1024; // 100MB Limit
        
        while (true) {
            memset(chunk, 0, chunk_size);
            ssize_t bytes = read(client_sock, chunk, chunk_size - 1);
            
            if (bytes <= 0) break;
            
            total_bytes += bytes;
            if (total_bytes > max_size) {
                throw std::runtime_error("Message too large");
            }
            
            result.append(chunk, bytes);
            
            // Prüfen ob die Nachricht komplett ist
            if (result.find("\n.\n") != std::string::npos) {
                break;
            }
        }
        return result;
    }

public:
    // Constructor for the server
    // It creates the socket and binds it to the address
    TwMailerServer(int port, const std::string& mail_dir) 
        : mail_spool_dir(mail_dir), is_authenticated(false) {
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
        std::cout << "Server läuft..." << std::endl;

        while (true) {
            client_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
            if (client_sock < 0) {
                std::cerr << "Accept fehlgeschlagen" << std::endl;
                continue;
            }

            pid_t pid = fork();
            if (pid == 0) {  // Child-Prozess
                close(server_fd);  // Child schließt Server-Socket
                handleClient();
                exit(0);
            } else if (pid > 0) {  // Parent-Prozess
                close(client_sock);  // Parent schließt Client-Socket
                // Zombie-Prozesse verhindern
                signal(SIGCHLD, SIG_IGN);
            } else {
                std::cerr << "Fork fehlgeschlagen" << std::endl;
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

                std::istringstream iss(input);
                std::string command;
                std::getline(iss, command);

                if (command == "LOGIN") {
                    handleLogin(iss);
                } else if (!is_authenticated && command != "QUIT") {
                    send(client_sock, "ERR\nNicht eingeloggt\n", 21, 0);
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
                    send(client_sock, "ERR\nUnbekannter Befehl\n", 23, 0);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error handling client: " << e.what() << std::endl;
        }
        
        close(client_sock);
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
    void handleList() {
        if (!is_authenticated) {
            send(client_sock, "ERR\nNicht eingeloggt\n", 21, 0);
            return;
        }

        fs::path inbox_path = fs::path(mail_spool_dir) / current_user;
        if (!fs::exists(inbox_path)) {
            std::string error_msg = "ERR\nKeine Nachrichten vorhanden.\n";
            send(client_sock, error_msg.c_str(), error_msg.length(), 0);
            std::cout << "Error: Empty list sent for user " << current_user << std::endl;
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
        std::cout << "OK: List of messages for user " << current_user << " sent." << std::endl;
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

    bool checkLDAPCredentials(const std::string& username, const std::string& password) {
        int rc;
        
        // LDAP-Verbindung initialisieren
        rc = ldap_initialize(&ldap, "ldap://ldap.technikum-wien.at:389");
        if (rc != LDAP_SUCCESS) {
            return false;
        }

        // Bind mit Benutzeranmeldeinformationen
        std::string bind_dn = "uid=" + username + ",dc=technikum-wien,dc=at";
        struct berval cred;
        cred.bv_val = (char*)password.c_str();
        cred.bv_len = password.length();

        rc = ldap_sasl_bind_s(ldap, bind_dn.c_str(), LDAP_SASL_SIMPLE, &cred, 
                             nullptr, nullptr, nullptr);
        
        ldap_unbind_ext_s(ldap, nullptr, nullptr);
        return rc == LDAP_SUCCESS;
    }

    void handleLogin(std::istringstream& iss) {
        std::string username, password;
        std::getline(iss, username);
        std::getline(iss, password);
        
        std::string client_ip = inet_ntoa(address.sin_addr);
        
        {
            std::lock_guard<std::mutex> lock(login_mutex);
            
            // Prüfen ob IP gesperrt ist
            auto it = blacklist.find(client_ip);
            if (it != blacklist.end()) {
                auto now = std::chrono::system_clock::now();
                if (now - it->second < std::chrono::minutes(1)) {
                    send(client_sock, "ERR\nIP ist gesperrt\n", 20, 0);
                    return;
                }
                blacklist.erase(it);
            }
            
            // Login-Versuche prüfen
            if (login_attempts[client_ip] >= 3) {
                blacklist[client_ip] = std::chrono::system_clock::now();
                login_attempts[client_ip] = 0;
                send(client_sock, "ERR\nZu viele Versuche\n", 22, 0);
                return;
            }
        }
        
        if (checkLDAPCredentials(username, password)) {
            current_user = username;
            is_authenticated = true;
            login_attempts[client_ip] = 0;
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

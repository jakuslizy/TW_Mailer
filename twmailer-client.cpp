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

    // Neue Hilfsfunktionen für sicheres Lesen/Schreiben
    std::string safeRead() {
        std::string result;
        const size_t chunk_size = 1024;
        char chunk[chunk_size];
        size_t total_bytes = 0;
        const size_t max_size = 100 * 1024 * 1024; // 100MB Limit

        while (true) {
            memset(chunk, 0, chunk_size);
            ssize_t bytes = read(sock, chunk, chunk_size - 1);
            
            if (bytes <= 0) break;
            
            total_bytes += bytes;
            if (total_bytes > max_size) {
                throw std::runtime_error("Nachricht zu groß");
            }
            
            result.append(chunk, bytes);
            
            // Prüfen ob die Nachricht komplett ist (OK\n oder ERR\n am Ende)
            if (result.find("OK\n") != std::string::npos || 
                result.find("ERR\n") != std::string::npos) {
                break;
            }
        }
        return result;
    }

    void safeSend(const std::string& message) {
        size_t total_sent = 0;
        while (total_sent < message.length()) {
            ssize_t sent = send(sock, 
                              message.c_str() + total_sent, 
                              message.length() - total_sent, 
                              0);
            if (sent <= 0) {
                throw std::runtime_error("Verbindung unterbrochen");
            }
            total_sent += sent;
        }
    }

public:
    TwMailerClient() : sock(0), is_logged_in(false) {}

    bool connect(const char* address, int port) {
        struct sockaddr_in serv_addr;
        
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            std::cout << "Socket-Erstellung fehlgeschlagen" << std::endl;
            return false;
        }
    
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, address, &serv_addr.sin_addr) <= 0) {
            std::cout << "Ungültige Adresse" << std::endl;
            return false;
        }
    
        if (::connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            std::cout << "Verbindung fehlgeschlagen" << std::endl;
            return false;
        }
        
        return true;
    }

    bool login() {
        if (is_logged_in) {
            std::cout << "Bereits eingeloggt als: " << username << std::endl;
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
                std::cout << "Login erfolgreich!" << std::endl;
                return true;
            } else {
                std::cout << "Login fehlgeschlagen: " << response << std::endl;
                return false;
            }
        } catch (const std::exception& e) {
            std::cerr << "Fehler beim Login: " << e.what() << std::endl;
            return false;
        }
    }

    void sendMail() {
        if (!checkLogin()) return;

        try {
            std::string receiver, subject, content;
            std::cout << "Empfänger: ";
            std::getline(std::cin, receiver);
            
            std::cout << "Betreff (max 80 Zeichen): ";
            std::getline(std::cin, subject);
            if (subject.length() > 80) {
                std::cout << "Betreff zu lang!" << std::endl;
                return;
            }
            
            std::cout << "Nachricht (Ende mit einzelnem '.' in neuer Zeile):\n";
            std::string message = "SEND\n" + receiver + "\n" + subject + "\n";
            
            std::string line;
            while (std::getline(std::cin, line) && line != ".") {
                message += line + "\n";
            }
            message += ".\n";

            safeSend(message);
            std::string response = safeRead();
            std::cout << "Server Antwort: " << response;
        } catch (const std::exception& e) {
            std::cerr << "Fehler beim Senden: " << e.what() << std::endl;
        }
    }

    void listMails() {
        if (!checkLogin()) return;

        try {
            safeSend("LIST\n.\n");
            std::string response = safeRead();
            std::cout << "Ihre Nachrichten:\n" << response;
        } catch (const std::exception& e) {
            std::cerr << "Fehler beim Auflisten: " << e.what() << std::endl;
        }
    }

    void readMail() {
        if (!checkLogin()) return;

        try {
            std::string number;
            std::cout << "Nachrichtennummer: ";
            std::getline(std::cin, number);

            safeSend("READ\n" + number + "\n");
            std::string response = safeRead();
            std::cout << "Nachricht:\n" << response;
        } catch (const std::exception& e) {
            std::cerr << "Fehler beim Lesen: " << e.what() << std::endl;
        }
    }

    void deleteMail() {
        if (!checkLogin()) return;

        try {
            std::string number;
            std::cout << "Nachrichtennummer zum Löschen: ";
            std::getline(std::cin, number);

            safeSend("DEL\n" + number + "\n");
            std::string response = safeRead();
            std::cout << "Server Antwort: " << response;
        } catch (const std::exception& e) {
            std::cerr << "Fehler beim Löschen: " << e.what() << std::endl;
        }
    }

private:
    bool checkLogin() {
        if (!is_logged_in) {
            std::cout << "Bitte zuerst einloggen!" << std::endl;
            return false;
        }
        return true;
    }
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "Verwendung: " << argv[0] << " <ip> <port>" << std::endl;
        return 1;
    }

    TwMailerClient client;
    if (!client.connect(argv[1], std::stoi(argv[2]))) {
        return 1;
    }

    std::string input;
    std::cout << "Befehle: LOGIN, SEND, LIST, READ, DEL, QUIT" << std::endl;

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
            std::cout << "Unbekannter Befehl" << std::endl;
        }
    }

    return 0;
}

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread
LDFLAGS_SERVER = -lldap -llber
LDFLAGS_CLIENT = 

# Targets
all: twmailer-server twmailer-client

# Server compilation with LDAP libraries
twmailer-server: twmailer-server.cpp
	$(CXX) $(CXXFLAGS) -o twmailer-server twmailer-server.cpp $(LDFLAGS_SERVER)

# Client compilation (no LDAP needed)
twmailer-client: twmailer-client.cpp
	$(CXX) $(CXXFLAGS) -o twmailer-client twmailer-client.cpp $(LDFLAGS_CLIENT)

# Clean build files
clean:
	rm -f twmailer-server twmailer-client
	rm -f blacklist.dat

# Install required packages (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libldap2-dev

.PHONY: all clean install-deps
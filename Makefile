# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic

# Source files
CLIENT_SRC = twmailer-client.cpp
SERVER_SRC = twmailer-server.cpp

# Output executables
CLIENT_OUT = twmailer-client
SERVER_OUT = twmailer-server

# Default target
all: $(CLIENT_OUT) $(SERVER_OUT)

# Client compilation
$(CLIENT_OUT): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Server compilation
$(SERVER_OUT): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Clean target
clean:
	rm -f $(CLIENT_OUT) $(SERVER_OUT)

# Phony targets
.PHONY: all clean
# TW-Mailer

TW-Mailer is a socket-based client-server application written in C++ that implements a secure internal mail server with LDAP authentication for Technikum Wien students and staff.

## Features

- Secure LDAP authentication against Technikum Wien's directory service
- Protection against brute-force attacks with IP blacklisting
- Send messages to other users
- List messages in user's inbox
- Read specific messages
- Delete messages
- Simple command-line interface
- Multi-process architecture for handling multiple clients
- Safe message handling with size limits and error checking

## Security Features

- LDAP authentication integration with Technikum Wien
- IP-based brute force protection:
    - 3 failed login attempts result in a temporary block
    - 1-minute cooldown period for blocked IPs
    - Persistent blacklist across server restarts
- Secure message handling with size limits
- Process isolation for each client connection

## Requirements

- C++17 compatible compiler
- POSIX-compliant operating system (Linux, macOS)
- OpenLDAP development libraries
- Network connection to Technikum Wien LDAP server

## Installation

### Dependencies

On Ubuntu/Debian systems, install the required LDAP development libraries:

```bash
make install-deps
```

or manually:

```bash
sudo apt-get update
sudo apt-get install -y libldap2-dev
```

### Compilation

To compile the project, use the provided Makefile:

```bash
make all
```

This will create two executables:
- `twmailer-server`: The mail server with LDAP authentication
- `twmailer-client`: The client application for accessing the mail server

## Usage

### Server

Start the server with:

```bash
./twmailer-server <port> <mail-spool-directoryname>
```

Example:
```bash
./twmailer-server 8080 ./mail_spool
```

Parameters:
- `<port>`: The port number on which the server will listen
- `<mail-spool-directoryname>`: Directory where messages will be stored

### Client

Start the client with:

```bash
./twmailer-client <ip> <port>
```

Example:
```bash
./twmailer-client 127.0.0.1 8080
```

## Client Commands

Once connected, the following commands are available:

- `LOGIN`: Authenticate using Technikum Wien credentials
- `SEND`: Send a new message
- `LIST`: List all messages in your inbox
- `READ`: Read a specific message by number
- `DEL`: Delete a specific message by number
- `QUIT`: Disconnect from the server

## Message Format

Messages are stored with the following structure:
```
From: <sender>
To: <recipient>
Subject: <subject>

<message content>
```

## Limitations

- Subject lines are limited to 80 characters
- Maximum message size is 100MB
- Messages must end with a single '.' on a new line
- Requires connection to Technikum Wien LDAP server for authentication

## Error Handling

The system includes robust error handling for:
- Network connectivity issues
- Authentication failures
- Invalid message numbers
- File system operations
- LDAP connection problems
- Message size limits

## File Structure

- `twmailer-server.cpp`: Server implementation with LDAP authentication
- `twmailer-client.cpp`: Client implementation with command interface
- `Makefile`: Compilation instructions
- `blacklist.dat`: Persistent storage for IP blacklist

## Maintenance

### Cleaning Build Files

Remove compiled executables and blacklist:

```bash
make clean
```

### Monitoring

The server logs important events to stdout, including:
- Login attempts
- Message operations
- LDAP connection status
- Error conditions

## Security Notes

- The server must have network access to `ldap.technikum-wien.at:389`
- User credentials are never stored locally
- All authentication is handled through LDAP
- Failed login attempts are tracked per IP address

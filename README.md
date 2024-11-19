# TW-Mailer Pro

A concurrent mail server with LDAP authentication for Technikum Wien, built in C++.

## Key Features

- Multi-process server architecture using fork()
- LDAP authentication with Technikum Wien's server
- IP-based brute force protection (3 attempts, 1-minute blacklist)
- Session-based user operations
- Secure message handling

## Technical Specifications

### Server Architecture
- Concurrent processing using fork() for each client
- Zombie process prevention with signal handling
- Critical section protection with mutex for login attempts
- TCP socket-based communication
- 1024-byte chunks for safe message handling

### LDAP Integration
- Server: ldap.technikum-wien.at:389
- Base DN: dc=technikum-wien,dc=at
- Simple bind authentication
- Automatic session tracking post-authentication

### Storage
- Mail spool directory hierarchy: `<base_dir>/<username>/`
- Sequential message numbering with `.txt` extension
- Persistent blacklist in binary format
- Automatic sender tracking from session data

## Requirements

- C++17 compiler
- OpenLDAP development libraries
- POSIX-compliant OS

## Protocol Commands

### LOGIN
```
LOGIN\n
<username>\n
<password>\n
.\n
```

### SEND
```
SEND\n
<receiver>\n
<subject>\n
<message>\n
.\n
```

### LIST/READ/DEL
```
COMMAND\n
[message-number]\n
.\n
```

## Build Instructions

```bash
# Install dependencies
make install-deps

# Build server and client
make all

# Clean build files
make clean
```

## Security Features

- LDAP-based authentication
- IP blacklisting after 3 failed attempts
- 1-minute cooldown for blocked IPs
- Session-based sender verification
- Process isolation

## File Structure
```
├── twmailer-server.cpp  # Server implementation
├── twmailer-client.cpp  # Client implementation
├── Makefile            # Build configuration
└── blacklist.dat       # IP blacklist storage
```

# TW-Mailer

TW-Mailer is a socket-based client-server application written in C++ that simulates an internal mail server. It allows users to send, list, read, and delete messages.

## Features

- Send messages to other users
- List messages in a user's inbox
- Read specific messages
- Delete messages
- Simple command-line interface

## Requirements

- C++17 compatible compiler
- POSIX-compliant operating system (Linux, macOS)

## Compilation

To compile the project, use the provided Makefile:

`make`

This will create two executables: `twmailer-client` and `twmailer-server`.

## Usage

### Server

To start the server, use the following command:

`./twmailer-server <port> <mail-spool-directoryname>`

Example:

`./twmailer-server 8080 ./mail_spool`

- `<port>`: The port number on which the server will listen
- `<mail-spool-directoryname>`: The directory where messages will be stored


### Client

To start the client, use the following command:

`./twmailer-client <ip> <port>`

Example:

`./twmailer-client 127.0.0.1 8080`

## Commands

Once connected, the client supports the following commands:

- `SEND`: Send a new message
- `LIST`: List all messages for a user
- `READ`: Read a specific message
- `DEL`: Delete a specific message
- `QUIT`: Disconnect from the server

## File Structure

- `twmailer-server.cpp`: Server implementation
- `twmailer-client.cpp`: Client implementation
- `Makefile`: Compilation instructions

## Limitations

- Usernames are limited to 8 characters (a-z, 0-9)
- Subject lines are limited to 80 characters

## Cleaning Up

To remove the compiled executables, use:

`make clean`

# Firewall Rules Manager

A lightweight client–server system for maintaining firewall rules, developed for the *Operating Systems & Systems Programming* module (UoB 2024).  
Supports interactive mode, socket mode, concurrent clients, rule validation, and connection checking.

---

## Features

- Add, delete, list, and query firewall rules  
- Validate IP ranges and port ranges  
- Track all requests submitted to the server  
- Store matching IP/port queries per rule  
- Supports both interactive (`-i`) and network modes  
- Client sends single commands to the server over TCP  
- Concurrency-safe and leak-free (designed for marking scripts)

---

## Commands

- R # List all requests
- A <rule> # Add a rule
- C <ip> <port> # Check connection
- D <rule> # Delete a rule
- L # List rules + stored matches

Invalid input → `Illegal request.`

Rule format example:

147.188.193.0-147.188.194.255 21-22
147.188.192.41 443

---

## Usage

### Build
make

### Server

Interactive:
./server -i

Socket mode:
./server <port>


### Client
./client <host> <port> <command>

Example:
./client localhost 2200 C 147.188.193.15 22

---

## Testing

./test.sh

---

## Files

- server.c
- client.c
- Makefile
- test.sh

---

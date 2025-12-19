#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Invalid usage %s\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    if(strcmp(server_ip, "localhost") == 0){
        server_ip = "127.0.0.1";
    }

    char *endptr;
    long port = strtol(argv[2], &endptr, 10);
    if (*endptr != '\0' || port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port number: %s\n", argv[2]);
        return 1;
    }
    int server_port = (int)port;

    int len = 0;
    for (int i = 3; i < argc; i++) {
        len += strlen(argv[i]) + 1;
    }
    char *command = malloc(len);
    if (!command) {
        perror("Memory allocation failed");
        return -1;
    }
    command[0] = '\0';
    for (int i = 3; i < argc; i++) {
        strcat(command, argv[i]);
        if (i < argc - 1) strcat(command, " ");
    }

    int sock;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        free(command);
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        free(command);
        close(sock);
        return -1;
    }


    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        free(command);
        close(sock);
        return -1;
    }

    if (send(sock, command, strlen(command), 0) < 0) {
        perror("Failed to send command");
        free(command);
        close(sock);
        return -1;
    }
    //printf("%s\n", command);
    free(command);

    
    char buffer[1024] = {0};
    ssize_t bytes_read = read(sock, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("%s\n", buffer);
    } else {
        perror("Failed to read response from server");
    }

    close(sock);
    return 0;
}


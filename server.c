#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>

#define PORT 2200
#define MAX_CONNECTIONS 100
#define MAX_MATCHED_QUERIES 1000
#define MAX_RULES 1000
#define MAX_REQUESTS 1000

char request_history[MAX_REQUESTS][1024];
int request_count=0;
pthread_mutex_t history_lock;
int interactive = 0;

char ip_str[256], port_str[256];
char ip_start[16], ip_end[16];
int port_start, port_end;
char extra[1024];

typedef struct{
    char rule[256];
    int matches_queries_count;
    struct{
        char ip_start[16];
        char ip_end[16];
        int port_start;
        int port_end;
    }
    matched_queries[MAX_MATCHED_QUERIES];
}FirewallRule;

FirewallRule rules[MAX_RULES];
int rules_count = 0;
pthread_mutex_t lock;

void initialise_server(int port);
void accept_client_connections(int server_socket);
void *handle_client(void *client_socket_ptr);
void process_request(const char *request, int client_socket);
void list_requests(int client_socket);
int check_validity(const char *rule, int client_socket);
void add_rule(const char *rule, int client_socket);
int is_valid_ip(const char *ip_str);
int is_valid_port(const char *port_str);
void check_rule(const char *ip, int port, int client_socket);
int ip_in_range(const char *ip_str, const char *ip_start, const char *ip_end);
int port_in_range(int port_str, int port_start, int port_end);
void delete_rule(const char *rule, int client_socket);
int check_rule_match(const char *ip, int port);
void output_response(int client_socket, const char *response);
void list_rules(int client_socket);


int main (int argc, char ** argv) {
    int port = PORT;  

    if (argc > 1) {
        if (strcmp(argv[1], "-i") == 0){
            interactive = 1;
        }else{
            port = atoi(argv[1]);
            if (port <= 0 || port > 65535) {
                
                fprintf(stderr, "Invalid port number: %s\n", argv[1]);
                exit(EXIT_FAILURE);
            }
        }
    }

    initialise_server(port);
    return 0;
}


void initialise_server(int port){
    int server_socket;
    struct sockaddr_in server_addr;

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, MAX_CONNECTIONS) < 0){
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    
 
    if (interactive == 0) {
        pthread_mutex_init(&lock, NULL);
        accept_client_connections(server_socket);
        pthread_mutex_destroy(&lock);
        close(server_socket);
    } else {
                
        char input[1024];
        while (1) {

            
            if (fgets(input, sizeof(input), stdin) != NULL) {
                
                input[strcspn(input, "\n")] = '\0';

             
                process_request(input, -1); 
            } 
        }
    } 
}

void accept_client_connections(int server_socket){
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while (1){
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0){
            perror("Accept failed");
            continue;
        }

        pthread_t client_thread;
        int *pclient = malloc(sizeof(int));
        *pclient = client_socket;

        if (pthread_create(&client_thread, NULL, handle_client, pclient) != 0){
            perror("Failed to create thread");
            free(pclient);
            close(client_socket);
            continue;
        }
        pthread_detach(client_thread);
    }
}

void *handle_client(void *client_socket_ptr){
    int client_socket = *((int *)client_socket_ptr);
    free(client_socket_ptr);

    char buffer[1024] = {0};
    ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0){
        perror("Failed to read from client");
        close(client_socket);
        return NULL;
    }

    buffer[bytes_read] = '\0';
    process_request(buffer, client_socket);
    close(client_socket);
    return NULL;
}

void process_request(const char *request, int client_socket){
    pthread_mutex_lock(&history_lock);

    if (request_count < MAX_REQUESTS){
        strncpy(request_history[request_count], request, sizeof(request_history[request_count]) - 1);
        request_history[request_count][sizeof(request_history[request_count]) - 1] = '\0';
        request_count++;
    }
    pthread_mutex_unlock(&history_lock);

    if (strncmp(request, "A", 1) == 0){
        add_rule(request + 2, client_socket);
    }else if(strncmp(request, "C", 1) == 0){
        char ip[16];
        int port;
        if(sscanf(request + 2, "%15s %d %1s", ip, &port, extra) == 2){
            check_rule(ip, port, client_socket);
        }else{
            output_response(client_socket, "Illegal IP address or port specified");
        }
    
    }else if (strncmp(request, "D", 1) == 0){
        delete_rule(request + 2, client_socket);
    }
    else if (strcmp(request, "R") == 0){
        list_requests(client_socket);
    }else if (strcmp(request, "L") == 0){
        list_rules(client_socket);
    }else{
        output_response(client_socket, "Illegal request");
    }
}

void list_requests(int client_socket){
    pthread_mutex_lock(&history_lock);

    char response[1024 * MAX_REQUESTS] = {0};
    size_t current_length = 0;
    for (int i = 0; i < request_count; i++) {
        int n = snprintf(response + current_length, sizeof(response) - current_length, "%s\n", request_history[i]);
        if (n > 0 && current_length + n < sizeof(response)) {
            current_length += n;
        } else {
            break;
        }
    }
    if (current_length > 0) {
        output_response(client_socket, response);
    } else {
        output_response(client_socket, "Error processing requests");
    }

    pthread_mutex_unlock(&history_lock);
}

int is_valid_ip(const char *ip_str){
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_str, &(sa.sin_addr)) != 0;
}

int is_valid_ip_range(const char *start_ip, const char *end_ip) {
    struct in_addr start_addr, end_addr;

    if (inet_pton(AF_INET, start_ip, &start_addr) <= 0 || inet_pton(AF_INET, end_ip, &end_addr) <= 0) {
        return 0; 
    }

    return ntohl(start_addr.s_addr) <= ntohl(end_addr.s_addr);
}

int is_valid_port(const char *port_str){
    for(int i = 0; port_str[i] != '\0'; i++){
        if(!isdigit(port_str[i]) && port_str[i] != '-'){
            return 0;
        }
    }

    int start_port, end_port;
    if(sscanf(port_str, "%d-%d", &start_port, &end_port) == 2){
        return start_port >= 0 && start_port <=65535 && end_port <= 65535 && start_port <=end_port;
    }else{
        return sscanf(port_str, "%d", &start_port) == 1 && start_port >=0 && start_port <= 65535;
    }
}

int check_validity(const char *rule, int client_socket){
    if(sscanf(rule, "%255s %255s %1s", ip_str, port_str, extra) != 2){        
        return 0;
    }

    if(strchr(ip_str, '-') != NULL){
        int ip_parsed = sscanf(ip_str, "%15[^-]-%15s", ip_start, ip_end);
        if(ip_parsed != 2 || !is_valid_ip(ip_start) || !is_valid_ip(ip_end) || !is_valid_ip_range(ip_start, ip_end)){
            return 0;
        }
    } else{
        if(!is_valid_ip(ip_str)){
            return 0;
        }else{
            strcpy(ip_start, ip_str);
            strcpy(ip_end, ip_str);
        }
    }

    if(!is_valid_port(port_str)){
        return 0;
    }

    if(sscanf(port_str, "%d-%d", &port_start, &port_end) != 2){
        port_end = port_start;
    }

    return 1;
}

void add_rule(const char *rule, int client_socket){
    if(check_validity(rule, client_socket) == 1){
        strcpy(rules[rules_count].rule, rule);
        strcpy(rules[rules_count].matched_queries[0].ip_start, ip_start);
        strcpy(rules[rules_count].matched_queries[0].ip_end, ip_end);
        rules[rules_count].matched_queries[0].port_start = port_start;
        rules[rules_count].matched_queries[0].port_end = port_end;
        rules_count++;
        output_response(client_socket, "Rule added");
    }else{
        output_response(client_socket, "Invalid rule");
    }
}

void delete_rule(const char *rule, int client_socket){
    int rule_found = 0;
    if(check_validity(rule, client_socket) == 1){
        for (int i = 0; i < rules_count; i++) {
            if (strcmp(rules[i].rule, rule) == 0) { 
                rule_found = 1;
                for (int j = i; j < rules_count - 1; j++) {
                    rules[j] = rules[j + 1]; 
                }

                rules_count--; 
                output_response(client_socket, "Rule deleted");
                break;
            }
        }

        if(rule_found == 0){
            output_response(client_socket, "Rule not found");
        }
    }else{
        output_response(client_socket, "Rule invalid");
    }

}


int ip_in_range(const char *ip_str, const char *ip_start, const char *ip_end){
    struct sockaddr_in sa_ip, sa_start, sa_end;
    inet_pton(AF_INET, ip_str, &(sa_ip.sin_addr));
    inet_pton(AF_INET, ip_start, &(sa_start.sin_addr));
    inet_pton(AF_INET, ip_end, &(sa_end.sin_addr));
    return ntohl(sa_ip.sin_addr.s_addr) >= ntohl(sa_start.sin_addr.s_addr) && ntohl(sa_ip.sin_addr.s_addr) <= ntohl(sa_end.sin_addr.s_addr);
}

int port_in_range(int port_str, int port_start, int port_end){
    return port_str >= port_start && port_str <= port_end;
}

void check_rule(const char *ip, int port, int client_socket){
    char port_str[6]; 
    snprintf(port_str, sizeof(port_str), "%d", port);

    if(!is_valid_ip(ip) || !is_valid_port(port_str)){
        output_response(client_socket, "Illegal IP address or port specified");
        return;
    }

    pthread_mutex_lock(&lock);
    int rule_found = 0;

    for(int i = 0; i<rules_count; i++){
        if(ip_in_range(ip, rules[i].matched_queries[0].ip_start, rules[i].matched_queries[0].ip_end) && port_in_range(port, rules[i].matched_queries[0].port_start, rules[i].matched_queries[0].port_end)){
            if(rules[i].matches_queries_count < MAX_MATCHED_QUERIES){
                strcpy(rules[i].matched_queries[rules[i].matches_queries_count].ip_start, ip);
                rules[i].matched_queries[rules[i].matches_queries_count].port_start = port;
                rules[i].matches_queries_count++;
            }

            rule_found = 1;
            break;
        }

    }

    pthread_mutex_unlock(&lock);

    if(rule_found == 1){
        output_response(client_socket, "Connection accepted");
    }else{
        output_response(client_socket, "Connection rejected");
    }
}

void list_rules(int client_socket){
    pthread_mutex_lock(&lock);

    char response[1024 * MAX_RULES] = {0};
    size_t current_length = 0;

    for (int i = 0; i < rules_count; i++) {
        int n = snprintf(response + current_length, sizeof(response) - current_length, "Rule: %s\n", rules[i].rule);
        if (n > 0 && current_length + n < sizeof(response)) {
            current_length += n;
        } else {
            break;
        }

        for (int j = 0; j < rules[i].matches_queries_count; j++) {
            n = snprintf(response + current_length, sizeof(response) - current_length, "Query: %s %d\n",
                          rules[i].matched_queries[j].ip_start, rules[i].matched_queries[j].port_start);
            if (n > 0 && current_length + n < sizeof(response)) {
                current_length += n;
            } else {
                break;
            }
        }
    }

    if (current_length > 0) {
        output_response(client_socket, response);
    } else {
        output_response(client_socket, "No rules found");
    }

    pthread_mutex_unlock(&lock);
}



void output_response(int client_socket, const char *response) {
    if(interactive == 1){
        printf("%s\n", response);
        fflush(stdout);
    }else if (client_socket >= 0) {
        ssize_t bytes_sent = send(client_socket, response, strlen(response), 0);
        if (bytes_sent < 0) {
            perror("Failed to send response to client");
        }
    }
}

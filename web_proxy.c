/*
* File Name: web_proxy.c
* Completed by: Shahzeb Ahmed
* Submission Date: October 19, 2023
*/

// Importing necessary header files
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <regex.h>

// Defining constants
#define BUFFER_SIZE 8192
#define NEW_SRC "https://img.freepik.com/free-vector/cute-green-frog-lotus-leaf_1308-103570.jpg\""



// Function to read an HTTP request from a client
int read_http_request(int sockfd, char *buffer, int buffer_size) {
    int total_bytes_read = 0, bytes_read;
    char *end_marker;

    // Continuously read from the socket until end of request headers is found
    while (1) {
        bytes_read = read(sockfd, buffer + total_bytes_read, buffer_size - total_bytes_read - 1);
        if (bytes_read <= 0) {
            return bytes_read;
        }

        total_bytes_read += bytes_read;
        buffer[total_bytes_read] = '\0';

        // Check for end of headers
        end_marker = strstr(buffer, "\r\n\r\n");
        if (end_marker) {
            break;
        }

        // Check for buffer overflow
        if (total_bytes_read == buffer_size - 1) {
            fprintf(stderr, "Buffer overflow detected, potential request too long.\n");
            return -1;
        }
    }

    return total_bytes_read;
}

// Function to send an HTTP response back to the client after modifications
int send_http_response(int client_sockfd, int server_sockfd) {
    char buffer[BUFFER_SIZE], *full_response = NULL, *updated_response = NULL;
    int total_bytes_read = 0, bytes_read;
    char *end_marker, *content_length_pos;
    int content_length = 0, header_length, total_length, response_size = 0;

    // Read the server's response
    bytes_read = read(server_sockfd, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        return bytes_read;
    }

    total_bytes_read += bytes_read;
    buffer[total_bytes_read] = '\0';

    // Check if the response has a proper header
    end_marker = strstr(buffer, "\r\n\r\n");
    if (!end_marker) {
        fprintf(stderr, "Malformed response, no header end found.\n");
        return -1;
    }

    header_length = end_marker - buffer + 4;

    // Extract the Content-Length value from the response
    content_length_pos = strstr(buffer, "Content-Length: ");
    if (content_length_pos) {
        sscanf(content_length_pos, "Content-Length: %d", &content_length);
    }

    // Calculate total response length
    total_length = header_length + content_length;

    // Allocate memory for the complete response
    full_response = (char*) malloc(total_length);
    if (!full_response) {
        perror("Memory allocation failed");
        return -1;
    }
    memcpy(full_response, buffer, total_bytes_read);

    // Read remaining parts of the response if any
    while (total_bytes_read < total_length) {
        bytes_read = read(server_sockfd, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            break;
        }
        memcpy(full_response + total_bytes_read, buffer, bytes_read);
        total_bytes_read += bytes_read;
    }


    regex_t regex;
    regmatch_t matches[2];

    // Compile the regex to find image sources
    if (regcomp(&regex, "src=\"[^\"]*\\.(jpg|jpeg)\"", REG_EXTENDED) != 0) {
        fprintf(stderr, "Could not compile regex.\n");
        return -1;
    }

    // Replace every image source with NEW_SRC
    int offset = 0;
    while (regexec(&regex, full_response + offset, 2, matches, 0) == 0) {
        int start = offset + matches[0].rm_so + 5; // +5 to skip "src="
        int end = offset + matches[0].rm_eo;

        total_length = total_length - (end - start) + strlen(NEW_SRC);
        full_response = realloc(full_response, total_length);

        if (!full_response) {
            perror("Memory reallocation failed");
            regfree(&regex);
            return -1;
        }

        memmove(full_response + start + strlen(NEW_SRC), full_response + end, total_bytes_read - end + 1);
        memcpy(full_response + start, NEW_SRC, strlen(NEW_SRC));

        total_bytes_read += strlen(NEW_SRC) - (end - start);
        offset = start + strlen(NEW_SRC);
    }

    // Compile regex to replace the word "Frog"
    regex_t regex_frog;
    if (regcomp(&regex_frog, "Frog ", REG_ICASE | REG_EXTENDED) != 0) {
    fprintf(stderr, "Could not compile regex for Frog.\n");
    return -1;
    }

    offset = 0; 

    // Replace every occurrence of the word "Frog" with "Fred"
    while (regexec(&regex_frog, full_response + offset, 1, matches, 0) == 0) {
    int start = offset + matches[0].rm_so;
    int end = offset + matches[0].rm_eo;

    memcpy(full_response + start, "Fred", 4);

    offset = start + 4;
    }
    regfree(&regex_frog);

    // Update the Content-Length header

    char new_content_length_header[BUFFER_SIZE];
    snprintf(new_content_length_header, sizeof(new_content_length_header), "Content-Length: %d", total_length - header_length);

    content_length_pos = strstr(full_response, "Content-Length: ");
    if (content_length_pos) {
        char *content_length_end = strstr(content_length_pos, "\r\n");
        memmove(content_length_pos + strlen(new_content_length_header), content_length_end, total_length - (content_length_end - full_response));
        memcpy(content_length_pos, new_content_length_header, strlen(new_content_length_header));
    }

    // Send the modified response back to the client
    write(client_sockfd, full_response, total_length);

    free(full_response);
    return total_length;
}

// Function to forward a client's request to the destination server
int forward_request_to_server(char* request) {
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char hostname[BUFFER_SIZE];

    if (sscanf(request, "GET http://%[^/]", hostname) == 0) {
        return -1;
    }
    
    // Creates a socket to communicate with the server.

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        return -1;
    }

    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host: %s\n", hostname);
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(80);

    // Connects to the server
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
        return -1;
    }

    // Forwards the request to the server.
    write(sockfd, request, strlen(request));
    return sockfd;
}

int main() {
    int port;
    char ip[16];
    char localhost[] = "localhost";

    printf("Please enter PORT number you would like the web-proxy to run on: ");
    scanf("%d", &port);

    printf("Please enter IP address (or localhost): ");
    scanf("%15s", ip);

    if (strcmp(ip, localhost) == 0) {
        printf("Entered IP is localhost\n");
        strcpy(ip, "127.0.0.1");
    }

    printf("Binding to IP %s and Port %d\n", ip, port);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        return 1;
    }

    struct sockaddr_in serv_addr, cli_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR on binding");
        return 1;
    }

    listen(sockfd, 5);

    while(1) {
        socklen_t clilen = sizeof(cli_addr);
        int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) {
            perror("ERROR on accept");
            continue;
        }

        char buffer[BUFFER_SIZE];
        int n = read_http_request(newsockfd, buffer, sizeof(buffer));

        if (n <= 0) {
            if (n == 0) {
                continue;
            } else {
                perror("ERROR reading from socket");
            }
            close(newsockfd);
            continue;
        }

        int server_sockfd = forward_request_to_server(buffer);
        if (server_sockfd >= 0) {
            send_http_response(newsockfd, server_sockfd);
            close(server_sockfd);
        }

        close(newsockfd);
    }

    close(sockfd);
    return 0;
}

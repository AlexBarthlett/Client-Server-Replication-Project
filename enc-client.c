/**
 * @file enc-client.c
 * @author ** Alexander E Barthlett, Richard Disimoni **
 * @date  ** October 20, 2024 **
 * @brief fill in here
*/

#include <netdb.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <stdbool.h>

// Constants for client configuration
#define DEFAULT_PORT        4433
#define DEFAULT_HOST        "localhost"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         256
#define STRING_SIZE         50

// Function prototypes
int create_socket(char* hostname, unsigned int port);
bool authenticate(SSL* ssl);

/**
 * Creates a socket and connects to the specified host and port.
 */
int create_socket(char* hostname, unsigned int port) {
    int sockfd;
    struct hostent* host;
    struct sockaddr_in dest_addr;

    // Resolve the hostname to an IP address
    host = gethostbyname(hostname);
    if (host == NULL) {
        fprintf(stderr, "Client: Cannot resolve hostname %s\n", hostname);
        exit(EXIT_FAILURE);
    }

    // Create a socket for IPv4 and TCP protocol
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Client: Unable to create socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Prepare the sockaddr_in structure
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) < 0) {
        fprintf(stderr, "Client: Cannot connect to host %s [%s] on port %d: %s\n",
                hostname, inet_ntoa(dest_addr.sin_addr), port, strerror(errno));
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

/**
 * Authenticates the client with the server.
 */
bool authenticate(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    int bytes;
    
    // Receive authentication request from server
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes] = 0;
    printf("Server: %s\n", buffer);
    
    // Get username and password from user
    char username[STRING_SIZE], password[STRING_SIZE];
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;  // Remove newline
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;  // Remove newline
    
    // Send credentials to server
    char credentials[BUFFER_SIZE];
    snprintf(credentials, sizeof(credentials), "%s %s", username, password);
    SSL_write(ssl, credentials, strlen(credentials));
    
    // Receive authentication result
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes] = 0;
    printf("Server: %s\n", buffer);
    
    // Check if authentication was successful
    return strstr(buffer, "successful") != NULL;
}

int main(int argc, char** argv) {
    const SSL_METHOD* method;
    unsigned int port = DEFAULT_PORT;
    char remote_host[MAX_HOSTNAME_LENGTH];
    char buffer[BUFFER_SIZE];
    char* temp_ptr;
    int sockfd;
    SSL_CTX* ssl_ctx;
    SSL* ssl;

    // Parse command line arguments
    if (argc != 2) {
        fprintf(stderr, "Client: Usage: ssl-client <server name>:<port>\n");
        exit(EXIT_FAILURE);
    } else {
        // Check if port is specified in the argument
        temp_ptr = strchr(argv[1], ':');
        if (temp_ptr == NULL) {
            // Only hostname provided, use default port
            strncpy(remote_host, argv[1], MAX_HOSTNAME_LENGTH);
        } else {
            // Hostname and port provided
            strncpy(remote_host, strtok(argv[1], ":"), MAX_HOSTNAME_LENGTH);
            port = (unsigned int) atoi(temp_ptr + sizeof(char));
        }
    }

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    if(SSL_library_init() < 0) {
        fprintf(stderr, "Client: Could not initialize the OpenSSL library!\n");
        exit(EXIT_FAILURE);
    }

    // Create new SSL connection state
    method = SSLv23_client_method();
    ssl_ctx = SSL_CTX_new(method);
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Unable to create a new SSL context structure.\n");
        exit(EXIT_FAILURE);
    }

    // Disallow SSLv2
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

    // Create new SSL connection state object
    ssl = SSL_new(ssl_ctx);

    // Create TCP connection
    sockfd = create_socket(remote_host, port);
    if(sockfd != 0) {
        fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", remote_host, port);
    } else {
        fprintf(stderr, "Client: Could not establish TCP connection to %s on port %u\n", remote_host, port);
        exit(EXIT_FAILURE);
    }

    // Bind the SSL object to the socket descriptor
    SSL_set_fd(ssl, sockfd);

    // Perform SSL handshake
    if (SSL_connect(ssl) == 1) {
        printf("Client: Established SSL/TLS session to '%s' on port %u\n", remote_host, port);
    } else {
        fprintf(stderr, "Client: Could not establish SSL session to '%s' on port %u\n", remote_host, port);
        exit(EXIT_FAILURE);
    }

    // Authenticate with the server
    if (!authenticate(ssl)) {
        fprintf(stderr, "Authentication failed. Exiting.\n");
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("Authentication successful. You can now send queries.\n");

    // Main communication loop
    while (1) {
        char query[BUFFER_SIZE];
        printf("Enter your query (or 'quit' to exit): ");
        fgets(query, sizeof(query), stdin);
        query[strcspn(query, "\n")] = 0;  // Remove newline

        if (strcmp(query, "quit") == 0) break;

        // Send query to server
        SSL_write(ssl, query, strlen(query));

        // Receive and display server response
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        buffer[bytes] = 0;
        printf("Server response: %s\n", buffer);
    }

    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sockfd);
    printf("Client: Terminated SSL/TLS connection with server '%s'\n", remote_host);

    return EXIT_SUCCESS;
}

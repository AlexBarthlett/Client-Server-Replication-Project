/**
* @file enc-server.c
* @author ** Alexander E Barthlett, Richard Disimoni **
* @date  ** Due: October 20, 2024 **
* @brief  fill in here
*/
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

#include <sqlite3.h>

// Constants for server configuration
#define BUFFER_SIZE       256
#define STRING_SIZE       50
#define DEFAULT_PORT      4433
#define CERTIFICATE_FILE  "cert.pem"
#define KEY_FILE          "key.pem"
#define DATABASE_NAME     "main_database.db"
#define REPLICA_DB_NAME   "replica_database.db"
#define REPLICA_SERVER    "localhost"
#define REPLICA_PORT      5433

// Configuration structure for server settings
typedef struct {
    int replication_interval;  // in seconds
} ServerConfig;

// Global configuration object with default values
ServerConfig config = {60};  // Default replication interval: 60 seconds

// Function prototypes
int create_socket(unsigned int port);
void init_openssl();
void cleanup_openssl();
SSL_CTX* create_new_context();
void configure_context(SSL_CTX* ssl_ctx);
void* replication_thread(void* arg);
bool authenticate_client(SSL* ssl);
void handle_client(SSL* ssl, int client, char* client_addr);

/**
 * Creates a socket and binds it to the specified port.
 */
int create_socket(unsigned int port) {
    int s;
    struct sockaddr_in addr;

    // Create a socket for IPv4 and TCP protocol
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Prepare the sockaddr_in structure
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind the socket to the port
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Server: Unable to bind to socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(s, 1) < 0) {
        fprintf(stderr, "Server: Unable to listen: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("Server: Listening on TCP port %u\n", port);

    return s;
}

/**
 * Initializes OpenSSL library.
 */
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

/**
 * Cleans up OpenSSL library.
 */
void cleanup_openssl() {
    EVP_cleanup();
}

/**
 * Creates a new SSL context.
 */
SSL_CTX* create_new_context() {
    const SSL_METHOD* ssl_method;
    SSL_CTX* ssl_ctx;

    ssl_method = SSLv23_server_method();
    ssl_ctx = SSL_CTX_new(ssl_method);
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Server: cannot create SSL context:\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ssl_ctx;
}

/**
 * Configures the SSL context with certificates and keys.
 */
void configure_context(SSL_CTX* ssl_ctx) {
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

    if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Server: cannot set certificate:\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
        fprintf(stderr, "Server: cannot set private key:\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

/**
 * Thread function for database replication.
 */
void* replication_thread(void* arg) {
    while (1) {
        sleep(config.replication_interval);
        
        // Open main and replica databases
        sqlite3 *main_db, *replica_db;
        char *err_msg = 0;
        
        if (sqlite3_open(DATABASE_NAME, &main_db) != SQLITE_OK) {
            fprintf(stderr, "Failed to open main database: %s\n", sqlite3_errmsg(main_db));
            continue;
        }
        
        if (sqlite3_open(REPLICA_DB_NAME, &replica_db) != SQLITE_OK) {
            fprintf(stderr, "Failed to open replica database: %s\n", sqlite3_errmsg(replica_db));
            sqlite3_close(main_db);
            continue;
        }
        
        // Perform the backup
        sqlite3_backup *backup = sqlite3_backup_init(replica_db, "main", main_db, "main");
        if (backup) {
            sqlite3_backup_step(backup, -1);
            sqlite3_backup_finish(backup);
        }
        
        // Check for errors
        if (sqlite3_errcode(replica_db) != SQLITE_OK) {
            fprintf(stderr, "Replication failed: %s\n", sqlite3_errmsg(replica_db));
        } else {
            printf("Database replicated successfully.\n");
        }
        
        // Close databases
        sqlite3_close(main_db);
        sqlite3_close(replica_db);
    }
    return NULL;
}

/**
 * Authenticates a client connection.
 */
bool authenticate_client(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    int bytes;
    
    // Send authentication request
    const char* auth_request = "Please provide your username and password.";
    SSL_write(ssl, auth_request, strlen(auth_request));
    
    // Receive credentials
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    buffer[bytes] = 0;
    
    char username[STRING_SIZE], password[STRING_SIZE];
    sscanf(buffer, "%s %s", username, password);
    
    // TODO: Implement proper authentication logic
    // For demonstration, we're using a simple hardcoded check
    if (strcmp(username, "admin") == 0 && strcmp(password, "password") == 0) {
        return true;
    }
    return false;
}

/**
 * Handles communication with an authenticated client.
 */
void handle_client(SSL* ssl, int client, char* client_addr) {
    char buffer[BUFFER_SIZE];
    int bytes;
    
    // Authenticate the client
    if (!authenticate_client(ssl)) {
        const char* auth_failed = "Authentication failed. Closing connection.";
        SSL_write(ssl, auth_failed, strlen(auth_failed));
        return;
    }
    
    // Inform client of successful authentication
    const char* auth_success = "Authentication successful. You can now send queries.";
    SSL_write(ssl, auth_success, strlen(auth_success));
    
    // Main communication loop
    while (1) {
        bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes <= 0) break;
        buffer[bytes] = 0;
        
        // TODO: Implement query handling logic here
        // For demonstration, we're just echoing the query back
        char response[BUFFER_SIZE + 32];
        snprintf(response, sizeof(response), "Received query: %s", buffer);
        SSL_write(ssl, response, strlen(response));
    }
}

int main(int argc, char **argv) {
    SSL_CTX* ssl_ctx;
    unsigned int sockfd;
    unsigned int port = DEFAULT_PORT;

    // Initialize OpenSSL
    init_openssl();
    ssl_ctx = create_new_context();
    configure_context(ssl_ctx);

    // Parse command line arguments for port
    if (argc == 2) {
        port = atoi(argv[1]);
    }

    // Create socket and start listening
    sockfd = create_socket(port);

    // Start replication thread
    pthread_t repl_thread;
    if (pthread_create(&repl_thread, NULL, replication_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create replication thread\n");
        return EXIT_FAILURE;
    }

    // Main server loop
    while(true) {
        SSL* ssl;
        int client;
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        char client_addr[INET_ADDRSTRLEN];

        // Accept incoming connection
        client = accept(sockfd, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            fprintf(stderr, "Server: Unable to accept connection: %s\n", strerror(errno));
            continue;
        }

        // Get client's IP address
        inet_ntop(AF_INET, &addr.sin_addr, client_addr, INET_ADDRSTRLEN);
        printf("Server: Established TCP connection with client (%s) on port %u\n", client_addr, port);

        // Create new SSL structure for this connection
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client);

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "Server: Could not establish secure connection:\n");
            ERR_print_errors_fp(stderr);
        } else {
            printf("Server: Established SSL/TLS connection with client (%s)\n", client_addr);

            // Fork a new process to handle the client
            pid_t pid = fork();
            if (pid == 0) {  // Child process
                close(sockfd);  // Close listening socket in child
                handle_client(ssl, client, client_addr);
                SSL_free(ssl);
                exit(EXIT_SUCCESS);
            } else if (pid > 0) {  // Parent process
                close(client);  // Close client socket in parent
                SSL_free(ssl);
            } else {
                fprintf(stderr, "Fork failed\n");
            }
        }
    }

    // Clean up (this part is never reached in this implementation)
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    close(sockfd);

    return EXIT_SUCCESS;
}

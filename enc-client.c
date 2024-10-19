/**
 * @file enc-client.c
 * @author ** Alexander E Barthlett, Richard Disimoni **
 * @date  ** October 20, 2024 **
 * @brief This program implements a client that securely communicates with the server over SSL.
 *        The client can perform authenticated operations such as adding users/products, viewing, deleting, updating etc.
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
#define BUFFER_SIZE         1024  // Increased to handle longer responses
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
    if (bytes <= 0) {
        fprintf(stderr, "Error receiving authentication request\n");
        return false;
    }

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

    if ((bytes = SSL_write(ssl, credentials, strlen(credentials))) < 0) {
        fprintf(stderr, "Failed to write, Error: %s\n", strerror(errno));
        return false;
    }
    
    // Receive authentication result
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        fprintf(stderr, "Error receiving authentication result\n");
        return false;
    }
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
        bool incorrect_password = true;
        char query[BUFFER_SIZE];
        printf("Enter your query (or 'quit' to exit): ");
        fgets(query, sizeof(query), stdin);
        query[strcspn(query, "\n")] = 0;  // Remove newline

        if (strcmp(query, "quit") == 0) break;

        if (strcmp(query, "Add_user") == 0) {
            char username[STRING_SIZE];
            char password[STRING_SIZE];
            char role[STRING_SIZE];

            printf("Enter the new username: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0;
            for (int i = 0; i < strlen(username); i++) { // Replaces all spaces to ensure a single string for marshalling.
                if (username[i] == ' ') {
                    username[i] = '_';
                }
            }

            while (incorrect_password) {
                printf("Enter a new password: ");
                fgets(password, sizeof(password), stdin);
                password[strcspn(password, "\n")] = 0;
                for (int i = 0; i < strlen(password); i++) { // Passwords cant have spaces, check for spaces.
                    if (password[i] == ' ') {
                        printf("Error: Spaces are not allowed in the password\n");

                        bzero(password, STRING_SIZE); // Clear buffer for next password.
                        break;
                    }
                    else if (password[i] != ' ' && i == strlen(password) - 1) {
                        incorrect_password = false; // No spaces, all good to break loop.
                    }
                }  
            }

            incorrect_password = true; // Reset back to true for the next use, may not be needed, but for robustness.

            printf("Enter a new user role (admin or none): ");
            fgets(role, sizeof(role), stdin);
            role[strcspn(role, "\n")] = 0;
            for (int i = 0; i < strlen(role); i++) { // Replaces all spaces to ensure a single string for marshalling.
                if (role[i] == ' ') {
                    role[i] = '_';
                }
            }

            sprintf(query, "%s %s %s %s", "Add_user", username, password, role);
        }
        else if (strcmp(query, "Delete_user") == 0) {
            char username[STRING_SIZE];
            printf("Enter the username to delete: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0;

            sprintf(query, "%s %s", "Delete_user", username);
        }
        else if (strcmp(query, "View_user") == 0) {
            char username[STRING_SIZE];
            printf("Enter the username to view: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0;

            sprintf(query, "%s %s", "View_user", username);
        }
        else if (strcmp(query, "View_all_users") == 0) {
            // No additional input needed
        }
        else if (strcmp(query, "Add_product") == 0) {
            char product_name[STRING_SIZE];
            char product_category[STRING_SIZE];
            char temp_buffer[STRING_SIZE];
            int product_quantity;
            double product_price;

            printf("Enter the new product's name: ");
            fgets(product_name, sizeof(product_name), stdin);
            product_name[strcspn(product_name, "\n")] = 0;
            for (int i = 0; i < strlen(product_name); i++) { // Replaces all spaces to ensure a single string for marshalling.
                if (product_name[i] == ' ') {
                    product_name[i] = '_';
                }
            }

            printf("Enter the new product's category: ");
            fgets(product_category, sizeof(product_category), stdin);
            product_category[strcspn(product_category, "\n")] = 0;
            for (int i = 0; i < strlen(product_category); i++) { // Replaces all spaces to ensure a single string for marshalling.
                if (product_category[i] == ' ') {
                    product_category[i] = '_';
                }
            }

            printf("Enter the new product's quantity: ");
            fgets(temp_buffer, sizeof(temp_buffer), stdin);
            temp_buffer[strcspn(temp_buffer, "\n")] = 0;
            product_quantity = atoi(temp_buffer);

            printf("Enter the new product's price: ");
            fgets(temp_buffer, sizeof(temp_buffer), stdin);
            temp_buffer[strcspn(temp_buffer, "\n")] = 0;
            product_price = atof(temp_buffer);

            sprintf(query, "%s %s %s %d %f", "Add_product", product_name, product_category, product_quantity, product_price);
        }
        else if (strcmp(query, "Update_product") == 0) {
            char product_name[STRING_SIZE];
            char product_category[STRING_SIZE];
            char temp_buffer[STRING_SIZE];
            int product_quantity;
            double product_price;

            printf("Enter the product's name to update: ");
            fgets(product_name, sizeof(product_name), stdin);
            product_name[strcspn(product_name, "\n")] = 0;

            printf("Enter the new category: ");
            fgets(product_category, sizeof(product_category), stdin);
            product_category[strcspn(product_category, "\n")] = 0;
            for (int i = 0; i < strlen(product_category); i++) { // Replaces all spaces to ensure a single string for marshalling.
                if (product_category[i] == ' ') {
                    product_category[i] = '_';
                }
            }

            printf("Enter the new quantity: ");
            fgets(temp_buffer, sizeof(temp_buffer), stdin);
            temp_buffer[strcspn(temp_buffer, "\n")] = 0;
            product_quantity = atoi(temp_buffer);

            printf("Enter the new price: ");
            fgets(temp_buffer, sizeof(temp_buffer), stdin);
            temp_buffer[strcspn(temp_buffer, "\n")] = 0;
            product_price = atof(temp_buffer);

            sprintf(query, "%s %s %s %d %f", "Update_product", product_name, product_category, product_quantity, product_price);
        }
        else if (strcmp(query, "Delete_product") == 0) {
            char product_name[STRING_SIZE];
            printf("Enter the product name to delete: ");
            fgets(product_name, sizeof(product_name), stdin);
            product_name[strcspn(product_name, "\n")] = 0;

            sprintf(query, "%s %s", "Delete_product", product_name);
        }
        else if (strcmp(query, "View_product") == 0) {
            char product_name[STRING_SIZE];
            printf("Enter the product name to view: ");
            fgets(product_name, sizeof(product_name), stdin);
            product_name[strcspn(product_name, "\n")] = 0;

            sprintf(query, "%s %s", "View_product", product_name);
        }
        else if (strcmp(query, "View_all_products") == 0) {
            // No additional input needed
        }

        int bytes_written = 0;
        // Send query to server
        if ((bytes_written = SSL_write(ssl, query, strlen(query))) < 0) {
            fprintf(stderr, "Failed to write, Error: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        if (strcmp(query, "View_all_products") == 0) { // Needs to read multiple lines.
            int bytes = 0;
            while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
                char endCheck[STRING_SIZE];
                sscanf(buffer, "%s", endCheck);
                if (strcmp(endCheck, "END_OF_QUERY") == 0) { // No more to read.
                    break;
                }
                else {
                    char name[STRING_SIZE];
                    char category[STRING_SIZE];
                    int quantity;
                    double price;

                    sscanf(buffer, "%s %s %d %le", name, category, &quantity, &price);
                    printf("Name: %s, Category: %s, Quantity: %d, Price: %.2f\n", name, category, quantity, price);
                }

                bzero(buffer, BUFFER_SIZE); // Clear out for next read.
            }

            if ((bytes < 0)) {
                fprintf(stderr, "Failed to read, Error: %s\n", strerror(errno));
                return EXIT_FAILURE;
            }

            bzero(buffer, BUFFER_SIZE); // Clear out for next read.
        }

        else if(strcmp(query, "View_all_users") == 0) { // Needs to read multiple lines.
            int bytes = 0;
            while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
                char endCheck[STRING_SIZE];
                sscanf(buffer, "%s", endCheck);
                if (strcmp(endCheck, "END_OF_QUERY") == 0) { // No more to read.
                    break;
                }
                else if(strcmp(endCheck, "NOT_ADMIN") == 0) { // Not an admin, cant use this query.
                    printf("Server Response: You do not have the proper role for that query\n");
                    break;
                }
                else {
                    char name[STRING_SIZE];
                    char role[STRING_SIZE];

                    sscanf(buffer, "%s %s", name, role);
                    printf("Name: %s, Role: %s\n", name, role);
                }

                bzero(buffer, BUFFER_SIZE); // Clear out for next read.
            }

            if (bytes < 0) {
                fprintf(stderr, "Failed to read, Error: %s\n", strerror(errno));
                return EXIT_FAILURE;
            }

            bzero(buffer, BUFFER_SIZE); // Clear out for next read.
        }

        else { // Every other query only needs one read call.

            // Receive and display server response
            int bytes = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes > 0) {
                buffer[bytes] = 0;
                printf("Server response: %s\n", buffer);
            } else {
                fprintf(stderr, "Error receiving server response\n");
            }
            bzero(buffer, BUFFER_SIZE);
        }
    }

    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sockfd);
    printf("Client: Terminated SSL/TLS connection with server '%s'\n", remote_host);

    return EXIT_SUCCESS;
}

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

#define DEFAULT_PORT        4433
#define DEFAULT_HOST        "localhost"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         256
#define STRING_NAME         50

/**
* @brief This function does the basic necessary housekeeping to establish a secure TCP
*        connection to the server specified by 'hostname'.
*/
int create_socket(char* hostname, unsigned int port) {
  int                sockfd;
  struct hostent*    host;
  struct sockaddr_in dest_addr;

  host = gethostbyname(hostname);
  if (host == NULL) {
    fprintf(stderr, "Client: Cannot resolve hostname %s\n",  hostname);
    exit(EXIT_FAILURE);
  }

  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // First we set up a network socket. An IP socket address is a combination
  // of an IP interface address plus a 16-bit port number. The struct field
  // sin_family is *always* set to AF_INET. Anything else returns an error.
  // The TCP port is stored in sin_port, but needs to be converted to the
  // format on the host machine to network byte order, which is why htons()
  // is called. The s_addr field is the network address of the remote host
  // specified on the command line. The earlier call to gethostbyname()
  // retrieves the IP address for the given hostname.
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

  // Now we connect to the remote host.  We pass the connect() system call the
  // socket descriptor, the address of the remote host, and the size in bytes
  // of the remote host's address
  if (connect(sockfd, (struct sockaddr *) &dest_addr,
	      sizeof(struct sockaddr)) <0) {
    fprintf(stderr, "Client: Cannot connect to host %s [%s] on port %d: %s\n",
	    hostname, inet_ntoa(dest_addr.sin_addr), port, strerror(errno));
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

void logInCall() {
    // if the LOG_IN message is received, call this function to loop, read and write until logged in or exit.
}

int exitFailureCall(SSL* ssl, SSL_CTX* ssl_ctx, int* sockfd, char* remote_host) {
    printf("Client: Terminating SSL session and TCP connection with server (%s)\n",
	    remote_host);
    SSL_CTX_free(ssl_ctx);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(*sockfd);

    return EXIT_FAILURE;
}


/**
* @brief The sequence of steps required to establish a secure SSL/TLS connection is:
*
*        1.  Initialize the SSL algorithms
*        2.  Create and configure an SSL context object
*        3.  Create an SSL session object
*        4.  Create a new network socket in the traditional way
*        5.  Bind the SSL object to the network socket descriptor
*        6.  Establish an SSL session on top of the network connection
*
* Once these steps are completed successfully, use the functions SSL_read() and
* SSL_write() to read from/write to the socket, but using the SSL object rather
* then the socket descriptor.  Once the session is complete, free the memory
* allocated to the SSL object and close the socket descriptor.
*/
int main(int argc, char** argv) {
  const SSL_METHOD* method;
  unsigned int      port = DEFAULT_PORT;
  char              remote_host[MAX_HOSTNAME_LENGTH];
  char              buffer[BUFFER_SIZE];
  char*             temp_ptr;
  int               sockfd;
  int               total = 0;
  int               messageRead;
  int               messageSent;
  SSL_CTX*          ssl_ctx;
  SSL*              ssl;
  char              userResponse[STRING_NAME];
  char              userName[STRING_NAME];
  char              userPassword[STRING_NAME];

  if (argc != 2) {
    fprintf(stderr, "Client: Usage: ssl-client <server name>:<port>\n");
    exit(EXIT_FAILURE);
  } else {
    // Search for ':' in the argument to see if port is specified
    temp_ptr = strchr(argv[1], ':');
    if (temp_ptr == NULL)    // Hostname only. Use default port
      strncpy(remote_host, argv[1], MAX_HOSTNAME_LENGTH);
    else {
      // Argument is formatted as <hostname>:<port>. Need to separate
      // First, split out the hostname from port, delineated with a colon
      // remote_host will have the <hostname> substring
      strncpy(remote_host, strtok(argv[1], ":"), MAX_HOSTNAME_LENGTH);
      // Port number will be the substring after the ':'. At this point
      // temp is a pointer to the array element containing the ':'
      port = (unsigned int) atoi(temp_ptr+sizeof(char));
    }
  }

  // Initialize OpenSSL ciphers and digests
  OpenSSL_add_all_algorithms();

  // SSL_library_init() registers the available SSL/TLS ciphers and digests.
  if(SSL_library_init() < 0) {
    fprintf(stderr, "Client: Could not initialize the OpenSSL library!\n");
    exit(EXIT_FAILURE);
  }

  // Use the SSL/TLS method for clients
  method = SSLv23_client_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(method);
  if (ssl_ctx == NULL) {
    fprintf(stderr, "Unable to create a new SSL context structure.\n");
    exit(EXIT_FAILURE);
  }

  // This disables SSLv2, which means only SSLv3 and TLSv1 are available
  // to be negotiated between client and server
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

  // Create a new SSL connection state object
  ssl = SSL_new(ssl_ctx);

  // Create the underlying TCP socket connection to the remote host
  sockfd = create_socket(remote_host, port);
  if(sockfd != 0)
    fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", remote_host, port);
  else {
    fprintf(stderr, "Client: Could not establish TCP connection to %s on port %u\n", remote_host, port);
    exit(EXIT_FAILURE);
  }

  // Bind the SSL object to the network socket descriptor. The socket descriptor
  // will be used by OpenSSL to communicate with a server. This function should
  // only be called once the TCP connection is established, i.e., after
  // create_socket()
  SSL_set_fd(ssl, sockfd);

  // Initiates an SSL session over the existing socket connection. SSL_connect()
  // will return 1 if successful.
  if (SSL_connect(ssl) == 1)
    printf("Client: Established SSL/TLS session to '%s' on port %u\n", remote_host, port);
  else {
    fprintf(stderr, "Client: Could not establish SSL session to '%s' on port %u\n", remote_host, port);
    exit(EXIT_FAILURE);
  }

  //*************************************************************************
  // YOUR CODE HERE
  //
  // You will need to use the SSL_read and SSL_write functions, which work in
  // the same manner as traditional read and write system calls, but use the
  // SSL socket descriptor ssl declared above instead of a file descriptor.
  // ************************************************************************

    bzero(buffer, BUFFER_SIZE);

    if ((messageRead = SSL_read(ssl, buffer, BUFFER_SIZE)) < 0) {
        fprintf(stderr, "Client: Failed to read the message from the server, Error: %s\n", strerror(errno));

        return exitFailureCall(ssl, ssl_ctx, &sockfd, remote_host);
    }

    else {
    
        printf("Client: Message Received, message: %s\n", buffer);

        bzero(buffer, BUFFER_SIZE);

        if ((messageRead = SSL_read(ssl, buffer, BUFFER_SIZE)) < 0) {
            fprintf(stderr, "Client: Failed to read the message from the server, Error: %s\n", strerror(errno));

            return exitFailureCall(ssl, ssl_ctx, &sockfd, remote_host);
        }
        else {
            fprintf(stdout, "Client: Message Received, message: %s\n", buffer);

            if ((strcmp(buffer, "LOG_IN")) == 0) {
                printf("Client: Please sign in:\n");
                printf("Client: Username (email): ");
                fgets(userName, STRING_NAME-1, stdin);
                userName[strlen(userName)-1] = '\0';
                printf("Client: Password: ");
                fgets(userPassword, STRING_NAME-1, stdin);
                userPassword[strlen(userPassword)-1] = '\0';

                bzero(buffer, BUFFER_SIZE);
                sprintf(buffer, "%s %s", userName, userPassword);

                if ((messageSent = SSL_write(ssl, buffer, strlen(buffer))) < 0) {
                    fprintf(stderr, "Client: Failed to send the message to the server, Error: %s\n", strerror(errno));
                    
                    return exitFailureCall(ssl, ssl_ctx, &sockfd, remote_host);
                }

                else {
                    printf("Client: Successfully sent the log in message: %s\n", buffer);
                }
            } 
        }
    }


  // Deallocate memory for the SSL data structures and close the socket
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  close(sockfd);
  printf("Client: Terminated SSL/TLS connection with server '%s'\n",
	 remote_host);

  return EXIT_SUCCESS;
}

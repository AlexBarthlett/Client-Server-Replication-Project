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

#include <sqlite3.h>

#define BUFFER_SIZE       256
#define STRING_SIZE       50
#define DEFAULT_PORT      4433
#define CERTIFICATE_FILE  "cert.pem"
#define KEY_FILE          "key.pem"
#define DATABASE_NAME     "test_database.db"

/**
* @brief This function does the basic necessary housekeeping to establish TCP connections
* to the server.  It first creates a new socket, binds the network interface of
* the machine to that socket, then listens on the socket for incoming TCP
* connections.
*/
int create_socket(unsigned int port) {
  int    s;
  struct sockaddr_in addr;

  // First we set up a network socket. An IP socket address is a combination
  // of an IP interface address plus a 16-bit port number. The struct field
  // sin_family is *always* set to AF_INET. Anything else returns an error.
  // The TCP port is stored in sin_port, but needs to be converted to the
  // format on the host machine to network byte order, which is why htons()
  // is called. Setting s_addr to INADDR_ANY binds the socket and listen on
  // any available network interface on the machine, so clients can connect
  // through any, e.g., external network interface, localhost, etc.

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // When you create a socket, it exists within a namespace, but does not have
  // a network address associated with it.  The bind system call creates the
  // association between the socket and the network interface.
  //
  // An error could result from an invalid socket descriptor, an address already
  // in use, or an invalid network address
  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Server: Unable to bind to socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // Listen for incoming TCP connections using the newly created and configured
  // socket. The second argument (1) indicates the number of pending connections
  // allowed, which in this case is one.  That means if the server is connected
  // to one client, a second client attempting to connect may receive an error,
  // e.g., connection refused.
  //
  // Failure could result from an invalid socket descriptor or from using a
  // socket descriptor that is already in use.
  if (listen(s, 1) < 0) {
    fprintf(stderr, "Server: Unable to listen: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  printf("Server: Listening on TCP port %u\n", port);

  return s;
}

/**
* @brief This function does some initialization of the OpenSSL library functions used in
*        this program.  The function SSL_load_error_strings registers the error strings
*        for all of the libssl and libcrypto functions so that appropriate textual error
*        messages are displayed when error conditions arise. OpenSSL_add_ssl_algorithms
*        registers the available SSL/TLS ciphers and digests used for encryption.
*/
void init_openssl() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

/**
* @brief EVP_cleanup removes all of the SSL/TLS ciphers and digests registered earlier.
*/
void cleanup_openssl() {
  EVP_cleanup();
}

/**
* @brief An SSL_CTX object is an instance of a factory design pattern that produces SSL
*        connection objects, each called a context. A context is used to set parameters
*        for the connection, and in this program, each context is configured using the
*        configure_context() function below. Each context object is created using the
*        function SSL_CTX_new(), and the result of that call is what is returned by this
*        function and subsequently configured with connection information.
*
*        One other thing to point out is when creating a context, the SSL protocol must
*        be specified ahead of time using an instance of an SSL_method object.  In this
*        case, we are creating an instance of an SSLv23_server_method, which is an
*        SSL_METHOD object for an SSL/TLS server. Of the available types in the OpenSSL
*        library, this provides the most functionality.
*/
SSL_CTX* create_new_context() {
  const SSL_METHOD* ssl_method; // This should be declared 'const' to avoid
                                // getting a compiler warning about the call to
                                // SSLv23_server_method()
  SSL_CTX*          ssl_ctx;

  // Use SSL/TLS method for server
  ssl_method = SSLv23_server_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(ssl_method);
  if (ssl_ctx == NULL) {
    fprintf(stderr, "Server: cannot create SSL context:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ssl_ctx;
}

/**
* @brief We will use Elliptic Curve Diffie Hellman anonymous key agreement protocol for
*        the session key shared between client and server.  We first configure the SSL
*        context to use that protocol by calling the function SSL_CTX_set_ecdh_auto().
*        The second argument (onoff) tells the function to automatically use the highest
*        preference curve (supported by both client and server) for the key agreement.
*
*        Note that for error conditions specific to SSL/TLS, the OpenSSL library does
*        not set the variable errno, so we must use the built-in error printing routines.
*/
void configure_context(SSL_CTX* ssl_ctx) {
  SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

  // Set the certificate to use, i.e., 'cert.pem'
  if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM)
      <= 0) {
    fprintf(stderr, "Server: cannot set certificate:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  // Set the private key contained in the key file, i.e., 'key.pem'
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
    fprintf(stderr, "Server: cannot set certificate:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

void exitClientCall(SSL* ssl, int* client, char* client_addr) {
    printf("Server: Terminating SSL session and TCP connection with client (%s)\n",
	    client_addr);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(*client);
}

bool createDatabaseAndUserTable(sqlite3** db, char* sql, char* err_msg, int* rc) {
    sql = "CREATE TABLE IF NOT EXISTS Users(Email TEXT, Password TEXT);";

    *rc = sqlite3_open(DATABASE_NAME, db); // Opens and/or creates a database.

    if (*rc) { // Error checking
        fprintf(stderr, "Failed to open the database: %s\n", sqlite3_errmsg(*db));
        return false;
    }

    else {
        fprintf(stdout, "Opened/created the database successfully\n");

        *rc = sqlite3_exec(*db, sql, 0, 0, &err_msg); // execute the sql statement creating the user table if doesnt exist

        if (*rc != SQLITE_OK) { // Failed executing the statement
          fprintf(stderr, "SQL error: %s\n", err_msg);
          sqlite3_free(err_msg);
          return false;
        }

        else { // Success executing the sql statement.
            fprintf(stdout, "User Table created successfully or already exists\n");
        }
    }

    return true;
}

void addUserToDatabase(sqlite3* db, char* sql, char* err_msg, int* rc) {
    const char *email_to_check = "test@regis.edu";
    sqlite3_stmt *res; // first statement to use to check if a user is in the users table.

    sql = "SELECT Email FROM Users WHERE Email = ?;";

    *rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

    if (*rc == SQLITE_OK) { // statement prepared okay, bind the test email to the '?' in the sql statement.
        sqlite3_bind_text(res, 1, email_to_check, -1, SQLITE_STATIC);
    }

    else { // Failed to prepare statement
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        
    }

    *rc = sqlite3_step(res); // execute the prepared statement

    if (*rc == SQLITE_ROW) { // User with that email exists
      fprintf(stdout, "User already exists with email: %s\n", email_to_check);
    }

    else if (*rc == SQLITE_DONE) { // User doesnt exist, lets add the new user.
        sql = "INSERT INTO Users (Email, Password) VALUES (?, ?);";

        sqlite3_stmt *insert_stmt; // next statement to use, insert statement.

        *rc = sqlite3_prepare_v2(db, sql, -1, &insert_stmt, 0); // prepare the insert statement

        if (*rc == SQLITE_OK) { // prepared successfully, bind the email and password to the '?' in the insert statement
          sqlite3_bind_text(insert_stmt, 1, "test@regis.edu", -1, SQLITE_STATIC);
          sqlite3_bind_text(insert_stmt, 2, "TestP@ss", -1, SQLITE_STATIC);
        
          *rc = sqlite3_step(insert_stmt); // execute the insert statement.

          if (*rc == SQLITE_DONE) { // execute statement success.
            fprintf(stdout, "Test user entered into table successfully\n");
          }

          else { // execute statement failure
            fprintf(stderr, "Failed to insert user: %s\n", sqlite3_errmsg(db));
          }
        }

        else { // Failed to prepare the statement
          fprintf(stderr, "Failed to prepare INSERT statement: %s\n", sqlite3_errmsg(db));
        }

        sqlite3_finalize(insert_stmt); // deallocate resources
    }

    else { // Failed to execute statement to find user
        fprintf(stderr, "Error while checking for user: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(res); // deallocate resources
}

bool logInCall() {
    // Handle the log in loop here, request that the client log in, check their input to the db, and continue until logged in or receive a exit code from client (maybe CLIENT_EXIT)
    return false;
}

/**
@brief The sequence of steps required to establish a secure SSL/TLS connection is:
*
*        1.  Initialize the SSL algorithms
*        2.  Create and configure an SSL context object
*        3.  Create a new network socket in the traditional way
*        4.  Listen for incoming connections
*        5.  Accept incoming connections as they arrive
*        6.  Create a new SSL object for the newly arrived connection
*        7.  Bind the SSL object to the network socket descriptor
*
*        Once these steps are completed successfully, use the functions SSL_read() and
*        SSL_write() to read from/write to the socket, but using the SSL object rather
*        then the socket descriptor.  Once the session is complete, free the memory
*        allocated to the SSL object and close the socket descriptor.
*/
int main(int argc, char **argv) {
  SSL_CTX*     ssl_ctx;
  unsigned int sockfd;
  unsigned int port;
  char         buffer[BUFFER_SIZE];
  int          rc;
  char         *err_msg = 0;
  char         *sql;
  sqlite3      *db;
  bool         dbAndUserTableCreated;

  if (dbAndUserTableCreated = createDatabaseAndUserTable(&db, sql, err_msg, &rc)) { // Creates/opens database and creates user table if it doesnt exist in the db.

    addUserToDatabase(db, sql, err_msg, &rc); // Adds a user to the db if they arent in it already.
  }

  else {
    fprintf(stdout, "Server: Failed to create database or user table, exiting now\n");

    return EXIT_FAILURE;
  }

  signal(SIGPIPE, SIG_IGN);

  // Initialize and create SSL data structures and algorithms
  init_openssl();
  ssl_ctx = create_new_context();
  configure_context(ssl_ctx);

  // Port can be specified on the command line. If it's not, use default port
  switch(argc) {
  case 1:
    port = DEFAULT_PORT;
    break;
  case 2:
    port = atoi(argv[1]);
    break;
  default:
    fprintf(stderr, "Usage: ssl-server <port> (optional)\n");
    exit(EXIT_FAILURE);
  }

  // This will create a network socket and return a socket descriptor, which is
  // and works just like a file descriptor, but for network communcations. Note
  // we have to specify which TCP/UDP port on which we are communicating as an
  // argument to our user-defined create_socket() function.
  sockfd = create_socket(port);

  // Wait for incoming connections and handle them as the arrive
  while(true) {
    SSL*               ssl;
    int                client;
    const  char        reply[] = "Hello World!";
    struct sockaddr_in addr;
    unsigned int       len = sizeof(addr);
    char               client_addr[INET_ADDRSTRLEN];
    char               initialMessage[] = "You have connect to the server, welcome!";
    char               logInMessage[] = "LOG_IN";
    int                initialMessageSent;
    int                logInMessageSent;
    int                messageRead;
    char               userName[STRING_SIZE];
    char               userPassword[STRING_SIZE];

    // Once an incoming connection arrives, accept it.  If this is successful,
    // we now have a connection between client and server and can communicate
    // using the socket descriptor
    client = accept(sockfd, (struct sockaddr*)&addr, &len);
    if (client < 0) {
      fprintf(stderr, "Server: Unable to accept connection: %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }

    // Display the IPv4 network address of the connected client
    inet_ntop(AF_INET, (struct in_addr*)&addr.sin_addr, client_addr,
	      INET_ADDRSTRLEN);
    printf("Server: Established TCP connection with client (%s) on port %u\n",
	   client_addr, port);

   // Here we are creating a new SSL object to bind to the socket descriptor
    ssl = SSL_new(ssl_ctx);

    // Bind the SSL object to the network socket descriptor. The socket
    // descriptor will be used by OpenSSL to communicate with a client. This
    // function should only be called once the TCP connection is established.
    
    SSL_set_fd(ssl, client);

    // The last step in establishing a secure connection is calling SSL_accept(),
    // which executes the SSL/TLS handshake.  Because network sockets are
    // blocking by default, this function will block as well until the handshake
    // is complete.
    if (SSL_accept(ssl) <= 0) {
      fprintf(stderr, "Server: Could not establish secure connection:\n");
      ERR_print_errors_fp(stderr);
    } else {
      printf("Server: Established SSL/TLS connection with client (%s)\n",
	     client_addr);

      // ***********************************************************************
      // YOUR CODE HERE
      //
      // You will need to use the SSL_read and SSL_write functions, which work
      // in the same manner as traditional read and write system calls, but use
      // the SSL socket descriptor 'ssl' declared above instead of a file
      // descriptor.
      // ***********************************************************************

        bzero(buffer, BUFFER_SIZE);

        if ((initialMessageSent = SSL_write(ssl, initialMessage, strlen(initialMessage))) < 0) {
            fprintf(stderr, "Server: Failed to send the initial message to the client, Error: %s\n", strerror(errno));

            exitClientCall(ssl, &client, client_addr);
        }

        else {
            fprintf(stdout, "Server: Sent message successfully, message: %s\n", initialMessage);

            if ((logInMessageSent = SSL_write(ssl, logInMessage, strlen(logInMessage))) < 0) {
                fprintf(stderr, "Server: Failed to send the log in message to the client, Error: %s\n", strerror(errno));
                
                exitClientCall(ssl, &client, client_addr);
            }

            else {
                fprintf(stdout, "Server: Sent log in message successfully, message: %s\n", logInMessage);
                bzero(buffer, BUFFER_SIZE);
                if ((messageRead = SSL_read(ssl, buffer, BUFFER_SIZE)) < 0) {
                    fprintf(stderr, "Server: Failed to send the log in message to the client, Error: %s\n", strerror(errno));
                    
                    exitClientCall(ssl, &client, client_addr);
                }

                else {
                    sscanf(buffer, "%s %s", userName, userPassword);
                    printf("Server: Message received, username received: %s, password received: %s\n", userName, userPassword);
                }
            }
        }

        // Terminate the SSL session, close the TCP connection, and clean up
        exitClientCall(ssl, &client, client_addr);
    }
  }

    // Tear down and clean up server data structures before terminating
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    close(sockfd);
    sqlite3_close(db);

    return EXIT_SUCCESS;
}

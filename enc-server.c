/**
* @file enc-server.c
* @author ** Alexander E Barthlett, Richard Disimoni **
* @date  ** Due: October 20, 2024 **
* @brief  This program implements a multi-threaded SSL server with database user authentication and product management.
          The server handles client requests over a secure connection, including adding, updating, deleting, and viewing users and products.
          It uses OpenSSL for secure communication, SQLite3 for the databe and POSIX threads for concurrent client handling.
          SQLite3 mutex locks are also in use for read/write operations.
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
#define BUFFER_SIZE       1024
#define STRING_SIZE       50
#define DEFAULT_PORT      4433
#define CERTIFICATE_FILE  "cert.pem"
#define KEY_FILE          "key.pem"
#define DATABASE_NAME     "main_database.db"
#define REPLICA_DB_NAME   "replica_database.db"
#define REPLICA_SERVER    "localhost"
#define REPLICA_PORT      5433
#define ADMIN_USERNAME    "test@regis.edu"
#define ADMIN_PASSWORD    "TestP@ss"

pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER; // Global mutex lock for threads to use.

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
bool authenticate_client(SSL* ssl, char** user_role);
void handle_client(SSL* ssl, int client, char* client_addr);
bool create_database();
bool add_user_query(char* username, char* password, char* new_role);
bool add_product_query(char* product_name, char* product_category, int product_quantity, double product_price);
bool login_query(char* username, char* password, char** user_role);

/**
 * This method converts a SHA256 binary hash into a hexidecimal string for readability.
 */
void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]) {
    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

/**
 * Converts a string representing a password, into a SHA256 binary string for encryption.
 */
void hash_password(const char *password, unsigned char *hash_output) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int hash_length;

    mdctx = EVP_MD_CTX_new();
    md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, hash_output, &hash_length);

    EVP_MD_CTX_free(mdctx);
}

/**
 * Creates the main database, creates a user table if it doesnt exist, and creates a product table if it doesnt exist.  
 * Also adds the initial admin user to the user table if it doesnt exist.
 */
bool create_database() {
    const char *create_table_sql = "CREATE TABLE IF NOT EXISTS Users(Username TEXT NOT NULL UNIQUE PRIMARY KEY, Password TEXT NOT NULL, Role Text NOT NULL);";
    const char *create_product_table_sql = "CREATE TABLE IF NOT EXISTS Products(ProductID INTEGER PRIMARY KEY AUTOINCREMENT, ProductName TEXT NOT NULL, Category TEXT NOT NULL, Quantity INTEGER NOT NULL, Price REAL NOT NULL);";
    const char *check_admin_sql = "SELECT COUNT(*) FROM Users WHERE Username=?;";

    sqlite3 *main_db;
    sqlite3_stmt *stmt;
    char *err_msg = 0;
    int dbResult;

    dbResult = sqlite3_open(DATABASE_NAME, &main_db);

    if (dbResult != SQLITE_OK) {
        fprintf(stderr, "Failed to open main database: %s\n", sqlite3_errmsg(main_db));
        sqlite3_close(main_db);
        return false;
    }
    
    dbResult = sqlite3_exec(main_db, create_table_sql, 0, 0, &err_msg);

    if (dbResult != SQLITE_OK) {
        fprintf(stderr,"SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(main_db);
        return false;
    }

    dbResult = sqlite3_exec(main_db, create_product_table_sql, 0, 0, &err_msg);

    if (dbResult != SQLITE_OK) {
        fprintf(stderr,"SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(main_db);
        return false;
    }
    
    printf("Users table checked/created successfully.\n");
    printf("Products table checked/created successfully.\n");

    dbResult = sqlite3_prepare_v2(main_db, check_admin_sql, -1, &stmt, 0);

    if (dbResult != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(main_db));
        sqlite3_close(main_db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, ADMIN_USERNAME, -1, SQLITE_STATIC);

    dbResult = sqlite3_step(stmt);
    int admin_exists = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (admin_exists == 0) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        char hash_string[SHA256_DIGEST_LENGTH * 2 + 1];

        hash_password(ADMIN_PASSWORD, hash);
        sha256_hash_string(hash, hash_string);

        const char *insert_admin_sql = "INSERT INTO Users (Username, Password, Role) VALUES (?, ?, 'admin');";

        dbResult = sqlite3_prepare_v2(main_db, insert_admin_sql, -1, &stmt, 0);

        if (dbResult != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare insert statement: %s\n", sqlite3_errmsg(main_db));
            sqlite3_close(main_db);
            return false;
        }

        sqlite3_bind_text(stmt, 1, ADMIN_USERNAME, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hash_string, -1, SQLITE_STATIC);
        dbResult = sqlite3_step(stmt);

        if (dbResult != SQLITE_DONE) {
            fprintf(stderr, "Failed to insert admin user: %s\n", sqlite3_errmsg(main_db));
        }
        else {
            printf("Admin user created successfully with hashed password.\n");
        }

        sqlite3_finalize(stmt);
    }
    else {
        printf("Admin user already exists.\n");
    }

    sqlite3_close(main_db);
    return true;
}

/**
 * Creates a socket and binds it to the specified port.
 */
int create_socket(unsigned int port) {
    int s;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Server: Unable to bind to socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

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
        
        pthread_rwlock_wrlock(&rwlock); // Write lock for replication
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
        
        sqlite3_backup *backup = sqlite3_backup_init(replica_db, "main", main_db, "main");
        if (backup) {
            sqlite3_backup_step(backup, -1);
            sqlite3_backup_finish(backup);
        }
        
        if (sqlite3_errcode(replica_db) != SQLITE_OK) {
            fprintf(stderr, "Replication failed: %s\n", sqlite3_errmsg(replica_db));
        } else {
            printf("Database replicated successfully.\n");
        }
        
        sqlite3_close(main_db);
        sqlite3_close(replica_db);
        pthread_rwlock_unlock(&rwlock); // unlock lock
    }

    return NULL;
}

/**
 * Function to add a new user to the SQLite database.
 */
bool add_user_query(char* username, char* password, char* new_role) {

    pthread_rwlock_wrlock(&rwlock); // write lock
    sqlite3 *main_db;
    sqlite3_stmt *stmt;
    int dbResult;

    dbResult = sqlite3_open(DATABASE_NAME, &main_db);

    if (dbResult != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(main_db));
        pthread_rwlock_unlock(&rwlock); // unlock lock
        return false;
    }

    const char *add_new_user_sql = "INSERT INTO Users (Username, Password, Role) VALUES (?, ?, ?);";

    unsigned char hash[SHA256_DIGEST_LENGTH];
    char hash_string[SHA256_DIGEST_LENGTH *2 +1];
    hash_password(password, hash);
    sha256_hash_string(hash, hash_string);

    dbResult = sqlite3_prepare_v2(main_db, add_new_user_sql, -1, &stmt, 0);

    if (dbResult != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(main_db));
        sqlite3_close(main_db);
        pthread_rwlock_unlock(&rwlock); // unlock lock
        return false;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash_string, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, new_role, -1, SQLITE_STATIC);

    dbResult = sqlite3_step(stmt);

    if (dbResult != SQLITE_DONE) {
        fprintf(stderr, "Failed to add new user: %s\n", sqlite3_errmsg(main_db));
        sqlite3_finalize(stmt);
        sqlite3_close(main_db);
        pthread_rwlock_unlock(&rwlock); // unlock lock
        return false;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(main_db);

    pthread_rwlock_unlock(&rwlock); // unlock lock

    printf("User added successfully.\n");
    return true;
}

/**
 * This function adds a new product to the product table in the SQLite database.
 */
bool add_product_query(char* product_name, char* product_category, int product_quantity, double product_price) {

    pthread_rwlock_wrlock(&rwlock); // write lock

    sqlite3 *main_db;
    sqlite3_stmt *stmt;
    int dbResult;

    dbResult = sqlite3_open(DATABASE_NAME, &main_db);

    if (dbResult != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(main_db));
        pthread_rwlock_unlock(&rwlock); // unlock lock
        return false;
    }

    const char *add_new_product_sql = "INSERT INTO Products (ProductName, Category, Quantity, Price) VALUES (?, ?, ?, ?);";

    dbResult = sqlite3_prepare_v2(main_db, add_new_product_sql, -1, &stmt, 0);

    if (dbResult != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(main_db));
        sqlite3_close(main_db);
        pthread_rwlock_unlock(&rwlock); // unlock lock
        return false;
    }

    sqlite3_bind_text(stmt, 1, product_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, product_category, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, product_quantity);
    sqlite3_bind_double(stmt, 4, product_price);

    dbResult = sqlite3_step(stmt);

    if (dbResult != SQLITE_DONE) {
        fprintf(stderr, "Failed to add new product: %s\n", sqlite3_errmsg(main_db));
        sqlite3_finalize(stmt);
        sqlite3_close(main_db);
        pthread_rwlock_unlock(&rwlock); // unlock lock
        return false;
}

    sqlite3_finalize(stmt);
    sqlite3_close(main_db);

    pthread_rwlock_unlock(&rwlock); // unlock lock

    printf("Product added successfully.\n");
    return true;
}

/**
 * This function checks to see if a user exists with the correct password and if so, 
 * changes a variable to represent the correct user role such as if they are a system admin, and return if logging in was successful.
 */
bool login_query(char* username, char* password, char** user_role) {

    pthread_rwlock_rdlock(&rwlock); // read lock

    sqlite3 *main_db;
    sqlite3_stmt *stmt;
    int dbResult;

    dbResult = sqlite3_open(DATABASE_NAME, &main_db);

    if (dbResult != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(main_db));
        pthread_rwlock_unlock(&rwlock); // unlock lock
        return false;
    }

    const char *get_user_sql = "SELECT Password, Role FROM Users WHERE Username = ?;";

    dbResult = sqlite3_prepare_v2(main_db, get_user_sql, -1, &stmt, 0);

    if (dbResult != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(main_db));
        sqlite3_close(main_db);
        pthread_rwlock_unlock(&rwlock); // unlock lock
        return false;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    dbResult = sqlite3_step(stmt);

    if (dbResult == SQLITE_ROW) {
        const char *stored_hash = (const char *)sqlite3_column_text(stmt, 0);
        const char *role = (const char *)sqlite3_column_text(stmt, 1);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        char hash_string[SHA256_DIGEST_LENGTH * 2 + 1];
        hash_password(password, hash);
        sha256_hash_string(hash, hash_string);

        if (strcmp(stored_hash, hash_string) == 0) {
            *user_role = strdup(role);
            sqlite3_finalize(stmt);
            sqlite3_close(main_db);
            pthread_rwlock_unlock(&rwlock); // unlock lock
            return true;
        }
        else {
            printf("Authentication failed: Invalid password.\n");
        }
    }
    else {
        printf("Authentication failed: Username not found.\n");
    }

    sqlite3_finalize(stmt);
    sqlite3_close(main_db);
    pthread_rwlock_unlock(&rwlock); // unlock lock
    return false;
}

/**
 * Authenticates a client connection.
 */
bool authenticate_client(SSL* ssl, char** user_role) {
    char buffer[BUFFER_SIZE];
    int bytes;
    
    const char* auth_request = "Please provide your username and password.";

    if ((bytes = SSL_write(ssl, auth_request, strlen(auth_request))) < 0) {
        fprintf(stderr, "Failed to write, Error: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    if ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) < 0) {
        fprintf(stderr, "Failed to read, Error: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    buffer[bytes] = 0;
    
    char username[STRING_SIZE], password[STRING_SIZE];
    sscanf(buffer, "%s %s", username, password);

    return login_query(username, password, user_role);
}

/**
 * Handles communication with an authenticated client.
 */
void handle_client(SSL* ssl, int client, char* client_addr) {
    char buffer[BUFFER_SIZE];
    int bytes;
    char* user_role = NULL; // admin or other
    
    if (!authenticate_client(ssl, &user_role)) {
        const char* auth_failed = "Authentication failed. Closing connection.";

        if ((bytes = SSL_write(ssl, auth_failed, strlen(auth_failed))) < 0) {
            fprintf(stderr, "Failed to write, Error: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        return;
    }
    
    char* auth_success;
    if (strcmp(user_role, "admin") == 0) { // is a admin
        auth_success = "Authentication successful. You can now send queries.\n"
                                    "1: Update_product\n"
                                    "2: Add_product\n"
                                    "3: Delete_product\n"
                                    "4: View_product\n"
                                    "5: View_all_products\n"
                                    "6: Add_user\n"
                                    "7: Delete_user\n"
                                    "8: View_user\n"
                                    "9: View_all_users\n";
    }
    else { // Not a admin
        auth_success = "Authentication successful. You can now send queries.\n"
                                    "1: Update_product\n"
                                    "2: Add_product\n"
                                    "3: Delete_product\n"
                                    "4: View_product\n"
                                    "5: View_all_products\n";                               
    }

    fprintf(stdout, "User role is: %s\n", user_role); // For testing

    if ((bytes = SSL_write(ssl, auth_success, strlen(auth_success))) < 0) {
        fprintf(stderr, "Failed to write, Error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    while (1) {

        if ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) < 0) { // Read a query from the client
            fprintf(stderr, "Failed to read, Error: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        
        buffer[bytes] = 0;
        char response[BUFFER_SIZE];

        char query_requested[STRING_SIZE];

        sscanf(buffer, "%s", query_requested);

        if (strcmp(query_requested, "Add_user") == 0) {

            if(strcmp(user_role, "admin") != 0) { // Must be a admin
                strcpy(response, "You do not have the proper role to make this query\n");
            }

            else {
                char username[STRING_SIZE];
                char password[STRING_SIZE];
                char role[STRING_SIZE];

                sscanf(buffer, "%s %s %s %s", query_requested, username, password, role);
                bool added_new_user = add_user_query(username, password, role);

                if (added_new_user) {
                    strcpy(response, "Added the new user successfully\n");
                }
                else {
                    strcpy(response, "Failed to add the new user\n");
                }
            }
        }

        else if (strcmp(query_requested, "Delete_user") == 0) {
            if(strcmp(user_role, "admin") != 0) { // Must be a admin
                strcpy(response, "You do not have the proper role to make this query\n");
            }

            else {
                char username[STRING_SIZE];
                sscanf(buffer, "%s %s", query_requested, username);

                pthread_rwlock_wrlock(&rwlock); // write lock
            
                sqlite3 *main_db;
                sqlite3_stmt *stmt;
                int dbResult;
            
                dbResult = sqlite3_open(DATABASE_NAME, &main_db);
                if (dbResult != SQLITE_OK) {
                    strcpy(response, "Failed to open database");
                } else {
                    const char *delete_user_sql = "DELETE FROM Users WHERE Username = ?;";
                    dbResult = sqlite3_prepare_v2(main_db, delete_user_sql, -1, &stmt, 0);
                
                    if (dbResult != SQLITE_OK) {
                        strcpy(response, "Failed to prepare statement");
                    } else {
                        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                        dbResult = sqlite3_step(stmt);
                    
                        if (dbResult == SQLITE_DONE) {
                            if (sqlite3_changes(main_db) > 0) {
                                strcpy(response, "User deleted successfully");
                            } else {
                                strcpy(response, "User not found");
                            }
                        } else {
                            strcpy(response, "Failed to delete user");
                        }
                    
                        sqlite3_finalize(stmt);
                    }
                
                    sqlite3_close(main_db);
                }

                pthread_rwlock_unlock(&rwlock); // unlock lock
            }
        }

        else if (strcmp(query_requested, "View_user") == 0) {
            if(strcmp(user_role, "admin") != 0) { // Must be a admin
                strcpy(response, "You do not have the proper role to make this query\n");
            }

            else {
                char username[STRING_SIZE];
                sscanf(buffer, "%s %s", query_requested, username);

                pthread_rwlock_rdlock(&rwlock); // read lock
            
                sqlite3 *main_db;
                sqlite3_stmt *stmt;
                int dbResult;
            
                dbResult = sqlite3_open(DATABASE_NAME, &main_db);
                if (dbResult != SQLITE_OK) {
                    strcpy(response, "Failed to open database");
                } else {
                    const char *view_user_sql = "SELECT Username, Role FROM Users WHERE Username = ?;";
                    dbResult = sqlite3_prepare_v2(main_db, view_user_sql, -1, &stmt, 0);
                
                    if (dbResult != SQLITE_OK) {
                        strcpy(response, "Failed to prepare statement");
                    } else {
                        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                        dbResult = sqlite3_step(stmt);
                    
                        if (dbResult == SQLITE_ROW) {
                            const char *user = (const char *)sqlite3_column_text(stmt, 0);
                            const char *role = (const char *)sqlite3_column_text(stmt, 1);
                            snprintf(response, BUFFER_SIZE, "Username: %s, Role: %s", user, role);
                        } else {
                            strcpy(response, "User not found");
                        }
                    
                        sqlite3_finalize(stmt);
                    }
                
                    sqlite3_close(main_db);
                }

                pthread_rwlock_unlock(&rwlock); // unlock lock
            }
        }

        else if (strcmp(query_requested, "View_all_users") == 0) {
            if(strcmp(user_role, "admin") != 0) {
                sprintf(response, "%s", "NOT_ADMIN"); // Error code for the client, must be an admin for this query.
                if ((bytes = SSL_write(ssl, response, strlen(response))) < 0) {
                    fprintf(stderr, "Failed to write, Error: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
                }

                bzero(response, BUFFER_SIZE); // reset the buffer
            }
            else {

                pthread_rwlock_rdlock(&rwlock); // read lock

                sqlite3 *main_db;
                sqlite3_stmt *stmt;
                int dbResult;
            
                dbResult = sqlite3_open(DATABASE_NAME, &main_db);
                if (dbResult != SQLITE_OK) {
                    strcpy(response, "Failed to open database");
                } else {
                    const char *sql = "SELECT Username, Role FROM Users;";
                    dbResult = sqlite3_prepare_v2(main_db, sql, -1, &stmt, 0);

                    if (dbResult != SQLITE_OK) {
                        strcpy(response, "Failed to prepare statement\n");
                        sqlite3_close(main_db);
                    }
                    else {
                        while (sqlite3_step(stmt) == SQLITE_ROW) {
                            const char *name = (const char *)sqlite3_column_text(stmt, 0);
                            const char *role = (const char *)sqlite3_column_text(stmt, 1);

                            sprintf(response, "%s %s", name, role);

                             if ((bytes = SSL_write(ssl, response, strlen(response))) < 0) {
                                fprintf(stderr, "Failed to write, Error: %s\n", strerror(errno));
                                exit(EXIT_FAILURE);
                             }

                            bzero(response, BUFFER_SIZE); // reset the buffer after writing.
                        }

                        sprintf(response, "%s", "END_OF_QUERY"); // Code for client to use to know to stop reading.

                        if ((bytes = SSL_write(ssl, response, strlen(response))) < 0) {
                            fprintf(stderr, "Failed to write, Error: %s\n", strerror(errno));
                            exit(EXIT_FAILURE);
                        }

                        bzero(response, BUFFER_SIZE); // reset the buffer after writing.
                    }

                    sqlite3_close(main_db);
                }

                pthread_rwlock_unlock(&rwlock); // unlock lock
            }
        }

        else if (strcmp(query_requested, "Update_product") == 0) {
            char product_name[STRING_SIZE];
            char product_category[STRING_SIZE];
            int product_quantity;
            double product_price;
            
            sscanf(buffer, "%s %s %s %d %le", query_requested, product_name, product_category, &product_quantity, &product_price);
            
            pthread_rwlock_wrlock(&rwlock); // write lock

            sqlite3 *main_db;
            sqlite3_stmt *stmt;
            int dbResult;
            
            dbResult = sqlite3_open(DATABASE_NAME, &main_db);
            if (dbResult != SQLITE_OK) {
                strcpy(response, "Failed to open database");
            } else {
                const char *update_product_sql = "UPDATE Products SET Category = ?, Quantity = ?, Price = ? WHERE ProductName = ?;";
                dbResult = sqlite3_prepare_v2(main_db, update_product_sql, -1, &stmt, 0);
                
                if (dbResult != SQLITE_OK) {
                    strcpy(response, "Failed to prepare statement");
                } else {
                    sqlite3_bind_text(stmt, 1, product_category, -1, SQLITE_STATIC);
                    sqlite3_bind_int(stmt, 2, product_quantity);
                    sqlite3_bind_double(stmt, 3, product_price);
                    sqlite3_bind_text(stmt, 4, product_name, -1, SQLITE_STATIC);
                    
                    dbResult = sqlite3_step(stmt);
                    
                    if (dbResult == SQLITE_DONE) {
                        if (sqlite3_changes(main_db) > 0) {
                            strcpy(response, "Product updated successfully");
                        } else {
                            strcpy(response, "Product not found");
                        }
                    } else {
                        strcpy(response, "Failed to update product");
                    }
                    
                    sqlite3_finalize(stmt);
                }
                
                sqlite3_close(main_db);
            }

            pthread_rwlock_unlock(&rwlock); // unlock lock
        }

        else if (strcmp(query_requested, "Add_product") == 0) {
            char product_name[STRING_SIZE];
            char product_category[STRING_SIZE];
            int product_quantity;
            double product_price;

            sscanf(buffer, "%s %s %s %d %le", query_requested, product_name, product_category, &product_quantity, &product_price);
            bool added_new_product = add_product_query(product_name, product_category, product_quantity, product_price);

            if (added_new_product) {
                strcpy(response, "Added the new product successfully\n");
            }
            else {
                strcpy(response, "Failed to add the new product\n");
            }
        }

        else if (strcmp(query_requested, "Delete_product") == 0) {
            char product_name[STRING_SIZE];
            sscanf(buffer, "%s %s", query_requested, product_name);
            
            pthread_rwlock_wrlock(&rwlock); // write lock

            sqlite3 *main_db;
            sqlite3_stmt *stmt;
            int dbResult;
            
            dbResult = sqlite3_open(DATABASE_NAME, &main_db);
            if (dbResult != SQLITE_OK) {
                strcpy(response, "Failed to open database");
            } else {
                const char *delete_product_sql = "DELETE FROM Products WHERE ProductName = ?;";
                dbResult = sqlite3_prepare_v2(main_db, delete_product_sql, -1, &stmt, 0);
                
                if (dbResult != SQLITE_OK) {
                    strcpy(response, "Failed to prepare statement");
                } else {
                    sqlite3_bind_text(stmt, 1, product_name, -1, SQLITE_STATIC);
                    dbResult = sqlite3_step(stmt);
                    
                    if (dbResult == SQLITE_DONE) {
                        if (sqlite3_changes(main_db) > 0) {
                            strcpy(response, "Product deleted successfully");
                        } else {
                            strcpy(response, "Product not found");
                        }
                    } else {
                        strcpy(response, "Failed to delete product");
                    }
                    
                    sqlite3_finalize(stmt);
                }
                
                sqlite3_close(main_db);
            }

            pthread_rwlock_unlock(&rwlock); // unlock lock
        }

        else if (strcmp(query_requested, "View_product") == 0) {
            char product_name[STRING_SIZE];
            sscanf(buffer, "%s %s", query_requested, product_name);
            
            pthread_rwlock_rdlock(&rwlock); // read lock

            sqlite3 *main_db;
            sqlite3_stmt *stmt;
            int dbResult;
            
            dbResult = sqlite3_open(DATABASE_NAME, &main_db);
            if (dbResult != SQLITE_OK) {
                strcpy(response, "Failed to open database");
            } else {
                const char *view_product_sql = "SELECT ProductName, Category, Quantity, Price FROM Products WHERE ProductName = ?;";
                dbResult = sqlite3_prepare_v2(main_db, view_product_sql, -1, &stmt, 0);
                
                if (dbResult != SQLITE_OK) {
                    strcpy(response, "Failed to prepare statement");
                } else {
                    sqlite3_bind_text(stmt, 1, product_name, -1, SQLITE_STATIC);
                    dbResult = sqlite3_step(stmt);
                    
                    if (dbResult == SQLITE_ROW) {
                        const char *name = (const char *)sqlite3_column_text(stmt, 0);
                        const char *category = (const char *)sqlite3_column_text(stmt, 1);
                        int quantity = sqlite3_column_int(stmt, 2);
                        double price = sqlite3_column_double(stmt, 3);
                        snprintf(response, BUFFER_SIZE, "Name: %s, Category: %s, Quantity: %d, Price: %.2f", name, category, quantity, price);
                    } else {
                        strcpy(response, "Product not found");
                    }
                    
                    sqlite3_finalize(stmt);
                }
                
                sqlite3_close(main_db);
            }

            pthread_rwlock_unlock(&rwlock); // unlock lock
        }

        else if (strcmp(query_requested, "View_all_products") == 0) {

            pthread_rwlock_rdlock(&rwlock); // read lock

            sqlite3 *main_db;
            sqlite3_stmt *stmt;
            int dbResult;
            
            dbResult = sqlite3_open(DATABASE_NAME, &main_db);
            if (dbResult != SQLITE_OK) {
                strcpy(response, "Failed to open database\n");
            }
            else {
                const char *sql = "SELECT ProductName, Category, Quantity, Price FROM Products;";
                dbResult = sqlite3_prepare_v2(main_db, sql, -1, &stmt, 0);

                if (dbResult != SQLITE_OK) {
                    strcpy(response, "Failed to prepare statement\n");
                    sqlite3_close(main_db);
                }
                else {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char *name = (const char *)sqlite3_column_text(stmt, 0);
                        const char *category = (const char *)sqlite3_column_text(stmt, 1);
                        int quantity = sqlite3_column_int(stmt, 2);
                        double price = sqlite3_column_double(stmt, 3);

                        sprintf(response, "%s %s %d %f", name, category, quantity, price);

                        if ((bytes = SSL_write(ssl, response, strlen(response))) < 0) {
                            fprintf(stderr, "Failed to write, Error: %s\n", strerror(errno));
                            exit(EXIT_FAILURE);
                        }

                        bzero(response, BUFFER_SIZE);
                    }

                    sprintf(response, "%s", "END_OF_QUERY");
                    if ((bytes = SSL_write(ssl, response, strlen(response))) < 0) {
                        fprintf(stderr, "Failed to write, Error: %s\n", strerror(errno));
                        exit(EXIT_FAILURE);
                    }

                    bzero(response, BUFFER_SIZE);
                }

                sqlite3_close(main_db);
            }   

            pthread_rwlock_unlock(&rwlock); // unlock lock
        }

        else {
            strcpy(response, "Server: Invalid Query, please try again");
        }

        if (strcmp(query_requested, "View_all_products") != 0 || strcmp(query_requested, "View_all_users") != 0) { // Writes are done within the related if statements, every other query will use this write call.
            if ((bytes = SSL_write(ssl, response, strlen(response))) < 0) {
                fprintf(stderr, "Failed to write or connection with client was closed/lost, if failure, Error is: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }

            bzero(response, BUFFER_SIZE); // Clear out the response/buffer for the next use.
        }
    }

    free(user_role); // Deallocate memory.
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

    if (!create_database()) {
        printf("Server: Failed to initially set up the main db and/or tables.\n");
        return EXIT_FAILURE;
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

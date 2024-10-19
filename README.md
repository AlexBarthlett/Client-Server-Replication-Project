# CS469_Final_Project
Final Project for Regis CS469 - Client/Server utilizing an SQLite DB that replicates to a new .db file.

Before running, ensure you have SQLite3 installed.

You will need to create a certificate, copy and paste:

openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem

-- Into your terminal to make one.

A make file is included, once everything is installed, type "make" into the terminal in the proper repository to compile the program.

When initially running the server, the main database will be created, and if the User and Products table does not exist, those will be created as well.

A initial admin account is created with the User table.

Start the server first by typing ./enc-server into the terminal.

Start the client by typing ./enc-client localhost  (or a port number instead of localhost).

Sign in using the admin account:
User: test@regis.edu
Password: TestP@ss

Use the prompts given to alter the database and to create new accounts such as none admin related accounts.

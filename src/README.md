Protocol
========

### 5 Authentication
>Where are the passwords stored? 

We decided to store the passwords encoded in a haspmap where each encrypted password is mapped to a username. This ensures that all usernames are unique and the time it takes to match a login attempt is minimal.

>Where are the salt strings stored?

A salt string is generated every time the server is started. It uses a random function with a seed depending on the local time. It is stored in memory in global scope, we decided not to store it in a file since it was out of the scope and time of this project to implement a secure way to produce and store a user-salt connection.

>Why do you send the plain text password/hashed password? 

We decided to send the password as plain text from the client to the server. The password is sent with ssl so we do not have to worry about packet sniffing and we immediately salt and hash the password on the server so sending the password as plain text should be secure. However we do recognize that some clients may be suspicious of the server for accepting their passwords as plain text so additional encryption might be implemented on the client side as well.

>What are the security implications of your decision?

Our conclusion is that although we have taken measures to secure the users passwords in a safe way a lot more work can and should be done in order to protect passwords. Encrypted files storing the passwords, hashes and salts would be optimal. The keys for these encrypted files should also be stored in a secure location so attackers could not acces them.

### 6 Private messages
>Should private messages be logged? 

No private messages should not be logged in our system. Because we have not implemented a way to retrieve them back and there fore we would be saving data we are not using. The messages could contain sensitive information and since we have no safe way of storing the messages we decided not to store any message sent to the server.

>If so, what should be logged about private messages? 

We log who sent the message and to whom or what room and at what time. No detailed information other than the user information and what action he is taking is logged.

>What are the consequences of your decisions?

We do not get access to the full history of what has been said on the server and cannot use the data for any analysis. However we gain some trust from our users in the sence that they know what they say will not end up in the wrong hands.


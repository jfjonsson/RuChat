#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <glib.h>

#include <arpa/inet.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define RSA_SERVER_CERT  "server.crt"
#define RSA_SERVER_KEY   "server.key"

#define UNUSED(x) (void)(x)

#define willy NULL

#define CLIENT_TIME_OUT 300

#define BUFF_SIZE 2048

struct user_info {
    SSL *ssl;
    int fd;
    char *username;
    char *nick;
    char *room;
    int login_attempts;
    time_t timeout;
} user_info;

struct chatroom {
    GList *room;
} chatroom;

struct pm {
    char *message;
    char *recipient;
    char *sender;
} pm;

void send_message(gpointer data, gpointer user_data);
/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert(_addr1 != NULL);
    g_assert(_addr2 != NULL);
    g_assert(_addr1->sin_family == _addr2->sin_family);

    if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
        return -1;
    } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
        return 1;
    } else if (_addr1->sin_port < _addr2->sin_port) {
        return -1;
    } else if (_addr1->sin_port > _addr2->sin_port) {
        return 1;
    }
    return 0;
}
int sockaddr_in_cmp_data(const void *addr1, const void *addr2, gpointer data) { UNUSED(data); return sockaddr_in_cmp(addr1, addr2); }

/* timeout function implementation from
http://stackoverflow.com/questions/3930363/implement-time-delay-in-c */
void wait_for (unsigned int secs) {
    time_t retTime = time(0) + secs;     /* Get finishing time. */
    while (time(0) < retTime);    /* Loop until it arrives. */
}

void gen_random(char *s, const int len) {
    static const char alphanum[] =     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    time_t now = time(0);
    srand((int) now);
    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len] = '\0';
}

int name_cmp(const void *str1, const void *str2) {
    return g_strcmp0(str1, str2);
}
int name_cmp_data(const void *str1, const void *str2, gpointer data) { UNUSED(data); return name_cmp(str1, str2); }

/* Connections tree */
GTree *connections;
GTree *chatrooms;
GKeyFile *users;
fd_set rfds;

/* configuration for hashing passwords. */
char *salt;
EVP_MD_CTX *mdctx;
const EVP_MD *md;

gchar *hash_password(char * salt, char *password){
    unsigned int md_len;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    gchar *userpass;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, salt, strlen(salt));
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        printf("no fault here\n");
    userpass = g_base64_encode(md_value,(unsigned long) md_len);
    EVP_cleanup();
    return g_strdup(userpass);
}


/* TRUE when server is active FALSE when server should stop. */
static int active = TRUE;

void sigint_handler(int signum)
{
    active = FALSE;
    UNUSED(signum);

    /* We should not use printf inside of signal handlers, this is not
     * considered safe. We may, however, use write() and fsync(). */
    write(STDOUT_FILENO, "Terminated.\n", 12);
    fsync(STDOUT_FILENO);
}

gboolean is_greater(gpointer key, gpointer user, gpointer data) {
    UNUSED(key);
    int user_fd = ((struct user_info *) user)->fd;
    int data_fd = *(int *)data;
    FD_SET(user_fd, &rfds);
    if(user_fd > data_fd) {
        *(int *)data = user_fd;
    }
    return FALSE;
}

int ssl_shut_down(SSL *ssl, int sockfd) {
    /* Shutdown the client side of the SSL connection */
    int err = SSL_shutdown(ssl);
    if(err == -1) {
        ERR_print_errors_fp(stderr);
    }

    /* Terminate communication on a socket */
    err = close(sockfd);
    if(err == -1) {
        return -1;
    }

    /* Free the SSL structure */
    SSL_free(ssl);

    return 1;
}

void log_message(char * message, struct sockaddr_in *client) {
    /* Get local time. */
    time_t timer;
    time(&timer);
    char time_now[20];
    struct tm* tm_info = localtime(&timer);
    strftime(time_now, 20, "%F %H:%M:%S", tm_info);

    /*<timestamp> : <client ip>:<client port> connected */
    printf("%s : %s:%d %s\n", time_now, inet_ntoa(client->sin_addr),
            client->sin_port, message);

    /* Log the connection to file. */
    FILE *f;
    if((f = fopen ("server_log.txt", "a"))) {
        fprintf (f, "%s : %s:%d %s\n", time_now, inet_ntoa(client->sin_addr),
            client->sin_port, message);
        fclose (f);
    }
}

gboolean list_users(gpointer key, gpointer value, gpointer data) {
    struct sockaddr_in *client = (struct sockaddr_in *)key;
    struct user_info *user = (struct user_info *) value;
    SSL *write_ssl = ((struct user_info *) data)->ssl;

    char port_str[5];
    sprintf(port_str, "%d", client->sin_port);

    printf("port: %s\n", port_str);

    gchar * message = g_strjoin(NULL, "Username: ",(user->username) ? user->username : "NULL", ", IP: ", inet_ntoa(client->sin_addr), ":", port_str, NULL);

    SSL_write(write_ssl, message, strlen(message));

    g_free(message);
    return FALSE;
}

gboolean list_rooms(gpointer key, gpointer value, gpointer data) {
    SSL *write_ssl = ((struct user_info *) data)->ssl;

    char num_users[10];
    sprintf(num_users, "%d", g_list_length(((struct chatroom *)value)->room));

    gchar * message = g_strjoin(NULL, " -", (char *) key, ", (", num_users, ")", NULL);

    SSL_write(write_ssl, message, strlen(message));

    g_free(message);
    return FALSE;
}
void remove_from_room(gpointer user) {
    struct user_info *u = (struct user_info *)user;
    if(u->room != NULL) {
        struct chatroom* old_room = g_tree_lookup(chatrooms, u->room);
        old_room->room = g_list_remove(old_room->room, user);
    }
}

void failed_login_attempt(gpointer key, struct user_info * current_user, char * username){
    gchar *message;
    current_user->login_attempts += 1;
    fflush(stdin);
    send_message(current_user, "authentication failed\n");
    wait_for(10 * current_user->login_attempts);
    message = g_strconcat(username, " authentication failed", NULL);
    log_message(message, key);
    if(current_user->login_attempts >= 3){
        ssl_shut_down(current_user->ssl, current_user->fd);
        remove_from_room(current_user);
        g_tree_remove(connections, key);
        /*<timestamp> : <client ip>:<client port> disconnected*/
        log_message("disconnected", key);
    }
    free(message);
}

void successful_login_attempt(gpointer key, struct user_info * current_user, char * username){
    gchar *message;
    current_user->login_attempts = 0;
    g_free(current_user->username);
    current_user->username = strdup(username);
    current_user->nick = strdup(username);
    message = g_strconcat(username, " authenticated", NULL);
    log_message(message, key);
    fflush(stdin);
    send_message(current_user, "login successful\n");
    free(message);
}

void authenticate_user(char * command, gpointer key, gpointer user){
    struct user_info * current_user = (struct user_info *) user;
    gchar** command_split = g_strsplit(command, ":", 3);
    gchar * username;
    gchar * userpass;

    if(command_split[2] == NULL || command_split[1] == NULL){
        failed_login_attempt(key, current_user, command_split[1]);
    } else {
        username = strdup(command_split[1]);
        userpass = hash_password(salt, command_split[2]);
        gchar *password = g_key_file_get_string(users, "users", username, NULL);
        if(password == NULL){
            g_key_file_set_value(users, "users", username, userpass);
            successful_login_attempt(key, current_user, username);
        } else if(g_strcmp0(password, userpass) == 0){
            successful_login_attempt(key, current_user, username);
        } else {
            failed_login_attempt(key, current_user, username);
        }
        g_free(username);
        g_free(userpass);
    }
    g_strfreev(command_split);
}

void join_room(char *room_name, gpointer user) {
    struct user_info *u = (struct user_info *) user;
    remove_from_room(user);
    struct chatroom* chatroom = g_tree_lookup(chatrooms, room_name);
    if(chatroom) {
        g_free(u->room);
        u->room = strdup(room_name);
        chatroom->room = g_list_insert_sorted(chatroom->room, user, name_cmp);
    } else {
        struct chatroom *new_room = g_new0(struct chatroom, 1);
        new_room->room = g_list_insert_sorted(new_room->room, user, name_cmp);
        g_free(u->room);
        u->room = strdup(room_name);
        g_tree_insert(chatrooms, strdup(room_name), new_room);
    }
}

gboolean send_private_message(gpointer key, gpointer value, gpointer data) {
    struct user_info *user = (struct user_info *) value;
    struct pm *message = (struct pm *) data;
    if(g_strcmp0(message->recipient, user->username) == 0) {

        log_message("received pm", key);
        gchar *send_data = g_strconcat("PM - ", message->sender, ": ", message->message, NULL);
        send_message(user, send_data);

        g_free(send_data);
        return TRUE;
    }
    return FALSE;
}

void private_message(gchar *command, struct sockaddr_in* client, struct user_info* user) {
    UNUSED(client);
    gchar **split = g_strsplit(command, " ", 2);

    struct pm message;
    message.recipient = strdup(split[0]);
    message.message = strdup(split[1]);
    message.sender = strdup(user->nick);

    g_tree_foreach(connections, send_private_message, &message);

    free(message.sender);
    free(message.message);
    free(message.recipient);
}

void set_nick(char *nick, struct user_info *user) {
    user->nick = strdup(nick);
}

/* command      key
 * ====================
 * bye / quit   0
 * game         1
 * join         2
 * list         3
 * roll         4
 * say          5
 * user         6
 * who          7
 * nick         8
 */
void command(char *command, gpointer key, gpointer user) {
    switch(command[1]) {
            case '1':
                log_message("command game", key);
                break;
            case '2':
                log_message("command join", key);
                join_room(&command[3], user);
                break;
            case '3':
                log_message("command list", key);
                g_tree_foreach(chatrooms, list_rooms, user);
                break;
            case '4':
                log_message("command roll", key);
                break;
            case '5':
                log_message("command say", key);
                private_message(&command[3], key, user);
                break;
            case '6':
                log_message("command user", key);
                authenticate_user(command, key, user);
                break;
            case '7':
                log_message("command who", key);
                g_tree_foreach(connections, list_users, user);
                break;
            case '8':
                log_message("command nick", key);
                set_nick(&command[3], user);
                break;
            default:
                log_message("invalid command", key);
                send_message(user, "Server: Invalid command!");
                break;
    }
}

void send_message(gpointer data, gpointer user_data) {
    struct user_info *user = (struct user_info *) data;
    char *message = (char *) user_data;

    int write_err = SSL_write(user->ssl, message, strlen(message));
    if(write_err == -1) {
        ERR_print_errors_fp(stderr);
    }
}

gboolean check_timeout(gpointer key, gpointer value, gpointer data) {
    UNUSED(data);
    struct user_info *user = (struct user_info *) value;
    struct sockaddr_in *client = (struct sockaddr_in *) key;
    if(difftime(time(0), user->timeout) > CLIENT_TIME_OUT) {
        /* Disconnect user */
        log_message("timed out.", client);
        ssl_shut_down(user->ssl, user->fd);
        g_tree_remove(connections, client);
    }

    return FALSE;
}

gboolean shut_down(gpointer key, gpointer value, gpointer data) {
    UNUSED(key);
    UNUSED(data);
    struct user_info *user = (struct user_info *) value;
    ssl_shut_down(user->ssl, user->fd);
    return FALSE;
}

gboolean read_data(gpointer key, gpointer value, gpointer data) {
    struct user_info *user = (struct user_info *) value;
    struct sockaddr_in *client = (struct sockaddr_in *) key;
    char message[BUFF_SIZE];
    if(FD_ISSET(user->fd, (fd_set *) data)) {
        memset(message, 0, BUFF_SIZE);
        int ret = SSL_read(user->ssl, message, sizeof(message) - 1);

        if(ret <= 0) {
            ssl_shut_down(user->ssl, user->fd);
            remove_from_room(user);
            g_tree_remove(connections, key);

            /*<timestamp> : <client ip>:<client port> disconnected*/
            log_message("disconnected", key);
        }

        if(ret > 0) {
            user->timeout = time(0);
            message[ret] = '\0';
            if(message[0] == '/') {
                command(message, key, user);
            } else {
                if(user->room) {
                    gchar *l_message = g_strconcat("message to ", user->room, NULL);
                    log_message(l_message, key);

                    char port_str[5];
                    sprintf(port_str, "%d", client->sin_port);
                    gchar *identity = (user->nick) ? strdup(user->nick) : g_strconcat(inet_ntoa(client->sin_addr), ":", port_str, NULL);

                    g_free(l_message);
                    l_message = g_strconcat(identity, ": ", message, NULL);
                    /* TODO: Set message sender nick or ip+port */
                    struct chatroom *room = g_tree_lookup(chatrooms, user->room);
                    g_list_foreach(room->room, send_message, l_message);
                    g_free(l_message);
                    g_free(identity);
                } else {
                    log_message("message to no room", key);
                    int write_err = SSL_write(user->ssl, "Error: Please join a chatroom to send messages.", 50);
                    if(write_err == -1) {
                        ERR_print_errors_fp(stderr);
                    }
                }
            }
        }
    }
    return FALSE;
}

void key_dest_func(gpointer key) {
    free((struct sockaddr_in *) key);
}
void data_dest_func_user(gpointer data) {
    if(data) {
        struct user_info *user = (struct user_info*) data;
        free(user->username);
        free(user->nick);
        free(user->room);
        free(user);
    }
}
void data_dest_func_list(gpointer data) {
    struct chatroom *room = (struct chatroom*) data;
    g_list_free_full((GList *) room->room, data_dest_func_user);
    free(room);
}

int main(int argc, char **argv)
{
    signal(SIGINT, sigint_handler);

    unsigned short int s_port; /* Check that port was provided */
    if(argc > 1) sscanf(argv[1], "%hu", &s_port);
    else exit(1);

    /* Initialize connections tree */
    connections = g_tree_new_full(sockaddr_in_cmp_data, NULL, key_dest_func, data_dest_func_user);
    chatrooms = g_tree_new_full(name_cmp_data, NULL, NULL, data_dest_func_list);
    users = g_key_file_new();

    struct chatroom *lobby = g_new0(struct chatroom, 1);
    struct chatroom *tsam= g_new0(struct chatroom, 1);

    g_tree_insert(chatrooms, "Lobby", lobby);
    g_tree_insert(chatrooms, "TSAM", tsam);

    /* SSL method and context */
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;
    int err;

    /* generating salt string */
    int salt_length = rand() % 40;
    char create_salt[salt_length];
    gen_random(create_salt, salt_length);
    salt = g_strdup(create_salt); 

    /* configuring hash function */
    mdctx = EVP_MD_CTX_create();
    md = EVP_sha256();
    /* Load encryption & hashing algorithms for the SSL program */
    SSL_library_init();

    /* Load the error strings for SSL & CRYPTO APIs */
    SSL_load_error_strings();

    /* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
    meth = SSLv3_server_method();

    /* Create a SSL_CTX structure */
    ctx = SSL_CTX_new(meth);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Load the server certificate into the SSL_CTX structure */
    if (SSL_CTX_use_certificate_file(ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Load the private-key corresponding to the server certificate */
    if (SSL_CTX_use_PrivateKey_file(ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Check if the server certificate and private-key matches */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr,"Private key does not match the certificate public key\n");
        exit(1);
    }


    int sockfd;
    struct sockaddr_in server;

    /* Create and bind a TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    /* Network functions need arguments in network byte order instead of
       host byte order. The macros htonl, htons convert the values, */
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(s_port);
    int err_bind = bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));
    if(err_bind == -1) {
        printf("Error binding sockfd");
        exit(1);
    }

    /* Before we can accept messages, we have to listen to the port. We allow one
     * 1 connection to queue for simplicity.
     */
    listen(sockfd, 1);

    while(active) {
        struct timeval tv;
        int retval;
        int connfd;
        int highest_fd = -1;

        /* Check whether there is data on the socket fd. */
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        g_tree_foreach(connections, is_greater, &highest_fd);

        if(FD_ISSET(4, &rfds))
            printf("highest %d\n", highest_fd);
        printf("highest %d\n", highest_fd);

        /* Wait for five seconds. */
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        retval = select(((highest_fd > sockfd) ? highest_fd : sockfd) + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            perror("select()");
        } else if (retval > 0) {
            /* New conection */
            if(FD_ISSET(sockfd, &rfds)) {
                struct sockaddr_in *client = g_new0(struct sockaddr_in, 1);
                /* Copy to len, since recvfrom may change it. */
                socklen_t len = (socklen_t) sizeof(client);

                /* For TCP connectios, we first have to accept. */
                connfd = accept(sockfd, (struct sockaddr *) client, &len);

                ssl = SSL_new(ctx);

                if(ssl) {
                    /* Assign the socket into the SSL structure (SSL and socket without BIO) */
                    SSL_set_fd(ssl, connfd);

                    /* Perform SSL Handshake */
                    err = SSL_accept(ssl);

                    if (err == -1) {
                        ERR_print_errors_fp(stderr);
                        printf("SSL connection failed. SSL_accept");
                    } else {
                        log_message("connected", client);

                        struct user_info *new_user = g_new0(struct user_info, 1);
                        new_user->fd = connfd;
                        new_user->ssl = ssl;
                        new_user->username = NULL;
                        new_user->room = NULL;
                        new_user->login_attempts = 0;
                        new_user->timeout = time(0);
                        g_tree_insert(connections, client, new_user);

                        /* Send welcome message */
                        err = SSL_write(ssl, "Server: Welcome!", 16);
                        if(err == -1) {
                            ERR_print_errors_fp(stderr);
                        }
                    }
                } else {
                    printf("SSL connection failed. SSL_new");
                }
            }

            g_tree_foreach(connections, read_data, &rfds);

        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
        g_tree_foreach(connections, check_timeout, NULL);
    }

    printf("Exiting\n");
    /* TODO: free everything */
    g_tree_foreach(connections, shut_down, NULL);
    g_tree_destroy(connections);
    g_tree_destroy(chatrooms);

    g_key_file_free(users);

    /* Free the SSL_CTX structure */
    SSL_CTX_free(ctx);
    ERR_remove_state(0);
    ERR_free_strings();
    EVP_MD_CTX_cleanup(mdctx);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    /* Free Willy! */
    free(willy);

}

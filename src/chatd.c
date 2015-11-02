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

#define RSA_SERVER_CERT  "server.crt"
#define RSA_SERVER_KEY   "server.key"

#define UNUSED(x) (void)(x)

#define BUFF_SIZE 2048

struct user_info {
    SSL *ssl;
    int fd;
    char *username;
    char *room;
    int login_attempts;
} user_info;

struct chatroom {
    GList *room;
} chatroom;

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

int name_cmp(const void *str1, const void *str2) {
    return g_strcmp0(str1, str2);
}

/* Connections tree */
GTree *connections;
GTree *chatrooms;
GKeyFile *users;
fd_set rfds;


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

    char users[10];
    sprintf(users, "%d", g_list_length(((struct chatroom *)value)->room));

    gchar * message = g_strjoin(NULL, " -", (char *) key, ", (", users, ")", NULL);

    SSL_write(write_ssl, message, strlen(message));

    g_free(message);
    return FALSE;
}

gboolean authenticate_user(char * command, gpointer key, gpointer user){
    gchar** command_split = g_strsplit(command, " ", 3);
    struct user_info * current_user = (struct user_info *) user;
    if(command_split[1] == NULL || command_split[2] == NULL){
        gchar * message = g_strconcat(command_split[1], " authentication failed", NULL);
        log_message(message, key);
        return FALSE;
    } else{
        gchar * password = g_key_file_get_string(users, "users", command_split[1], NULL);
        if(password == NULL){
            g_free(current_user->username);
            current_user->username = strdup(command_split[1]);
            g_key_file_set_value(users, "users", command_split[1], command_split[2]);
            //printf("username: %s", current_user->username);
            gchar * message = g_strconcat(command_split[1], " authenticated", NULL);
            log_message(message, key);
            return TRUE;
        } else if(password == command_split[2]){
            g_free(current_user->username);
            current_user->username = strdup(command_split[1]);
            return TRUE;
        } 

        else {
            
            gchar * message = g_strconcat(command_split[1], " authentication failed", NULL);
            log_message(message, key);
            return FALSE; 
        }
    }
}

void remove_from_room(gpointer user) {
    struct user_info *u = (struct user_info *)user;
    if(u->room != NULL) {
        struct chatroom* old_room = g_tree_lookup(chatrooms, u->room);
        old_room->room = g_list_remove(old_room->room, user);
    }
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
                break;
            case '6':
                log_message("command user", key);
                authenticate_user(command, key, user);
                break;
            case '7':
                log_message("command who", key);
                g_tree_foreach(connections, list_users, user);
                break;
            default:
                log_message("invalid command", key);
                break;
    }
}

gboolean read_data(gpointer key, gpointer value, gpointer data) {
    struct user_info *user = (struct user_info *) value;
    char message[BUFF_SIZE];
    memset(message, 0, BUFF_SIZE);
    if(FD_ISSET(user->fd, (fd_set *) data)) {
        int ret = SSL_read(user->ssl, message, sizeof(message) - 1);

        if(ret <= 0) {
            ssl_shut_down(user->ssl, user->fd);
            remove_from_room(user);
            g_tree_remove(connections, key);

            /*<timestamp> : <client ip>:<client port> disconnected*/
            log_message("disconnected", key);
        }

        if(ret > 0) {
            message[ret] = '\0';
            if(message[0] == '/') {
                command(message, key, user);
            } else {
                if(user->room) {
                    gchar *l_message = g_strjoin(NULL, "message to ", user->room, ": ", message, NULL);
                    log_message(l_message, key);

                    /* TODO: Send message to all users in chat room */

                } else {
                    log_message("message to no room", key);
                    SSL_write(user->ssl, "Error: Please join a chatroom to send messages.", 50);
                }
            }
        }
    }
    return FALSE;
}


int main(int argc, char **argv)
{
    unsigned short int s_port; /* Check that port was provided */
    if(argc > 1) sscanf(argv[1], "%hu", &s_port);
    else exit(1);

    /* Initialize connections tree */
    connections = g_tree_new(sockaddr_in_cmp);
    chatrooms = g_tree_new(name_cmp);
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
    //char message[512];

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

    for (;;) {
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
    }

    /* TODO: free chat rooms */
    /* TODO: free everything */

    /* Free the SSL_CTX structure */
    SSL_CTX_free(ctx);
}

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
    char *chatroom;
    int login_attempts;
} user_info;

struct chatroom {
    gchar * room_name;
    GList * users;
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

/* Connections tree */
GTree *connections;
GTree *chatrooms;
GTree *users;
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
    printf("list_users\n");
    struct sockaddr_in *client = (struct sockaddr_in *)key;
    struct user_info *user = (struct user_info *) value;
    SSL *write_ssl = ((struct user_info *) data)->ssl;

    char port_str[5];
    sprintf(port_str, "%d", client->sin_port);

    printf("port: %s\n", port_str);

    gchar * message = g_strjoin(NULL, "Username: ",(user->username) ? user->username : "NULL", ", IP: ", inet_ntoa(client->sin_addr), ":", port_str, NULL);

    SSL_write(write_ssl, message, strlen(message));
    return FALSE;
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
                break;
            case '3':
                log_message("command list", key);
                break;
            case '4':
                log_message("command roll", key);
                break;
            case '5':
                log_message("command say", key);
                break;
            case '6':
                log_message("command user", key);
                printf("%s\n", command);
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

gboolean read_data(gpointer key, gpointer user, gpointer data) {
    int user_fd = ((struct user_info *) user)->fd;
    SSL *user_ssl = ((struct user_info *) user)->ssl;
    char message[BUFF_SIZE];
    memset(message, 0, BUFF_SIZE);
    if(FD_ISSET(user_fd, (fd_set *) data)) {
        int ret = SSL_read(user_ssl, message, sizeof(message) - 1);

        if(ret <= 0) {
            ssl_shut_down(((struct user_info *) user)->ssl, user_fd);
            g_tree_remove(connections, key);
            /*<timestamp> : <client ip>:<client port> disconnected*/
            log_message("disconnected", key);
        }

        if(ret > 0) {
            if(message[0] == '/') {
                command(message, key, user);
            } else {
                /* TODO: write message to chatroom */
                log_message("message", key);
                message[ret] = '\0';
                printf ("Received %d chars:'%s'\n", ret, message);
                SSL_write(user_ssl, "What did you call me", 20);
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
                        g_tree_insert(connections, client, new_user);

                        /* Send welcome message */
                        err = SSL_write(ssl, "Welcome!", 8);
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

    /* Free the SSL_CTX structure */
    SSL_CTX_free(ctx);
}

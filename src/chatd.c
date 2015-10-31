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

#define ON  1
#define OFF 0

#define BUFF_SIZE 2048

struct user_info {
    SSL *ssl;
    int fd;
    char *username;
} user_info;

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
            (_addr1->sin_family != _addr2->sin_family));

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

gboolean is_greater(gpointer key, gpointer user, gpointer data) {
    printf("%p\n",key);
    int user_fd = ((struct user_info *) user)->fd;
    int data_fd = *(int *)data;
    if(user_fd > data_fd) {
        *(int *)data = user_fd;
    }
    return FALSE;
}

gboolean read_data(gpointer key, gpointer user, gpointer data) {
    printf("%p\n",key);
    int user_fd = ((struct user_info *) user)->fd;
    char message[BUFF_SIZE];

    if(FD_ISSET(user_fd, (fd_set *) data)) {
        int len = SSL_read(((struct user_info *) user)->ssl, message, sizeof(message) - 1);

        if(len == 0) {

        }
    }
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


int main(int argc, char **argv)
{
    unsigned short int s_port; /* Check that port was provided */
    if(argc > 1) sscanf(argv[1], "%hu", &s_port);
    else exit(1);

    /* Connections tree */
    GTree *connections = g_tree_new(sockaddr_in_cmp);

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
        fd_set rfds;
        struct timeval tv;
        int retval;
        int connfd;
        int highest_fd = -1;

        /* Check whether there is data on the socket fd. */
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        printf("highest %d\n", highest_fd);

        g_tree_foreach(connections, is_greater, &highest_fd);

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

                printf("Connection from %s, port %d\n", inet_ntoa(client->sin_addr),
                        client->sin_port);

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
                        printf("SSL connection using %s\n", SSL_get_cipher (ssl));

                        struct user_info *new_user = g_new0(struct user_info, 1);
                        new_user->fd = connfd;
                        new_user->ssl = ssl;
                        g_tree_insert(connections, client, new_user);

                        /* Send welcome message */
                        err = SSL_write(ssl, "Welcome!", 8);
                        if(err == -1) {
                            ERR_print_errors_fp(stderr);
                        }

                        /* Receive data from the SSL client */
                        /*err = SSL_read(ssl, message, sizeof(message) - 1);

                        if(err == -1) {
                            ERR_print_errors_fp(stderr);
                        }

                        message[err] = '\0';

                        printf ("Received %d chars:'%s'\n", err, message);

                        //ssl_shut_down(ssl, connfd);
                        */
                    }
                } else {
                    printf("SSL connection failed. SSL_new");
                }
            }

            g_tree_foreach(connections, read_data, &rfds);

            /* TODO: go through connections and find all set fds */

        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
    }

    /* Free the SSL_CTX structure */
    SSL_CTX_free(ctx);
}

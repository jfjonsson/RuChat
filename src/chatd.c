/* A TCP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

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

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define RSA_SERVER_CERT  "server.crt"
#define RSA_SERVER_KEY   "server.key"

#define ON  1
#define OFF 0


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



int main(int argc, char **argv)
{
    unsigned short int s_port; /* Check that port was provided */
    if(argc > 1) sscanf(argv[1], "%hu", &s_port);
    else exit(1);

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
    meth = SSLv3_method();

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
    struct sockaddr_in server, client;
    char message[512];

    /* Create and bind a TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    /* Network functions need arguments in network byte order instead of
       host byte order. The macros htonl, htons convert the values, */
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(s_port);
    bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

    /* Before we can accept messages, we have to listen to the port. We allow one
     * 1 connection to queue for simplicity.
     */
    listen(sockfd, 1);

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        int retval;

        /* Check whether there is data on the socket fd. */
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        /* Wait for five seconds. */
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            perror("select()");
        } else if (retval > 0) {
            /* Data is available, receive it. */
            assert(FD_ISSET(sockfd, &rfds));

            /* Copy to len, since recvfrom may change it. */
            socklen_t len = (socklen_t) sizeof(client);

            /* For TCP connectios, we first have to accept. */
            int connfd;
            connfd = accept(sockfd, (struct sockaddr *) &client, &len);

            ssl = SSL_new(ctx);

            if(ssl) {
                /* Assign the socket into the SSL structure (SSL and socket without BIO) */
                SSL_set_fd(ssl, connfd);

                /* Perform SSL Handshake on the SSL server */
                err = SSL_accept(ssl);

                if (err == -1) {
                    ERR_print_errors_fp(stderr);
                    printf("SSL connection failed. SSL_accept");
                } else {
                    printf("SSL connection using %s\n", SSL_get_cipher (ssl));

                    /* Receive one byte less than declared,
                    because it will be zero-termianted
                    below. */
                    ssize_t n = read(connfd, message, sizeof(message) - 1);

                    /* Send the message back. */
                    write(connfd, message, (size_t) n);

                    /* We should close the connection. */
                    shutdown(connfd, SHUT_RDWR);
                    close(connfd);

                    /* Zero terminate the message, otherwise
                    printf may access memory outside of the
                    string. */
                    message[n] = '\0';
                    /* Print the message to stdout and flush. */
                    fprintf(stdout, "Received:\n%s\n", message);
                    fflush(stdout);
                }
            } else {
                printf("SSL connection failed. SSL_new");
            }
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
    }
}

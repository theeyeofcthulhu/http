#include <ifaddrs.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <assert.h>

#include <dbg.h>

#define SV_IMPLEMENTATION
#include "sv.h"

#include "url.h"
#include "request.h"
#include "handler.h"

#define BUF_SZ 2048

bool running = true;

void get_local_ip(char *out)
{
    char buf[BUF_SZ];

    FILE *f = fopen("/proc/net/route", "r");
    sv default_interface;

    while (fgets(buf, sizeof(buf), f)) {
        sv in = sv_from_cstr(buf);
        sv out;

        sv_chop_delim('\t', &in, &out);
        if (sv_starts_with(SV_Lit("00000000"), in)) {
            default_interface = out;
            break;
        }
    }

    const int fm = AF_INET;
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(1);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        int family = ifa->ifa_addr->sa_family;
        // As of now, we can use a string view for holding the interface,
        // because buf only gets overwritten after the fact. Be careful
        // not to run into errors because of this.
        if (sv_cstr_eq(default_interface, ifa->ifa_name)) {
            if (family == fm) {
                int err = getnameinfo(ifa->ifa_addr,
                                      (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), 
                                      buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);

                if (err != 0) {
                    printf("getnameinfo: %s\n", gai_strerror(err));
                    exit(1);
                }
                
                sprintf(out, "%s", buf);
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    fclose(f);
}

void handler_get(struct request req, int connfd)
{
    sv read_view, buf;
    bool sending_file = true;

    read_view = req.header;

    sv_chop_delim(' ', &read_view, &buf);
    sv_chop_delim(' ', &read_view, &buf);

    printf("Client requested route: "SV_Fmt".\n", SV_Arg(buf));

    /* Special cases for file resolution */
    if (sv_eq(buf, SV_Lit("/"))) {
        buf = SV_Lit("/index.html");
    } else if (sv_eq(buf, SV_Lit("/quit"))) {
        buf = SV_Lit("/quit.html");
        puts("Quitting on client request.");
        running = false;
    } else if (sv_eq(buf, SV_Lit("/mute"))) {
        puts("Muting on client request.");
        system("pactl set-sink-mute @DEFAULT_SINK@ toggle");
        sending_file = false;
        send_ok(connfd);
    } else if (sv_eq(buf, SV_Lit("/Download/contents"))) {
        puts("Sending contents of Download folder.");
        sending_file = false;
        send_json_dir(connfd, "Download");
    } else {
        puts("WARNING: Unknown GET request.");
    }

    if (sending_file) {
        resolve_file(connfd, buf);
    }
}

void handler_post(struct request req, int connfd)
{
    sv read_view = req.text;
    sv buf;

    puts("Client wants to POST");

    sv_chop_delim(' ', &read_view, &buf);
    sv_chop_delim(' ', &read_view, &buf);
    printf("Client requested post: "SV_Fmt".\n", SV_Arg(buf));

    if (sv_eq(buf, SV_Lit("/upload"))) {
        puts("Client wants to upload");

        sv boundary = get_field_value(req.header, SV_Lit("Content-Type"));
        sv content_type;
        sv_chop_delim('=', &boundary, &content_type);
        printf("Boundary: "SV_Fmt"\n", SV_Arg(boundary));

        sv content = req.data;

        // Only expect one boundary pair
        // Handle fields like a barbarian, but who cares
        if (SV_Contains(boundary, content)) {
            puts("Found first boundary");
            sv_chop_delim('\n', &content, &buf);
            sv_chop_delim('\n', &content, &buf);

            // Get filename
            size_t idx = sv_idx_long(SV_Lit("filename="), buf);
            sv fn = sv_substr(idx, SV_END_POS, buf);

            fn = sv_substr(sv_idx('"', fn) + 1, SV_END_POS, fn);
            fn.len = sv_last_idx('"', fn);

            if (fn.len == 0) {
                puts("WARNING: Empty filename. Continuing.");
                return;
            }

            char *fn_cstr = strndup(fn.ptr, fn.len);

            printf("Filename: "SV_Fmt"\n", SV_Arg(fn));

            sv_chop_delim('\n', &content, &buf);
            sv_chop_delim('\n', &content, &buf);

            size_t close = sv_idx_long(boundary, content);
            if (close == SV_END_POS) {
                puts("WARNING: No terminating boundary found");
            } else {
                puts("Found terminating boundary.");
            }

            sv file_content = sv_substr(0, close, content);
            file_content.len = sv_last_idx('\n', file_content) - 1; // Remove two lines not belonging to file // Remove two lines not belonging to file

            if (chdir("Upload") == -1)
                perror("chdir");
            FILE *w = fopen(fn_cstr, "w");
            fwrite(file_content.ptr, sizeof(char), file_content.len, w);
            fclose(w);
            if (chdir("..") == -1)
                perror("chdir");

            printf("SUCCESS: Wrote %zu bytes to Upload/%s\n\n", file_content.len, fn_cstr);

            free(fn_cstr);
        } else {
            puts("WARNING: No boundaries in payload.");
        }
        send_see_other(connfd);
    } else {
        printf("WARNING: Unknown POST request: '"SV_Fmt"'\n", SV_Arg(buf));
    }
}

int main(int argc, char **argv)
{
    int sockfd, connfd;
    socklen_t len, addrlen;
    struct sockaddr_in servaddr, cli;
    bool open = false;

    int flag;
    while ((flag = getopt(argc, argv, "o")) != -1) {
        switch (flag) {
            case 'o':
                open = true;
                break;
            default:
                return 1;
        }
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return 1;
    }

    puts("Socket created.");

    memset(&servaddr, '\0', sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = 0;

    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) == -1) {
        perror("bind");
        return 1;
    }

    /* Extract the assigned port number */
    addrlen = sizeof(servaddr);
    if (getsockname(sockfd, (struct sockaddr *)&servaddr, &addrlen) == -1) {
        perror("getsockname");
        return 1;
    }

    puts("Socket bound.");

    if (listen(sockfd, 5) == -1) {
        perror("listen");
        return 1;
    }

    char ip_buf[BUF_SZ];
    get_local_ip(ip_buf);

    printf("Listening on port %d. (http://%s:%d)\n", ntohs(servaddr.sin_port), ip_buf, ntohs(servaddr.sin_port));

    if (open) {
        char command[BUF_SZ];

        sprintf(command, "%s http://localhost:%d 1>/dev/null 2>&1", getenv("BROWSER"), ntohs(servaddr.sin_port));

        puts(command);

        pid_t pid = fork();
        if (pid == 0) {
            execv("/bin/sh", (char *[]){ "/bin/sh", "-c", command, NULL });
        }
    }

    len = sizeof(cli);

    handler_not_found_redirect = "notfound.html";

    register_handler(SV_Lit("GET /"), handler_get);
    register_handler(SV_Lit("GET /quit"), handler_get);
    register_handler(SV_Lit("GET /mute"), handler_get);
    register_handler(SV_Lit("GET /Download/contents"), handler_get);
    register_handler(SV_Lit("GET /"), handler_get);

    register_handler(SV_Lit("POST /upload"), handler_post);

    while (running) {
        if ((connfd = accept(sockfd, (struct sockaddr *)&cli, &len)) == -1) {
            perror("accept");
            return 1;
        }

        puts("Accepted.");

        struct request rq = receive_into_dynamic_buffer(connfd);
        handle_request(rq, connfd);

        free((void *)rq.text.ptr);

        close(connfd);
    }

    close(sockfd);
}

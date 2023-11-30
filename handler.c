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

#include "sv.h"

#include "request.h"
#include "url.h"
#include "handler.h"

#define BUF_SZ 2048

#define HANDLER_ARR_SZ 512
struct handler {
    sv req;
    void (*handler)(struct request, int connfd);
};

struct handler handlers[HANDLER_ARR_SZ];
size_t handlers_off = 0;

char *handler_not_found_redirect = "";

void register_handler(sv req, void (*handler)(struct request, int connfd))
{
    handlers[handlers_off].req = req;
    handlers[handlers_off].handler = handler;
    handlers_off += 1;
}

// Send a json representation of the contents of dirname
// to connfd
// TODO: dynamic memory?
void send_json_dir(int connfd, const char *dirname)
{
    DIR *stream;
    struct dirent *dir_buf;
    char json_buf[BUF_SZ], msg_buf[BUF_SZ];
    size_t off, msg_len;
    bool first_run = true;

    off = sprintf(json_buf, "[\n");

    if ((stream = opendir(dirname)) == NULL) {
        perror("opendir");
        exit(1);
    }

    errno = 0;
    while ((dir_buf = readdir(stream)) != NULL) {
        if (strcmp(dir_buf->d_name, ".") == 0 || strcmp(dir_buf->d_name, "..") == 0)
            continue;

        if (!first_run) {
            off += sprintf(json_buf + off, ",\n");
        } else {
            first_run = false;
        }

        off += sprintf(json_buf + off, "\t[\"%s\", \"%s/%s\"]", dir_buf->d_name, dirname, dir_buf->d_name);
    }

    if (errno != 0) {
        perror("readdir");
        exit(1);
    }

    closedir(stream);

    off += sprintf(json_buf + off, "\n]\n");
    puts(json_buf);

    msg_len = sprintf(msg_buf, "HTTP/1.1 200 OK\r\n"
                               "Server: MyTCP\r\n"
                               "Content-Length: %zu\r\n"
                               "Connection: close\r\n"
                               "Content-Type: application/json\r\n"
                               "\r\n", off);

    send(connfd, msg_buf, msg_len, MSG_MORE);
    send(connfd, json_buf, off, 0);
}

void send_ok(int connfd)
{
    const char *msg = "HTTP/1.1 200 OK\r\n"
                      "Server: MyTCP\r\n"
                      "Connection: close\r\n";

    send(connfd, msg, strlen(msg), 0);
}

void send_see_other(int connfd)
{
    const char *msg = "HTTP/1.1 303 See Other\r\n"
                      "Server: MyTCP\r\n"
                      "Location: /\r\n"
                      "Connection: close\r\n";

    send(connfd, msg, strlen(msg), 0);
}

void resolve_file(int connfd, sv fn)
{
    sv exten;
    int fd, msg_len;
    struct stat statbuf;
    off_t file_len;
    char buf[BUF_SZ], url_buf[BUF_SZ];

    exten = fn;
    sv_chopl(sv_last_idx('.', exten), &exten);

    /* Remove leading '/' */
    sv_chopl(1, &fn);

    if (sv_starts_with(SV_Lit("/"), fn)) {
        fprintf(stderr, "Refusing absolute path.\n");
        goto not_found;
    }
    if (sv_idx_long(SV_Lit(".."), fn) != SV_END_POS) {
        fprintf(stderr, "Refusing directory jumps.\n");
        goto not_found;
    }
    escape_url(fn, url_buf);
    printf("Resolved: %s\n", url_buf);

    if ((fd = open(url_buf, O_RDONLY)) == -1) {
        perror("open");
        goto not_found;
    }

    if (fstat(fd, &statbuf) == -1){
        perror("fstat");
        goto not_found;
    }
    file_len = statbuf.st_size;

    msg_len = sprintf(buf, "HTTP/1.1 200 OK\r\n"
                           "Server: MyTCP\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: close\r\n"
                           "Content-Type: %s\r\n"
                           "\r\n", file_len, extension_to_filetype(exten));
    printf("Responding:\n%.*s", msg_len, buf);

    send(connfd, buf, msg_len, MSG_MORE);
    sendfile(connfd, fd, NULL, statbuf.st_size);

    close(fd);

    return;

not_found:
    msg_len = sprintf(buf, "HTTP/1.1 303 See Other\r\n"
                           "Server: MyTCP\r\n"
                           "Location: /%s\r\n"
                           "Connection: close\r\n", handler_not_found_redirect);
    printf("Responding:\n%.*s", msg_len, buf);
    send(connfd, buf, msg_len, 0);

    return;
}

void handle_request(struct request rq, int connfd)
{
    sv read_view, buf, base_read;

    base_read = rq.text;

    read_view = base_read;
    printf("Client sent header: "SV_Fmt"\n", SV_Arg(rq.header));

    size_t i, spaces;
    for (i = 0, spaces = 0; spaces < 2 && i < rq.header.len; i++) {
        if (rq.header.ptr[i] == ' ')
            spaces += 1;
    }
    sv request = sv_from_data(rq.header.ptr, i-1);

    bool handler_found = false;

    for (size_t j = 0; j < handlers_off && !handler_found; j++) {
        if (sv_eq(request, handlers[j].req)) {
            printf("Handler found: "SV_Fmt"\n", SV_Arg(handlers[j].req));
            handler_found = true;
            handlers[j].handler(rq, connfd);
        }
    }

    if(!handler_found) {
        sv_chop_delim(' ', &read_view, &buf);
        if (sv_eq(buf, SV_Lit("GET"))) {
            sv_chop_delim(' ', &read_view, &buf);
            printf("FALLBACK: Attempting to send file: "SV_Fmt".\n", SV_Arg(buf));
            resolve_file(connfd, buf);
        } else {
            puts("WARNING: No handler for request.");
        }
    }
}

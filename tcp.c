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

#define SV_IMPLEMENTATION
#include "sv.h"

#include <dbg.h>

#define BUF_SZ 2048

struct url_escape_code {
    const char *res;
    const char *code;
};

// TODO: what are those characters?
// 	%8D	%C5%8D
// 		%8F
// 		%C2%90
// 	%9D	%9D
// 		%81
struct url_escape_code codes[] = {
{ " ",  	"%20" },
{ "!",	    "%21" },
{ "\"",	    "%22" },
{ "#",		"%23" },
{ "$",		"%24" },
{ "%",		"%25" },
{ "&",		"%26" },
{ "'",		"%27" },
{ "(",		"%28" },
{ ")",		"%29" },
{ "*",		"%2A" },
{ "+",		"%2B" },
{ ",",		"%2C" },
{ "-",		"%2D" },
{ ".",		"%2E" },
{ "/",		"%2F" },
{ "0",		"%30" },
{ "1",		"%31" },
{ "2",		"%32" },
{ "3",		"%33" },
{ "4",		"%34" },
{ "5",		"%35" },
{ "6",		"%36" },
{ "7",		"%37" },
{ "8",		"%38" },
{ "9",		"%39" },
{ ":",		"%3A" },
{ ";",		"%3B" },
{ "<",		"%3C" },
{ "=",		"%3D" },
{ ">",		"%3E" },
{ "?",		"%3F" },
{ "@",		"%40" },
{ "A",		"%41" },
{ "B",		"%42" },
{ "C",		"%43" },
{ "D",		"%44" },
{ "E",		"%45" },
{ "F",		"%46" },
{ "G",		"%47" },
{ "H",		"%48" },
{ "I",		"%49" },
{ "J",		"%4A" },
{ "K",		"%4B" },
{ "L",		"%4C" },
{ "M",		"%4D" },
{ "N",		"%4E" },
{ "O",		"%4F" },
{ "P",		"%50" },
{ "Q",		"%51" },
{ "R",		"%52" },
{ "S",		"%53" },
{ "T",		"%54" },
{ "U",		"%55" },
{ "V",		"%56" },
{ "W",		"%57" },
{ "X",		"%58" },
{ "Y",		"%59" },
{ "Z",		"%5A" },
{ "[",		"%5B" },
{ "\\",		"%5C" },
{ "]",		"%5D" },
{ "^",		"%5E" },
{ "_",		"%5F" },
{ "`",		"%60" },
{ "a",		"%61" },
{ "b",		"%62" },
{ "c",		"%63" },
{ "d",		"%64" },
{ "e",		"%65" },
{ "f",		"%66" },
{ "g",		"%67" },
{ "h",		"%68" },
{ "i",		"%69" },
{ "j",		"%6A" },
{ "k",		"%6B" },
{ "l",		"%6C" },
{ "m",		"%6D" },
{ "n",		"%6E" },
{ "o",		"%6F" },
{ "p",		"%70" },
{ "q",		"%71" },
{ "r",		"%72" },
{ "s",		"%73" },
{ "t",		"%74" },
{ "u",		"%75" },
{ "v",		"%76" },
{ "w",		"%77" },
{ "x",		"%78" },
{ "y",		"%79" },
{ "z",		"%7A" },
{ "{",		"%7B" },
{ "|",		"%7C" },
{ "}",		"%7D" },
{ "~",		"%7E" },
{ " ",		"%7F" },
{ "€",		"%E2%82%AC" },
{ "‚",		"%E2%80%9A" },
{ "ƒ",		"%C6%92" },
{ "„",		"%E2%80%9E" },
{ "…",		"%E2%80%A6" },
{ "†",		"%E2%80%A0" },
{ "‡",		"%E2%80%A1" },
{ "ˆ",		"%CB%86" },
{ "‰",		"%E2%80%B0" },
{ "Š",		"%C5%A0" },
{ "‹",		"%E2%80%B9" },
{ "Œ",		"%C5%92" },
{ "Ž",		"%C5%BD" },
{ "‘",		"%E2%80%98" },
{ "’",		"%E2%80%99" },
{ "“",		"%E2%80%9C" },
{ "”",		"%E2%80%9D" },
{ "•",		"%E2%80%A2" },
{ "–",		"%E2%80%93" },
{ "—",		"%E2%80%94" },
{ "˜",		"%CB%9C" },
{ "™",		"%E2%84" },
{ "š",		"%C5%A1" },
{ "›",		"%E2%80" },
{ "œ",		"%C5%93" },
{ "ž",		"%C5%BE" },
{ "Ÿ",		"%C5%B8" },
{ " ",		"%C2%A0" },
{ "¡",		"%C2%A1" },
{ "¢",		"%C2%A2" },
{ "£",		"%C2%A3" },
{ "¤",		"%C2%A4" },
{ "¥",		"%C2%A5" },
{ "¦",		"%C2%A6" },
{ "§",		"%C2%A7" },
{ "¨",		"%C2%A8" },
{ "©",		"%C2%A9" },
{ "ª",		"%C2%AA" },
{ "«",		"%C2%AB" },
{ "¬",		"%C2%AC" },
{ "­",		"%C2%AD" },
{ "®",		"%C2%AE" },
{ "¯",		"%C2%AF" },
{ "°",		"%C2%B0" },
{ "±",		"%C2%B1" },
{ "²",		"%C2%B2" },
{ "³",		"%C2%B3" },
{ "´",		"%C2%B4" },
{ "µ",		"%C2%B5" },
{ "¶",		"%C2%B6" },
{ "·",		"%C2%B7" },
{ "¸",		"%C2%B8" },
{ "¹",		"%C2%B9" },
{ "º",		"%C2%BA" },
{ "»",		"%C2%BB" },
{ "¼",		"%C2%BC" },
{ "½",		"%C2%BD" },
{ "¾",		"%C2%BE" },
{ "¿",		"%C2%BF" },
{ "À",		"%C3%80" },
{ "Á",		"%C3%81" },
{ "Â",		"%C3%82" },
{ "Ã",		"%C3%83" },
{ "Ä",		"%C3%84" },
{ "Å",		"%C3%85" },
{ "Æ",		"%C3%86" },
{ "Ç",		"%C3%87" },
{ "È",		"%C3%88" },
{ "É",		"%C3%89" },
{ "Ê",		"%C3%8A" },
{ "Ë",		"%C3%8B" },
{ "Ì",		"%C3%8C" },
{ "Í",		"%C3%8D" },
{ "Î",		"%C3%8E" },
{ "Ï",		"%C3%8F" },
{ "Ð",		"%C3%90" },
{ "Ñ",		"%C3%91" },
{ "Ò",		"%C3%92" },
{ "Ó",		"%C3%93" },
{ "Ô",		"%C3%94" },
{ "Õ",		"%C3%95" },
{ "Ö",		"%C3%96" },
{ "×",		"%C3%97" },
{ "Ø",		"%C3%98" },
{ "Ù",		"%C3%99" },
{ "Ú",		"%C3%9A" },
{ "Û",		"%C3%9B" },
{ "Ü",		"%C3%9C" },
{ "Ý",		"%C3%9D" },
{ "Þ",		"%C3%9E" },
{ "ß",		"%C3%9F" },
{ "à",		"%C3%A0" },
{ "á",		"%C3%A1" },
{ "â",		"%C3%A2" },
{ "ã",		"%C3%A3" },
{ "ä",		"%C3%A4" },
{ "å",		"%C3%A5" },
{ "æ",		"%C3%A6" },
{ "ç",		"%C3%A7" },
{ "è",		"%C3%A8" },
{ "é",		"%C3%A9" },
{ "ê",		"%C3%AA" },
{ "ë",		"%C3%AB" },
{ "ì",		"%C3%AC" },
{ "í",		"%C3%AD" },
{ "î",		"%C3%AE" },
{ "ï",		"%C3%AF" },
{ "ð",		"%C3%B0" },
{ "ñ",		"%C3%B1" },
{ "ò",		"%C3%B2" },
{ "ó",		"%C3%B3" },
{ "ô",		"%C3%B4" },
{ "õ",		"%C3%B5" },
{ "ö",		"%C3%B6" },
{ "÷",		"%C3%B7" },
{ "ø",		"%C3%B8" },
{ "ù",		"%C3%B9" },
{ "ú",		"%C3%BA" },
{ "û",		"%C3%BB" },
{ "ü",		"%C3%BC" },
{ "ý",		"%C3%BD" },
{ "þ",		"%C3%BE" },
{ "ÿ",		"%C3%BF" },
};

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
}

const char *extension_to_filetype(sv exten)
{
    if (sv_eq(exten, SV_Lit(".html")))
        return "text/html";
    else if (sv_eq(exten, SV_Lit(".ico")))
        return "image/x-icon";
    else if (sv_eq(exten, SV_Lit(".pdf")))
        return "application/pdf";
    else
        return "text/plain";
}

const char *resolve_escape_code(sv code, size_t *codelen) {
    for (size_t i = 0; i < (sizeof(codes)/sizeof(codes[0])); i++) {
        size_t i_codelen = strlen(codes[i].code);

        if (sv_cstr_eq(sv_substr(0, i_codelen, code), codes[i].code)) {
            *codelen = i_codelen;
            return codes[i].res;
        }
    }

    // We should never default on a code
    assert(false);

    return NULL;
}

void escape_url(sv url, char *buf)
{
    size_t off = 0;

    for (size_t i = 0; i < url.len; i++) {
        if (url.ptr[i] == '%') {
            size_t codelen;
            off += sprintf(buf + off, "%s", resolve_escape_code(sv_substr(i, SV_END_POS, url), &codelen));

            i += codelen - 1;
            continue;
        }

        buf[off++] = url.ptr[i];
    }

    buf[off++] = '\0';
}

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

    off += sprintf(json_buf + off, "\n]\n");
    puts(json_buf);

    msg_len = sprintf(msg_buf, "HTTP/1.1 200 OK\r\n"
                               "Server: MyTCP\r\n"
                               "Content-Length: %zu\r\n"
                               "Connection: Closed\r\n"
                               "Content-Type: application/json\r\n"
                               "\r\n", off);

    send(connfd, msg_buf, msg_len, MSG_MORE);
    send(connfd, json_buf, off, 0);
}

void send_ok(int connfd)
{
    const char *msg = "HTTP/1.1 200 OK\r\n"
                      "Server: MyTCP\r\n"
                      "Connection: Closed\r\n";

    send(connfd, msg, strlen(msg), 0);
}

void send_see_other(int connfd)
{
    const char *msg = "HTTP/1.1 303 See Other\r\n"
                      "Server: MyTCP\r\n"
                      "Location: /\r\n"
                      "Connection: Closed\r\n";

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
                           "Connection: Closed\r\n"
                           "Content-Type: %s\r\n"
                           "\r\n", file_len, extension_to_filetype(exten));
    printf("Responding:\n%.*s", msg_len, buf);

    send(connfd, buf, msg_len, MSG_MORE);
    sendfile(connfd, fd, NULL, statbuf.st_size);

    close(fd);

    return;

not_found:
    msg_len = sprintf(buf, "HTTP/1.1 404 Not Found\r\n"
                           "Server: MyTCP\r\n"
                           "Connection: Closed\r\n");
    printf("Responding:\n%.*s", msg_len, buf);
    send(connfd, buf, msg_len, 0);

    return;
}

sv get_field_value(sv txt, sv field)
{
    sv ret = { 0 };
    size_t pos = sv_idx_long(field, txt);
    if (pos == SV_END_POS)
        return ret;

    sv_chopl(pos, &txt);
    sv_chop_delim(' ', &txt, &ret);
    sv_chop_delim('\n', &txt, &ret);

    return ret;
}

size_t remove_carriage_return(char *str)
{
    size_t len = 0;
    char *dst;
    for (dst = str; *str; str++, len++) {
        *dst = *str;
        if (*dst != '\r') dst++; // Overwrite the '\r' next time
    }
    *dst = '\0';

    return len;
}

sv receive_into_dynamic_buffer(int connfd)
{
    char buf[BUF_SZ];
    char *ret = NULL;

    size_t received = recv(connfd, buf, sizeof(buf), 0);
    // printf("Buffer is %zu bytes; msg is %zu bytes\n", sizeof(readbuf), received);

    // If the the full message was not read, read the whole thing into dynamic
    // memory
    size_t full_msg_size = received;
    if (received == sizeof(buf)) {
        ret = malloc(full_msg_size);
        memcpy(ret, buf, received);

        for (char *i = ret + received; received == sizeof(buf); i += received) {
            received = recv(connfd, buf, sizeof(buf), 0);

            full_msg_size += received;
            ret = realloc(ret, full_msg_size);

            i = ret + full_msg_size - received; // Important reassignment: realloc possibly moves ret

            memcpy(i, buf, received);
        }
    } else {
        ret = malloc(received * sizeof(char));
        strncpy(ret, buf, received);
    }

    // If there is 'Content-Length', wait until all of it was read
    sv text_sv = sv_from_data(ret, full_msg_size);
    sv l = get_field_value(text_sv, SV_Lit("Content-Length:"));
    SV_Dbg(l);

    if (l.len) {
        size_t start_of_message = sv_idx_long(SV_Lit("\n\r\n"), text_sv) + 3;
        size_t message_received = full_msg_size - start_of_message;

        long to_read = strtol(l.ptr, NULL, 10);

        if (message_received < to_read) {
            size_t bytes_read = 0;
            for (char *i = ret + full_msg_size; message_received < to_read; i += bytes_read, message_received += bytes_read) {
                bytes_read = recv(connfd, buf, sizeof(buf), 0);
                full_msg_size += bytes_read;

                ret = realloc(ret, full_msg_size);
                i = ret + full_msg_size - bytes_read;

                memcpy(i, buf, bytes_read);
            }
        }
    }

    remove_carriage_return(ret);

    return sv_from_data(ret, full_msg_size);
}

int main(int argc, char **argv)
{
    int sockfd, connfd;
    socklen_t len, addrlen;
    struct sockaddr_in servaddr, cli;
    bool running = true;
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

    while (running) {
        bool sending_file;
        sv read_view, buf, base_read;

        if ((connfd = accept(sockfd, (struct sockaddr *)&cli, &len)) == -1) {
            perror("accept");
            return 1;
        }

        puts("Accepted.");

        base_read = receive_into_dynamic_buffer(connfd);
        read_view = base_read;
        printf("Client said: "SV_Fmt"\n", SV_Arg(read_view));

        sv_chop_delim(' ', &read_view, &buf);

        if (sv_eq(buf, SV_Lit("GET"))) {
            sv_chop_delim(' ', &read_view, &buf);
            printf("Client requested route: "SV_Fmt".\n", SV_Arg(buf));

            sending_file = true;

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
            }
            if (sending_file) {
                printf("Attempting to send file: "SV_Fmt".\n", SV_Arg(buf));
                resolve_file(connfd, buf);
            }
        } else if (sv_eq(buf, SV_Lit("POST"))) {
            puts("Client wants to POST");

            sv_chop_delim(' ', &read_view, &buf);
            printf("Client requested post: "SV_Fmt".\n", SV_Arg(buf));

            if (sv_eq(buf, SV_Lit("/upload"))) {
                puts("Client wants to upload");

                bool boundary_found = false;
                sv line_buf;
                sv boundary;
                while (sv_chop_delim('\n', &read_view, &buf)) {
                    if (!boundary_found && sv_starts_with(SV_Lit("Content-Type:"), buf)) {
                        sv_chop_delim(' ', &buf, &line_buf); // Content-Type:
                        sv_chop_delim(' ', &buf, &line_buf); // multipart/form-data
                        printf("Content-Type: "SV_Fmt"\n", SV_Arg(line_buf));

                        sv_chop_delim(' ', &buf, &boundary); // boundary=…
                        sv_chop_delim('=', &boundary, &line_buf); // boundary=…

                        printf("Boundary: '");
                        printf(SV_Fmt, SV_Arg(boundary));
                        printf("'\n");

                        boundary_found = true;
                    }

                    // Only expect one boundary pair
                    // Handle fields like a barbarian, but who cares
                    if (boundary_found && SV_Contains(boundary, buf)) {
                        puts("Found first boundary");
                        sv_chop_delim('\n', &read_view, &buf);

                        // Get filename
                        size_t idx = sv_idx_long(SV_Lit("filename="), buf);
                        sv fn = sv_substr(idx, SV_END_POS, buf);

                        fn = sv_substr(sv_idx('"', fn) + 1, SV_END_POS, fn);
                        fn.len = sv_last_idx('"', fn);

                        if (fn.len == 0) {
                            puts("WARNING: Empty filename. Continuing.");
                            break;
                        }

                        char *fn_cstr = strndup(fn.ptr, fn.len);
                        char *boundary_cstr = strndup(boundary.ptr, boundary.len + 1);

                        printf("Filename: "SV_Fmt"\n", SV_Arg(fn));

                        sv_chop_delim('\n', &read_view, &buf);

                        size_t close = sv_idx_long(boundary, read_view);
                        if (close == SV_END_POS) {
                            puts("WARNING: No terminating boundary found");
                        }

                        sv file_content = sv_substr(0, close, read_view);
                        file_content.len = sv_last_idx('\n', file_content) - 1; // Remove two lines not belonging to file // Remove two lines not belonging to file

                        if (chdir("Upload") == -1)
                            perror("chdir");
                        FILE *w = fopen(fn_cstr, "w");
                        fwrite(file_content.ptr, sizeof(char), file_content.len, w);
                        fclose(w);
                        if (chdir("..") == -1)
                            perror("chdir");

                        free(fn_cstr);
                        free(boundary_cstr);

                        break;
                    }
                }
                send_see_other(connfd);
            } else {
                printf("WARNING: Unknown POST request: '"SV_Fmt"'\n", SV_Arg(buf));
            }

            /** close(connfd);

            if ((connfd = accept(sockfd, (struct sockaddr *)&cli, &len)) == -1) {
                perror("accept");
                return 1;
            }

            puts("Accepted.");

            memset(readbuf, '\0', sizeof(readbuf));
            received = recv(connfd, readbuf, sizeof(readbuf), 0);

            printf("Client said: \n%s", readbuf);*/
        } else {
            printf("WARNING: Could not handle request: '"SV_Fmt"'\n", SV_Arg(read_view));
        }

        free((void *)base_read.ptr);

        close(connfd);
    }

    close(sockfd);
}

#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sv.h"

#include "request.h"

sv get_field_value(sv txt, sv field);

sv get_field_value(sv txt, sv field)
{
    sv ret = { 0 };
    size_t pos = sv_idx_long(field, txt);
    if (pos == SV_END_POS)
        return ret;

    sv_chopl(pos, &txt);
    sv_chop_delim(' ', &txt, &ret);
    sv_chop_delim('\r', &txt, &ret);

    return ret;
}

#define BUF_SZ 2048
struct request receive_into_dynamic_buffer(int connfd)
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
            size_t old_size = full_msg_size;

            received = recv(connfd, buf, sizeof(buf), 0);

            full_msg_size += received;
            ret = realloc(ret, full_msg_size);

            i = ret + old_size; // Important reassignment: realloc possibly moves ret

            memcpy(i, buf, received);
        }
    } else {
        ret = malloc(received * sizeof(char));
        strncpy(ret, buf, received);
    }

    sv text_sv = sv_from_data(ret, full_msg_size);

    // Read header values after first batch
    sv header = text_sv;
    header = sv_substr(0, sv_idx_long(SV_Lit("\n\r\n"), header), header);

    // If there is 'Content-Length', wait until all of it was read
    sv l = get_field_value(header, SV_Lit("Content-Length"));

    size_t start_of_message = 0;
    long to_read = 0;
    if (l.len) {
        start_of_message = sv_idx_long(SV_Lit("\n\r\n"), text_sv) + 3;
        long message_received = full_msg_size - start_of_message;

        to_read = strtol(l.ptr, NULL, 10);

        if (message_received < to_read) {
            size_t bytes_read = 0;
            for (char *i = ret + full_msg_size; message_received < to_read; i += bytes_read, message_received += bytes_read) {
                size_t old_size = full_msg_size;

                bytes_read = recv(connfd, buf, sizeof(buf), 0);
                full_msg_size += bytes_read;

                ret = realloc(ret, full_msg_size);
                i = ret + old_size;

                memcpy(i, buf, bytes_read);
            }
        }
    }

    // remove_carriage_return(ret, header.len);

    struct request return_struct;
    // NOTE: Overshoot with len after carriage return
    // Fix this or depend on responsible caller? (We own
    // the memory anyway)
    return_struct.text = sv_from_data(ret, full_msg_size);
    return_struct.header = sv_substr(0, sv_idx_long(SV_Lit("\n\r\n"), return_struct.text), return_struct.text);
    return_struct.data = sv_from_data(ret + start_of_message, to_read);

    return return_struct;
}


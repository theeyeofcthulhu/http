#pragma once

extern char *handler_not_found_redirect;

void send_ok(int connfd);
void send_see_other(int connfd);

void resolve_file(int connfd, sv fn);
void send_json_dir(int connfd, const char *dirname);

void register_handler(sv req, void (*handler)(struct request, int connfd));

void handle_request(struct request rq, int connfd);

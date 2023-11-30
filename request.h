#pragma once

struct request {
    sv text;
    sv header;
    sv data;
};

sv get_field_value(sv txt, sv field);
struct request receive_into_dynamic_buffer(int connfd);

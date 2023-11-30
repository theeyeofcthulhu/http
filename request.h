#pragma once

struct request {
    sv text;
    sv header;
};

struct request receive_into_dynamic_buffer(int connfd);

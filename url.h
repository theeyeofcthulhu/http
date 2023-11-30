#pragma once

struct url_escape_code {
    const char *res;
    const char *code;
};

void escape_url(sv url, char *buf);
const char *extension_to_filetype(sv exten);

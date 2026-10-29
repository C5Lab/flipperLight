#include "scan_csv.h"

#include <stdlib.h>
#include <string.h>

bool csv_next_quoted_field(const char** p, char* out, size_t out_size) {
    if(!p || !*p || !out || out_size == 0) return false;

    out[0] = '\0';
    const char* s = *p;
    while(*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    if(*s != '"') return false;
    s++; // opening quote

    size_t i = 0;
    while(*s) {
        if(*s == '"') {
            if(s[1] == '"') {
                // RFC 4180: a doubled quote is one literal quote.
                if(i + 1 < out_size) out[i++] = '"';
                s += 2;
                continue;
            }
            break; // closing quote
        }
        if(i + 1 < out_size) out[i++] = *s;
        s++;
    }

    out[i] = '\0';
    if(*s != '"') {
        out[0] = '\0';
        return false;
    }

    s++; // closing quote
    if(*s == ',') s++;
    *p = s;
    return true;
}

bool parse_network_csv(const char* line, ScanCsvNetwork* net) {
    if(!line || !net) return false;

    memset(net, 0, sizeof(*net));

    char index_str[8] = {0};
    char channel_str[8] = {0};
    char rssi_str[8] = {0};
    const char* p = line;

    if(!csv_next_quoted_field(&p, index_str, sizeof(index_str))) return false;
    if(!csv_next_quoted_field(&p, net->ssid, sizeof(net->ssid))) return false;
    if(!csv_next_quoted_field(&p, net->vendor, sizeof(net->vendor))) return false;
    if(!csv_next_quoted_field(&p, net->bssid, sizeof(net->bssid))) return false;
    if(!csv_next_quoted_field(&p, channel_str, sizeof(channel_str))) return false;
    if(!csv_next_quoted_field(&p, net->auth, sizeof(net->auth))) return false;
    if(!csv_next_quoted_field(&p, rssi_str, sizeof(rssi_str))) return false;
    if(!csv_next_quoted_field(&p, net->band, sizeof(net->band))) return false;

    if(channel_str[0] != '\0') net->channel = atoi(channel_str);
    if(rssi_str[0] != '\0') net->rssi = atoi(rssi_str);
    return true;
}

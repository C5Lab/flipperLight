#pragma once

#include <stddef.h>
#include <stdbool.h>

/* Field sizes include the terminating NUL.
 * SSID is the 802.11 maximum (32 octets). Vendor uses the same bound.
 * BSSID is "AA:BB:CC:DD:EE:FF". Band holds values such as "2.4GHz". */
#define SCAN_CSV_SSID_MAX 33
#define SCAN_CSV_VENDOR_MAX 33
#define SCAN_CSV_BSSID_MAX 18
#define SCAN_CSV_AUTH_MAX 32
#define SCAN_CSV_BAND_MAX 8

/* One scan_networks / show_scan_results row after RFC 4180 unescaping.
 * A quote inside a field is stored as one ", not as the CSV "". */
typedef struct {
    char ssid[SCAN_CSV_SSID_MAX];
    char vendor[SCAN_CSV_VENDOR_MAX];
    char bssid[SCAN_CSV_BSSID_MAX];
    char auth[SCAN_CSV_AUTH_MAX];
    char band[SCAN_CSV_BAND_MAX];
    int channel;
    int rssi;
} ScanCsvNetwork;

/* Read the next quoted CSV field. "" inside the field becomes one ".
 * Stops at the closing quote even when out is too small: extra source
 * bytes are discarded, never written past out[out_size - 1].
 * On success, *p is advanced past the closing quote and a following comma.
 * On failure, *p is left unchanged and out is an empty string. */
bool csv_next_quoted_field(const char** p, char* out, size_t out_size);

/* Parse "index","SSID","vendor","BSSID","channel","auth","RSSI","band". */
bool parse_network_csv(const char* line, ScanCsvNetwork* net);

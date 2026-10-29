#include "scan_csv.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void expect_example(void) {
    const char* line =
        "\"1\",\"moja \"\"specjalna\"\" siec\",\"Acme \"\"X\"\" Inc\","
        "\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-50\",\"2.4GHz\"";
    ScanCsvNetwork net;
    assert(parse_network_csv(line, &net));
    assert(strcmp(net.ssid, "moja \"specjalna\" siec") == 0);
    assert(strcmp(net.vendor, "Acme \"X\" Inc") == 0);
    assert(strcmp(net.bssid, "AA:BB:CC:DD:EE:FF") == 0);
    assert(strcmp(net.auth, "WPA2") == 0);
    assert(strcmp(net.band, "2.4GHz") == 0);
    assert(net.channel == 6);
    assert(net.rssi == -50);

    /* Strings the network-info screen draws for this row. */
    char shown[48];
    snprintf(shown, sizeof(shown), "%s", net.ssid);
    assert(strcmp(shown, "moja \"specjalna\" siec") == 0);
    snprintf(shown, sizeof(shown), "Vendor: %s", net.vendor);
    assert(strcmp(shown, "Vendor: Acme \"X\" Inc") == 0);
}

static void expect_plain_unchanged(void) {
    const char* line =
        "\"2\",\"HomeNetwork\",\"Cisco\",\"11:22:33:44:55:66\","
        "\"11\",\"WPA3\",\"-70\",\"5GHz\"";
    ScanCsvNetwork net;
    assert(parse_network_csv(line, &net));
    assert(strcmp(net.ssid, "HomeNetwork") == 0);
    assert(strcmp(net.vendor, "Cisco") == 0);
    assert(strcmp(net.bssid, "11:22:33:44:55:66") == 0);
    assert(strcmp(net.auth, "WPA3") == 0);
    assert(strcmp(net.band, "5GHz") == 0);
    assert(net.channel == 11);
    assert(net.rssi == -70);
}

static void expect_commas_and_quotes(void) {
    const char* line =
        "\"3\",\"cafe, \"\"main\"\"\",\"Vendor, \"\"Y\"\"\","
        "\"10:00:00:00:00:01\",\"36\",\"OPEN\",\"-61\",\"5GHz\"";
    ScanCsvNetwork net;
    assert(parse_network_csv(line, &net));
    assert(strcmp(net.ssid, "cafe, \"main\"") == 0);
    assert(strcmp(net.vendor, "Vendor, \"Y\"") == 0);
    assert(net.channel == 36);
    assert(net.rssi == -61);
    assert(strcmp(net.bssid, "10:00:00:00:00:01") == 0);
}

static void expect_truncation_keeps_following_fields(void) {
    const char* line =
        "\"9\",\"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXYYYY\",\"Acme\","
        "\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-50\",\"2.4GHz\"";
    ScanCsvNetwork net;
    assert(parse_network_csv(line, &net));
    assert(strlen(net.ssid) == 32);
    assert(strncmp(net.ssid, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 32) == 0);
    assert(strcmp(net.vendor, "Acme") == 0);
    assert(strcmp(net.bssid, "AA:BB:CC:DD:EE:FF") == 0);
    assert(net.channel == 6);
    assert(net.rssi == -50);

    const char* quoted =
        "\"9\",\"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\"\"Y\",\"Acme\","
        "\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-50\",\"2.4GHz\"";
    assert(parse_network_csv(quoted, &net));
    assert(strlen(net.ssid) == 32);
    assert(strcmp(net.vendor, "Acme") == 0);
    assert(strcmp(net.auth, "WPA2") == 0);
    assert(strcmp(net.band, "2.4GHz") == 0);

    const char* fit = "\"9\",\"XX\"\"YY\",\"Acme\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-50\",\"2.4GHz\"";
    assert(parse_network_csv(fit, &net));
    assert(strcmp(net.ssid, "XX\"YY") == 0);
}

static void expect_field_bounds(void) {
    struct {
        unsigned char before[4];
        char out[4];
        unsigned char after[4];
    } box;
    memset(&box, 0xA5, sizeof(box));

    const char* p = "\"abcdef\",\"z\"";
    const char* start = p;
    assert(csv_next_quoted_field(&p, box.out, sizeof(box.out)));
    assert(strcmp(box.out, "abc") == 0);
    assert(p > start);
    char next[4];
    assert(csv_next_quoted_field(&p, next, sizeof(next)));
    assert(strcmp(next, "z") == 0);
    for(int i = 0; i < 4; i++) {
        assert(box.before[i] == 0xA5);
        assert(box.after[i] == 0xA5);
    }

    char tiny[1];
    p = "\"ab\"";
    assert(csv_next_quoted_field(&p, tiny, sizeof(tiny)));
    assert(tiny[0] == '\0');

    char buf[8];
    p = "\"abc";
    const char* stuck = p;
    assert(!csv_next_quoted_field(&p, buf, sizeof(buf)));
    assert(p == stuck);
    assert(buf[0] == '\0');

    p = "\"\"\"\"";
    assert(csv_next_quoted_field(&p, buf, sizeof(buf)));
    assert(strcmp(buf, "\"") == 0);

    p = "\"a,b\",\"c,d\"";
    assert(csv_next_quoted_field(&p, buf, sizeof(buf)));
    assert(strcmp(buf, "a,b") == 0);
    assert(csv_next_quoted_field(&p, buf, sizeof(buf)));
    assert(strcmp(buf, "c,d") == 0);

    /* show_pass evil / portal rows share this reader. Plain rows stay intact. */
    char wide[40];
    p = "\"Home\",\"secret\"";
    assert(csv_next_quoted_field(&p, wide, sizeof(wide)));
    assert(strcmp(wide, "Home") == 0);
    assert(csv_next_quoted_field(&p, wide, sizeof(wide)));
    assert(strcmp(wide, "secret") == 0);

    p = "\"moja \"\"specjalna\"\" siec\",\"p\"\"w\"";
    assert(csv_next_quoted_field(&p, wide, sizeof(wide)));
    assert(strcmp(wide, "moja \"specjalna\" siec") == 0);
    assert(csv_next_quoted_field(&p, wide, sizeof(wide)));
    assert(strcmp(wide, "p\"w") == 0);

    p = " \"1\", \"Home\"";
    assert(csv_next_quoted_field(&p, wide, sizeof(wide)));
    assert(strcmp(wide, "1") == 0);
    assert(csv_next_quoted_field(&p, wide, sizeof(wide)));
    assert(strcmp(wide, "Home") == 0);

    assert(!csv_next_quoted_field(NULL, buf, sizeof(buf)));
    const char* none = NULL;
    assert(!csv_next_quoted_field(&none, buf, sizeof(buf)));
    p = "\"a\"";
    assert(!csv_next_quoted_field(&p, NULL, sizeof(buf)));
    assert(!csv_next_quoted_field(&p, buf, 0));
}

static void expect_rejects_broken_rows(void) {
    ScanCsvNetwork net;
    assert(!parse_network_csv(NULL, &net));
    assert(!parse_network_csv("\"1\"", NULL));
    assert(!parse_network_csv("not csv", &net));
    assert(!parse_network_csv(
        "\"1\",\"only\",\"seven\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-50\"",
        &net));
    assert(!parse_network_csv(
        "\"1\",\"unterminated,\"Acme\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-50\",\"2.4GHz\"",
        &net));
    assert(!parse_network_csv("\"1\",\"moja \"\"specjalna\"\" siec", &net));

    assert(parse_network_csv(
        "\"4\",\"\",\"\",\"AA:BB:CC:DD:EE:FF\",\"1\",\"OPEN\",\"0\",\"6GHz\"",
        &net));
    assert(net.ssid[0] == '\0');
    assert(net.vendor[0] == '\0');
    assert(net.channel == 1);
    assert(net.rssi == 0);
    assert(strcmp(net.band, "6GHz") == 0);
}

int main(void) {
    expect_example();
    expect_plain_unchanged();
    expect_commas_and_quotes();
    expect_truncation_keeps_following_fields();
    expect_field_bounds();
    expect_rejects_broken_rows();
    puts("scan csv PASS");
    return 0;
}

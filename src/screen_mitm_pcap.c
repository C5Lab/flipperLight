/**
 * MITM PCAP Sniffer Screen
 *
 * Connects to a WiFi network and starts PCAP network capture.
 * Flow:
 *   1. select_networks <index>
 *   2. show_pass evil  -> check if password is known
 *   3. (optional) TextInput for password
 *   4. wifi_connect <SSID> <password>
 *   5. start_pcap net  -> parse filename from response
 *   6. Status screen showing capture active + filename
 *   7. Back -> stop
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <gui/modules/text_input.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "MitmPcap"

#define MITM_PASSWORD_MAX    64
#define MITM_TEXT_INPUT_ID   998

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;
    // 0 = checking password
    // 1 = waiting for password input (TextInput)
    // 2 = connecting to WiFi
    // 3 = starting PCAP capture
    // 4 = capture active (status screen)

    char ssid[33];
    char password[MITM_PASSWORD_MAX + 1];
    uint32_t net_index; // 1-based

    uint8_t hosts_spoofed;
    char pcap_filename[48];
    char status_text[64];
    bool connect_failed;

    FuriThread* thread;
    TextInput* text_input;
    bool text_input_added;
    bool password_entered;
    View* main_view;
} MitmPcapData;

typedef struct {
    MitmPcapData* data;
} MitmPcapModel;

// ============================================================================
// Cleanup
// ============================================================================

static void mitm_pcap_cleanup_impl(View* view, void* data) {
    UNUSED(view);
    MitmPcapData* d = (MitmPcapData*)data;
    if(!d) return;

    FURI_LOG_I(TAG, "Cleanup starting");

    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }

    if(d->text_input) {
        if(d->text_input_added) {
            view_dispatcher_remove_view(d->app->view_dispatcher, MITM_TEXT_INPUT_ID);
        }
        text_input_free(d->text_input);
    }

    free(d);
    FURI_LOG_I(TAG, "Cleanup complete");
}

void mitm_pcap_cleanup_internal(View* view, void* data) {
    mitm_pcap_cleanup_impl(view, data);
}

// ============================================================================
// TextInput callback
// ============================================================================

static void mitm_password_callback(void* context) {
    MitmPcapData* data = (MitmPcapData*)context;
    if(!data || !data->app) return;

    FURI_LOG_I(TAG, "Password entered: %s", data->password);
    data->password_entered = true;
    data->state = 2;

    uint32_t main_view_id = screen_get_current_view_id();
    view_dispatcher_switch_to_view(data->app->view_dispatcher, main_view_id);
}

static void mitm_show_text_input(MitmPcapData* data) {
    if(!data || !data->text_input) return;

    if(!data->text_input_added) {
        View* ti_view = text_input_get_view(data->text_input);
        view_dispatcher_add_view(data->app->view_dispatcher, MITM_TEXT_INPUT_ID, ti_view);
        data->text_input_added = true;
    }

    view_dispatcher_switch_to_view(data->app->view_dispatcher, MITM_TEXT_INPUT_ID);
}

// ============================================================================
// Drawing
// ============================================================================

static void mitm_pcap_draw(Canvas* canvas, void* model) {
    MitmPcapModel* m = (MitmPcapModel*)model;
    if(!m || !m->data) return;
    MitmPcapData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    if(data->state == 0) {
        screen_draw_title(canvas, "MITM PCAP Sniffer");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Checking password...", 32);

    } else if(data->state == 1) {
        screen_draw_title(canvas, "MITM PCAP Sniffer");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Enter password", 32);

    } else if(data->state == 2) {
        screen_draw_title(canvas, "MITM PCAP Sniffer");
        canvas_set_font(canvas, FontSecondary);
        char line[48];
        char ssid_trunc[20];
        strncpy(ssid_trunc, data->ssid, sizeof(ssid_trunc) - 1);
        ssid_trunc[sizeof(ssid_trunc) - 1] = '\0';
        snprintf(line, sizeof(line), "Connecting to %s...", ssid_trunc);
        screen_draw_centered_text(canvas, line, 32);
        if(data->connect_failed) {
            screen_draw_centered_text(canvas, "Connection FAILED", 46);
            screen_draw_centered_text(canvas, "Press Back", 58);
        }

    } else if(data->state == 3) {
        screen_draw_title(canvas, "MITM PCAP Sniffer");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Starting capture...", 28);
        if(data->status_text[0]) {
            screen_draw_centered_text(canvas, data->status_text, 42);
        }

    } else if(data->state == 4) {
        screen_draw_title(canvas, "MITM PCAP Sniffer");
        canvas_set_font(canvas, FontSecondary);

        char line[56];
        snprintf(line, sizeof(line), "Spoofing %u hosts", data->hosts_spoofed);
        canvas_draw_str(canvas, 2, 24, line);

        if(data->pcap_filename[0]) {
            snprintf(line, sizeof(line), "File: %.48s", data->pcap_filename);
            canvas_draw_str(canvas, 2, 38, line);
        }

        canvas_draw_str(canvas, 2, 56, "Press Back to stop");
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool mitm_pcap_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    MitmPcapModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    MitmPcapData* data = m->data;

    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }

    if(data->state == 1 && event->key == InputKeyOk) {
        mitm_show_text_input(data);
        view_commit_model(view, false);
        return true;
    }

    if(event->key == InputKeyBack) {
        data->attack_finished = true;
        uart_send_command(data->app, "stop");
        view_commit_model(view, false);
        screen_pop_to_main(data->app);
        return true;
    }

    view_commit_model(view, false);
    return true;
}

// ============================================================================
// Password discovery helper (same logic as ARP Poisoning)
// ============================================================================

static bool mitm_check_password(MitmPcapData* data) {
    WiFiApp* app = data->app;

    uart_clear_buffer(app);
    uart_send_command(app, "show_pass evil");
    furi_delay_ms(200);

    uint32_t start = furi_get_tick();
    uint32_t last_rx = start;

    while((furi_get_tick() - last_rx) < 1000 &&
          (furi_get_tick() - start) < 5000 &&
          !data->attack_finished) {
        const char* line = uart_read_line(app, 300);
        if(line) {
            last_rx = furi_get_tick();
            FURI_LOG_I(TAG, "show_pass: %s", line);

            const char* p = line;
            while(*p == ' ' || *p == '\t') p++;
            if(*p != '"') continue;
            p++;
            const char* ssid_start = p;
            while(*p && *p != '"') p++;
            if(*p != '"') continue;
            size_t ssid_len = p - ssid_start;
            p++;

            while(*p == ',' || *p == ' ' || *p == '\t') p++;

            if(*p != '"') continue;
            p++;
            const char* pass_start = p;
            while(*p && *p != '"') p++;
            if(*p != '"') continue;
            size_t pass_len = p - pass_start;

            if(ssid_len == strlen(data->ssid) &&
               strncmp(ssid_start, data->ssid, ssid_len) == 0) {
                if(pass_len < sizeof(data->password)) {
                    strncpy(data->password, pass_start, pass_len);
                    data->password[pass_len] = '\0';
                    FURI_LOG_I(TAG, "Password found: %s", data->password);
                    return true;
                }
            }
        }
    }
    return false;
}

// ============================================================================
// Attack Thread
// ============================================================================

static int32_t mitm_pcap_thread(void* context) {
    MitmPcapData* data = (MitmPcapData*)context;
    WiFiApp* app = data->app;

    FURI_LOG_I(TAG, "Thread started for SSID: %s (index %lu)", data->ssid, (unsigned long)data->net_index);

    // Step 1: select_networks
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "select_networks %lu", (unsigned long)data->net_index);
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);

    if(data->attack_finished) return 0;

    // Step 2: Check if password is known
    data->state = 0;
    bool found = mitm_check_password(data);

    if(data->attack_finished) return 0;

    if(!found) {
        data->state = 1;
        FURI_LOG_I(TAG, "Password unknown, requesting user input");
        mitm_show_text_input(data);

        while(!data->password_entered && !data->attack_finished) {
            furi_delay_ms(100);
        }
        if(data->attack_finished) return 0;
    } else {
        data->state = 2;
    }

    // Step 3: Connect to WiFi
    data->state = 2;
    snprintf(cmd, sizeof(cmd), "wifi_connect %s %s", data->ssid, data->password);
    FURI_LOG_I(TAG, "Sending: wifi_connect %s ***", data->ssid);
    uart_clear_buffer(app);
    uart_send_command(app, cmd);

    bool connected = false;
    uint32_t start = furi_get_tick();
    while((furi_get_tick() - start) < 15000 && !data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            FURI_LOG_I(TAG, "wifi_connect: %s", line);
            strncpy(data->status_text, line, sizeof(data->status_text) - 1);

            if(strstr(line, "SUCCESS")) {
                connected = true;
                app->wifi_connected = true;
                break;
            }
            if(strstr(line, "FAIL") || strstr(line, "Error") || strstr(line, "error")) {
                data->connect_failed = true;
                FURI_LOG_E(TAG, "Connection failed");
                break;
            }
        }
    }

    if(data->attack_finished) return 0;

    if(!connected) {
        data->connect_failed = true;
        FURI_LOG_E(TAG, "Connection timed out or failed");
        while(!data->attack_finished) {
            furi_delay_ms(100);
        }
        return 0;
    }

    // Step 4: Start PCAP capture
    data->state = 3;
    FURI_LOG_I(TAG, "Starting PCAP net capture");
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "start_pcap net");

    start = furi_get_tick();
    while((furi_get_tick() - start) < 15000 && !data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            FURI_LOG_I(TAG, "start_pcap: %s", line);
            strncpy(data->status_text, line, sizeof(data->status_text) - 1);

            const char* found_str = strstr(line, "Found");
            if(found_str && strstr(line, "hosts to spoof")) {
                data->hosts_spoofed = (uint8_t)atoi(found_str + 6);
                FURI_LOG_I(TAG, "Hosts to spoof: %u", data->hosts_spoofed);
            }

            const char* marker = strstr(line, "PCAP net capture started");
            if(marker) {
                const char* arrow = strstr(marker, "->");
                if(arrow) {
                    arrow += 2;
                    while(*arrow == ' ') arrow++;
                    const char* basename = arrow;
                    for(const char* s = arrow; *s; s++) {
                        if(*s == '/') basename = s + 1;
                    }
                    strncpy(data->pcap_filename, basename, sizeof(data->pcap_filename) - 1);
                    data->pcap_filename[sizeof(data->pcap_filename) - 1] = '\0';
                    size_t len = strlen(data->pcap_filename);
                    while(len > 0 && (data->pcap_filename[len - 1] == '\n' ||
                                      data->pcap_filename[len - 1] == '\r' ||
                                      data->pcap_filename[len - 1] == ' ')) {
                        data->pcap_filename[--len] = '\0';
                    }
                }
                break;
            }
        }
    }

    data->state = 4;
    FURI_LOG_I(TAG, "Capture active, spoofing %u hosts, file: %s",
        data->hosts_spoofed, data->pcap_filename);

    // Stay in capture mode, reading and logging UART output
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 100);
        if(line) {
            FURI_LOG_I(TAG, "pcap output: %s", line);
        }
    }

    FURI_LOG_I(TAG, "Thread finished");
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_mitm_pcap_create(WiFiApp* app, void** out_data) {
    FURI_LOG_I(TAG, "Creating MITM PCAP Sniffer screen");

    if(!app || app->selected_count != 1) {
        FURI_LOG_E(TAG, "Exactly 1 network must be selected");
        return NULL;
    }

    MitmPcapData* data = (MitmPcapData*)malloc(sizeof(MitmPcapData));
    if(!data) return NULL;

    memset(data, 0, sizeof(MitmPcapData));
    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    data->net_index = app->selected_networks[0]; // 1-based
    data->password_entered = false;
    data->text_input_added = false;
    data->connect_failed = false;

    uint32_t idx0 = data->net_index - 1;
    if(idx0 < app->scan_result_count && app->scan_results) {
        strncpy(data->ssid, app->scan_results[idx0].ssid, sizeof(data->ssid) - 1);
        data->ssid[sizeof(data->ssid) - 1] = '\0';
    } else {
        strncpy(data->ssid, "Unknown", sizeof(data->ssid) - 1);
    }

    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    data->main_view = view;

    view_allocate_model(view, ViewModelTypeLocking, sizeof(MitmPcapModel));
    MitmPcapModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, mitm_pcap_draw);
    view_set_input_callback(view, mitm_pcap_input);
    view_set_context(view, view);

    data->text_input = text_input_alloc();
    if(data->text_input) {
        text_input_set_header_text(data->text_input, "Enter Password:");
        text_input_set_result_callback(
            data->text_input,
            mitm_password_callback,
            data,
            data->password,
            MITM_PASSWORD_MAX,
            true);
        FURI_LOG_I(TAG, "TextInput created");
    }

    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "MitmPcap");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, mitm_pcap_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;

    FURI_LOG_I(TAG, "MITM PCAP Sniffer screen created");
    return view;
}

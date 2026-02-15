/**
 * WPA-SEC Upload Screen
 * 
 * Uploads captured handshakes to wpa-sec.stanev.org.
 * Flow:
 *   1. wpasec_key read -> check if API key is configured
 *   2. Check SD card presence (app->sd_card_ok)
 *   3. If not connected to WiFi: scan_networks -> user selects ->
 *      show_pass evil (try known password) -> (optional TextInput) -> wifi_connect
 *   4. wpasec_upload -> parse "Done: X uploaded, Y duplicate, Z failed"
 *
 * Memory lifecycle:
 * - screen_wpasec_create(): Allocates WpasecData, thread, view, TextInput
 * - wpasec_cleanup_internal(): Frees everything on screen pop
 */

#include "screen_compromised_data.h"
#include "uart_comm.h"
#include "screen.h"
#include <gui/modules/text_input.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "WpaSec"

// ============================================================================
// Data Structures
// ============================================================================

#define WPASEC_PASSWORD_MAX  64
#define WPASEC_TEXT_INPUT_ID 998
#define WPASEC_MAX_VISIBLE   5

typedef struct {
    WiFiApp* app;
    volatile bool should_exit;
    uint8_t state;
    // 0 = checking key
    // 1 = no key found
    // 2 = no SD card
    // 3 = scanning WiFi
    // 4 = network list (user selects)
    // 5 = checking Evil Twin password
    // 6 = password input (TextInput)
    // 7 = connecting to WiFi
    // 8 = uploading
    // 9 = done (show results)
    // 10 = upload failed

    // WiFi connect
    char ssid[33];
    char password[WPASEC_PASSWORD_MAX + 1];
    uint8_t selected_net;
    volatile bool network_selected;  // set by input handler when user picks a network
    volatile bool password_entered;  // set by TextInput callback
    bool connect_failed;
    char status_text[64];

    // Upload results
    int uploaded;
    int duplicate;
    int failed;

    // Flipper resources
    FuriThread* thread;
    TextInput* text_input;
    bool text_input_added;
    View* main_view;
} WpasecData;

typedef struct {
    WpasecData* data;
} WpasecModel;

// ============================================================================
// Cleanup
// ============================================================================

static void wpasec_cleanup_impl(View* view, void* data) {
    UNUSED(view);
    WpasecData* d = (WpasecData*)data;
    if(!d) return;

    FURI_LOG_I(TAG, "Cleanup starting");

    d->should_exit = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }

    if(d->text_input) {
        if(d->text_input_added) {
            view_dispatcher_remove_view(d->app->view_dispatcher, WPASEC_TEXT_INPUT_ID);
        }
        text_input_free(d->text_input);
    }

    free(d);
    FURI_LOG_I(TAG, "Cleanup complete");
}

void wpasec_cleanup_internal(View* view, void* data) {
    wpasec_cleanup_impl(view, data);
}

// ============================================================================
// TextInput callback
// ============================================================================

static void wpasec_password_callback(void* context) {
    WpasecData* data = (WpasecData*)context;
    if(!data || !data->app) return;

    FURI_LOG_I(TAG, "Password entered: %s", data->password);
    data->password_entered = true;
    data->state = 7; // Move to connecting

    uint32_t main_view_id = screen_get_current_view_id();
    view_dispatcher_switch_to_view(data->app->view_dispatcher, main_view_id);
}

static void wpasec_show_text_input(WpasecData* data) {
    if(!data || !data->text_input) return;

    if(!data->text_input_added) {
        View* ti_view = text_input_get_view(data->text_input);
        view_dispatcher_add_view(data->app->view_dispatcher, WPASEC_TEXT_INPUT_ID, ti_view);
        data->text_input_added = true;
    }

    view_dispatcher_switch_to_view(data->app->view_dispatcher, WPASEC_TEXT_INPUT_ID);
}

// ============================================================================
// Password discovery helper (Evil Twin passwords)
// ============================================================================

static bool wpasec_check_password(WpasecData* data) {
    WiFiApp* app = data->app;

    uart_clear_buffer(app);
    uart_send_command(app, "show_pass evil");
    furi_delay_ms(200);

    uint32_t start = furi_get_tick();
    uint32_t last_rx = start;

    while((furi_get_tick() - last_rx) < 1000 &&
          (furi_get_tick() - start) < 5000 &&
          !data->should_exit) {
        const char* line = uart_read_line(app, 300);
        if(line) {
            last_rx = furi_get_tick();
            FURI_LOG_I(TAG, "show_pass: %s", line);

            // Parse "SSID", "password"
            const char* p = line;
            while(*p == ' ' || *p == '\t') p++;
            if(*p != '"') continue;
            p++;
            const char* ssid_start = p;
            while(*p && *p != '"') p++;
            if(*p != '"') continue;
            size_t ssid_len = (size_t)(p - ssid_start);
            p++;

            while(*p == ',' || *p == ' ' || *p == '\t') p++;

            if(*p != '"') continue;
            p++;
            const char* pass_start = p;
            while(*p && *p != '"') p++;
            if(*p != '"') continue;
            size_t pass_len = (size_t)(p - pass_start);

            if(ssid_len == strlen(data->ssid) &&
               strncmp(ssid_start, data->ssid, ssid_len) == 0) {
                if(pass_len < sizeof(data->password)) {
                    strncpy(data->password, pass_start, pass_len);
                    data->password[pass_len] = '\0';
                    FURI_LOG_I(TAG, "Password found via Evil Twin: %s", data->password);
                    return true;
                }
            }
        }
    }
    return false;
}

// ============================================================================
// Drawing
// ============================================================================

static void wpasec_draw(Canvas* canvas, void* model) {
    WpasecModel* m = (WpasecModel*)model;
    if(!m || !m->data) return;
    WpasecData* data = m->data;
    WiFiApp* app = data->app;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    if(data->state == 0) {
        // Checking key
        screen_draw_title(canvas, "Send to wpa-sec");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Checking API key...", 32);

    } else if(data->state == 1) {
        // No key
        screen_draw_title(canvas, "Send to wpa-sec");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Add your key to", 24);
        screen_draw_centered_text(canvas, "/lab/wpa-sec.txt", 34);
        screen_draw_centered_text(canvas, "in C5Monster and reboot.", 44);
        canvas_draw_str(canvas, 2, 62, "< Back");

    } else if(data->state == 2) {
        // No SD card
        screen_draw_title(canvas, "Send to wpa-sec");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "SD card not found", 32);
        screen_draw_centered_text(canvas, "Insert SD card and restart.", 44);
        canvas_draw_str(canvas, 2, 62, "< Back");

    } else if(data->state == 3) {
        // Scanning WiFi
        screen_draw_title(canvas, "Connecting to WiFi");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Scanning networks...", 32);

    } else if(data->state == 4) {
        // Network list
        screen_draw_title(canvas, "Select Network");
        canvas_set_font(canvas, FontSecondary);

        uint32_t count = app->scan_result_count;
        if(count == 0) {
            screen_draw_centered_text(canvas, "No networks found", 32);
        } else {
            uint8_t start_idx = 0;
            if(data->selected_net >= WPASEC_MAX_VISIBLE) {
                start_idx = data->selected_net - WPASEC_MAX_VISIBLE + 1;
            }

            for(uint8_t i = 0; i < WPASEC_MAX_VISIBLE && (start_idx + i) < count; i++) {
                uint8_t y = 22 + (i * 10);
                uint8_t idx = start_idx + i;
                const char* name = app->scan_results[idx].ssid;
                if(!name[0]) name = "(hidden)";

                char line[30];
                snprintf(line, sizeof(line), "%.24s", name);

                if(idx == data->selected_net) {
                    canvas_draw_box(canvas, 0, y - 8, 128, 10);
                    canvas_set_color(canvas, ColorWhite);
                    canvas_draw_str(canvas, 2, y, line);
                    canvas_set_color(canvas, ColorBlack);
                } else {
                    canvas_draw_str(canvas, 2, y, line);
                }
            }
        }

    } else if(data->state == 5) {
        // Checking Evil Twin password
        screen_draw_title(canvas, "Send to wpa-sec");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Checking password...", 32);

    } else if(data->state == 6) {
        // Password input - TextInput is shown by the thread (not here!)
        // Drawing "Enter WiFi password" as a brief flash before TextInput appears
        screen_draw_title(canvas, "Send to wpa-sec");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Enter WiFi password", 32);

    } else if(data->state == 7) {
        // Connecting
        screen_draw_title(canvas, "Connecting to WiFi");
        canvas_set_font(canvas, FontSecondary);
        char line[48];
        char ssid_trunc[20];
        strncpy(ssid_trunc, data->ssid, sizeof(ssid_trunc) - 1);
        ssid_trunc[sizeof(ssid_trunc) - 1] = '\0';
        snprintf(line, sizeof(line), "Connecting to %s...", ssid_trunc);
        screen_draw_centered_text(canvas, line, 32);
        if(data->connect_failed) {
            screen_draw_centered_text(canvas, "Connection FAILED", 46);
            canvas_draw_str(canvas, 2, 62, "< Back");
        }

    } else if(data->state == 8) {
        // Uploading
        screen_draw_title(canvas, "Send to wpa-sec");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Uploading handshakes...", 32);
        if(data->status_text[0]) {
            screen_draw_centered_text(canvas, data->status_text, 46);
        }

    } else if(data->state == 9) {
        // Done
        screen_draw_title(canvas, "Send to wpa-sec");
        canvas_set_font(canvas, FontSecondary);

        char line[48];
        snprintf(line, sizeof(line), "Uploaded: %d", data->uploaded);
        screen_draw_centered_text(canvas, line, 24);
        snprintf(line, sizeof(line), "Duplicate: %d", data->duplicate);
        screen_draw_centered_text(canvas, line, 36);
        snprintf(line, sizeof(line), "Failed: %d", data->failed);
        screen_draw_centered_text(canvas, line, 48);

        canvas_draw_str(canvas, 2, 62, "< Back");

    } else if(data->state == 10) {
        // Upload failed
        screen_draw_title(canvas, "Send to wpa-sec");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Failed to send", 32);
        canvas_draw_str(canvas, 2, 62, "< Back");
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool wpasec_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    WpasecModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    WpasecData* data = m->data;

    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }

    if(event->key == InputKeyBack) {
        data->should_exit = true;
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }

    // Network selection (state 4)
    if(data->state == 4) {
        WiFiApp* app = data->app;
        uint32_t count = app->scan_result_count;

        if(event->key == InputKeyUp) {
            if(data->selected_net > 0) data->selected_net--;
        } else if(event->key == InputKeyDown) {
            if(count > 0 && data->selected_net < count - 1) data->selected_net++;
        } else if(event->key == InputKeyOk && count > 0) {
            // Copy selected SSID - thread will handle state transition
            strncpy(data->ssid, app->scan_results[data->selected_net].ssid, sizeof(data->ssid) - 1);
            data->ssid[sizeof(data->ssid) - 1] = '\0';
            FURI_LOG_I(TAG, "Selected network: %s", data->ssid);
            data->network_selected = true;
        }

        view_commit_model(view, true);
        return true;
    }

    view_commit_model(view, true);
    return true;
}

// ============================================================================
// WPA-SEC Thread
// ============================================================================

static int32_t wpasec_thread(void* context) {
    WpasecData* data = (WpasecData*)context;
    WiFiApp* app = data->app;

    FURI_LOG_I(TAG, "Thread started");

    // ---- Step 1: Check WPA-SEC key ----
    data->state = 0;
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "wpasec_key read");

    bool key_found = false;
    uint32_t deadline = furi_get_tick() + 5000;
    while(furi_get_tick() < deadline && !data->should_exit) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            FURI_LOG_I(TAG, "wpasec_key: %s", line);
            if(strstr(line, "WPA-SEC key:")) {
                if(strstr(line, "not set")) {
                    FURI_LOG_I(TAG, "Key not set");
                    data->state = 1;
                    return 0;
                } else {
                    key_found = true;
                    FURI_LOG_I(TAG, "Key found");
                    break;
                }
            }
        }
    }

    if(data->should_exit) return 0;

    if(!key_found) {
        FURI_LOG_W(TAG, "No key response, assuming not set");
        data->state = 1;
        return 0;
    }

    // ---- Step 2: Check SD card ----
    if(!app->sd_card_ok) {
        FURI_LOG_W(TAG, "SD card not available");
        data->state = 2;
        return 0;
    }

    // ---- Step 3: Check WiFi / connect ----
    if(!app->wifi_connected) {
        // Scan networks
        data->state = 3;
        FURI_LOG_I(TAG, "Starting WiFi scan");
        uart_start_scan(app);

        // Wait for scan to complete
        while(app->scanning_in_progress && !data->should_exit) {
            furi_delay_ms(200);
        }
        if(data->should_exit) return 0;

        FURI_LOG_I(TAG, "Scan done, found %lu networks", (unsigned long)app->scan_result_count);

        if(app->scan_result_count == 0) {
            data->state = 10;
            snprintf(data->status_text, sizeof(data->status_text), "No WiFi networks found");
            return 0;
        }

        // Show network list and wait for user to select
        data->state = 4;
        data->selected_net = 0;

        while(!data->network_selected && !data->should_exit) {
            furi_delay_ms(100);
        }
        if(data->should_exit) return 0;

        // Try to get password from Evil Twin data
        data->state = 5;
        FURI_LOG_I(TAG, "Checking Evil Twin passwords for %s", data->ssid);
        bool pw_found = wpasec_check_password(data);

        if(data->should_exit) return 0;

        if(!pw_found) {
            // No known password - show TextInput for manual entry
            data->state = 6;
            FURI_LOG_I(TAG, "Password unknown, requesting user input");

            // Show TextInput from the thread context (NOT from draw callback,
            // which would deadlock due to ViewModelTypeLocking mutex)
            wpasec_show_text_input(data);

            while(!data->password_entered && !data->should_exit) {
                furi_delay_ms(100);
            }
            if(data->should_exit) return 0;
        }

        // Connect to WiFi
        data->state = 7;
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "wifi_connect %s %s", data->ssid, data->password);
        FURI_LOG_I(TAG, "Sending: %s", cmd);
        uart_clear_buffer(app);
        uart_send_command(app, cmd);

        bool connected = false;
        uint32_t start = furi_get_tick();
        while((furi_get_tick() - start) < 15000 && !data->should_exit) {
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

        if(data->should_exit) return 0;

        if(!connected) {
            data->connect_failed = true;
            FURI_LOG_E(TAG, "Connection timed out or failed");
            // Stay in state 7 with connect_failed showing error
            while(!data->should_exit) {
                furi_delay_ms(100);
            }
            return 0;
        }
    }

    // ---- Step 4: Upload handshakes ----
    data->state = 8;
    data->status_text[0] = '\0';
    FURI_LOG_I(TAG, "Starting upload");
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "wpasec_upload");

    bool done = false;
    deadline = furi_get_tick() + 60000; // 60s timeout for upload
    while(furi_get_tick() < deadline && !data->should_exit) {
        const char* line = uart_read_line(app, 1000);
        if(line) {
            FURI_LOG_I(TAG, "wpasec_upload: %s", line);
            strncpy(data->status_text, line, sizeof(data->status_text) - 1);

            if(strstr(line, "Done:")) {
                int up = 0, dup = 0, fail = 0;
                if(sscanf(line, "Done: %d uploaded, %d duplicate, %d failed", &up, &dup, &fail) == 3) {
                    data->uploaded = up;
                    data->duplicate = dup;
                    data->failed = fail;
                    data->state = 9;
                    done = true;
                    FURI_LOG_I(TAG, "Upload done: %d up, %d dup, %d fail", up, dup, fail);
                    break;
                }
            }
        }
    }

    if(!done && !data->should_exit) {
        FURI_LOG_E(TAG, "Upload failed or timed out");
        data->state = 10;
    }

    FURI_LOG_I(TAG, "Thread exiting");
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_wpasec_create(WiFiApp* app, void** out_data) {
    FURI_LOG_I(TAG, "Creating WPA-SEC screen");

    WpasecData* data = (WpasecData*)malloc(sizeof(WpasecData));
    if(!data) return NULL;

    memset(data, 0, sizeof(WpasecData));
    data->app = app;
    data->should_exit = false;
    data->state = 0;
    data->selected_net = 0;
    data->network_selected = false;
    data->password_entered = false;
    data->text_input_added = false;
    data->connect_failed = false;

    // Create main view
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    data->main_view = view;

    view_allocate_model(view, ViewModelTypeLocking, sizeof(WpasecModel));
    WpasecModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, wpasec_draw);
    view_set_input_callback(view, wpasec_input);
    view_set_context(view, view);

    // Create TextInput for WiFi password entry
    data->text_input = text_input_alloc();
    if(data->text_input) {
        text_input_set_header_text(data->text_input, "WiFi Password:");
        text_input_set_result_callback(
            data->text_input,
            wpasec_password_callback,
            data,
            data->password,
            WPASEC_PASSWORD_MAX,
            true);
        FURI_LOG_I(TAG, "TextInput created");
    }

    // Start thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "WpaSec");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, wpasec_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;

    FURI_LOG_I(TAG, "WPA-SEC screen created");
    return view;
}

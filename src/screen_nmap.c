/**
 * Nmap Port Scanner Screen
 *
 * Connects to a WiFi network, discovers hosts, lets user pick target(s)
 * and scan level, then runs start_nmap and displays results.
 * Flow:
 *   1. select_networks <index>
 *   2. show_pass evil  -> check if password is known
 *   3. (optional) TextInput for password
 *   4. wifi_connect <SSID> <password>
 *   5. list_hosts -> discover hosts
 *   6. User selects host(s) (one or all)
 *   7. User picks scan level (quick/medium/heavy)
 *   8. start_nmap <level> [IP] -> parse progress + results
 *   9. Show results
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <gui/modules/text_input.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "Nmap"

#define NMAP_PASSWORD_MAX       64
#define NMAP_TEXT_INPUT_ID      996
#define NMAP_MAX_HOSTS          32
#define NMAP_MAX_PORTS_PER_HOST 20

typedef struct {
    char ip[16];
    char mac[18];
    bool selected;
} NmapHostEntry;

typedef struct {
    int port;
    char service[16];
} NmapPort;

typedef struct {
    char ip[16];
    char mac[18];
    NmapPort ports[NMAP_MAX_PORTS_PER_HOST];
    uint8_t port_count;
    bool no_open_ports;
} NmapResultHost;

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;
    // 0 = checking password
    // 1 = waiting for password input (TextInput)
    // 2 = connecting to WiFi
    // 3 = scanning hosts (list_hosts)
    // 4 = host list with selection
    // 5 = scan level picker
    // 6 = nmap scanning in progress
    // 7 = results display

    char ssid[33];
    char password[NMAP_PASSWORD_MAX + 1];
    uint32_t net_index; // 1-based

    // Host discovery
    NmapHostEntry hosts[NMAP_MAX_HOSTS];
    uint8_t host_count;
    uint8_t host_cursor;
    bool all_hosts_selected;
    volatile bool host_selection_confirmed;

    // Scan level
    uint8_t scan_level_cursor; // 0=quick,1=medium,2=heavy
    volatile bool scan_level_confirmed;

    // Results
    NmapResultHost results[NMAP_MAX_HOSTS];
    uint8_t result_count;
    uint16_t total_open_ports;

    // Progress
    char progress_ip[16];
    uint8_t progress_pct;
    uint8_t hosts_scanned;
    uint8_t hosts_total;

    char status_text[64];
    bool connect_failed;

    // UI scroll for results
    int16_t scroll_pos;

    FuriThread* thread;
    TextInput* text_input;
    bool text_input_added;
    bool password_entered;
    View* main_view;
} NmapData;

typedef struct {
    NmapData* data;
} NmapModel;

// ============================================================================
// Cleanup
// ============================================================================

static void nmap_cleanup_impl(View* view, void* data) {
    UNUSED(view);
    NmapData* d = (NmapData*)data;
    if(!d) return;

    FURI_LOG_I(TAG, "Cleanup starting");

    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }

    if(d->text_input) {
        if(d->text_input_added) {
            view_dispatcher_remove_view(d->app->view_dispatcher, NMAP_TEXT_INPUT_ID);
        }
        text_input_free(d->text_input);
    }

    free(d);
    FURI_LOG_I(TAG, "Cleanup complete");
}

void nmap_cleanup_internal(View* view, void* data) {
    nmap_cleanup_impl(view, data);
}

// ============================================================================
// TextInput callback
// ============================================================================

static void nmap_password_callback(void* context) {
    NmapData* data = (NmapData*)context;
    if(!data || !data->app) return;

    FURI_LOG_I(TAG, "Password entered: %s", data->password);
    data->password_entered = true;
    data->state = 2;

    uint32_t main_view_id = screen_get_current_view_id();
    view_dispatcher_switch_to_view(data->app->view_dispatcher, main_view_id);
}

static void nmap_show_text_input(NmapData* data) {
    if(!data || !data->text_input) return;

    if(!data->text_input_added) {
        View* ti_view = text_input_get_view(data->text_input);
        view_dispatcher_add_view(data->app->view_dispatcher, NMAP_TEXT_INPUT_ID, ti_view);
        data->text_input_added = true;
    }

    view_dispatcher_switch_to_view(data->app->view_dispatcher, NMAP_TEXT_INPUT_ID);
}

// ============================================================================
// Helper: count total result lines for scroll
// ============================================================================

static int16_t nmap_result_line_count(NmapData* data) {
    int16_t lines = 0;
    for(uint8_t i = 0; i < data->result_count; i++) {
        lines++; // host header line
        if(data->results[i].no_open_ports) {
            lines++; // "(no open ports)"
        } else {
            lines += data->results[i].port_count;
        }
    }
    return lines;
}

// ============================================================================
// Drawing
// ============================================================================

static const char* scan_level_names[] = {"Quick (20 ports)", "Medium (50 ports)", "Heavy (100 ports)"};
static const char* scan_level_cmds[] = {"quick", "medium", "heavy"};

static void nmap_draw(Canvas* canvas, void* model) {
    NmapModel* m = (NmapModel*)model;
    if(!m || !m->data) return;
    NmapData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    if(data->state == 0) {
        screen_draw_title(canvas, "Nmap");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Checking password...", 32);

    } else if(data->state == 1) {
        screen_draw_title(canvas, "Nmap");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Enter password", 32);
        if(!data->text_input_added) {
            nmap_show_text_input(data);
        }

    } else if(data->state == 2) {
        screen_draw_title(canvas, "Nmap");
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
        screen_draw_title(canvas, "Nmap");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Discovering hosts...", 32);
        if(data->status_text[0]) {
            screen_draw_centered_text(canvas, data->status_text, 46);
        }

    } else if(data->state == 4) {
        // Host selection with checkboxes
        screen_draw_title(canvas, "Select Hosts");
        canvas_set_font(canvas, FontSecondary);

        if(data->host_count == 0) {
            screen_draw_centered_text(canvas, "No hosts found", 32);
        } else {
            // Item 0 = "All hosts", items 1..host_count = individual hosts
            uint8_t total_items = data->host_count + 1;
            uint8_t y = 22;
            uint8_t max_visible = 4;
            uint8_t start = 0;
            if(data->host_cursor >= max_visible) {
                start = data->host_cursor - max_visible + 1;
            }

            for(uint8_t i = start; i < total_items && (i - start) < max_visible; i++) {
                uint8_t display_y = y + ((i - start) * 9);
                char line[42];

                if(i == 0) {
                    snprintf(line, sizeof(line), "[%c] All hosts (%u)",
                        data->all_hosts_selected ? 'x' : ' ', data->host_count);
                } else {
                    uint8_t hi = i - 1;
                    snprintf(line, sizeof(line), "[%c] %s",
                        data->hosts[hi].selected ? 'x' : ' ',
                        data->hosts[hi].ip);
                }

                if(i == data->host_cursor) {
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                    canvas_draw_str(canvas, 1, display_y, line);
                    canvas_set_color(canvas, ColorBlack);
                } else {
                    canvas_draw_str(canvas, 1, display_y, line);
                }
            }

            // Hint bar
            canvas_draw_str(canvas, 2, 64, "ok:toggle");
            canvas_draw_str(canvas, 76, 64, "right:scan");
        }

    } else if(data->state == 5) {
        // Scan level picker
        screen_draw_title(canvas, "Scan Level");
        canvas_set_font(canvas, FontSecondary);

        for(uint8_t i = 0; i < 3; i++) {
            uint8_t display_y = 24 + (i * 12);
            if(i == data->scan_level_cursor) {
                canvas_draw_box(canvas, 0, display_y - 8, 128, 11);
                canvas_set_color(canvas, ColorWhite);
                canvas_draw_str(canvas, 4, display_y, scan_level_names[i]);
                canvas_set_color(canvas, ColorBlack);
            } else {
                canvas_draw_str(canvas, 4, display_y, scan_level_names[i]);
            }
        }

    } else if(data->state == 6) {
        // Scanning in progress
        screen_draw_title(canvas, "Nmap Scanning");
        canvas_set_font(canvas, FontSecondary);

        if(data->hosts_total > 0) {
            char line[48];
            snprintf(line, sizeof(line), "Host %u/%u", data->hosts_scanned + 1, data->hosts_total);
            canvas_draw_str(canvas, 2, 22, line);
        }

        if(data->progress_ip[0]) {
            char line[48];
            snprintf(line, sizeof(line), "IP: %s", data->progress_ip);
            canvas_draw_str(canvas, 2, 34, line);
        }

        // Progress bar
        canvas_draw_frame(canvas, 2, 40, 124, 8);
        uint8_t fill = (data->progress_pct * 120) / 100;
        if(fill > 120) fill = 120;
        if(fill > 0) {
            canvas_draw_box(canvas, 4, 42, fill, 4);
        }

        {
            char line[48];
            snprintf(line, sizeof(line), "Ports found: %u", data->total_open_ports);
            canvas_draw_str(canvas, 2, 58, line);
        }

    } else if(data->state == 7) {
        // Results display
        screen_draw_title(canvas, "Nmap Results");
        canvas_set_font(canvas, FontSecondary);

        if(data->result_count == 0) {
            screen_draw_centered_text(canvas, "No results", 32);
        } else {
            // Flatten results into scrollable lines
            int16_t total_lines = nmap_result_line_count(data);
            uint8_t max_visible = 5;
            int16_t y = 20;
            int16_t line_idx = 0;

            for(uint8_t h = 0; h < data->result_count; h++) {
                NmapResultHost* rh = &data->results[h];

                // Host header line
                if(line_idx >= data->scroll_pos && line_idx < data->scroll_pos + max_visible) {
                    uint8_t dy = y + ((line_idx - data->scroll_pos) * 9);
                    char line[42];
                    if(rh->mac[0]) {
                        snprintf(line, sizeof(line), "%s (%s)", rh->ip, rh->mac);
                    } else {
                        snprintf(line, sizeof(line), "%s", rh->ip);
                    }
                    canvas_set_font(canvas, FontSecondary);
                    canvas_draw_str(canvas, 1, dy, line);
                }
                line_idx++;

                if(rh->no_open_ports) {
                    if(line_idx >= data->scroll_pos && line_idx < data->scroll_pos + max_visible) {
                        uint8_t dy = y + ((line_idx - data->scroll_pos) * 9);
                        canvas_draw_str(canvas, 8, dy, "(no open ports)");
                    }
                    line_idx++;
                } else {
                    for(uint8_t p = 0; p < rh->port_count; p++) {
                        if(line_idx >= data->scroll_pos && line_idx < data->scroll_pos + max_visible) {
                            uint8_t dy = y + ((line_idx - data->scroll_pos) * 9);
                            char line[42];
                            snprintf(line, sizeof(line), " %d/%s %s",
                                rh->ports[p].port, "tcp", rh->ports[p].service);
                            canvas_draw_str(canvas, 6, dy, line);
                        }
                        line_idx++;
                    }
                }
            }

            // Summary at bottom
            {
                char line[48];
                snprintf(line, sizeof(line), "%u hosts, %u ports  [%d/%d]",
                    data->result_count, data->total_open_ports,
                    data->scroll_pos + 1, total_lines);
                canvas_draw_str(canvas, 2, 64, line);
            }
        }
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool nmap_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    NmapModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    NmapData* data = m->data;

    bool is_navigation = (event->key == InputKeyUp || event->key == InputKeyDown);
    if(is_navigation) {
        if(event->type != InputTypePress && event->type != InputTypeRepeat) {
            view_commit_model(view, false);
            return false;
        }
    } else {
        if(event->type != InputTypeShort) {
            view_commit_model(view, false);
            return false;
        }
    }

    if(data->state == 0 || data->state == 1) {
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
        if(data->state == 1 && event->key == InputKeyOk) {
            nmap_show_text_input(data);
            view_commit_model(view, false);
            return true;
        }

    } else if(data->state == 2 || data->state == 3) {
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }

    } else if(data->state == 4) {
        // Host selection
        uint8_t total_items = data->host_count + 1; // +1 for "All hosts"
        if(event->key == InputKeyUp) {
            if(data->host_cursor > 0) data->host_cursor--;
        } else if(event->key == InputKeyDown) {
            if(data->host_cursor + 1 < total_items) data->host_cursor++;
        } else if(event->key == InputKeyOk) {
            if(data->host_cursor == 0) {
                // Toggle "All hosts"
                data->all_hosts_selected = !data->all_hosts_selected;
                for(uint8_t i = 0; i < data->host_count; i++) {
                    data->hosts[i].selected = data->all_hosts_selected;
                }
            } else {
                uint8_t hi = data->host_cursor - 1;
                data->hosts[hi].selected = !data->hosts[hi].selected;
                // Update "all" state
                bool all = true;
                for(uint8_t i = 0; i < data->host_count; i++) {
                    if(!data->hosts[i].selected) { all = false; break; }
                }
                data->all_hosts_selected = all;
            }
        } else if(event->key == InputKeyRight) {
            // Check if any host is selected
            bool any_selected = false;
            for(uint8_t i = 0; i < data->host_count; i++) {
                if(data->hosts[i].selected) { any_selected = true; break; }
            }
            if(any_selected) {
                data->host_selection_confirmed = true;
                data->state = 5;
                data->scan_level_cursor = 0;
            }
        } else if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }

    } else if(data->state == 5) {
        // Scan level picker
        if(event->key == InputKeyUp) {
            if(data->scan_level_cursor > 0) data->scan_level_cursor--;
        } else if(event->key == InputKeyDown) {
            if(data->scan_level_cursor < 2) data->scan_level_cursor++;
        } else if(event->key == InputKeyOk) {
            data->scan_level_confirmed = true;
        } else if(event->key == InputKeyBack) {
            data->state = 4;
        }

    } else if(data->state == 6) {
        // Scanning - only back
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }

    } else if(data->state == 7) {
        // Results - scroll
        int16_t total_lines = nmap_result_line_count(data);
        int16_t max_visible = 5;
        if(event->key == InputKeyUp) {
            if(data->scroll_pos > 0) data->scroll_pos--;
        } else if(event->key == InputKeyDown) {
            if(data->scroll_pos + max_visible < total_lines) data->scroll_pos++;
        } else if(event->key == InputKeyBack) {
            data->attack_finished = true;
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }
    }

    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Password discovery helper
// ============================================================================

static bool nmap_check_password(NmapData* data) {
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

static int32_t nmap_thread(void* context) {
    NmapData* data = (NmapData*)context;
    WiFiApp* app = data->app;

    FURI_LOG_I(TAG, "Thread started for SSID: %s (index %lu)",
        data->ssid, (unsigned long)data->net_index);

    // Step 1: select_networks
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "select_networks %lu", (unsigned long)data->net_index);
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);

    if(data->attack_finished) return 0;

    // Step 2: Check if password is known
    data->state = 0;
    bool found = nmap_check_password(data);

    if(data->attack_finished) return 0;

    if(!found) {
        data->state = 1;
        FURI_LOG_I(TAG, "Password unknown, requesting user input");
        nmap_show_text_input(data);

        while(!data->password_entered && !data->attack_finished) {
            furi_delay_ms(100);
        }
        if(data->attack_finished) return 0;
    } else {
        data->state = 2;
    }

    // Step 3: Connect to WiFi
    data->state = 2;
    snprintf(cmd, sizeof(cmd), "wifi_connect \"%s\" \"%s\"", data->ssid, data->password);
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

    // Step 4: Scan hosts (list_hosts)
    data->state = 3;
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

                if(data->host_count >= NMAP_MAX_HOSTS) continue;

                if(strstr(line, "(MAC unknown)")) {
                    // Store ICMP-only hosts (nmap can scan them by IP)
                    const char* arrow = strstr(line, "->");
                    if(arrow) {
                        const char* p = line;
                        while(*p == ' ') p++;
                        size_t ip_len = 0;
                        char ip[16] = {0};
                        while(p < arrow && *p != ' ' && ip_len < sizeof(ip) - 1) {
                            ip[ip_len++] = *p++;
                        }
                        ip[ip_len] = '\0';
                        if(ip[0]) {
                            strncpy(data->hosts[data->host_count].ip, ip,
                                sizeof(data->hosts[0].ip) - 1);
                            strncpy(data->hosts[data->host_count].mac, "unknown",
                                sizeof(data->hosts[0].mac) - 1);
                            data->hosts[data->host_count].selected = false;
                            data->host_count++;
                        }
                    }
                    continue;
                }

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
                    while(*p && *p != ' ' && *p != '\n' && *p != '\r' &&
                          mac_len < sizeof(mac) - 1) {
                        mac[mac_len++] = *p++;
                    }
                    mac[mac_len] = '\0';

                    if(ip[0] && mac[0]) {
                        strncpy(data->hosts[data->host_count].ip, ip,
                            sizeof(data->hosts[0].ip) - 1);
                        strncpy(data->hosts[data->host_count].mac, mac,
                            sizeof(data->hosts[0].mac) - 1);
                        data->hosts[data->host_count].selected = false;
                        data->host_count++;
                    }
                }
            }

            snprintf(data->status_text, sizeof(data->status_text),
                "Found %u hosts", data->host_count);
        }
    }

    FURI_LOG_I(TAG, "Found %u hosts", data->host_count);

    if(data->attack_finished) return 0;

    // Step 5: Wait for user to select hosts
    data->state = 4;
    data->host_cursor = 0;

    while(!data->host_selection_confirmed && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) return 0;

    // Step 6: Wait for scan level selection
    // (state is already set to 5 by the input handler)
    while(!data->scan_level_confirmed && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) return 0;

    // Step 7: Build and send nmap command
    data->state = 6;
    data->progress_pct = 0;
    data->hosts_scanned = 0;

    // Count selected hosts and find if single
    uint8_t selected_count = 0;
    int8_t single_host_idx = -1;
    for(uint8_t i = 0; i < data->host_count; i++) {
        if(data->hosts[i].selected) {
            selected_count++;
            single_host_idx = i;
        }
    }

    if(selected_count == 1) {
        snprintf(cmd, sizeof(cmd), "start_nmap %s %s",
            scan_level_cmds[data->scan_level_cursor],
            data->hosts[single_host_idx].ip);
    } else {
        snprintf(cmd, sizeof(cmd), "start_nmap %s",
            scan_level_cmds[data->scan_level_cursor]);
    }

    FURI_LOG_I(TAG, "Sending: %s", cmd);
    uart_clear_buffer(app);
    uart_send_command(app, cmd);

    // Step 8: Parse nmap output
    bool scan_complete = false;
    int8_t current_result_idx = -1;
    start = furi_get_tick();

    while(!scan_complete && !data->attack_finished &&
          (furi_get_tick() - start) < 300000) { // 5 min max
        const char* line = uart_read_line(app, 500);
        if(!line) continue;

        FURI_LOG_I(TAG, "nmap: %s", line);

        // Host discovery total
        if(strstr(line, "Total:") && strstr(line, "hosts discovered")) {
            int n = 0;
            const char* tp = strstr(line, "Total:");
            if(tp) {
                n = atoi(tp + 6);
            }
            data->hosts_total = (uint8_t)n;
            FURI_LOG_I(TAG, "Total hosts to scan: %u", data->hosts_total);
            continue;
        }

        // Single-host mode
        if(strstr(line, "Single-host mode")) {
            data->hosts_total = 1;
            continue;
        }

        // Scan phase start
        if(strstr(line, "host(s)") && strstr(line, "ports each")) {
            int n = 0;
            const char* sp = strstr(line, "Scanning ");
            if(sp) {
                n = atoi(sp + 9);
            }
            if(n > 0) data->hosts_total = (uint8_t)n;
            continue;
        }

        // New host block: "Host: IP  (MAC)" or "Host: IP  (MAC unknown)"
        if(strncmp(line, "Host:", 5) == 0) {
            if(data->result_count < NMAP_MAX_HOSTS) {
                current_result_idx = data->result_count;
                NmapResultHost* rh = &data->results[current_result_idx];
                memset(rh, 0, sizeof(NmapResultHost));

                char ip_buf[16] = {0};
                char mac_buf[18] = {0};
                const char* p = line + 5;
                while(*p == ' ') p++;

                size_t ip_len = 0;
                while(*p && *p != ' ' && ip_len < sizeof(ip_buf) - 1) {
                    ip_buf[ip_len++] = *p++;
                }
                ip_buf[ip_len] = '\0';
                strncpy(rh->ip, ip_buf, sizeof(rh->ip) - 1);

                const char* paren = strchr(p, '(');
                if(paren) {
                    paren++;
                    if(strncmp(paren, "MAC unknown", 11) != 0) {
                        size_t mac_len = 0;
                        while(*paren && *paren != ')' && mac_len < sizeof(mac_buf) - 1) {
                            mac_buf[mac_len++] = *paren++;
                        }
                        mac_buf[mac_len] = '\0';
                        strncpy(rh->mac, mac_buf, sizeof(rh->mac) - 1);
                    }
                }

                strncpy(data->progress_ip, rh->ip, sizeof(data->progress_ip) - 1);
                data->result_count++;
                data->hosts_scanned = data->result_count;

                FURI_LOG_I(TAG, "Result host #%u: %s (%s)",
                    data->result_count, rh->ip, rh->mac);
            }
            continue;
        }

        // Progress: "  Scanning IP ports from-to [current/total] ..."
        if(strstr(line, "Scanning") && strstr(line, "ports") && strchr(line, '[')) {
            const char* bracket = strchr(line, '[');
            if(bracket) {
                int current = 0, total = 0;
                if(sscanf(bracket, "[%d/%d]", &current, &total) == 2 && total > 0) {
                    data->progress_pct = (uint8_t)((current * 100) / total);
                }
            }
            continue;
        }

        // Open port: "    PORT/tcp  open  SERVICE"
        {
            const char* p = line;
            while(*p == ' ') p++;
            int port = 0;
            char service[16] = {0};
            if(sscanf(p, "%d/tcp open %15s", &port, service) == 2 ||
               sscanf(p, "%d/tcp  open  %15s", &port, service) == 2) {
                if(current_result_idx >= 0 && current_result_idx < NMAP_MAX_HOSTS) {
                    NmapResultHost* rh = &data->results[current_result_idx];
                    if(rh->port_count < NMAP_MAX_PORTS_PER_HOST) {
                        rh->ports[rh->port_count].port = port;
                        strncpy(rh->ports[rh->port_count].service, service,
                            sizeof(rh->ports[0].service) - 1);
                        rh->port_count++;
                        data->total_open_ports++;
                        FURI_LOG_I(TAG, "  Port %d/%s open", port, service);
                    }
                }
                continue;
            }
        }

        // No open ports
        if(strstr(line, "(no open ports)")) {
            if(current_result_idx >= 0 && current_result_idx < NMAP_MAX_HOSTS) {
                data->results[current_result_idx].no_open_ports = true;
            }
            continue;
        }

        // Completion: "Scanned N hosts, found M open ports"
        if(strstr(line, "Scanned") && strstr(line, "open ports")) {
            scan_complete = true;
            data->progress_pct = 100;
            FURI_LOG_I(TAG, "Scan complete: %u hosts, %u open ports",
                data->result_count, data->total_open_ports);
            continue;
        }

        // Stopped by user
        if(strstr(line, "(scan stopped by user)")) {
            scan_complete = true;
            continue;
        }
    }

    // Step 9: Show results
    data->state = 7;
    data->scroll_pos = 0;

    while(!data->attack_finished) {
        furi_delay_ms(100);
    }

    FURI_LOG_I(TAG, "Thread finished");
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_nmap_create(WiFiApp* app, void** out_data) {
    FURI_LOG_I(TAG, "Creating Nmap screen");

    if(!app || app->selected_count != 1) {
        FURI_LOG_E(TAG, "Exactly 1 network must be selected");
        return NULL;
    }

    NmapData* data = (NmapData*)malloc(sizeof(NmapData));
    if(!data) return NULL;

    memset(data, 0, sizeof(NmapData));
    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    data->net_index = app->selected_networks[0];
    data->password_entered = false;
    data->text_input_added = false;
    data->connect_failed = false;
    data->host_selection_confirmed = false;
    data->scan_level_confirmed = false;

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

    view_allocate_model(view, ViewModelTypeLocking, sizeof(NmapModel));
    NmapModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, nmap_draw);
    view_set_input_callback(view, nmap_input);
    view_set_context(view, view);

    data->text_input = text_input_alloc();
    if(data->text_input) {
        text_input_set_header_text(data->text_input, "Enter Password:");
        text_input_set_result_callback(
            data->text_input,
            nmap_password_callback,
            data,
            data->password,
            NMAP_PASSWORD_MAX,
            true);
        FURI_LOG_I(TAG, "TextInput created");
    }

    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "NmapScan");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, nmap_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;

    FURI_LOG_I(TAG, "Nmap screen created");
    return view;
}

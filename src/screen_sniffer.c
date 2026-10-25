/**
 * Sniffer Screen
 * 
 * Passive packet capture with Results and Probes views.
 * Scan selection already sent select_networks. This screen sends start_sniffer,
 * which stays on the selected channels. start_sniffer_noscan hops every band.
 * Left = clients (stop, show_sniffer_clients), Right = probes (stop, show_probes)
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include "sniffer_clients_host.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Data Structures
// ============================================================================

#define MAX_RESULTS_LINES 20
#define MAX_LINE_LEN 40

#define SNIFF_JOB_NONE 0
#define SNIFF_JOB_CLIENTS 1
#define SNIFF_JOB_PROBES 2
#define SNIFF_JOB_RESUME 3

typedef struct {
    WiFiApp* app;
    volatile bool running;
    volatile bool attack_finished;
    volatile uint8_t job;
    volatile bool list_busy;
    uint32_t packet_count;
    uint8_t display_mode;       // 0 = counter, 1 = results, 2 = probes
    
    JsSession js;
    volatile bool clients_loaded;
    unsigned selected_client;
    unsigned client_scroll;
    char probes[MAX_RESULTS_LINES][MAX_LINE_LEN];
    uint8_t probes_count;
    uint8_t scroll_offset;
    uint8_t selected_probe;     // For Probes list selection
    
    View* view;
    FuriThread* thread;
} SnifferData;

typedef struct {
    SnifferData* data;
} SnifferModel;

static void sniffer_refresh(SnifferData* data) {
    if(!data || !data->view) return;
    with_view_model(data->view, SnifferModel* model, { UNUSED(model); }, true);
}

// ============================================================================
// Cleanup
// ============================================================================

static void sniffer_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    SnifferData* d = (SnifferData*)data;
    if(!d) return;
    
    d->running = false;
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    js_free(&d->js);
    free(d);
}

// ============================================================================
// Helper - Get network name
// ============================================================================

static const char* get_network_name(WiFiApp* app, uint32_t idx_one_based) {
    if(!app || !app->scan_results || idx_one_based == 0 || idx_one_based > app->scan_result_count) {
        return "(unknown)";
    }
    const char* name = app->scan_results[idx_one_based - 1].ssid;
    return (name && name[0]) ? name : "(hidden)";
}

// ============================================================================
// Drawing
// ============================================================================

static void sniffer_draw(Canvas* canvas, void* model) {
    SnifferModel* m = (SnifferModel*)model;
    if(!m || !m->data) return;
    SnifferData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    
    if(data->display_mode == 0) {
        // Counter mode
        screen_draw_title(canvas, "Sniffer");
        
        canvas_set_font(canvas, FontSecondary);
        
        // Show target networks (first 2)
        uint8_t y = 20;
        uint8_t shown = 0;
        for(uint32_t i = 0; i < data->app->selected_count && shown < 2; i++) {
            const char* name = get_network_name(data->app, data->app->selected_networks[i]);
            canvas_draw_str(canvas, 2, y, name);
            y += 9;
            shown++;
        }
        
        // Packet counter - large centered
        canvas_set_font(canvas, FontBigNumbers);
        char count_str[16];
        snprintf(count_str, sizeof(count_str), "%lu", data->packet_count);
        uint8_t count_width = strlen(count_str) * 10;
        canvas_draw_str(canvas, (128 - count_width) / 2, 48, count_str);
        
        // Navigation hints
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 62, "<Results");
        canvas_draw_str(canvas, 88, 62, "Probes>");
        
    } else if(data->display_mode == 1) {
        screen_draw_title(canvas, "Clients");
        if(data->list_busy) {
            canvas_set_font(canvas, FontSecondary);
            screen_draw_centered_text(canvas, "Loading...", 32);
        } else {
            fl_draw_client_rows(
                canvas,
                data->clients_loaded ? &data->js.model : NULL,
                data->selected_client,
                &data->client_scroll,
                data->js.error);
        }
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 62, "<Back");
        canvas_draw_str(canvas, 76, 62, "OK:Deauth");
        
    } else {
        // Probes mode - selectable list for Karma attack
        screen_draw_title(canvas, "Probes");
        
        canvas_set_font(canvas, FontSecondary);
        
        if(data->list_busy) {
            screen_draw_centered_text(canvas, "Loading...", 32);
        } else if(data->probes_count == 0) {
            screen_draw_centered_text(canvas, "No probe requests", 32);
        } else {
            uint8_t y = 21;  // 1px more spacing under title
            uint8_t max_lines = 4;  // 4 rows to avoid overlap with hint bar
            
            // Adjust scroll to keep selection visible
            if(data->selected_probe < data->scroll_offset) {
                data->scroll_offset = data->selected_probe;
            } else if(data->selected_probe >= data->scroll_offset + max_lines) {
                data->scroll_offset = data->selected_probe - max_lines + 1;
            }
            
            for(uint8_t i = data->scroll_offset; i < data->probes_count && (i - data->scroll_offset) < max_lines; i++) {
                uint8_t display_y = y + ((i - data->scroll_offset) * 9);
                
                if(i == data->selected_probe) {
                    // Highlight selected probe
                    canvas_set_color(canvas, ColorBlack);
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                    canvas_draw_str(canvas, 2, display_y, data->probes[i]);
                    canvas_set_color(canvas, ColorBlack);
                } else {
                    canvas_draw_str(canvas, 2, display_y, data->probes[i]);
                }
            }
        }
        
        canvas_draw_str(canvas, 2, 62, "<Back");
        canvas_draw_str(canvas, 78, 62, "OK:Karma");
    }
}

// ============================================================================
// Load Results from UART
// ============================================================================

static void load_results(SnifferData* data) {
    WiFiApp* app = data->app;
    uart_clear_buffer(app);
    js_free(&data->js);
    js_init(&data->js, fl_js_send, app);
    data->selected_client = 0;
    data->client_scroll = 0;
    data->clients_loaded = js_load(&data->js, fl_now_ms());
    while(data->clients_loaded && data->js.phase == JS_LOADING &&
          data->job == SNIFF_JOB_NONE && !data->attack_finished) {
        const char* line = uart_read_line(app, 200);
        uint32_t now = fl_now_ms();
        if(line) js_line(&data->js, line, now);
        js_tick(&data->js, now);
    }
    data->clients_loaded = (data->js.phase == JS_READY);
}

static void load_probes(SnifferData* data) {
    WiFiApp* app = data->app;
    
    data->probes_count = 0;
    uart_clear_buffer(app);
    uart_send_command(app, "show_probes");
    furi_delay_ms(200);
    
    // Parse output
    // Format: "Probe requests: N" followed by "SSID (MAC)"
    uint32_t start = furi_get_tick();
    bool past_header = false;
    while(!data->attack_finished && data->job == SNIFF_JOB_NONE &&
          (furi_get_tick() - start) < 3000 &&
          data->probes_count < MAX_RESULTS_LINES) {
        const char* line = uart_read_line(app, 500);
        if(!line) continue;
        
        // Skip command echo and prompt
        if(strstr(line, "show_probes") || line[0] == '>') continue;
        
        // Skip header line "Probe requests: N"
        if(strstr(line, "Probe requests:")) {
            past_header = true;
            continue;
        }
        
        if(!past_header) continue;
        
        // Store line (truncate if needed)
        strncpy(data->probes[data->probes_count], line, MAX_LINE_LEN - 1);
        data->probes[data->probes_count][MAX_LINE_LEN - 1] = '\0';
        data->probes_count++;
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool sniffer_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    SnifferModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    SnifferData* data = m->data;
    
    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }
    
    if(data->display_mode == 0) {
        // Counter mode
        if(event->key == InputKeyBack) {
            data->running = false;
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        } else if(event->key == InputKeyLeft) {
            if(data->job != SNIFF_JOB_NONE) {
                view_commit_model(view, false);
                return true;
            }
            data->running = false;
            data->clients_loaded = false;
            data->js.error[0] = 0;
            data->scroll_offset = 0;
            data->selected_client = 0;
            data->display_mode = 1;
            data->job = SNIFF_JOB_CLIENTS;
        } else if(event->key == InputKeyRight) {
            if(data->job != SNIFF_JOB_NONE) {
                view_commit_model(view, false);
                return true;
            }
            data->running = false;
            data->probes_count = 0;
            data->scroll_offset = 0;
            data->selected_probe = 0;
            data->display_mode = 2;
            data->job = SNIFF_JOB_PROBES;
        }
    } else if(data->display_mode == 1) {
        // Results mode - selectable list
        if(event->key == InputKeyBack || event->key == InputKeyLeft) {
            data->scroll_offset = 0;
            data->selected_client = 0;
            data->display_mode = 0;
            data->job = SNIFF_JOB_RESUME;
        } else if(event->key == InputKeyUp) {
            if(data->selected_client > 0) data->selected_client--;
        } else if(event->key == InputKeyDown) {
            unsigned client_count = data->clients_loaded ? data->js.model.client_count : 0;
            if(data->selected_client + 1 < client_count) data->selected_client++;
        } else if(event->key == InputKeyOk) {
            unsigned client_count = data->clients_loaded ? data->js.model.client_count : 0;
            if(data->selected_client < client_count) {
                const sc_client_t* client = &data->js.model.clients[data->selected_client];
                const sc_ap_t* ap = &data->js.model.aps[client->ap];
                char mac[18];
                char ssid[33];
                sc_mac_text(mac, client->mac);
                sc_ap_label(ap, ssid, sizeof(ssid));
                if(fl_js_pump_start(&data->js, data->app, data->selected_client)) {
                    WiFiApp* app = data->app;
                    view_commit_model(view, false);
                    void* deauth_data = NULL;
                    View* next = screen_deauth_client_create(
                        app, 0, mac, ssid, ap->channel, true, &deauth_data);
                    if(next) {
                        screen_push_with_cleanup(app, next, deauth_client_cleanup_internal, deauth_data);
                    }
                    return true;
                }
            }
        }
    } else {
        // Probes mode - selectable list
        if(event->key == InputKeyBack || event->key == InputKeyLeft) {
            data->scroll_offset = 0;
            data->selected_probe = 0;
            data->display_mode = 0;
            data->job = SNIFF_JOB_RESUME;
        } else if(event->key == InputKeyUp) {
            if(data->selected_probe > 0) data->selected_probe--;
        } else if(event->key == InputKeyDown) {
            if(data->selected_probe + 1 < data->probes_count) data->selected_probe++;
        } else if(event->key == InputKeyOk) {
            // Launch Karma attack with selected probe SSID
            if(data->probes_count > 0) {
                // Extract SSID from probe line (format: "SSID (MAC)")
                char probe_ssid[64] = {0};
                const char* probe_line = data->probes[data->selected_probe];
                const char* paren = strstr(probe_line, " (");
                if(paren) {
                    size_t len = paren - probe_line;
                    if(len >= sizeof(probe_ssid)) len = sizeof(probe_ssid) - 1;
                    strncpy(probe_ssid, probe_line, len);
                    probe_ssid[len] = '\0';
                } else {
                    strncpy(probe_ssid, probe_line, sizeof(probe_ssid) - 1);
                    probe_ssid[sizeof(probe_ssid) - 1] = '\0';
                }

                WiFiApp* app = data->app;
                view_commit_model(view, false);

                void* karma_data = NULL;
                View* next = screen_karma_probe_create(app, probe_ssid, &karma_data);
                if(next) {
                    screen_push_with_cleanup(app, next, karma_probe_cleanup_internal, karma_data);
                }
                return true;
            }
        }
    }

    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Sniffer Thread
// ============================================================================

static void sniffer_run_job(SnifferData* data, uint8_t job) {
    WiFiApp* app = data->app;
    data->running = false;
    data->list_busy = true;

    if(job == SNIFF_JOB_CLIENTS) {
        uart_send_command(app, "stop");
        furi_delay_ms(200);
        load_results(data);
        if(data->job == SNIFF_JOB_NONE && !data->attack_finished) {
            data->display_mode = 1;
        }
    } else if(job == SNIFF_JOB_PROBES) {
        uart_send_command(app, "stop");
        furi_delay_ms(200);
        load_probes(data);
        if(data->job == SNIFF_JOB_NONE && !data->attack_finished) {
            data->display_mode = 2;
        }
    } else if(job == SNIFF_JOB_RESUME) {
        uart_clear_buffer(app);
        uart_send_command(app, "start_sniffer");
        data->running = true;
        if(data->job == SNIFF_JOB_NONE && !data->attack_finished) {
            data->display_mode = 0;
        }
    }

    data->list_busy = false;
    sniffer_refresh(data);
}

static int32_t sniffer_thread(void* context) {
    SnifferData* data = (SnifferData*)context;
    WiFiApp* app = data->app;
    
    furi_delay_ms(200);
    uart_clear_buffer(app);

    // Commit the scan selection, then start. start_sniffer locks onto the
    // selected channels. start_sniffer_noscan always hops every band.
    uart_send_select_networks(app);
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "start_sniffer");
    data->running = true;
    
    while(!data->attack_finished) {
        uint8_t job = data->job;
        if(job != SNIFF_JOB_NONE) {
            data->job = SNIFF_JOB_NONE;
            sniffer_run_job(data, job);
            continue;
        }

        if(data->running) {
            const char* line = uart_read_line(app, 100);
            if(line && data->running && data->job == SNIFF_JOB_NONE) {
                const char* count_marker = strstr(line, "Sniffer packet count:");
                if(count_marker) {
                    count_marker += 21; // Skip marker
                    while(*count_marker == ' ') count_marker++;
                    uint32_t count = (uint32_t)strtol(count_marker, NULL, 10);
                    if(count != data->packet_count) {
                        data->packet_count = count;
                        sniffer_refresh(data);
                    }
                }
            }
        } else {
            furi_delay_ms(20);
        }
    }
    
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_sniffer_create(WiFiApp* app, void** out_data) {
    SnifferData* data = (SnifferData*)calloc(1, sizeof(SnifferData));
    if(!data) return NULL;
    
    data->app = app;
    data->running = false;
    data->attack_finished = false;
    data->packet_count = 0;
    data->display_mode = 0;
    data->clients_loaded = false;
    data->selected_client = 0;
    data->client_scroll = 0;
    data->probes_count = 0;
    data->scroll_offset = 0;
    data->selected_probe = 0;
    memset(data->probes, 0, sizeof(data->probes));
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(SnifferModel));
    SnifferModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, sniffer_draw);
    view_set_input_callback(view, sniffer_input);
    view_set_context(view, view);
    data->view = view;
    
    // Start sniffer thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "Sniffer");
    furi_thread_set_stack_size(data->thread, 6144);
    furi_thread_set_callback(data->thread, sniffer_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}

void sniffer_cleanup(View* view, void* data) {
    sniffer_cleanup_internal(view, data);
}

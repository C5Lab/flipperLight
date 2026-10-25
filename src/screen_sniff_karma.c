/**
 * WiFi Sniff & Karma Menu and Screens
 * 
 * Contains:
 * - Sniff & Karma Menu
 * - Global Sniffer (no select_networks)
 * - Browse Clients
 * - Show Probes
 * - Karma Attack
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include "sniffer_clients_host.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Forward declarations
// ============================================================================

static View* global_sniffer_screen_create(WiFiApp* app, void** out_data);
static View* browse_clients_screen_create(WiFiApp* app, void** out_data);
static View* show_probes_screen_create(WiFiApp* app, void** out_data);
static View* karma_menu_screen_create(WiFiApp* app, void** out_data);

static void global_sniffer_cleanup(View* view, void* data);
static void browse_clients_cleanup(View* view, void* data);
static void show_probes_cleanup(View* view, void* data);
static void karma_menu_cleanup(View* view, void* data);

// ============================================================================
// Sniff & Karma Menu
// ============================================================================

typedef struct {
    WiFiApp* app;
    uint8_t selected;
} SniffKarmaMenuModel;

static void sniff_karma_menu_draw(Canvas* canvas, void* model) {
    SniffKarmaMenuModel* m = (SniffKarmaMenuModel*)model;
    if(!m) return;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Sniff & Karma");
    
    const char* items[] = {
        "Sniffer",
        "Browse Clients",
        "Show Probes",
        "Karma"
    };
    const uint8_t item_count = 4;
    
    canvas_set_font(canvas, FontSecondary);
    for(uint8_t i = 0; i < item_count; i++) {
        uint8_t y = 22 + (i * 10);
        if(i == m->selected) {
            canvas_draw_box(canvas, 0, y - 8, 128, 10);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, 2, y, items[i]);
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_draw_str(canvas, 2, y, items[i]);
        }
    }
}

static bool sniff_karma_menu_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    SniffKarmaMenuModel* m = view_get_model(view);
    if(!m) {
        view_commit_model(view, false);
        return false;
    }
    WiFiApp* app = m->app;
    
    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }
    
    if(event->key == InputKeyUp) {
        if(m->selected > 0) m->selected--;
    } else if(event->key == InputKeyDown) {
        if(m->selected < 3) m->selected++;
    } else if(event->key == InputKeyOk) {
        uint8_t sel = m->selected;
        view_commit_model(view, false);
        
        View* next = NULL;
        void* data = NULL;
        void (*cleanup)(View*, void*) = NULL;
        
        if(sel == 0) {
            next = global_sniffer_screen_create(app, &data);
            cleanup = global_sniffer_cleanup;
        } else if(sel == 1) {
            next = browse_clients_screen_create(app, &data);
            cleanup = browse_clients_cleanup;
        } else if(sel == 2) {
            next = show_probes_screen_create(app, &data);
            cleanup = show_probes_cleanup;
        } else if(sel == 3) {
            next = karma_menu_screen_create(app, &data);
            cleanup = karma_menu_cleanup;
        }
        
        if(next) {
            screen_push_with_cleanup(app, next, cleanup, data);
        }
        return true;
    } else if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(app);
        return true;
    }
    
    view_commit_model(view, true);
    return true;
}

View* screen_sniff_karma_menu_create(WiFiApp* app) {
    View* view = view_alloc();
    if(!view) return NULL;
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(SniffKarmaMenuModel));
    SniffKarmaMenuModel* m = view_get_model(view);
    m->app = app;
    m->selected = 0;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, sniff_karma_menu_draw);
    view_set_input_callback(view, sniff_karma_menu_input);
    view_set_context(view, view);
    
    return view;
}

// ============================================================================
// Global Sniffer - Like regular Sniffer but no select_networks
// ============================================================================

#define MAX_SNIFFER_RESULTS 20
#define MAX_SNIFFER_PROBES 20

#define GSNIFF_JOB_NONE 0
#define GSNIFF_JOB_CLIENTS 1
#define GSNIFF_JOB_PROBES 2
#define GSNIFF_JOB_RESUME_LIST 3
#define GSNIFF_JOB_RESUME_PROBES 4

typedef struct {
    WiFiApp* app;
    volatile bool running;
    volatile bool attack_finished;
    volatile uint8_t job;
    volatile bool list_busy;
    volatile bool gui_rx;
    volatile bool rx_idle;
    uint8_t display_mode;  // 0=counter, 1=results, 2=probes
    uint32_t packet_count;
    JsSession js;
    volatile bool clients_loaded;
    unsigned selected_client;
    unsigned client_scroll;
    char probes[MAX_SNIFFER_PROBES][64];
    uint8_t probes_count;
    uint8_t scroll_offset;
    uint8_t selected_result;
    uint8_t selected_probe;
    View* view;
    FuriThread* thread;
} GlobalSnifferData;

typedef struct {
    GlobalSnifferData* data;
} GlobalSnifferModel;

static void global_sniffer_refresh(GlobalSnifferData* data) {
    if(!data || !data->view) return;
    with_view_model(data->view, GlobalSnifferModel* model, { UNUSED(model); }, true);
}

static void global_sniffer_release_clients(GlobalSnifferData* data) {
    if(data->view) {
        with_view_model(data->view, GlobalSnifferModel* model, {
            UNUSED(model);
            js_free(&data->js);
            data->clients_loaded = false;
        }, false);
    } else {
        js_free(&data->js);
        data->clients_loaded = false;
    }
}

static void global_sniffer_cleanup(View* view, void* data) {
    UNUSED(view);
    GlobalSnifferData* d = (GlobalSnifferData*)data;
    if(!d) return;
    
    d->attack_finished = true;
    d->running = false;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    js_free(&d->js);
    free(d);
}

static void global_sniffer_load_results(GlobalSnifferData* data) {
    WiFiApp* app = data->app;
    uart_clear_buffer(app);
    js_free(&data->js);
    js_init(&data->js, fl_js_send, app);
    data->client_scroll = 0;
    data->selected_client = 0;
    data->clients_loaded = js_load(&data->js, fl_now_ms());
    while(data->clients_loaded && data->js.phase == JS_LOADING &&
          data->job == GSNIFF_JOB_NONE && !data->gui_rx && !data->attack_finished) {
        const char* line = uart_read_line(app, 200);
        uint32_t now = fl_now_ms();
        if(line) js_line(&data->js, line, now);
        js_tick(&data->js, now);
    }
    data->clients_loaded = (data->js.phase == JS_READY);
}

static void global_sniffer_load_probes(GlobalSnifferData* data) {
    uart_clear_buffer(data->app);
    uart_send_command(data->app, "show_probes");
    furi_delay_ms(100);
    
    data->probes_count = 0;
    data->scroll_offset = 0;
    data->selected_probe = 0;
    
    uint32_t start = furi_get_tick();
    while(!data->attack_finished && data->job == GSNIFF_JOB_NONE && !data->gui_rx &&
          (furi_get_tick() - start) < 2000 && data->probes_count < MAX_SNIFFER_PROBES) {
        const char* line = uart_read_line(data->app, 200);
        if(line && line[0] && !strstr(line, "Probe requests") && !strstr(line, "show_probes")) {
            strncpy(data->probes[data->probes_count], line, 63);
            data->probes[data->probes_count][63] = '\0';
            data->probes_count++;
        }
    }
}

static void global_sniffer_draw(Canvas* canvas, void* model) {
    GlobalSnifferModel* m = (GlobalSnifferModel*)model;
    if(!m || !m->data) return;
    GlobalSnifferData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    
    if(data->display_mode == 0) {
        screen_draw_title(canvas, "Sniffer");
        
        // Large packet counter
        canvas_set_font(canvas, FontBigNumbers);
        char count[16];
        snprintf(count, sizeof(count), "%lu", data->packet_count);
        screen_draw_centered_text(canvas, count, 38);
        
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "L:Results  R:Probes", 62);
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
        screen_draw_title(canvas, "Probes");
        canvas_set_font(canvas, FontSecondary);
        
        if(data->list_busy) {
            screen_draw_centered_text(canvas, "Loading...", 32);
        } else if(data->probes_count == 0) {
            screen_draw_centered_text(canvas, "No probe requests", 32);
        } else {
            uint8_t y = 21;
            uint8_t max_visible = 5;
            
            if(data->selected_probe >= data->scroll_offset + max_visible) {
                data->scroll_offset = data->selected_probe - max_visible + 1;
            } else if(data->selected_probe < data->scroll_offset) {
                data->scroll_offset = data->selected_probe;
            }
            
            for(uint8_t i = data->scroll_offset; i < data->probes_count && (i - data->scroll_offset) < max_visible; i++) {
                uint8_t display_y = y + ((i - data->scroll_offset) * 9);
                if(i == data->selected_probe) {
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                }
                canvas_draw_str(canvas, 2, display_y, data->probes[i]);
                canvas_set_color(canvas, ColorBlack);
            }
        }
        canvas_draw_str(canvas, 78, 62, "OK:Karma");
    }
}

static bool global_sniffer_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    GlobalSnifferModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    GlobalSnifferData* data = m->data;
    
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    if(data->display_mode == 0) {
        // Counter mode
        if(event->key == InputKeyLeft) {
            if(data->job != GSNIFF_JOB_NONE) {
                view_commit_model(view, false);
                return true;
            }
            data->running = false;
            data->clients_loaded = false;
            data->js.error[0] = 0;
            data->selected_client = 0;
            data->display_mode = 1;
            data->job = GSNIFF_JOB_CLIENTS;
        } else if(event->key == InputKeyRight) {
            if(data->job != GSNIFF_JOB_NONE) {
                view_commit_model(view, false);
                return true;
            }
            data->running = false;
            data->probes_count = 0;
            data->selected_probe = 0;
            data->display_mode = 2;
            data->job = GSNIFF_JOB_PROBES;
        } else if(event->key == InputKeyBack) {
            data->attack_finished = true;
            data->running = false;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }
    } else if(data->display_mode == 1) {
        unsigned client_count = data->clients_loaded ? data->js.model.client_count : 0;
        if(event->key == InputKeyUp) {
            if(data->selected_client > 0) data->selected_client--;
        } else if(event->key == InputKeyDown) {
            if(data->selected_client + 1 < client_count) data->selected_client++;
        } else if(event->key == InputKeyOk) {
            if(data->list_busy || data->job != GSNIFF_JOB_NONE) {
                view_commit_model(view, false);
                return true;
            }
            if(data->clients_loaded && data->selected_client < client_count) {
                const sc_client_t* client = &data->js.model.clients[data->selected_client];
                const sc_ap_t* ap = &data->js.model.aps[client->ap];
                char mac[18];
                char ssid[33];
                uint8_t channel = ap->channel;
                sc_mac_text(mac, client->mac);
                sc_ap_label(ap, ssid, sizeof(ssid));
                data->gui_rx = true;
                view_commit_model(view, false);
                uint32_t wait_start = furi_get_tick();
                while(!data->rx_idle && (furi_get_tick() - wait_start) < 400) {
                    furi_delay_ms(10);
                }
                bool started = fl_js_pump_start(&data->js, data->app, data->selected_client);
                data->gui_rx = false;
                if(started) {
                    WiFiApp* app = data->app;
                    void* deauth_data = NULL;
                    View* next = screen_deauth_client_create(
                        app, 0, mac, ssid, channel, true, &deauth_data);
                    if(next) {
                        screen_push_with_cleanup(app, next, deauth_client_cleanup_internal, deauth_data);
                    }
                    return true;
                }
                global_sniffer_refresh(data);
                return true;
            }
        } else if(event->key == InputKeyBack || event->key == InputKeyLeft) {
            data->display_mode = 0;
            data->selected_client = 0;
            data->job = GSNIFF_JOB_RESUME_LIST;
        }
    } else {
        // Probes mode
        if(event->key == InputKeyUp) {
            if(data->selected_probe > 0) data->selected_probe--;
        } else if(event->key == InputKeyDown) {
            if(data->selected_probe + 1 < data->probes_count) data->selected_probe++;
        } else if(event->key == InputKeyOk) {
            // Launch Karma attack with selected probe SSID
            if(data->probes_count > 0) {
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
        } else if(event->key == InputKeyBack || event->key == InputKeyLeft) {
            data->display_mode = 0;
            data->selected_probe = 0;
            data->job = GSNIFF_JOB_RESUME_PROBES;
        }
    }
    
    view_commit_model(view, true);
    return true;
}

static void global_sniffer_run_job(GlobalSnifferData* data, uint8_t job) {
    WiFiApp* app = data->app;
    data->running = false;
    data->list_busy = true;

    if(job == GSNIFF_JOB_CLIENTS) {
        global_sniffer_load_results(data);
        if(data->job == GSNIFF_JOB_NONE && !data->attack_finished) {
            data->display_mode = 1;
        }
    } else if(job == GSNIFF_JOB_PROBES) {
        uart_send_command(app, "stop");
        furi_delay_ms(200);
        global_sniffer_load_probes(data);
        if(data->job == GSNIFF_JOB_NONE && !data->attack_finished) {
            data->display_mode = 2;
        }
    } else if(job == GSNIFF_JOB_RESUME_LIST) {
        global_sniffer_release_clients(data);
        uart_clear_buffer(app);
        uart_send_command(app, "unselect_networks");
        furi_delay_ms(50);
        uart_send_command(app, "start_sniffer_noscan");
        data->running = true;
        if(data->job == GSNIFF_JOB_NONE && !data->attack_finished) {
            data->display_mode = 0;
        }
    } else if(job == GSNIFF_JOB_RESUME_PROBES) {
        uart_clear_buffer(app);
        uart_send_command(app, "start_sniffer");
        data->running = true;
        if(data->job == GSNIFF_JOB_NONE && !data->attack_finished) {
            data->display_mode = 0;
        }
    }

    data->list_busy = false;
    global_sniffer_refresh(data);
}

static int32_t global_sniffer_thread(void* context) {
    GlobalSnifferData* data = (GlobalSnifferData*)context;
    WiFiApp* app = data->app;
    
    furi_delay_ms(200);
    uart_clear_buffer(app);

    uart_send_command(app, "unselect_networks");
    furi_delay_ms(50);
    uart_send_command(app, "start_sniffer");
    data->running = true;
    
    while(!data->attack_finished) {
        if(data->gui_rx) {
            data->rx_idle = true;
            furi_delay_ms(10);
            continue;
        }

        uint8_t job = data->job;
        if(job != GSNIFF_JOB_NONE) {
            data->rx_idle = false;
            data->job = GSNIFF_JOB_NONE;
            global_sniffer_run_job(data, job);
            continue;
        }

        data->rx_idle = false;
        if(data->running) {
            const char* line = uart_read_line(app, 100);
            if(line && data->running && data->job == GSNIFF_JOB_NONE && !data->gui_rx) {
                const char* marker = strstr(line, "Sniffer packet count:");
                if(marker) {
                    marker += 22;
                    while(*marker == ' ') marker++;
                    uint32_t count = (uint32_t)strtol(marker, NULL, 10);
                    if(count != data->packet_count) {
                        data->packet_count = count;
                        global_sniffer_refresh(data);
                    }
                }
            }
        } else if(data->display_mode == 1) {
            const char* line = uart_read_line(app, 100);
            UNUSED(line);
        } else {
            data->rx_idle = true;
            furi_delay_ms(20);
        }
    }
    
    return 0;
}

static View* global_sniffer_screen_create(WiFiApp* app, void** out_data) {
    GlobalSnifferData* data = (GlobalSnifferData*)malloc(sizeof(GlobalSnifferData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(GlobalSnifferData));
    data->app = app;
    data->attack_finished = false;
    data->running = false;
    data->display_mode = 0;
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(GlobalSnifferModel));
    GlobalSnifferModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, global_sniffer_draw);
    view_set_input_callback(view, global_sniffer_input);
    view_set_context(view, view);
    data->view = view;
    
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "GSniffer");
    furi_thread_set_stack_size(data->thread, 6144);
    furi_thread_set_callback(data->thread, global_sniffer_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}

// ============================================================================
// Browse Clients - snapshot from show_sniffer_clients
// ============================================================================

typedef struct {
    WiFiApp* app;
    JsSession js;
    unsigned selected;
    unsigned scroll_offset;
    bool loaded;
    FuriThread* thread;
    volatile bool cancel;
} BrowseClientsData;

typedef struct {
    BrowseClientsData* data;
} BrowseClientsModel;

static void browse_clients_cleanup(View* view, void* data) {
    UNUSED(view);
    BrowseClientsData* d = (BrowseClientsData*)data;
    if(!d) return;
    d->cancel = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    js_free(&d->js);
    free(d);
}

static int32_t browse_clients_thread(void* context) {
    BrowseClientsData* data = (BrowseClientsData*)context;
    uart_clear_buffer(data->app);
    js_init(&data->js, fl_js_send, data->app);
    if(data->cancel) {
        data->loaded = true;
        return 0;
    }
    if(!js_load(&data->js, fl_now_ms())) {
        data->loaded = true;
        return 0;
    }
    while(!data->cancel && data->js.phase == JS_LOADING) {
        const char* line = uart_read_line(data->app, 200);
        uint32_t now = fl_now_ms();
        if(line) js_line(&data->js, line, now);
        js_tick(&data->js, now);
    }
    data->loaded = true;
    return 0;
}

static void browse_clients_draw(Canvas* canvas, void* model) {
    BrowseClientsModel* m = (BrowseClientsModel*)model;
    if(!m || !m->data) return;
    BrowseClientsData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Clients");
    
    if(!data->loaded) {
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Loading...", 32);
        return;
    }
    
    fl_draw_client_rows(
        canvas,
        &data->js.model,
        data->selected,
        &data->scroll_offset,
        data->js.error);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 62, "<Back");
    if(data->js.phase == JS_READY && data->js.model.client_count > 0) {
        canvas_draw_str(canvas, 76, 62, "OK:Deauth");
    }
}

static bool browse_clients_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    BrowseClientsModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    BrowseClientsData* data = m->data;
    
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    unsigned client_count = (data->loaded && data->js.phase == JS_READY) ? data->js.model.client_count : 0;
    
    if(event->key == InputKeyUp) {
        if(data->selected > 0) data->selected--;
    } else if(event->key == InputKeyDown) {
        if(data->selected + 1 < client_count) data->selected++;
    } else if(event->key == InputKeyOk) {
        if(data->loaded && data->selected < client_count) {
            const sc_client_t* client = &data->js.model.clients[data->selected];
            const sc_ap_t* ap = &data->js.model.aps[client->ap];
            char mac[18];
            char ssid[33];
            sc_mac_text(mac, client->mac);
            sc_ap_label(ap, ssid, sizeof(ssid));
            if(fl_js_pump_start(&data->js, data->app, data->selected)) {
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
    } else if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }
    
    view_commit_model(view, true);
    return true;
}

static View* browse_clients_screen_create(WiFiApp* app, void** out_data) {
    BrowseClientsData* data = (BrowseClientsData*)malloc(sizeof(BrowseClientsData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(BrowseClientsData));
    data->app = app;
    data->loaded = false;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(BrowseClientsModel));
    BrowseClientsModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, browse_clients_draw);
    view_set_input_callback(view, browse_clients_input);
    view_set_context(view, view);
    
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "BClients");
    furi_thread_set_stack_size(data->thread, 4096);
    furi_thread_set_callback(data->thread, browse_clients_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}

// ============================================================================
// Show Probes - Shows probe list from show_probes
// ============================================================================

typedef struct {
    WiFiApp* app;
    char probes[MAX_SNIFFER_PROBES][64];
    uint8_t probe_count;
    uint8_t selected;
    uint8_t scroll_offset;
    bool loaded;
} ShowProbesData;

typedef struct {
    ShowProbesData* data;
} ShowProbesModel;

static void show_probes_cleanup(View* view, void* data) {
    UNUSED(view);
    if(data) free(data);
}

static void show_probes_draw(Canvas* canvas, void* model) {
    ShowProbesModel* m = (ShowProbesModel*)model;
    if(!m || !m->data) return;
    ShowProbesData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Probes");
    canvas_set_font(canvas, FontSecondary);
    
    if(!data->loaded) {
        screen_draw_centered_text(canvas, "Loading...", 32);
        return;
    }
    
    if(data->probe_count == 0) {
        screen_draw_centered_text(canvas, "No probe requests", 32);
        return;
    }
    
    uint8_t y = 21;
    uint8_t max_visible = 5;
    
    if(data->selected >= data->scroll_offset + max_visible) {
        data->scroll_offset = data->selected - max_visible + 1;
    } else if(data->selected < data->scroll_offset) {
        data->scroll_offset = data->selected;
    }
    
    for(uint8_t i = data->scroll_offset; i < data->probe_count && (i - data->scroll_offset) < max_visible; i++) {
        uint8_t display_y = y + ((i - data->scroll_offset) * 9);
        if(i == data->selected) {
            canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_draw_str(canvas, 2, display_y, data->probes[i]);
        canvas_set_color(canvas, ColorBlack);
    }
}

static bool show_probes_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    ShowProbesModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    ShowProbesData* data = m->data;
    
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    if(event->key == InputKeyUp) {
        if(data->selected > 0) data->selected--;
    } else if(event->key == InputKeyDown) {
        if(data->selected + 1 < data->probe_count) data->selected++;
    } else if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }
    
    view_commit_model(view, true);
    return true;
}

static View* show_probes_screen_create(WiFiApp* app, void** out_data) {
    ShowProbesData* data = (ShowProbesData*)malloc(sizeof(ShowProbesData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(ShowProbesData));
    data->app = app;
    data->loaded = false;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(ShowProbesModel));
    ShowProbesModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, show_probes_draw);
    view_set_input_callback(view, show_probes_input);
    view_set_context(view, view);
    
    // Load probes synchronously
    uart_clear_buffer(app);
    uart_send_command(app, "show_probes");
    furi_delay_ms(100);
    
    uint32_t start = furi_get_tick();
    while((furi_get_tick() - start) < 2000 && data->probe_count < MAX_SNIFFER_PROBES) {
        const char* line = uart_read_line(app, 200);
        if(line && line[0] && !strstr(line, "Probe requests") && !strstr(line, "show_probes")) {
            strncpy(data->probes[data->probe_count], line, 63);
            data->probes[data->probe_count][63] = '\0';
            data->probe_count++;
        }
    }
    data->loaded = true;
    
    if(out_data) *out_data = data;
    return view;
}

// ============================================================================
// Karma Attack - Select probe, select HTML, start karma
// ============================================================================

#define KARMA_MAX_PROBES 20
#define KARMA_MAX_HTML 20

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;  // 0=probe list, 1=html list, 2=running
    char probes[KARMA_MAX_PROBES][64];
    uint8_t probe_count;
    uint8_t selected_probe;
    char html_files[KARMA_MAX_HTML][64];
    uint8_t html_count;
    uint8_t selected_html;
    bool data_loaded;
    char portal_ssid[64];
    char last_mac[20];
    char last_password[64];
    FuriThread* thread;
} KarmaData;

typedef struct {
    KarmaData* data;
} KarmaModel;

static void karma_menu_cleanup(View* view, void* data) {
    UNUSED(view);
    KarmaData* d = (KarmaData*)data;
    if(!d) return;
    
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
}

static void karma_draw(Canvas* canvas, void* model) {
    KarmaModel* m = (KarmaModel*)model;
    if(!m || !m->data) return;
    KarmaData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    
    if(data->state == 0) {
        screen_draw_title(canvas, "Select Probe");
        canvas_set_font(canvas, FontSecondary);
        
        if(!data->data_loaded) {
            screen_draw_centered_text(canvas, "Loading...", 32);
        } else if(data->probe_count == 0) {
            screen_draw_centered_text(canvas, "No probes found", 32);
        } else {
            uint8_t y = 21;
            uint8_t max_visible = 5;
            uint8_t scroll = 0;
            if(data->selected_probe >= max_visible) {
                scroll = data->selected_probe - max_visible + 1;
            }
            
            for(uint8_t i = scroll; i < data->probe_count && (i - scroll) < max_visible; i++) {
                uint8_t display_y = y + ((i - scroll) * 9);
                if(i == data->selected_probe) {
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                }
                canvas_draw_str(canvas, 2, display_y, data->probes[i]);
                canvas_set_color(canvas, ColorBlack);
            }
        }
    } else if(data->state == 1) {
        screen_draw_title(canvas, "Select HTML");
        canvas_set_font(canvas, FontSecondary);
        
        if(data->html_count == 0) {
            screen_draw_centered_text(canvas, "No HTML files", 32);
        } else {
            uint8_t y = 21;
            uint8_t max_visible = 5;
            uint8_t scroll = 0;
            if(data->selected_html >= max_visible) {
                scroll = data->selected_html - max_visible + 1;
            }
            
            for(uint8_t i = scroll; i < data->html_count && (i - scroll) < max_visible; i++) {
                uint8_t display_y = y + ((i - scroll) * 9);
                if(i == data->selected_html) {
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                }
                canvas_draw_str(canvas, 2, display_y, data->html_files[i]);
                canvas_set_color(canvas, ColorBlack);
            }
        }
    } else {
        screen_draw_title(canvas, "Karma");
        canvas_set_font(canvas, FontSecondary);
        
        char line[48];
        snprintf(line, sizeof(line), "Portal: %.18s", data->portal_ssid);
        canvas_draw_str(canvas, 2, 24, line);
        
        if(data->last_mac[0]) {
            snprintf(line, sizeof(line), "Last: %s", data->last_mac);
            canvas_draw_str(canvas, 2, 38, line);
        }
        
        if(data->last_password[0]) {
            snprintf(line, sizeof(line), "Pass: %.18s", data->last_password);
            canvas_draw_str(canvas, 2, 52, line);
        }
    }
}

static bool karma_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    KarmaModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    KarmaData* data = m->data;
    
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    if(data->state == 0) {
        // Probe selection
        if(event->key == InputKeyUp) {
            if(data->selected_probe > 0) data->selected_probe--;
        } else if(event->key == InputKeyDown) {
            if(data->selected_probe + 1 < data->probe_count) data->selected_probe++;
        } else if(event->key == InputKeyOk) {
            if(data->probe_count > 0) {
                data->state = 1;  // Move to HTML selection
            }
        } else if(event->key == InputKeyBack) {
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
    } else if(data->state == 1) {
        // HTML selection
        if(event->key == InputKeyUp) {
            if(data->selected_html > 0) data->selected_html--;
        } else if(event->key == InputKeyDown) {
            if(data->selected_html + 1 < data->html_count) data->selected_html++;
        } else if(event->key == InputKeyOk) {
            if(data->html_count > 0) {
                data->state = 2;  // Start attack
            }
        } else if(event->key == InputKeyBack) {
            data->state = 0;  // Back to probe selection
        }
    } else {
        // Attack running
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

static int32_t karma_thread(void* context) {
    KarmaData* data = (KarmaData*)context;
    WiFiApp* app = data->app;
    
    // Load probes using list_probes (numbered list)
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "list_probes");
    furi_delay_ms(100);
    
    uint32_t start = furi_get_tick();
    while((furi_get_tick() - start) < 2000 && data->probe_count < KARMA_MAX_PROBES && !data->attack_finished) {
        const char* line = uart_read_line(app, 200);
        if(line && line[0]) {
            uint32_t idx = 0;
            char name[64] = {0};
            if(sscanf(line, "%lu %63[^\n]", &idx, name) == 2 && idx > 0) {
                strncpy(data->probes[data->probe_count], name, 63);
                data->probes[data->probe_count][63] = '\0';
                data->probe_count++;
            }
        }
    }
    data->data_loaded = true;
    
    // Wait for probe selection
    while(data->state == 0 && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) return 0;
    
    // Save selected probe SSID
    strncpy(data->portal_ssid, data->probes[data->selected_probe], sizeof(data->portal_ssid) - 1);
    
    // Load HTML files
    uart_clear_buffer(app);
    uart_send_command(app, "list_sd");
    furi_delay_ms(100);
    
    start = furi_get_tick();
    while((furi_get_tick() - start) < 2000 && data->html_count < KARMA_MAX_HTML && !data->attack_finished) {
        const char* line = uart_read_line(app, 200);
        if(line) {
            if(strstr(line, "HTML files") || strstr(line, "SD card")) continue;
            
            uint32_t idx = 0;
            char name[64] = {0};
            if(sscanf(line, "%lu %63s", &idx, name) == 2 && idx > 0 && name[0]) {
                strncpy(data->html_files[data->html_count], name, 63);
                data->html_files[data->html_count][63] = '\0';
                data->html_count++;
            }
        }
    }
    
    // Wait for HTML selection
    while(data->state == 1 && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) return 0;
    
    // Send select_html
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "select_html %u", data->selected_html + 1);
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);
    
    // Start karma with probe index (1-based)
    snprintf(cmd, sizeof(cmd), "start_karma %u", data->selected_probe + 1);
    uart_send_command(app, cmd);
    
    // Monitor for connections and passwords
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            // Check for client connection
            const char* mac = strstr(line, "Client connected - MAC:");
            if(mac) {
                mac += 24;
                while(*mac == ' ') mac++;
                size_t i = 0;
                while(*mac && *mac != '\n' && i < 17) {
                    data->last_mac[i++] = *mac++;
                }
                data->last_mac[i] = '\0';
            }
            
            // Check for password
            const char* pwd = strstr(line, "Password:");
            if(pwd) {
                pwd += 10;
                while(*pwd == ' ') pwd++;
                strncpy(data->last_password, pwd, sizeof(data->last_password) - 1);
                data->last_password[sizeof(data->last_password) - 1] = '\0';
            }
        }
        furi_delay_ms(100);
    }
    
    return 0;
}

static View* karma_menu_screen_create(WiFiApp* app, void** out_data) {
    KarmaData* data = (KarmaData*)malloc(sizeof(KarmaData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(KarmaData));
    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(KarmaModel));
    KarmaModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, karma_draw);
    view_set_input_callback(view, karma_input);
    view_set_context(view, view);
    
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "Karma");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, karma_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}

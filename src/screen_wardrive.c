/**
 * Wardrive Screen + Menu
 *
 * Menu options:
 *   - Start Wardrive        → start_wardrive_promisc[_trace]
 *   - Upload to Wdgwars     (placeholder)
 *   - Upload to Wigle       (placeholder)
 *   - Trace: Yes / No       (toggle, default Yes)
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Wardrive Run Screen — Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    bool gps_fix;
    bool gps_lost;
    bool wardrive_active;
    bool trace;
    char last_ssid[33];
    char last_coords[32];
    uint32_t network_count;
    uint32_t bt_count;
    uint32_t sat_count;
    char distance[16];
    uint32_t wait_seconds;
    bool confirm_exit;   // showing "exit?" overlay
    uint8_t confirm_sel; // 0=No (default), 1=Yes
    bool no_sd_prompt;   // showing "no SD" warning, waiting for user decision
    uint8_t no_sd_sel;   // 0=No (default), 1=Yes (continue anyway)
    volatile bool no_sd_decided; // set by input handler
    FuriThread* thread;
} WardriveData;

typedef struct {
    WardriveData* data;
} WardriveModel;

// ============================================================================
// Wardrive Run Screen — Cleanup
// ============================================================================

void wardrive_screen_cleanup(View* view, void* data) {
    UNUSED(view);
    WardriveData* d = (WardriveData*)data;
    if(!d) return;

    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
}

// ============================================================================
// Wardrive Run Screen — Drawing
// ============================================================================

static void wardrive_draw(Canvas* canvas, void* model) {
    WardriveModel* m = (WardriveModel*)model;
    if(!m || !m->data) return;
    WardriveData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, data->trace ? "Wardrive+Trace" : "Wardrive");

    canvas_set_font(canvas, FontSecondary);

    if(data->gps_lost) {
        screen_draw_centered_text(canvas, "GPS fix lost!", 24);
        char line[48];
        snprintf(line, sizeof(line), "Paused. Networks: %lu", (unsigned long)data->network_count);
        screen_draw_centered_text(canvas, line, 36);
        screen_draw_centered_text(canvas, "Waiting for signal...", 48);
        screen_draw_centered_text(canvas, "BACK = stop", 60);
    } else if(!data->gps_fix) {
        screen_draw_centered_text(canvas, "Waiting for GPS fix...", 24);
        if(data->wait_seconds > 0) {
            char line[32];
            snprintf(line, sizeof(line), "Elapsed: %lus", (unsigned long)data->wait_seconds);
            screen_draw_centered_text(canvas, line, 36);
        }
        screen_draw_centered_text(canvas, "Need clear sky view", 48);
        screen_draw_centered_text(canvas, "BACK = cancel", 60);
    } else {
        char line[48];

        snprintf(line, sizeof(line), "Sat: %lu  Dist: %s",
            (unsigned long)data->sat_count,
            data->distance[0] ? data->distance : "?");
        canvas_draw_str(canvas, 2, 22, line);

        snprintf(line, sizeof(line), "BT: %lu  WiFi: %lu",
            (unsigned long)data->bt_count,
            (unsigned long)data->network_count);
        canvas_draw_str(canvas, 2, 34, line);

        if(data->last_coords[0]) {
            canvas_draw_str(canvas, 2, 46, data->last_coords);
        }

        screen_draw_centered_text(canvas, "BACK = stop", 60);
    }

    // No SD card warning overlay
    if(data->no_sd_prompt) {
        canvas_draw_box(canvas, 4, 10, 120, 44);
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_box(canvas, 5, 11, 118, 42);
        canvas_set_color(canvas, ColorBlack);
        canvas_draw_str(canvas, 8, 22, "No SD card!");
        canvas_draw_str(canvas, 8, 33, "Logs won't be saved.");
        canvas_draw_str(canvas, 8, 42, "Continue anyway?");

        if(data->no_sd_sel == 0) {
            canvas_draw_box(canvas, 8, 44, 28, 11);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, 13, 53, "No");
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_draw_frame(canvas, 8, 44, 28, 11);
            canvas_draw_str(canvas, 13, 53, "No");
        }
        if(data->no_sd_sel == 1) {
            canvas_draw_box(canvas, 84, 44, 28, 11);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, 89, 53, "Yes");
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_draw_frame(canvas, 84, 44, 28, 11);
            canvas_draw_str(canvas, 89, 53, "Yes");
        }
    }

    // Confirmation overlay
    if(data->confirm_exit) {
        // Dim background with a filled box border
        canvas_draw_box(canvas, 14, 18, 100, 30);
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_box(canvas, 15, 19, 98, 28);
        canvas_set_color(canvas, ColorBlack);
        canvas_draw_str(canvas, 20, 30, "Stop wardrive?");

        // No button (left)
        if(data->confirm_sel == 0) {
            canvas_draw_box(canvas, 18, 33, 28, 11);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, 23, 42, "No");
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_draw_frame(canvas, 18, 33, 28, 11);
            canvas_draw_str(canvas, 23, 42, "No");
        }

        // Yes button (right)
        if(data->confirm_sel == 1) {
            canvas_draw_box(canvas, 78, 33, 28, 11);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, 83, 42, "Yes");
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_draw_frame(canvas, 78, 33, 28, 11);
            canvas_draw_str(canvas, 83, 42, "Yes");
        }
    }
}

// ============================================================================
// Wardrive Run Screen — Input
// ============================================================================

static bool wardrive_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    WardriveModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    WardriveData* data = m->data;

    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }

    if(data->no_sd_prompt) {
        if(event->key == InputKeyLeft || event->key == InputKeyRight) {
            data->no_sd_sel ^= 1;
        } else if(event->key == InputKeyBack || event->key == InputKeyOk) {
            if(event->key == InputKeyOk && data->no_sd_sel == 1) {
                // Yes — continue without SD
                data->no_sd_prompt  = false;
                data->no_sd_decided = true;
            } else {
                // No — cancel, go back to wardrive menu
                data->attack_finished = true;
                data->no_sd_decided   = true;
                view_commit_model(view, false);
                screen_pop(data->app);
                return true;
            }
        }
        view_commit_model(view, true);
        return true;
    }

    if(data->confirm_exit) {
        if(event->key == InputKeyLeft || event->key == InputKeyRight) {
            data->confirm_sel ^= 1;
        } else if(event->key == InputKeyBack) {
            data->confirm_exit = false;
            data->confirm_sel  = 0;
        } else if(event->key == InputKeyOk) {
            if(data->confirm_sel == 1) {
                // Yes — stop and return to wardrive menu
                data->attack_finished = true;
                uart_send_command(data->app, "stop");
                view_commit_model(view, false);
                screen_pop(data->app);
                return true;
            } else {
                // No — dismiss
                data->confirm_exit = false;
                data->confirm_sel  = 0;
            }
        }
        view_commit_model(view, true);
        return true;
    }

    if(event->key == InputKeyBack) {
        data->confirm_exit = true;
        data->confirm_sel  = 0;  // default: No
        view_commit_model(view, true);
        return true;
    }

    view_commit_model(view, false);
    return true;
}

// ============================================================================
// Wardrive Run Screen — Parsers
// ============================================================================

static void wardrive_parse_csv_coords(const char* line, char* out, size_t out_size) {
    const char* p = line;
    int field = 0;
    const char* lat_start = NULL;
    const char* lat_end = NULL;
    const char* lon_start = NULL;
    const char* lon_end = NULL;
    while(*p) {
        if(field == 6 && !lat_start) { lat_start = p; }
        if(field == 7 && !lon_start) { lon_start = p; }
        if(*p == ',') {
            if(field == 6) { lat_end = p; }
            if(field == 7) { lon_end = p; break; }
            field++;
        }
        p++;
    }
    if(lat_start && lat_end && lon_start && lon_end) {
        int lat_len = (int)(lat_end - lat_start);
        int lon_len = (int)(lon_end - lon_start);
        snprintf(out, out_size, "%.*s, %.*s", lat_len, lat_start, lon_len, lon_start);
    }
}

static void wardrive_parse_fix_coords(const char* line, char* out, size_t out_size) {
    const char* lat_p = strstr(line, "Lat=");
    const char* lon_p = strstr(line, "Lon=");
    if(!lat_p || !lon_p || out_size == 0) return;
    lat_p += 4;
    lon_p += 4;
    char lat[16] = {0};
    char lon[16] = {0};
    int i = 0;
    while(lat_p[i] && lat_p[i] != ' ' && lat_p[i] != ',' && i < 15) {
        lat[i] = lat_p[i]; i++;
    }
    lat[i] = '\0';
    i = 0;
    while(lon_p[i] && ((lon_p[i] >= '0' && lon_p[i] <= '9') || lon_p[i] == '.' || lon_p[i] == '-') && i < 15) {
        lon[i] = lon_p[i]; i++;
    }
    lon[i] = '\0';
    if(i > 0 && lon[i - 1] == '.') lon[i - 1] = '\0';
    size_t lat_len = 0;
    size_t lon_len = 0;
    size_t pos = 0;

    while(lat_len < sizeof(lat) && lat[lat_len] != '\0') lat_len++;
    while(lon_len < sizeof(lon) && lon[lon_len] != '\0') lon_len++;

    if(lat_len > out_size - 1) lat_len = out_size - 1;
    memcpy(out, lat, lat_len);
    pos = lat_len;

    if(pos < out_size - 1) out[pos++] = ',';
    if(pos < out_size - 1) out[pos++] = ' ';

    if(lon_len > out_size - 1 - pos) lon_len = out_size - 1 - pos;
    memcpy(out + pos, lon, lon_len);
    pos += lon_len;
    out[pos] = '\0';
}

static void wardrive_parse_csv_ssid(const char* line, char* out, size_t out_size) {
    const char* first_comma = strchr(line, ',');
    if(!first_comma) {
        strncpy(out, "(unknown)", out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }
    const char* ssid_start = first_comma + 1;
    const char* second_comma = strchr(ssid_start, ',');
    if(!second_comma) {
        strncpy(out, "(unknown)", out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }
    size_t ssid_len = (size_t)(second_comma - ssid_start);
    if(ssid_len == 0) {
        strncpy(out, "(hidden)", out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }
    if(ssid_len >= out_size) ssid_len = out_size - 1;
    memcpy(out, ssid_start, ssid_len);
    out[ssid_len] = '\0';
}

// ============================================================================
// Wardrive Run Screen — Thread
// ============================================================================

static int32_t wardrive_thread(void* context) {
    WardriveData* data = (WardriveData*)context;
    WiFiApp* app = data->app;

    furi_delay_ms(200);

    // Check SD card — warn user if missing
    if(!app->sd_card_ok) {
        data->no_sd_prompt  = true;
        data->no_sd_sel     = 0;
        data->no_sd_decided = false;
        while(!data->no_sd_decided && !data->attack_finished) {
            furi_delay_ms(100);
        }
        if(data->attack_finished) return 0;
    }

    uart_clear_buffer(app);
    uart_send_command(app, data->trace ? "start_wardrive_promisc_trace" : "start_wardrive_promisc");

    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(!line) {
            furi_delay_ms(50);
            continue;
        }

        if(strstr(line, "GPS fix obtained")) {
            data->gps_fix = true;
            data->gps_lost = false;
            data->wait_seconds = 0;
            wardrive_parse_fix_coords(line, data->last_coords, sizeof(data->last_coords));
        } else if(strstr(line, "GPS fix recovered")) {
            data->gps_fix = true;
            data->gps_lost = false;
            wardrive_parse_fix_coords(line, data->last_coords, sizeof(data->last_coords));
        } else if(strstr(line, "GPS fix lost")) {
            data->gps_lost = true;
        } else if(strstr(line, "Still waiting for GPS fix")) {
            const char* paren = strchr(line, '(');
            if(paren) {
                data->wait_seconds = (uint32_t)strtol(paren + 1, NULL, 10);
            }
        } else if(strstr(line, "Promiscuous wardrive started")) {
            data->wardrive_active = true;
        } else if(strstr(line, "Wardrive promisc:")) {
            const char* p = strstr(line, "Wardrive promisc: ");
            if(p) {
                p += 18;
                data->network_count = (uint32_t)strtol(p, NULL, 10);
            }
            const char* bt_p = strstr(line, "BT devices");
            if(bt_p) {
                const char* num = bt_p - 1;
                while(num > line && *(num - 1) >= '0' && *(num - 1) <= '9') num--;
                data->bt_count = (uint32_t)strtol(num, NULL, 10);
            }
            const char* sat_p = strstr(line, "sats: ");
            if(sat_p) {
                data->sat_count = (uint32_t)strtol(sat_p + 6, NULL, 10);
            }
            const char* dist_p = strstr(line, "dist: ");
            if(dist_p) {
                dist_p += 6;
                // Serial sends metres (e.g. "67.3m") — convert to km
                float dist_m = 0.0f;
                char* end = NULL;
                dist_m = strtof(dist_p, &end);
                float dist_km = dist_m / 1000.0f;
                snprintf(data->distance, sizeof(data->distance), "%.2fkm", (double)dist_km);
            }
        } else if(strstr(line, "Flushed ")) {
            const char* p = strstr(line, "Flushed ") + 8;
            uint32_t flushed = (uint32_t)strtol(p, NULL, 10);
            if(flushed > data->network_count) {
                data->network_count = flushed;
            }
            const char* bt_p = strstr(line, "+ ");
            if(bt_p) {
                uint32_t bt_flushed = (uint32_t)strtol(bt_p + 2, NULL, 10);
                if(bt_flushed > data->bt_count) {
                    data->bt_count = bt_flushed;
                }
            }
        } else if(strstr(line, ",WIFI")) {
            data->network_count++;
            wardrive_parse_csv_ssid(line, data->last_ssid, sizeof(data->last_ssid));
            wardrive_parse_csv_coords(line, data->last_coords, sizeof(data->last_coords));
        }

        furi_delay_ms(10);
    }

    return 0;
}

// ============================================================================
// Wardrive Run Screen — Creation
// ============================================================================

View* wardrive_screen_create(WiFiApp* app, void** out_data, bool trace) {
    WardriveData* data = (WardriveData*)malloc(sizeof(WardriveData));
    if(!data) return NULL;

    data->app = app;
    data->attack_finished = false;
    data->gps_fix = false;
    data->gps_lost = false;
    data->wardrive_active = false;
    data->trace = trace;
    memset(data->last_ssid, 0, sizeof(data->last_ssid));
    memset(data->last_coords, 0, sizeof(data->last_coords));
    memset(data->distance, 0, sizeof(data->distance));
    data->network_count = 0;
    data->bt_count = 0;
    data->sat_count = 0;
    data->wait_seconds = 0;
    data->confirm_exit  = false;
    data->confirm_sel   = 0;
    data->no_sd_prompt  = false;
    data->no_sd_sel     = 0;
    data->no_sd_decided = false;
    data->thread = NULL;

    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }

    view_allocate_model(view, ViewModelTypeLocking, sizeof(WardriveModel));
    WardriveModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, wardrive_draw);
    view_set_input_callback(view, wardrive_input);
    view_set_context(view, view);

    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "Wardrive");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, wardrive_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;
    return view;
}

// ============================================================================
// Forward declarations for upload screen
// ============================================================================

extern View* wardrive_upload_screen_create(WiFiApp* app, void** out_data, int provider);
extern void  wardrive_upload_cleanup(View* view, void* data);

// ============================================================================
// Wardrive Menu — Data Structures
// ============================================================================

// Menu items (indices):
//   0 = Start Wardrive
//   1 = Upload to Wdgwars
//   2 = Upload to Wigle
//   3 = Trace toggle

#define WARDRIVE_MENU_ITEMS 4

typedef struct {
    WiFiApp* app;
    uint8_t selected;
    bool trace;
} WardriveMenuModel;

// ============================================================================
// Wardrive Menu — Cleanup
// ============================================================================

void wardrive_menu_cleanup(View* view, void* data) {
    UNUSED(view);
    UNUSED(data);
    // WardriveMenuModel is allocated inside the view model — nothing extra to free
}

// ============================================================================
// Wardrive Menu — Drawing
// ============================================================================

static void wardrive_menu_draw(Canvas* canvas, void* model) {
    WardriveMenuModel* m = (WardriveMenuModel*)model;
    if(!m) return;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Wardrive");

    canvas_set_font(canvas, FontSecondary);

    // Build label for trace item dynamically
    char trace_label[20];
    snprintf(trace_label, sizeof(trace_label), "Trace: %s", m->trace ? "Yes" : "No");

    const char* items[WARDRIVE_MENU_ITEMS] = {
        "Start Wardrive",
        "Upload to Wdgwars",
        "Upload to Wigle",
        trace_label,
    };

    for(uint8_t i = 0; i < WARDRIVE_MENU_ITEMS; i++) {
        uint8_t y = 22 + (i * 11);
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

// ============================================================================
// Wardrive Menu — Input
// ============================================================================

static bool wardrive_menu_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    WardriveMenuModel* m = view_get_model(view);
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
        view_commit_model(view, true);
        return true;
    } else if(event->key == InputKeyDown) {
        if(m->selected < WARDRIVE_MENU_ITEMS - 1) m->selected++;
        view_commit_model(view, true);
        return true;
    } else if(event->key == InputKeyOk) {
        uint8_t sel = m->selected;
        bool trace = m->trace;
        view_commit_model(view, false);

        if(sel == 0) {
            // Start Wardrive
            View* next = NULL;
            void* data = NULL;
            next = wardrive_screen_create(app, &data, trace);
            if(next) {
                screen_push_with_cleanup(app, next, wardrive_screen_cleanup, data);
            }
        } else if(sel == 1) {
            // Upload to Wdgwars
            View* next = NULL;
            void* udata = NULL;
            next = wardrive_upload_screen_create(app, &udata, 1 /* WDUP_WDGWARS */);
            if(next) screen_push_with_cleanup(app, next, wardrive_upload_cleanup, udata);
        } else if(sel == 2) {
            // Upload to Wigle
            View* next = NULL;
            void* udata = NULL;
            next = wardrive_upload_screen_create(app, &udata, 0 /* WDUP_WIGLE */);
            if(next) screen_push_with_cleanup(app, next, wardrive_upload_cleanup, udata);
        } else if(sel == 3) {
            // Toggle trace
            WardriveMenuModel* m2 = view_get_model(view);
            if(m2) m2->trace = !m2->trace;
            view_commit_model(view, true);
        }
        return true;
    } else if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(app);
        return true;
    }

    view_commit_model(view, false);
    return true;
}

// ============================================================================
// Wardrive Menu — Creation
// ============================================================================

View* wardrive_menu_create(WiFiApp* app, void** out_data) {
    UNUSED(out_data);

    View* view = view_alloc();
    if(!view) return NULL;

    view_allocate_model(view, ViewModelTypeLocking, sizeof(WardriveMenuModel));
    WardriveMenuModel* m = view_get_model(view);
    if(!m) {
        view_free(view);
        return NULL;
    }
    m->app = app;
    m->selected = 0;
    m->trace = true; // default: Trace ON
    view_commit_model(view, true);

    view_set_draw_callback(view, wardrive_menu_draw);
    view_set_input_callback(view, wardrive_menu_input);
    view_set_context(view, view);

    return view;
}

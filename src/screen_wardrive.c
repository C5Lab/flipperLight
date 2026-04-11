/**
 * Wardrive Screen
 * 
 * GPS-based promiscuous network logging.
 * Command: start_wardrive_promisc
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    bool gps_fix;
    bool gps_lost;
    bool wardrive_active;
    char last_ssid[33];
    char last_coords[32];
    uint32_t network_count;
    uint32_t wait_seconds;
    FuriThread* thread;
} WardriveData;

typedef struct {
    WardriveData* data;
} WardriveModel;

// ============================================================================
// Cleanup
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
// Drawing
// ============================================================================

static void wardrive_draw(Canvas* canvas, void* model) {
    WardriveModel* m = (WardriveModel*)model;
    if(!m || !m->data) return;
    WardriveData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Wardrive");
    
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
        snprintf(line, sizeof(line), "Networks: %lu", (unsigned long)data->network_count);
        screen_draw_centered_text(canvas, line, 24);
        
        if(data->last_ssid[0]) {
            canvas_draw_str(canvas, 2, 38, data->last_ssid);
        }
        
        if(data->last_coords[0]) {
            canvas_draw_str(canvas, 2, 50, data->last_coords);
        }
        
        screen_draw_centered_text(canvas, "BACK = stop", 62);
    }
}

// ============================================================================
// Input Handling
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
// Attack Thread
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

    while(lat_len < sizeof(lat) && lat[lat_len] != '\0') {
        lat_len++;
    }
    while(lon_len < sizeof(lon) && lon[lon_len] != '\0') {
        lon_len++;
    }

    if(lat_len > out_size - 1) lat_len = out_size - 1;
    memcpy(out, lat, lat_len);
    pos = lat_len;

    if(pos < out_size - 1) {
        out[pos++] = ',';
    }
    if(pos < out_size - 1) {
        out[pos++] = ' ';
    }

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

static int32_t wardrive_thread(void* context) {
    WardriveData* data = (WardriveData*)context;
    WiFiApp* app = data->app;
    
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "start_wardrive_promisc");
    
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
        } else if(strstr(line, "Flushed ")) {
            const char* p = strstr(line, "Flushed ") + 8;
            uint32_t flushed = (uint32_t)strtol(p, NULL, 10);
            if(flushed > data->network_count) {
                data->network_count = flushed;
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
// Screen Creation
// ============================================================================

View* wardrive_screen_create(WiFiApp* app, void** out_data) {
    WardriveData* data = (WardriveData*)malloc(sizeof(WardriveData));
    if(!data) return NULL;
    
    data->app = app;
    data->attack_finished = false;
    data->gps_fix = false;
    data->gps_lost = false;
    data->wardrive_active = false;
    memset(data->last_ssid, 0, sizeof(data->last_ssid));
    memset(data->last_coords, 0, sizeof(data->last_coords));
    data->network_count = 0;
    data->wait_seconds = 0;
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

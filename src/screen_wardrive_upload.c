/**
 * Wardrive Upload Screen
 *
 * State Machine:
 *
 *   [WUS_PROVIDER_SELECT] ──OK──> [WUS_LISTING_FILES]
 *          (skip if provider pre-set)            │
 *                                               list_dir done
 *                                                │
 *                                         [WUS_FILE_SELECT]  <──BACK──
 *                                          checkboxes + Send │
 *                                               Send pressed  │
 *                                                │
 *                                         [WUS_CHECKING_KEY]
 *                                          send *_key read    │
 *                                      key ok ─┤├── no key ──> [WUS_NO_KEY]
 *                                              │
 *                                    sd_card_ok?──no──> [WUS_NO_SD]
 *                                              │yes
 *                                    wifi_connected?──yes──────────────┐
 *                                              │no                     │
 *                                     [WUS_SCANNING_WIFI]              │
 *                                              │                       │
 *                                      [WUS_WIFI_LIST]                 │
 *                               real net ─────┤├─── "Other..." ──> [WUS_MANUAL_SSID]
 *                                              │                       │
 *                                    [WUS_CHECKING_PASS]  <───────────┘
 *                                  found ──┤├── not found ──> [WUS_PASSWORD_INPUT]
 *                                          │                       │
 *                                   [WUS_CONNECTING] <────────────┘
 *                               ok ──┤├── fail ──> [WUS_ERROR]
 *                                    │
 *                        ┌───────────┘
 *                        │  (also reached when already wifi_connected)
 *                        │
 *                  [WUS_UPLOADING]  ── per-file loop ──
 *                        │
 *               all done ─┤├── fatal error ──> [WUS_ERROR]
 *                         │
 *                   [WUS_DONE]
 *
 * Commands used:
 *   list_dir <path>
 *   wigle_key read  /  wdgwars_key read
 *   scan_networks
 *   show_scan_results
 *   show_pass evil
 *   wifi_connect "<ssid>" "<password>"
 *   wigle_upload <filepath>
 *   wdgwars_upload <filepath>
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <gui/modules/text_input.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "WdupUpload"

// ============================================================================
// Constants
// ============================================================================

#define WDUP_TEXT_INPUT_ID  997
#define WDUP_MAX_FILES      20
#define WDUP_PATH_MAX       64
#define WDUP_NAME_MAX       24
#define WDUP_VISIBLE_FILES  4      // rows visible in file list
#define WDUP_VISIBLE_WIFI   4      // rows visible in wifi list
#define WDUP_UPLOAD_TIMEOUT 150000 // ms per file
#define WDUP_LIST_TIMEOUT   3000   // ms for list_dir response
#define WDUP_KEY_TIMEOUT    5000
#define WDUP_WIFI_TIMEOUT   30000
#define WDUP_SCAN_TIMEOUT   20000

static const char* const WDUP_SEARCH_DIRS[] = {
    "/sdcard/lab/wardrives",
};
#define WDUP_SEARCH_DIR_COUNT 1

// ============================================================================
// Types
// ============================================================================

typedef enum {
    WDUP_WIGLE   = 0,
    WDUP_WDGWARS = 1,
    WDUP_NONE    = 2,  // sentinel: show provider selector first
} WdupProvider;

typedef enum {
    WUS_PROVIDER_SELECT = 0,
    WUS_LISTING_FILES,
    WUS_FILE_SELECT,
    WUS_CHECKING_KEY,
    WUS_NO_KEY,
    WUS_NO_SD,
    WUS_SCANNING_WIFI,
    WUS_WIFI_LIST,
    WUS_CHECKING_PASS,
    WUS_MANUAL_SSID,
    WUS_PASSWORD_INPUT,
    WUS_CONNECTING,
    WUS_UPLOADING,
    WUS_DONE,
    WUS_ERROR,
} WdupState;

typedef struct {
    char path[WDUP_PATH_MAX];   // full path sent to upload command
    char name[WDUP_NAME_MAX];   // display-only filename
    bool checked;
} WdupFile;

typedef struct {
    WiFiApp*  app;
    volatile bool should_exit;
    WdupState state;
    WdupProvider provider;

    // File list (heap-allocated)
    WdupFile* files;
    uint8_t   file_count;
    uint8_t   file_cursor;  // 0..file_count-1 = files; file_count = "Send" button
    uint8_t   file_scroll;  // index of topmost visible row

    // WiFi
    char     ssid[33];
    char     password[65];
    uint8_t  wifi_cursor;
    volatile bool network_selected;
    volatile bool text_entered;
    bool     manual_ssid_mode;   // true = "Other..." chosen
    bool     connect_failed;

    // Upload progress
    char    status[64];
    uint8_t upload_current;   // which file we're on (among checked ones)
    uint8_t upload_total;
    int     total_uploaded;
    int     total_skipped;
    int     total_failed;

    // Live debug console (ring buffer)
#define WDUP_DBG_LINES   12   // total stored lines
#define WDUP_DBG_VISIBLE  3   // rows visible at once
#define WDUP_DBG_W        22  // chars per row
    char    dbg[WDUP_DBG_LINES][WDUP_DBG_W];
    uint8_t dbg_scroll;  // top visible line index (for Done/Error screens)

    // Flipper resources
    FuriThread* thread;
    TextInput*  text_input;
    bool        text_input_added;
    View*       main_view;
} WdupData;

typedef struct {
    WdupData* data;
} WdupModel;

// ============================================================================
// Forward declarations
// ============================================================================

static void wdup_show_text_input(WdupData* data, const char* header,
                                  char* buf, size_t buf_size);

// Append a line to the rolling debug console (shifts up, newest at bottom)
static void wdup_dbg_push(WdupData* d, const char* line) {
    for(int i = 0; i < WDUP_DBG_LINES - 1; i++) {
        memcpy(d->dbg[i], d->dbg[i + 1], WDUP_DBG_W);
    }
    strncpy(d->dbg[WDUP_DBG_LINES - 1], line, WDUP_DBG_W - 1);
    d->dbg[WDUP_DBG_LINES - 1][WDUP_DBG_W - 1] = '\0';
    // Auto-scroll to newest line
    if(WDUP_DBG_LINES > WDUP_DBG_VISIBLE)
        d->dbg_scroll = WDUP_DBG_LINES - WDUP_DBG_VISIBLE;
}

// ============================================================================
// Cleanup
// ============================================================================

void wardrive_upload_cleanup(View* view, void* ctx) {
    UNUSED(view);
    WdupData* d = (WdupData*)ctx;
    if(!d) return;

    d->should_exit = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    if(d->text_input) {
        if(d->text_input_added) {
            view_dispatcher_remove_view(d->app->view_dispatcher, WDUP_TEXT_INPUT_ID);
        }
        text_input_free(d->text_input);
    }
    if(d->files) free(d->files);
    free(d);
}

// ============================================================================
// TextInput callback
// ============================================================================

static void wdup_text_callback(void* ctx) {
    WdupData* data = (WdupData*)ctx;
    if(!data) return;
    data->text_entered = true;
    uint32_t vid = screen_get_current_view_id();
    view_dispatcher_switch_to_view(data->app->view_dispatcher, vid);
}

static void wdup_show_text_input(WdupData* data, const char* header,
                                  char* buf, size_t buf_size) {
    if(!data->text_input) return;
    text_input_reset(data->text_input);
    text_input_set_header_text(data->text_input, header);
    text_input_set_result_callback(data->text_input, wdup_text_callback,
                                   data, buf, buf_size, true);
    if(!data->text_input_added) {
        view_dispatcher_add_view(data->app->view_dispatcher, WDUP_TEXT_INPUT_ID,
                                 text_input_get_view(data->text_input));
        data->text_input_added = true;
    }
    view_dispatcher_switch_to_view(data->app->view_dispatcher, WDUP_TEXT_INPUT_ID);
}

// ============================================================================
// Drawing helpers
// ============================================================================

// Draw scrollable debug log starting at y, returns bottom y used
static void wdup_draw_dbg(Canvas* canvas, WdupData* d, uint8_t start_y) {
    const uint8_t row_h = 10;
    for(int i = 0; i < WDUP_DBG_VISIBLE; i++) {
        int idx = (int)d->dbg_scroll + i;
        if(idx >= WDUP_DBG_LINES) break;
        if(d->dbg[idx][0])
            canvas_draw_str(canvas, 2, start_y + i * row_h, d->dbg[idx]);
    }
    // Scroll indicator on right edge (only if scrollable)
    bool can_up   = d->dbg_scroll > 0;
    bool can_down = (d->dbg_scroll + WDUP_DBG_VISIBLE) < WDUP_DBG_LINES;
    if(can_up)   canvas_draw_str(canvas, 122, start_y, "^");
    if(can_down) canvas_draw_str(canvas, 122, start_y + (WDUP_DBG_VISIBLE - 1) * row_h, "v");
}

static void wdup_draw_list_item(Canvas* canvas, uint8_t y, const char* text,
                                 bool selected, bool checked, bool is_checkbox) {
    if(selected) {
        canvas_draw_box(canvas, 0, y - 8, 128, 10);
        canvas_set_color(canvas, ColorWhite);
    }
    if(is_checkbox) {
        canvas_draw_str(canvas, 2, y, checked ? "[x]" : "[ ]");
        canvas_draw_str(canvas, 26, y, text);
    } else {
        canvas_draw_str(canvas, 2, y, text);
    }
    if(selected) canvas_set_color(canvas, ColorBlack);
}

// ============================================================================
// Drawing
// ============================================================================

static void wdup_draw(Canvas* canvas, void* model) {
    WdupModel* m = (WdupModel*)model;
    if(!m || !m->data) return;
    WdupData* d = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    switch(d->state) {

    case WUS_PROVIDER_SELECT:
        screen_draw_title(canvas, "Wardrive Upload");
        canvas_set_font(canvas, FontSecondary);
        wdup_draw_list_item(canvas, 28, "WiGLE",   d->wifi_cursor == 0, false, false);
        wdup_draw_list_item(canvas, 40, "WDGWars", d->wifi_cursor == 1, false, false);
        break;

    case WUS_LISTING_FILES:
        screen_draw_title(canvas, "Wardrive Upload");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Scanning SD card...", 36);
        break;

    case WUS_FILE_SELECT: {
        screen_draw_title(canvas, "Select Files");
        canvas_set_font(canvas, FontSecondary);

        uint8_t row = 0;
        for(uint8_t i = d->file_scroll;
            i < d->file_count && row < WDUP_VISIBLE_FILES;
            i++, row++) {
            uint8_t y = 20 + row * 10;
            bool sel = (d->file_cursor == i);
            wdup_draw_list_item(canvas, y, d->files[i].name, sel,
                                d->files[i].checked, true);
        }
        // "Send" button at bottom
        {
            char send_label[24];
            uint8_t n = 0;
            for(uint8_t i = 0; i < d->file_count; i++) if(d->files[i].checked) n++;
            snprintf(send_label, sizeof(send_label), "Send (%u files)", n);
            bool sel = (d->file_cursor == d->file_count);
            if(sel) {
                canvas_draw_box(canvas, 64, 53, 64, 10);
                canvas_set_color(canvas, ColorWhite);
                canvas_draw_str(canvas, 66, 62, send_label);
                canvas_set_color(canvas, ColorBlack);
            } else {
                canvas_draw_str(canvas, 66, 62, send_label);
            }
            canvas_draw_str(canvas, 2, 62, "< Back");
        }
        break;
    }

    case WUS_CHECKING_KEY:
        screen_draw_title(canvas, "Wardrive Upload");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Checking API key...", 36);
        break;

    case WUS_NO_KEY:
        screen_draw_title(canvas, "Wardrive Upload");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "No API key found.", 26);
        screen_draw_centered_text(canvas, "Set key in C5Monster", 38);
        screen_draw_centered_text(canvas, "and reboot.", 50);
        canvas_draw_str(canvas, 2, 62, "< Back");
        break;

    case WUS_NO_SD:
        screen_draw_title(canvas, "Wardrive Upload");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "SD card not found.", 32);
        screen_draw_centered_text(canvas, "Insert SD and restart.", 44);
        canvas_draw_str(canvas, 2, 62, "< Back");
        break;

    case WUS_SCANNING_WIFI:
        screen_draw_title(canvas, "Connect to WiFi");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Scanning networks...", 36);
        break;

    case WUS_WIFI_LIST: {
        screen_draw_title(canvas, "Select Network");
        canvas_set_font(canvas, FontSecondary);
        uint32_t count = d->app->scan_result_count;
        uint32_t total = count + 1; // +1 for "Other..."
        uint8_t start = 0;
        if(d->wifi_cursor >= WDUP_VISIBLE_WIFI)
            start = d->wifi_cursor - WDUP_VISIBLE_WIFI + 1;

        for(uint8_t i = 0; i < WDUP_VISIBLE_WIFI && (start + i) < total; i++) {
            uint8_t y = 20 + i * 10;
            uint8_t idx = start + i;
            bool sel = (d->wifi_cursor == idx);
            const char* name = (idx < count)
                ? (d->app->scan_results[idx].ssid[0]
                    ? d->app->scan_results[idx].ssid : "(hidden)")
                : "Other...";
            wdup_draw_list_item(canvas, y, name, sel, false, false);
        }
        break;
    }

    case WUS_CHECKING_PASS:
        screen_draw_title(canvas, "Connect to WiFi");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Checking password...", 36);
        break;

    case WUS_MANUAL_SSID:
    case WUS_PASSWORD_INPUT:
        // TextInput widget is shown; this state flickers briefly
        screen_draw_title(canvas, "Connect to WiFi");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Enter credentials", 36);
        break;

    case WUS_CONNECTING: {
        screen_draw_title(canvas, "Connect to WiFi");
        canvas_set_font(canvas, FontSecondary);
        char line[48];
        snprintf(line, sizeof(line), "Connecting: %.18s", d->ssid);
        screen_draw_centered_text(canvas, line, 28);
        if(d->connect_failed) {
            screen_draw_centered_text(canvas, "Connection FAILED", 44);
            canvas_draw_str(canvas, 2, 62, "< Back");
        } else if(d->status[0]) {
            screen_draw_centered_text(canvas, d->status, 44);
        }
        break;
    }

    case WUS_UPLOADING: {
        screen_draw_title(canvas, d->provider == WDUP_WIGLE ? "Upload WiGLE"
                                                            : "Upload WDGWars");
        canvas_set_font(canvas, FontSecondary);

        // Header: current file progress
        char line[48];
        snprintf(line, sizeof(line), "%u/%u: %.14s",
                 d->upload_current + 1, d->upload_total,
                 d->upload_total > 0 ? d->files[d->upload_current].name : "");
        canvas_draw_str(canvas, 2, 20, line);

        // Separator line
        canvas_draw_line(canvas, 0, 22, 127, 22);

        // Debug console — last 3 UART lines
        const uint8_t dbg_y[WDUP_DBG_LINES] = {32, 42, 52};
        for(int i = 0; i < WDUP_DBG_LINES; i++) {
            if(d->dbg[i][0]) {
                canvas_draw_str(canvas, 2, dbg_y[i], d->dbg[i]);
            }
        }

        // Bottom: running totals
        canvas_draw_line(canvas, 0, 54, 127, 54);
        snprintf(line, sizeof(line), "up:%d  sk:%d  err:%d",
                 d->total_uploaded, d->total_skipped, d->total_failed);
        canvas_draw_str(canvas, 2, 63, line);
        break;
    }

    case WUS_DONE: {
        screen_draw_title(canvas, "Upload Done");
        canvas_set_font(canvas, FontSecondary);
        // Counters on one line
        char line[48];
        snprintf(line, sizeof(line), "up:%d  sk:%d  fail:%d",
                 d->total_uploaded, d->total_skipped, d->total_failed);
        canvas_draw_str(canvas, 2, 22, line);
        canvas_draw_line(canvas, 0, 24, 127, 24);
        wdup_draw_dbg(canvas, d, 34);
        canvas_draw_str(canvas, 2, 63, "< Back");
        break;
    }

    case WUS_ERROR:
        screen_draw_title(canvas, "Upload Error");
        canvas_set_font(canvas, FontSecondary);
        // Show status on line 1
        if(d->status[0]) {
            canvas_draw_str(canvas, 2, 22, d->status);
        }
        wdup_draw_dbg(canvas, d, 33);
        canvas_draw_str(canvas, 2, 62, "< Back");
        break;
    }
}

// ============================================================================
// Input
// ============================================================================

static bool wdup_input(InputEvent* event, void* ctx) {
    View* view = (View*)ctx;
    if(!view) return false;

    WdupModel* m = view_get_model(view);
    if(!m || !m->data) { view_commit_model(view, false); return false; }
    WdupData* d = m->data;

    if(event->type != InputTypeShort) { view_commit_model(view, false); return false; }

    if(event->key == InputKeyBack) {
        d->should_exit = true;
        view_commit_model(view, false);
        screen_pop(d->app);
        return true;
    }

    switch(d->state) {

    case WUS_PROVIDER_SELECT:
        if(event->key == InputKeyUp)   { if(d->wifi_cursor > 0) d->wifi_cursor--; }
        if(event->key == InputKeyDown) { if(d->wifi_cursor < 1) d->wifi_cursor++; }
        if(event->key == InputKeyOk) {
            d->provider = (d->wifi_cursor == 0) ? WDUP_WIGLE : WDUP_WDGWARS;
            d->network_selected = true;  // reuse flag as "provider chosen"
        }
        break;

    case WUS_FILE_SELECT: {
        uint8_t max_cursor = d->file_count; // file_count = Send button
        if(event->key == InputKeyUp) {
            if(d->file_cursor > 0) {
                d->file_cursor--;
                if(d->file_cursor < d->file_scroll) d->file_scroll = d->file_cursor;
            }
        } else if(event->key == InputKeyDown) {
            if(d->file_cursor < max_cursor) {
                d->file_cursor++;
                if(d->file_cursor < d->file_count &&
                   d->file_cursor >= d->file_scroll + WDUP_VISIBLE_FILES) {
                    d->file_scroll = d->file_cursor - WDUP_VISIBLE_FILES + 1;
                }
            }
        } else if(event->key == InputKeyRight) {
            // Jump to Send button
            d->file_cursor = d->file_count;
        } else if(event->key == InputKeyOk) {
            if(d->file_cursor < d->file_count) {
                // Toggle checkbox
                d->files[d->file_cursor].checked = !d->files[d->file_cursor].checked;
            } else {
                // "Send" button
                d->network_selected = true;
            }
        }
        break;
    }

    case WUS_WIFI_LIST: {
        uint32_t total = d->app->scan_result_count + 1;
        if(event->key == InputKeyUp)   { if(d->wifi_cursor > 0) d->wifi_cursor--; }
        if(event->key == InputKeyDown) { if(d->wifi_cursor < total - 1) d->wifi_cursor++; }
        if(event->key == InputKeyOk) {
            uint32_t count = d->app->scan_result_count;
            if(d->wifi_cursor < count) {
                strncpy(d->ssid, d->app->scan_results[d->wifi_cursor].ssid,
                        sizeof(d->ssid) - 1);
                d->ssid[sizeof(d->ssid) - 1] = '\0';
                d->manual_ssid_mode = false;
            } else {
                d->manual_ssid_mode = true;
                d->ssid[0] = '\0';
            }
            d->network_selected = true;
        }
        break;
    }

    case WUS_DONE:
    case WUS_ERROR:
        // Scroll debug log with Up/Down
        if(event->key == InputKeyUp) {
            if(d->dbg_scroll > 0) d->dbg_scroll--;
        } else if(event->key == InputKeyDown) {
            if(d->dbg_scroll + WDUP_DBG_VISIBLE < WDUP_DBG_LINES)
                d->dbg_scroll++;
        }
        break;

    default:
        break;
    }

    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Parser helpers
// ============================================================================

/**
 * Parse summary line from upload response.
 *
 * Handles three formats:
 *   "Done: 3 uploaded, 1 duplicate, 0 failed"
 *   "uploaded=3 failed=0 skipped=1"
 *   Fallback: count "-> OK" / "-> skipped" / "-> FAILED" markers
 *
 * Returns true if any of the first two formats matched.
 */
static bool wdup_parse_summary(const char* line,
                                int* uploaded, int* skipped, int* failed) {
    // Format 1: "Done: X uploaded, Y duplicate, Z failed"
    int u = 0, dup = 0, f = 0;
    if(sscanf(line, "Done: %d uploaded, %d skipped, %d failed", &u, &dup, &f) == 3) {
        *uploaded += u;
        *skipped  += dup;
        *failed   += f;
        return true;
    }

    // Format 2: "uploaded=X failed=Y skipped=Z" (any order)
    {
        const char* p;
        p = strstr(line, "uploaded=");
        if(p) { u = (int)strtol(p + 9, NULL, 10); *uploaded += u; }
        p = strstr(line, "failed=");
        if(p) { f = (int)strtol(p + 7, NULL, 10); *failed += f; }
        p = strstr(line, "skipped=");
        if(p) { int s = (int)strtol(p + 8, NULL, 10); *skipped += s; }
        if(strstr(line, "uploaded=")) return true;
    }

    return false;
}

/**
 * Check per-file marker lines (fallback when no summary block arrives).
 * Returns: 1=ok, -1=fail, 0=skipped, -2=no match
 */
static int wdup_parse_file_marker(const char* line) {
    if(strstr(line, "-> OK"))      return  1;
    if(strstr(line, "-> FAILED"))  return -1;
    if(strstr(line, "-> skipped")) return  0;
    return -2;
}

/**
 * Returns true if the line signals a hard / terminal error.
 */
static bool wdup_is_fatal_error(const char* line) {
    return strstr(line, "Unrecognized command") ||
           strstr(line, "NO WIGLE_CREDENTIALS") ||
           strstr(line, "NO WDGWARS_CREDENTIALS") ||
           strstr(line, "WDGWARS AUTH FAILED")   ||
           strstr(line, "WIFI NOT CONNECTED");
}

// ============================================================================
// File listing
// ============================================================================

static bool wdup_has_wardrive_ext(const char* name) {
    size_t n = strlen(name);
    if(n > 4 && strcmp(name + n - 4, ".log") == 0) return true;
    if(n > 4 && strcmp(name + n - 4, ".txt") == 0) return true;
    if(n > 4 && strcmp(name + n - 4, ".csv") == 0) return true;
    return false;
}

static bool wdup_file_known(WdupData* d, const char* path) {
    for(uint8_t i = 0; i < d->file_count; i++) {
        if(strcmp(d->files[i].path, path) == 0) return true;
    }
    return false;
}

static void wdup_add_file(WdupData* d, const char* dir, const char* name) {
    if(d->file_count >= WDUP_MAX_FILES) return;
    if(!wdup_has_wardrive_ext(name)) return;

    char full[WDUP_PATH_MAX];
    snprintf(full, sizeof(full), "%s/%s", dir, name);
    if(wdup_file_known(d, full)) return;

    WdupFile* f = &d->files[d->file_count++];
    strncpy(f->path, full, WDUP_PATH_MAX - 1);
    f->path[WDUP_PATH_MAX - 1] = '\0';
    strncpy(f->name, name, WDUP_NAME_MAX - 1);
    f->name[WDUP_NAME_MAX - 1] = '\0';
    f->checked = false;
}

static void wdup_list_dir(WdupData* d, const char* dir) {
    WiFiApp* app = d->app;
    char cmd[80];
    snprintf(cmd, sizeof(cmd), "list_dir %s", dir);

    uart_clear_buffer(app);
    uart_send_command(app, cmd);

    uint32_t deadline = furi_get_tick() + WDUP_LIST_TIMEOUT;
    uint32_t last_rx  = furi_get_tick();

    while(furi_get_tick() < deadline && !d->should_exit) {
        const char* line = uart_read_line(app, 300);
        if(!line) {
            // Stop early if 1.5 s of silence after first response
            if((furi_get_tick() - last_rx) > 1500 && last_rx != deadline - WDUP_LIST_TIMEOUT)
                break;
            continue;
        }
        last_rx = furi_get_tick();

        // Log raw response to debug buffer so errors are visible on screen
        wdup_dbg_push(d, line);
        FURI_LOG_I(TAG, "list_dir: [%s]", line);

        // Strip leading whitespace
        while(*line == ' ' || *line == '\t') line++;

        // Skip status/error lines
        if(strstr(line, "Error") || strstr(line, "not found") ||
           strstr(line, "Unrecognized") || strstr(line, "Found ")) continue;

        // Strip leading numeric prefix: "6 w5.log" -> "w5.log"
        //                               "6. w5.log" -> "w5.log"
        const char* p = line;
        while(*p >= '0' && *p <= '9') p++;
        if(p > line) {
            if(*p == '.') p++;   // optional dot
            if(*p == ' ') p++;   // space after number
            line = p;
        }

        // line might be bare filename or full path
        const char* name = line;
        const char* slash = strrchr(line, '/');
        if(slash) name = slash + 1;

        if(name[0] && name[0] != '.') {
            wdup_add_file(d, dir, name);
        }
    }
}

// ============================================================================
// WiFi helpers (shared with wpasec pattern)
// ============================================================================

static bool wdup_check_evil_password(WdupData* d) {
    WiFiApp* app = d->app;
    uart_clear_buffer(app);
    uart_send_command(app, "show_pass evil");

    uint32_t start   = furi_get_tick();
    uint32_t last_rx = start;

    while((furi_get_tick() - last_rx) < 1000 &&
          (furi_get_tick() - start)   < 5000 &&
          !d->should_exit) {
        const char* line = uart_read_line(app, 300);
        if(!line) continue;
        last_rx = furi_get_tick();

        // Expect: "ssid", "password"
        const char* p = line;
        while(*p == ' ' || *p == '\t') p++;
        if(*p != '"') continue;
        p++;
        const char* ss = p;
        while(*p && *p != '"') p++;
        if(*p != '"') continue;
        size_t sl = (size_t)(p - ss);
        p++;
        while(*p == ',' || *p == ' ') p++;
        if(*p != '"') continue;
        p++;
        const char* ps = p;
        while(*p && *p != '"') p++;
        if(*p != '"') continue;
        size_t pl = (size_t)(p - ps);

        if(sl == strlen(d->ssid) && strncmp(ss, d->ssid, sl) == 0) {
            if(pl < sizeof(d->password)) {
                strncpy(d->password, ps, pl);
                d->password[pl] = '\0';
                return true;
            }
        }
    }
    return false;
}

static bool wdup_connect_wifi(WdupData* d) {
    WiFiApp* app = d->app;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "wifi_connect %s %s", d->ssid, d->password);
    FURI_LOG_I(TAG, "wifi_connect: ssid=%s", d->ssid);

    uart_clear_buffer(app);
    uart_send_command(app, cmd);

    uint32_t start = furi_get_tick();
    while((furi_get_tick() - start) < WDUP_WIFI_TIMEOUT && !d->should_exit) {
        const char* line = uart_read_line(app, 500);
        if(!line) continue;
        FURI_LOG_I(TAG, "wifi_connect resp: %s", line);
        strncpy(d->status, line, sizeof(d->status) - 1);

        if(strstr(line, "SUCCESS")) {
            app->wifi_connected = true;
            return true;
        }
        if(strstr(line, "FAILED:") || strstr(line, "wrong password") ||
           strstr(line, "not found") || strstr(line, "Unrecognized")) {
            return false;
        }
    }
    return false;
}

// ============================================================================
// Upload one file, return true on success
// ============================================================================

static bool wdup_upload_file(WdupData* d, const char* filepath) {
    WiFiApp* app = d->app;
    char cmd[80];

    if(d->provider == WDUP_WIGLE) {
        snprintf(cmd, sizeof(cmd), "wigle_upload %s", filepath);
    } else {
        snprintf(cmd, sizeof(cmd), "wdgwars_upload %s", filepath);
    }

    FURI_LOG_I(TAG, "upload: %s", cmd);
    wdup_dbg_push(d, cmd);   // show sent command as first dbg line
    uart_clear_buffer(app);
    uart_send_command(app, cmd);

    uint32_t deadline  = furi_get_tick() + WDUP_UPLOAD_TIMEOUT;
    uint32_t last_rx   = furi_get_tick();
#define WDUP_SILENCE_TIMEOUT 45000  // ms of silence before giving up
    bool     got_done  = false;
    bool     got_fatal = false;

    while(furi_get_tick() < deadline && !d->should_exit && !got_done && !got_fatal) {
        const char* line = uart_read_line(app, 500);
        if(!line) {
            if((furi_get_tick() - last_rx) > WDUP_SILENCE_TIMEOUT) break;
            continue;
        }
        last_rx = furi_get_tick();
        FURI_LOG_I(TAG, "upload resp: %s", line);
        strncpy(d->status, line, sizeof(d->status) - 1);
        wdup_dbg_push(d, line);

        if(wdup_is_fatal_error(line)) {
            got_fatal = true;
            break;
        }

        // "Done:" summary — primary terminator, covers all files in batch
        int u = 0, s = 0, f = 0;
        if(wdup_parse_summary(line, &u, &s, &f)) {
            d->total_uploaded += u;
            d->total_skipped  += s;
            d->total_failed   += f;
            got_done = true;
            break;
        }

        // Per-file markers — count but keep reading until Done: arrives
        int marker = wdup_parse_file_marker(line);
        if(marker == 1)  { d->total_uploaded++; got_done = true; /* keep reading */ }
        if(marker == 0)  { d->total_skipped++;  got_done = true; }
        if(marker == -1) { d->total_failed++;   got_done = true; }
    }

    if(got_fatal) {
        d->status[sizeof(d->status) - 1] = '\0';
        return false;
    }

    if(!got_done) {
        d->total_failed++;
        strncpy(d->status, "No response", sizeof(d->status) - 1);
    }

    return !got_fatal;
}

// ============================================================================
// Worker thread
// ============================================================================

static int32_t wdup_thread(void* ctx) {
    WdupData* d = (WdupData*)ctx;
    WiFiApp*  app = d->app;
    FURI_LOG_I(TAG, "Worker started");

    // ── Step 0: provider selection (if not pre-set) ──────────────────────────
    if(d->provider == WDUP_NONE) {
        d->state = WUS_PROVIDER_SELECT;
        d->network_selected = false;
        while(!d->network_selected && !d->should_exit) furi_delay_ms(100);
        if(d->should_exit) return 0;
        d->network_selected = false;
    }

    // ── Step 1: list wardrive files ──────────────────────────────────────────
    d->state = WUS_LISTING_FILES;
    memset(d->dbg, 0, sizeof(d->dbg));
    d->dbg_scroll = 0;
    furi_delay_ms(100);

    for(uint8_t i = 0; i < WDUP_SEARCH_DIR_COUNT && !d->should_exit; i++) {
        wdup_list_dir(d, WDUP_SEARCH_DIRS[i]);
    }

    if(d->should_exit) return 0;

    if(d->file_count == 0) {
        strncpy(d->status, "No wardrive files found", sizeof(d->status) - 1);
        d->state = WUS_ERROR;
        return 0;
    }

    // ── Step 2: user selects files ───────────────────────────────────────────
    d->state       = WUS_FILE_SELECT;
    d->file_cursor = 0;
    d->file_scroll = 0;
    d->network_selected = false;

    while(!d->network_selected && !d->should_exit) furi_delay_ms(100);
    if(d->should_exit) return 0;
    d->network_selected = false;

    // Count selected files
    uint8_t checked = 0;
    for(uint8_t i = 0; i < d->file_count; i++) if(d->files[i].checked) checked++;
    if(checked == 0) {
        strncpy(d->status, "No files selected", sizeof(d->status) - 1);
        d->state = WUS_ERROR;
        return 0;
    }

    // ── Step 3: check API key ────────────────────────────────────────────────
    d->state = WUS_CHECKING_KEY;
    furi_delay_ms(100);
    uart_clear_buffer(app);
    uart_send_command(app,
        d->provider == WDUP_WIGLE ? "wigle_key read" : "wdgwars_key read");

    bool key_ok = false;
    uint32_t deadline = furi_get_tick() + WDUP_KEY_TIMEOUT;
    while(furi_get_tick() < deadline && !d->should_exit) {
        const char* line = uart_read_line(app, 500);
        if(!line) continue;
        FURI_LOG_I(TAG, "key check: %s", line);
        if(strstr(line, "not set") || strstr(line, "NO ")) {
            d->state = WUS_NO_KEY;
            return 0;
        }
        // Any non-error response that contains the key name = found
        if(strstr(line, "key:") || strstr(line, "KEY") || strstr(line, "=")) {
            key_ok = true;
            break;
        }
    }
    if(d->should_exit) return 0;
    if(!key_ok) { d->state = WUS_NO_KEY; return 0; }

    // ── Step 4: SD card ──────────────────────────────────────────────────────
    if(!app->sd_card_ok) { d->state = WUS_NO_SD; return 0; }

    // ── Step 5: WiFi ─────────────────────────────────────────────────────────
    if(!app->wifi_connected) {

        // 5a. scan
        d->state = WUS_SCANNING_WIFI;
        uart_start_scan(app);

        deadline = furi_get_tick() + WDUP_SCAN_TIMEOUT;
        while(app->scanning_in_progress && !d->should_exit &&
              furi_get_tick() < deadline) {
            furi_delay_ms(200);
        }
        if(d->should_exit) return 0;

        if(app->scan_result_count == 0) {
            strncpy(d->status, "No WiFi networks found", sizeof(d->status) - 1);
            d->state = WUS_ERROR;
            return 0;
        }

        // 5b. user picks network
        d->state = WUS_WIFI_LIST;
        d->wifi_cursor = 0;
        d->network_selected = false;

        while(!d->network_selected && !d->should_exit) furi_delay_ms(100);
        if(d->should_exit) return 0;
        d->network_selected = false;

        // 5c. manual SSID if "Other..."
        if(d->manual_ssid_mode) {
            d->state = WUS_MANUAL_SSID;
            d->text_entered = false;
            wdup_show_text_input(d, "SSID:", d->ssid, sizeof(d->ssid));
            while(!d->text_entered && !d->should_exit) furi_delay_ms(100);
            if(d->should_exit) return 0;
            d->text_entered = false;
            // Go straight to password input (no evil-twin lookup for unknown SSIDs)
            d->state = WUS_PASSWORD_INPUT;
            d->text_entered = false;
            wdup_show_text_input(d, "Password:", d->password, sizeof(d->password));
            while(!d->text_entered && !d->should_exit) furi_delay_ms(100);
            if(d->should_exit) return 0;
            d->text_entered = false;
        } else {
            // 5d. try evil-twin password
            d->state = WUS_CHECKING_PASS;
            bool pw_found = wdup_check_evil_password(d);
            if(d->should_exit) return 0;

            if(!pw_found) {
                d->state = WUS_PASSWORD_INPUT;
                d->text_entered = false;
                wdup_show_text_input(d, "WiFi Password:", d->password, sizeof(d->password));
                while(!d->text_entered && !d->should_exit) furi_delay_ms(100);
                if(d->should_exit) return 0;
                d->text_entered = false;
            }
        }

        // 5e. connect
        d->state = WUS_CONNECTING;
        d->connect_failed = false;
        if(!wdup_connect_wifi(d)) {
            d->connect_failed = true;
            d->state = WUS_ERROR;
            if(!d->status[0])
                strncpy(d->status, "WiFi connection failed", sizeof(d->status) - 1);
            while(!d->should_exit) furi_delay_ms(100);
            return 0;
        }
    }

    // ── Step 6: upload ───────────────────────────────────────────────────────
    // Firmware uploads all specified files in one batch per command call.
    // We call once per checked file; firmware may respond with a combined
    // "Done: X uploaded, Y skipped, Z failed" covering all files in the batch.
    d->state          = WUS_UPLOADING;
    d->upload_total   = checked;
    d->upload_current = 0;
    d->total_uploaded = 0;
    d->total_skipped  = 0;
    d->total_failed   = 0;
    memset(d->dbg, 0, sizeof(d->dbg));
    d->dbg_scroll = 0;

    uint8_t cur = 0;
    for(uint8_t i = 0; i < d->file_count && !d->should_exit; i++) {
        if(!d->files[i].checked) continue;

        d->upload_current = cur++;
        snprintf(d->status, sizeof(d->status), "%.22s", d->files[i].name);

        bool ok = wdup_upload_file(d, d->files[i].path);
        if(!ok && wdup_is_fatal_error(d->status)) {
            d->state = WUS_ERROR;
            FURI_LOG_E(TAG, "Fatal upload error: %s", d->status);
            return 0;
        }

        // If firmware returned a Done: summary covering all files, stop here
        if(d->total_uploaded + d->total_skipped + d->total_failed >= checked) break;
    }

    if(d->should_exit) return 0;

    d->state = WUS_DONE;
    snprintf(d->status, sizeof(d->status), "up:%d sk:%d fail:%d",
             d->total_uploaded, d->total_skipped, d->total_failed);
    FURI_LOG_I(TAG, "Upload complete: %s", d->status);
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* wardrive_upload_screen_create(WiFiApp* app, void** out_data, WdupProvider provider) {
    WdupData* data = (WdupData*)malloc(sizeof(WdupData));
    if(!data) return NULL;
    memset(data, 0, sizeof(WdupData));

    data->app      = app;
    data->provider = provider;
    data->state    = (provider == WDUP_NONE) ? WUS_PROVIDER_SELECT : WUS_LISTING_FILES;

    data->files = (WdupFile*)malloc(sizeof(WdupFile) * WDUP_MAX_FILES);
    if(!data->files) { free(data); return NULL; }
    memset(data->files, 0, sizeof(WdupFile) * WDUP_MAX_FILES);

    View* view = view_alloc();
    if(!view) { free(data->files); free(data); return NULL; }
    data->main_view = view;

    view_allocate_model(view, ViewModelTypeLocking, sizeof(WdupModel));
    WdupModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, wdup_draw);
    view_set_input_callback(view, wdup_input);
    view_set_context(view, view);

    // TextInput for WiFi credential entry
    data->text_input = text_input_alloc();
    if(data->text_input) {
        // callback and buffer set just before showing
        FURI_LOG_I(TAG, "TextInput allocated");
    }

    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "WdupUpload");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, wdup_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;
    return view;
}

// ============================================================================
// Parser tests  (compile with -DWDUP_TEST and run standalone)
// ============================================================================
#ifdef WDUP_TEST
#include <assert.h>
/*
 * Test: wdup_parse_summary
 *
 *  Input: "Done: 3 uploaded, 1 duplicate, 0 failed"
 *  Expected: uploaded+=3, skipped+=1, failed+=0  → true
 *
 *  Input: "uploaded=5 failed=2 skipped=0"
 *  Expected: uploaded+=5, skipped+=0, failed+=2  → true
 *
 *  Input: "-> OK"
 *  Expected: no summary, returns false; wdup_parse_file_marker returns 1
 *
 *  Input: "-> skipped"
 *  Expected: wdup_parse_file_marker returns 0
 *
 *  Input: "-> FAILED"
 *  Expected: wdup_parse_file_marker returns -1
 *
 *  Input: "Unrecognized command"
 *  Expected: wdup_is_fatal_error returns true
 *
 *  Input: "NO WIGLE_CREDENTIALS"
 *  Expected: wdup_is_fatal_error returns true
 */
static void wdup_run_tests(void) {
    int u, s, f;

    u = s = f = 0;
    assert(wdup_parse_summary("Done: 3 uploaded, 1 duplicate, 0 failed", &u, &s, &f));
    assert(u == 3 && s == 1 && f == 0);

    u = s = f = 0;
    assert(wdup_parse_summary("uploaded=5 failed=2 skipped=0", &u, &s, &f));
    assert(u == 5 && f == 2 && s == 0);

    u = s = f = 0;
    assert(!wdup_parse_summary("-> OK", &u, &s, &f));
    assert(wdup_parse_file_marker("-> OK")      ==  1);
    assert(wdup_parse_file_marker("-> skipped") ==  0);
    assert(wdup_parse_file_marker("-> FAILED")  == -1);
    assert(wdup_parse_file_marker("random line") == -2);

    assert(wdup_is_fatal_error("Unrecognized command foo"));
    assert(wdup_is_fatal_error("NO WIGLE_CREDENTIALS"));
    assert(wdup_is_fatal_error("WDGWARS AUTH FAILED"));
    assert(!wdup_is_fatal_error("Upload complete"));
}
#endif // WDUP_TEST

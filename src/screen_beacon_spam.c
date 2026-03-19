/**
 * Beacon Spam Screen
 *
 * Submenu with two options:
 *   - Edit SSID List: scrollable list from list_ssids, add/remove SSIDs
 *   - Start Attack: sends start_beacon_spam_ssids, shows attack-in-progress
 *
 * UART commands:
 *   list_ssids, add_ssid <name>, remove_ssid <index>,
 *   start_beacon_spam_ssids, stop
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <gui/modules/text_input.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>
#include <ctype.h>

#define TAG "BeaconSpam"

// ============================================================================
// Forward declarations
// ============================================================================

static View* beacon_ssid_list_create(WiFiApp* app, void** out_data);
static void beacon_ssid_list_cleanup(View* view, void* data);
static View* beacon_attack_create(WiFiApp* app, void** out_data);
static void beacon_attack_cleanup(View* view, void* data);

// ============================================================================
// A. Beacon Spam Submenu
// ============================================================================

typedef struct {
    WiFiApp* app;
} BeaconSpamMenuData;

typedef struct {
    BeaconSpamMenuData* data;
    uint8_t selected;
} BeaconSpamMenuModel;

static void beacon_spam_menu_draw_cb(Canvas* canvas, void* model) {
    BeaconSpamMenuModel* m = (BeaconSpamMenuModel*)model;
    if(!m || !m->data) return;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Beacon Spam");

    const char* items[] = {"Edit SSID List", "Start Attack"};
    const uint8_t item_count = 2;

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

static bool beacon_spam_menu_input_cb(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    BeaconSpamMenuModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    WiFiApp* app = m->data->app;

    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }

    if(event->key == InputKeyUp) {
        if(m->selected > 0) m->selected--;
    } else if(event->key == InputKeyDown) {
        if(m->selected < 1) m->selected++;
    } else if(event->key == InputKeyOk) {
        uint8_t sel = m->selected;
        view_commit_model(view, false);

        View* next = NULL;
        void* data = NULL;
        void (*cleanup)(View*, void*) = NULL;

        if(sel == 0) {
            next = beacon_ssid_list_create(app, &data);
            cleanup = beacon_ssid_list_cleanup;
        } else if(sel == 1) {
            next = beacon_attack_create(app, &data);
            cleanup = beacon_attack_cleanup;
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

static void beacon_spam_menu_cleanup_impl(View* view, void* data) {
    UNUSED(view);
    BeaconSpamMenuData* d = (BeaconSpamMenuData*)data;
    if(d) free(d);
}

View* beacon_spam_menu_create(WiFiApp* app, void** out_data) {
    BeaconSpamMenuData* data = (BeaconSpamMenuData*)malloc(sizeof(BeaconSpamMenuData));
    if(!data) return NULL;
    data->app = app;

    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }

    view_allocate_model(view, ViewModelTypeLocking, sizeof(BeaconSpamMenuModel));
    BeaconSpamMenuModel* m = view_get_model(view);
    m->data = data;
    m->selected = 0;
    view_commit_model(view, true);

    view_set_draw_callback(view, beacon_spam_menu_draw_cb);
    view_set_input_callback(view, beacon_spam_menu_input_cb);
    view_set_context(view, view);

    if(out_data) *out_data = data;
    return view;
}

void beacon_spam_menu_cleanup(View* view, void* data) {
    beacon_spam_menu_cleanup_impl(view, data);
}

// ============================================================================
// B. SSID List Screen
// ============================================================================

#define SSID_MAX_COUNT   64
#define SSID_MAX_LEN     33
#define SSID_TEXT_INPUT_ID 999

typedef struct {
    WiFiApp* app;
    volatile bool finished;

    char ssids[SSID_MAX_COUNT][SSID_MAX_LEN];
    uint8_t ssid_count;
    uint8_t selected;
    bool loaded;

    char new_ssid[SSID_MAX_LEN];
    bool ssid_entered;
    bool adding;
    bool deleting;

    FuriThread* thread;
    TextInput* text_input;
    bool text_input_added;
    View* main_view;
} SsidListData;

typedef struct {
    SsidListData* data;
} SsidListModel;

static void ssid_list_load(SsidListData* data) {
    WiFiApp* app = data->app;
    data->ssid_count = 0;

    uart_clear_buffer(app);
    uart_send_command(app, "list_ssids");
    furi_delay_ms(200);

    uint32_t start = furi_get_tick();
    uint32_t last_rx = start;

    while((furi_get_tick() - last_rx) < 1500 &&
          (furi_get_tick() - start) < 5000 &&
          !data->finished) {
        const char* line = uart_read_line(app, 300);
        if(line) {
            last_rx = furi_get_tick();
            FURI_LOG_I(TAG, "list_ssids: %s", line);

            const char* p = line;
            while(*p == ' ') p++;
            if(isdigit((unsigned char)*p) && data->ssid_count < SSID_MAX_COUNT) {
                while(isdigit((unsigned char)*p)) p++;
                while(*p == ' ') p++;
                if(*p != '\0') {
                    strncpy(data->ssids[data->ssid_count], p, SSID_MAX_LEN - 1);
                    data->ssids[data->ssid_count][SSID_MAX_LEN - 1] = '\0';
                    size_t len = strlen(data->ssids[data->ssid_count]);
                    while(len > 0 && (data->ssids[data->ssid_count][len - 1] == '\n' ||
                                      data->ssids[data->ssid_count][len - 1] == '\r' ||
                                      data->ssids[data->ssid_count][len - 1] == ' ')) {
                        data->ssids[data->ssid_count][--len] = '\0';
                    }
                    data->ssid_count++;
                }
            }
        }
    }
    data->loaded = true;
    FURI_LOG_I(TAG, "Loaded %u SSIDs", data->ssid_count);
}

static int32_t ssid_list_thread(void* context) {
    SsidListData* data = (SsidListData*)context;

    ssid_list_load(data);

    while(!data->finished) {
        if(data->adding && data->ssid_entered) {
            data->adding = false;
            data->ssid_entered = false;

            if(data->new_ssid[0]) {
                char cmd[64];
                snprintf(cmd, sizeof(cmd), "add_ssid \"%s\"", data->new_ssid);
                FURI_LOG_I(TAG, "Sending: %s", cmd);
                uart_send_command(data->app, cmd);
                furi_delay_ms(500);
                uart_clear_buffer(data->app);
            }
            data->loaded = false;
            ssid_list_load(data);

        } else if(data->deleting) {
            data->deleting = false;

            if(data->ssid_count > 0 && data->selected < data->ssid_count) {
                char cmd[32];
                snprintf(cmd, sizeof(cmd), "remove_ssid %u", data->selected + 1);
                FURI_LOG_I(TAG, "Sending: %s", cmd);
                uart_send_command(data->app, cmd);
                furi_delay_ms(500);
                uart_clear_buffer(data->app);

                data->loaded = false;
                ssid_list_load(data);

                if(data->selected > 0 && data->selected >= data->ssid_count) {
                    data->selected = data->ssid_count - 1;
                }
            }
        } else {
            furi_delay_ms(100);
        }
    }

    FURI_LOG_I(TAG, "SSID list thread finished");
    return 0;
}

static void ssid_add_callback(void* context) {
    SsidListData* data = (SsidListData*)context;
    if(!data || !data->app) return;

    FURI_LOG_I(TAG, "SSID entered: %s", data->new_ssid);
    data->ssid_entered = true;

    uint32_t main_view_id = screen_get_current_view_id();
    view_dispatcher_switch_to_view(data->app->view_dispatcher, main_view_id);
}

static void ssid_show_text_input(SsidListData* data) {
    if(!data || !data->text_input) return;

    if(!data->text_input_added) {
        View* ti_view = text_input_get_view(data->text_input);
        view_dispatcher_add_view(data->app->view_dispatcher, SSID_TEXT_INPUT_ID, ti_view);
        data->text_input_added = true;
    }

    memset(data->new_ssid, 0, sizeof(data->new_ssid));
    view_dispatcher_switch_to_view(data->app->view_dispatcher, SSID_TEXT_INPUT_ID);
}

static void ssid_list_draw(Canvas* canvas, void* model) {
    SsidListModel* m = (SsidListModel*)model;
    if(!m || !m->data) return;
    SsidListData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "SSID List");

    canvas_set_font(canvas, FontSecondary);

    if(!data->loaded) {
        screen_draw_centered_text(canvas, "Loading...", 32);
        return;
    }

    if(data->ssid_count == 0) {
        screen_draw_centered_text(canvas, "No SSIDs", 28);
        screen_draw_centered_text(canvas, "OK to add", 42);
        return;
    }

    const uint8_t max_visible = 5;
    uint8_t start = 0;
    if(data->selected >= max_visible) {
        start = data->selected - max_visible + 1;
    }

    for(uint8_t i = start; i < data->ssid_count && (i - start) < max_visible; i++) {
        uint8_t y = 20 + ((i - start) * 9);
        char line[40];
        snprintf(line, sizeof(line), "%u %.32s", i + 1, data->ssids[i]);

        if(i == data->selected) {
            canvas_draw_box(canvas, 0, y - 7, 128, 9);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, 2, y, line);
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_draw_str(canvas, 2, y, line);
        }
    }

    canvas_draw_str(canvas, 2, 62, "OK:Add");
    canvas_draw_str(canvas, 70, 62, "Right:Del");
}

static bool ssid_list_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    SsidListModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    SsidListData* data = m->data;

    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }

    if(event->key == InputKeyUp) {
        if(data->selected > 0) data->selected--;
    } else if(event->key == InputKeyDown) {
        if(data->ssid_count > 0 && data->selected < data->ssid_count - 1) data->selected++;
    } else if(event->key == InputKeyOk) {
        data->adding = true;
        data->ssid_entered = false;
        view_commit_model(view, false);
        ssid_show_text_input(data);
        return true;
    } else if(event->key == InputKeyRight) {
        if(data->ssid_count > 0) {
            data->deleting = true;
        }
    } else if(event->key == InputKeyBack) {
        data->finished = true;
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }

    view_commit_model(view, true);
    return true;
}

static void ssid_list_cleanup_impl(View* view, void* data_ptr) {
    UNUSED(view);
    SsidListData* data = (SsidListData*)data_ptr;
    if(!data) return;

    FURI_LOG_I(TAG, "SSID list cleanup");
    data->finished = true;
    if(data->thread) {
        furi_thread_join(data->thread);
        furi_thread_free(data->thread);
    }
    if(data->text_input) {
        if(data->text_input_added) {
            view_dispatcher_remove_view(data->app->view_dispatcher, SSID_TEXT_INPUT_ID);
        }
        text_input_free(data->text_input);
    }
    free(data);
}

static void beacon_ssid_list_cleanup(View* view, void* data) {
    ssid_list_cleanup_impl(view, data);
}

static View* beacon_ssid_list_create(WiFiApp* app, void** out_data) {
    FURI_LOG_I(TAG, "Creating SSID list screen");

    SsidListData* data = (SsidListData*)malloc(sizeof(SsidListData));
    if(!data) return NULL;

    memset(data, 0, sizeof(SsidListData));
    data->app = app;
    data->finished = false;
    data->loaded = false;
    data->selected = 0;

    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    data->main_view = view;

    view_allocate_model(view, ViewModelTypeLocking, sizeof(SsidListModel));
    SsidListModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, ssid_list_draw);
    view_set_input_callback(view, ssid_list_input);
    view_set_context(view, view);

    data->text_input = text_input_alloc();
    if(data->text_input) {
        text_input_set_header_text(data->text_input, "Enter SSID:");
        text_input_set_result_callback(
            data->text_input,
            ssid_add_callback,
            data,
            data->new_ssid,
            SSID_MAX_LEN - 1,
            true);
    }

    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "SSIDList");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, ssid_list_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;
    return view;
}

// ============================================================================
// C. Attack Running Screen
// ============================================================================

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state; // 0=starting, 1=running
    FuriThread* thread;
} BeaconAttackData;

typedef struct {
    BeaconAttackData* data;
} BeaconAttackModel;

static void beacon_attack_draw_cb(Canvas* canvas, void* model) {
    BeaconAttackModel* m = (BeaconAttackModel*)model;
    if(!m || !m->data) return;
    BeaconAttackData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Beacon Spam");

    canvas_set_font(canvas, FontSecondary);

    if(data->state == 0) {
        screen_draw_centered_text(canvas, "Starting attack...", 32);
    } else {
        screen_draw_centered_text(canvas, "Attack in progress", 32);
        canvas_draw_str(canvas, 2, 50, "Press Back to stop");
    }
}

static bool beacon_attack_input_cb(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    BeaconAttackModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    BeaconAttackData* data = m->data;

    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }

    if(event->key == InputKeyBack) {
        data->attack_finished = true;
        uart_send_command(data->app, "stop");
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }

    view_commit_model(view, false);
    return true;
}

static int32_t beacon_attack_thread(void* context) {
    BeaconAttackData* data = (BeaconAttackData*)context;
    WiFiApp* app = data->app;

    FURI_LOG_I(TAG, "Beacon attack thread started");

    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "start_beacon_spam_ssids");

    uint32_t start = furi_get_tick();
    while((furi_get_tick() - start) < 10000 && !data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            FURI_LOG_I(TAG, "beacon: %s", line);
            if(strstr(line, "Beacon spam started")) {
                data->state = 1;
                break;
            }
        }
    }

    if(!data->attack_finished && data->state == 0) {
        data->state = 1;
    }

    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 100);
        if(line) {
            FURI_LOG_I(TAG, "beacon output: %s", line);
        }
    }

    FURI_LOG_I(TAG, "Beacon attack thread finished");
    return 0;
}

static void beacon_attack_cleanup_impl(View* view, void* data_ptr) {
    UNUSED(view);
    BeaconAttackData* data = (BeaconAttackData*)data_ptr;
    if(!data) return;

    data->attack_finished = true;
    if(data->thread) {
        furi_thread_join(data->thread);
        furi_thread_free(data->thread);
    }
    free(data);
}

static void beacon_attack_cleanup(View* view, void* data) {
    beacon_attack_cleanup_impl(view, data);
}

static View* beacon_attack_create(WiFiApp* app, void** out_data) {
    FURI_LOG_I(TAG, "Creating beacon attack screen");

    BeaconAttackData* data = (BeaconAttackData*)malloc(sizeof(BeaconAttackData));
    if(!data) return NULL;

    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    data->thread = NULL;

    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }

    view_allocate_model(view, ViewModelTypeLocking, sizeof(BeaconAttackModel));
    BeaconAttackModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, beacon_attack_draw_cb);
    view_set_input_callback(view, beacon_attack_input_cb);
    view_set_context(view, view);

    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "BeaconAtk");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, beacon_attack_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;
    return view;
}

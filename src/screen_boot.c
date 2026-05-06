/**
 * Boot Screen
 *
 * Shows a live progress log while the application powers up the ESP32 board
 * and verifies UART connectivity. Steps:
 *   1. Enable 5V power (OTG)
 *   2. Initialize UART
 *   3. Wait for board boot (visible countdown)
 *   4. Probe board (ping/pong with retries)
 *   5. Board detected
 *   6. Check SD card (best-effort, never blocks success)
 *
 * On full success the worker thread posts BOOT_EVENT_DONE through the
 * ViewDispatcher custom event queue, which the app handler turns into a
 * "pop boot, push main menu" transition.
 *
 * On failure the user can press OK to continue without the board (sends
 * BOOT_EVENT_CONTINUE) or BACK to exit (BOOT_EVENT_CANCELLED).
 */

#include "screen_boot.h"
#include "uart_comm.h"
#include "screen.h"
#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_power.h>
#include <gui/view_dispatcher.h>
#include <power/power_service/power.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define TAG "BootScreen"

#define BOOT_STEP_COUNT          6
#define BOOT_BOOT_WAIT_MS        2000
#define BOOT_PING_ATTEMPTS       6
#define BOOT_PING_TIMEOUT_MS     700
#define BOOT_PING_INTER_DELAY_MS 200
#define BOOT_SUCCESS_DWELL_MS    400

typedef enum {
    BootStepPending = 0,
    BootStepInProgress,
    BootStepDone,
    BootStepFailed,
} BootStepState;

typedef enum {
    BootPhaseRunning = 0,
    BootPhaseSuccess,
    BootPhaseFailed,
} BootPhase;

typedef struct {
    WiFiApp* app;

    FuriThread* thread;
    volatile bool cancel;     // set by BACK / cleanup
    volatile bool finished;   // set by worker when done (success or failure)

    BootStepState step_state[BOOT_STEP_COUNT];
    char step_label[BOOT_STEP_COUNT][40];
    uint8_t spinner_phase;
    BootPhase phase;
    uint32_t ping_attempt;    // 1-based current attempt for status display

    View* main_view;
} BootData;

typedef struct {
    BootData* data;
} BootModel;

static const char* const BOOT_STEP_NAMES[BOOT_STEP_COUNT] = {
    "5V power",
    "Init UART",
    "Wait boot",
    "Probe board",
    "Board detected",
    "Check SD card",
};

// ============================================================================
// Drawing helpers
// ============================================================================

static char boot_status_glyph(BootStepState s, uint8_t spinner_phase) {
    switch(s) {
    case BootStepDone: return 'v';
    case BootStepFailed: return 'x';
    case BootStepInProgress: {
        static const char spin[] = {'|', '/', '-', '\\'};
        return spin[spinner_phase & 0x3];
    }
    case BootStepPending:
    default: return ' ';
    }
}

static void boot_draw(Canvas* canvas, void* model) {
    BootModel* m = (BootModel*)model;
    if(!m || !m->data) return;
    BootData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "C5Lab boot");

    canvas_set_font(canvas, FontSecondary);

    uint8_t y = 21;
    for(uint8_t i = 0; i < BOOT_STEP_COUNT; i++) {
        char glyph = boot_status_glyph(data->step_state[i], data->spinner_phase);
        char line[64];
        const char* label = data->step_label[i][0] ? data->step_label[i] : BOOT_STEP_NAMES[i];
        snprintf(line, sizeof(line), "[%c] %s", glyph, label);
        canvas_draw_str(canvas, 2, y, line);
        y += 8;
    }

    if(data->phase == BootPhaseFailed) {
        canvas_draw_line(canvas, 0, 60, 128, 60);
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 68, "OK=continue BACK=exit");
    }
}

// ============================================================================
// Input
// ============================================================================

static bool boot_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    BootModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    BootData* data = m->data;
    WiFiApp* app = data->app;

    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }

    if(data->phase == BootPhaseRunning) {
        if(event->key == InputKeyBack) {
            data->cancel = true;
            view_commit_model(view, false);
            view_dispatcher_send_custom_event(app->view_dispatcher, BOOT_EVENT_CANCELLED);
            return true;
        }
    } else if(data->phase == BootPhaseFailed) {
        if(event->key == InputKeyOk) {
            view_commit_model(view, false);
            view_dispatcher_send_custom_event(app->view_dispatcher, BOOT_EVENT_CONTINUE);
            return true;
        }
        if(event->key == InputKeyBack) {
            data->cancel = true;
            view_commit_model(view, false);
            view_dispatcher_send_custom_event(app->view_dispatcher, BOOT_EVENT_CANCELLED);
            return true;
        }
    } else if(data->phase == BootPhaseSuccess) {
        // Defensive: in normal flow the boot screen is removed from the stack
        // immediately after BOOT_EVENT_DONE. If for any reason it is still
        // reachable (e.g. user navigates back through everything), make sure
        // BACK / OK still let the user exit instead of being trapped here.
        if(event->key == InputKeyBack || event->key == InputKeyOk) {
            view_commit_model(view, false);
            view_dispatcher_send_custom_event(app->view_dispatcher, BOOT_EVENT_CANCELLED);
            return true;
        }
    }

    view_commit_model(view, false);
    return true;
}

// ============================================================================
// Model mutation helpers (always go through view_commit_model so the GUI
// thread re-renders).
// ============================================================================

static void boot_set_step(BootData* data, uint8_t idx, BootStepState s, const char* label) {
    if(idx >= BOOT_STEP_COUNT || !data->main_view) return;
    BootModel* m = view_get_model(data->main_view);
    if(m && m->data) {
        m->data->step_state[idx] = s;
        if(label) {
            strncpy(m->data->step_label[idx], label, sizeof(m->data->step_label[idx]) - 1);
            m->data->step_label[idx][sizeof(m->data->step_label[idx]) - 1] = '\0';
        } else {
            m->data->step_label[idx][0] = '\0';
        }
    }
    view_commit_model(data->main_view, true);
}

static void boot_set_phase(BootData* data, BootPhase phase) {
    if(!data->main_view) return;
    BootModel* m = view_get_model(data->main_view);
    if(m && m->data) m->data->phase = phase;
    view_commit_model(data->main_view, true);
}

static void boot_set_ping_attempt(BootData* data, uint32_t attempt) {
    if(!data->main_view) return;
    BootModel* m = view_get_model(data->main_view);
    if(m && m->data) m->data->ping_attempt = attempt;
    view_commit_model(data->main_view, true);
}

static void boot_tick_spinner(BootData* data) {
    if(!data->main_view) return;
    BootModel* m = view_get_model(data->main_view);
    if(m && m->data) m->data->spinner_phase++;
    view_commit_model(data->main_view, true);
}

// Cancel-aware delay: sleeps in ~50ms slices, returns false if cancel was raised.
static bool boot_sleep(BootData* data, uint32_t ms) {
    const uint32_t slice = 50;
    uint32_t remaining = ms;
    while(remaining > 0) {
        if(data->cancel) return false;
        uint32_t s = remaining > slice ? slice : remaining;
        furi_delay_ms(s);
        remaining -= s;
    }
    return !data->cancel;
}

// ============================================================================
// Worker thread
// ============================================================================

static int32_t boot_worker(void* context) {
    BootData* data = (BootData*)context;
    if(!data || !data->app) return -1;
    WiFiApp* app = data->app;

    FURI_LOG_I(TAG, "Boot worker started");

    // ---------------- Step 1: enable 5V power ----------------
    // Use power service (RECORD_POWER) instead of furi_hal directly:
    // - On battery: it retries OTG enable up to 5x (BQ25896 boost converter
    //   often needs more than one attempt to lock in).
    // - On USB cable (VBUS >= 4.5V): it intentionally skips OTG because the
    //   board is already powered from USB - we still treat that as success.
    boot_set_step(data, 0, BootStepInProgress, "5V power...");
    bool was_on = furi_hal_power_is_otg_enabled();
    if(!was_on) {
        Power* power = furi_record_open(RECORD_POWER);
        power_enable_otg(power, true);
        furi_record_close(RECORD_POWER);

        // Power service kicks retries asynchronously; poll up to ~600 ms for
        // the actual hardware state. Done in 50 ms slices so BACK stays snappy.
        for(int i = 0; i < 12; i++) {
            if(data->cancel) goto cancelled;
            if(furi_hal_power_is_otg_enabled()) break;
            furi_delay_ms(50);
        }
    }
    if(furi_hal_power_is_otg_enabled() || was_on) {
        boot_set_step(data, 0, BootStepDone, was_on ? "5V power (already on)" : "5V power on");
    } else {
        // OTG didn't lock in. Don't fail outright - on USB the board still has
        // VBUS, and the ping in step 4 is the real authoritative liveness test.
        boot_set_step(data, 0, BootStepFailed, "5V power: OTG not confirmed");
    }
    if(data->cancel) goto cancelled;

    // ---------------- Step 2: init UART ----------------
    boot_set_step(data, 1, BootStepInProgress, "Init UART...");
    uart_comm_init(app);
    if(!app->serial) {
        boot_set_step(data, 1, BootStepFailed, "Init UART: serial busy");
        FURI_LOG_E(TAG, "Failed to acquire serial handle");
        boot_set_phase(data, BootPhaseFailed);
        data->finished = true;
        view_dispatcher_send_custom_event(app->view_dispatcher, BOOT_EVENT_FAILED);
        return 0;
    }
    boot_set_step(data, 1, BootStepDone, "Init UART (115200)");
    if(data->cancel) goto cancelled;

    // ---------------- Step 3: wait for board boot with countdown ----------------
    boot_set_step(data, 2, BootStepInProgress, "Wait boot 2.0s");
    {
        const uint32_t step_ms = 100;
        uint32_t elapsed = 0;
        while(elapsed < BOOT_BOOT_WAIT_MS) {
            if(data->cancel) goto cancelled;
            uint32_t remaining = BOOT_BOOT_WAIT_MS - elapsed;
            char buf[32];
            snprintf(buf, sizeof(buf), "Wait boot %lu.%lus",
                (unsigned long)(remaining / 1000),
                (unsigned long)((remaining % 1000) / 100));
            // Update label and tick spinner together to keep the UI alive.
            BootModel* m = view_get_model(data->main_view);
            if(m && m->data) {
                strncpy(m->data->step_label[2], buf, sizeof(m->data->step_label[2]) - 1);
                m->data->step_label[2][sizeof(m->data->step_label[2]) - 1] = '\0';
                m->data->spinner_phase++;
            }
            view_commit_model(data->main_view, true);
            furi_delay_ms(step_ms);
            elapsed += step_ms;
        }
    }
    // Drain any boot-time noise the ESP printed during the wait.
    uart_clear_buffer(app);
    boot_set_step(data, 2, BootStepDone, "Wait boot 2.0s");

    // ---------------- Step 4: probe board (ping/pong, retries) ----------------
    boot_set_step(data, 3, BootStepInProgress, "Probe board (1/6)");
    bool pong = false;
    for(uint32_t attempt = 1; attempt <= BOOT_PING_ATTEMPTS && !data->cancel; attempt++) {
        boot_set_ping_attempt(data, attempt);
        {
            char buf[40];
            snprintf(buf, sizeof(buf), "Probe board (%lu/%u)",
                (unsigned long)attempt, BOOT_PING_ATTEMPTS);
            boot_set_step(data, 3, BootStepInProgress, buf);
        }

        if(uart_ping_once(app, BOOT_PING_TIMEOUT_MS)) {
            pong = true;
            break;
        }
        boot_tick_spinner(data);
        if(!boot_sleep(data, BOOT_PING_INTER_DELAY_MS)) goto cancelled;
    }
    if(data->cancel) goto cancelled;

    if(!pong) {
        boot_set_step(data, 3, BootStepFailed, "Probe board: no pong");
        boot_set_step(data, 4, BootStepFailed, "Board not detected");
        boot_set_step(data, 5, BootStepPending, NULL);
        boot_set_phase(data, BootPhaseFailed);
        data->finished = true;
        FURI_LOG_W(TAG, "Board did not respond after %u attempts", BOOT_PING_ATTEMPTS);
        view_dispatcher_send_custom_event(app->view_dispatcher, BOOT_EVENT_FAILED);
        return 0;
    }
    {
        char buf[40];
        snprintf(buf, sizeof(buf), "Probe board OK (%lu/%u)",
            (unsigned long)data->ping_attempt, BOOT_PING_ATTEMPTS);
        boot_set_step(data, 3, BootStepDone, buf);
    }

    // ---------------- Step 5: board detected ----------------
    boot_set_step(data, 4, BootStepDone, "Board detected");
    app->board_connected = true;
    if(data->cancel) goto cancelled;

    // ---------------- Step 6: SD card check (best-effort, optional) ----------------
    boot_set_step(data, 5, BootStepInProgress, "Check SD card...");
    bool sd_ok = uart_check_sd_card(app);
    app->sd_card_ok = sd_ok;
    app->sd_card_checked = true;
    boot_set_step(data, 5, sd_ok ? BootStepDone : BootStepFailed,
        sd_ok ? "SD card OK" : "SD card not found");
    if(data->cancel) goto cancelled;

    // ---------------- Done ----------------
    boot_set_phase(data, BootPhaseSuccess);
    data->finished = true;
    boot_sleep(data, BOOT_SUCCESS_DWELL_MS); // let user read the final state
    if(data->cancel) goto cancelled;

    FURI_LOG_I(TAG, "Boot complete, posting BOOT_EVENT_DONE");
    view_dispatcher_send_custom_event(app->view_dispatcher, BOOT_EVENT_DONE);
    return 0;

cancelled:
    FURI_LOG_I(TAG, "Boot cancelled");
    data->finished = true;
    return 0;
}

// ============================================================================
// Cleanup
// ============================================================================

void screen_boot_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    BootData* d = (BootData*)data;
    if(!d) return;

    FURI_LOG_I(TAG, "Boot cleanup starting");

    d->cancel = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
        d->thread = NULL;
    }

    free(d);
    FURI_LOG_I(TAG, "Boot cleanup complete");
}

// ============================================================================
// Screen creation
// ============================================================================

View* screen_boot_create(WiFiApp* app, void** out_data) {
    if(!app) return NULL;

    BootData* data = (BootData*)malloc(sizeof(BootData));
    if(!data) return NULL;
    memset(data, 0, sizeof(BootData));
    data->app = app;
    for(uint8_t i = 0; i < BOOT_STEP_COUNT; i++) {
        data->step_state[i] = BootStepPending;
        data->step_label[i][0] = '\0';
    }
    data->phase = BootPhaseRunning;

    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    data->main_view = view;

    view_allocate_model(view, ViewModelTypeLocking, sizeof(BootModel));
    BootModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, boot_draw);
    view_set_input_callback(view, boot_input);
    view_set_context(view, view);

    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "C5LabBoot");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, boot_worker);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;
    return view;
}

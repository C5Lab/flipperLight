#include "app.h"
#include "uart_comm.h"
#include "screen_main_menu.h"
#include "screen_boot.h"
#include "screen.h"
#include <furi_hal.h>
#include <furi_hal_power.h>
#include <storage/storage.h>
#include <string.h>

// ============================================================================
// Custom event handler
//
// Boot screen worker thread posts BOOT_EVENT_* to drive the post-boot
// transition. We MUST NOT call screen_pop / push directly from inside the
// boot worker thread - those manipulate the global view stack and the GUI
// dispatcher state, so we route the work through the dispatcher's custom
// event queue which runs callbacks on the GUI thread.
// ============================================================================

static void app_push_main_menu(WiFiApp* app) {
    void* main_menu_data = NULL;
    View* main_menu = screen_main_menu_create(app, &main_menu_data);
    if(!main_menu) {
        view_dispatcher_stop(app->view_dispatcher);
        return;
    }
    screen_push_with_cleanup(app, main_menu, main_menu_cleanup_internal, main_menu_data);
}

static bool app_custom_event_handler(void* context, uint32_t event) {
    WiFiApp* app = (WiFiApp*)context;
    if(!app) return false;

    switch(event) {
    case BOOT_EVENT_DONE:
        screen_pop(app);            // pop boot screen (cleanup joins worker)
        app_push_main_menu(app);
        return true;

    case BOOT_EVENT_CONTINUE:
        // User chose to continue without a connected board.
        app->board_connected = false;
        screen_pop(app);
        app_push_main_menu(app);
        return true;

    case BOOT_EVENT_FAILED:
        // Boot worker is now waiting for user input. Nothing to do here -
        // the screen draws its own "OK=continue BACK=exit" footer.
        return true;

    case BOOT_EVENT_CANCELLED:
        // BACK pressed during/after boot - tear down the app.
        screen_pop(app);
        view_dispatcher_stop(app->view_dispatcher);
        return true;

    default:
        return false;
    }
}

int32_t wifi_attacks_app(void* p) {
    UNUSED(p);

    WiFiApp* app = (WiFiApp*)malloc(sizeof(WiFiApp));
    if(!app) return -1;
    memset(app, 0, sizeof(WiFiApp));

    // GUI plumbing
    app->gui = furi_record_open(RECORD_GUI);
    if(!app->gui) {
        free(app);
        return -1;
    }
    app->view_dispatcher = view_dispatcher_alloc();
    if(!app->view_dispatcher) {
        furi_record_close(RECORD_GUI);
        free(app);
        return -1;
    }
    app->view_stack = view_stack_alloc();

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, app_custom_event_handler);

    // CRITICAL: Disable expansion service BEFORE the boot worker acquires USART.
    // Expansion service owns USART by default (waiting for an expansion module);
    // skipping this triggers furi_check failures inside furi_hal_serial when we
    // try to take the port - especially visible on battery power.
    app->expansion = furi_record_open(RECORD_EXPANSION);
    expansion_disable(app->expansion);

    // App state init (5V, UART, board check are deferred to the boot screen
    // worker thread so the user sees live progress instead of a frozen UI).
    app->networks = NULL;
    app->network_count = 0;
    memset(app->selected_networks, 0, sizeof(app->selected_networks));
    app->selected_count = 0;

    app->scan_results = NULL;
    app->scan_result_count = 0;
    app->scan_result_capacity = 0;
    app->scanning_in_progress = false;
    app->scan_bytes_received = 0;
    app->last_scan_line = furi_string_alloc();

    app->attack_status = furi_string_alloc();
    app->attack_log = furi_string_alloc();
    app->current_ssid = furi_string_alloc();
    app->current_password = furi_string_alloc();
    app->attack_in_progress = false;

    app->sniffer_packet_count = 0;
    app->evil_twin_html_selection = 0;
    app->html_files = NULL;
    app->html_file_count = 0;
    app->evil_twin_password = furi_string_alloc();

    // Load red team mode from persistent storage
    app->red_team_mode = false;
    {
        Storage* storage = furi_record_open(RECORD_STORAGE);
        File* file = storage_file_alloc(storage);
        if(storage_file_open(file, APP_DATA_PATH("redteam.conf"), FSAM_READ, FSOM_OPEN_EXISTING)) {
            uint8_t val = 0;
            if(storage_file_read(file, &val, 1) == 1) {
                app->red_team_mode = (val == 1);
            }
        }
        storage_file_close(file);
        storage_file_free(file);
        furi_record_close(RECORD_STORAGE);
    }

    // Push the boot screen as the first view. Its worker thread powers up the
    // board, probes UART, and posts BOOT_EVENT_DONE / BOOT_EVENT_FAILED via
    // the custom event handler above.
    void* boot_data = NULL;
    View* boot_view = screen_boot_create(app, &boot_data);
    if(!boot_view) {
        if(app->expansion) {
            expansion_enable(app->expansion);
            furi_record_close(RECORD_EXPANSION);
        }
        view_dispatcher_free(app->view_dispatcher);
        view_stack_free(app->view_stack);
        furi_record_close(RECORD_GUI);
        free(app);
        return -1;
    }
    screen_push_with_cleanup(app, boot_view, screen_boot_cleanup_internal, boot_data);

    // Run the ViewDispatcher event loop
    view_dispatcher_run(app->view_dispatcher);

    // Cleanup - remove all views first
    screen_pop_all(app);

    // Disable 5V GPIO power output
    if(furi_hal_power_is_otg_enabled()) {
        furi_hal_power_disable_otg();
    }

    uart_comm_deinit(app);

    // Restore expansion service ownership of USART per SDK contract.
    if(app->expansion) {
        expansion_enable(app->expansion);
        furi_record_close(RECORD_EXPANSION);
        app->expansion = NULL;
    }

    furi_string_free(app->attack_status);
    furi_string_free(app->attack_log);
    furi_string_free(app->current_ssid);
    furi_string_free(app->current_password);
    furi_string_free(app->evil_twin_password);
    furi_string_free(app->last_scan_line);

    if(app->scan_results) free(app->scan_results);

    for(uint32_t i = 0; i < app->network_count; i++) {
        free(app->networks[i]);
    }
    if(app->networks) free(app->networks);

    for(uint32_t i = 0; i < app->html_file_count; i++) {
        free(app->html_files[i]);
    }
    if(app->html_files) free(app->html_files);

    view_dispatcher_free(app->view_dispatcher);
    view_stack_free(app->view_stack);
    furi_record_close(RECORD_GUI);

    free(app);

    return 0;
}

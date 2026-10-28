#include "uart_comm.h"
#include <furi_hal.h>
#include <furi_hal_serial_control.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <furi.h>

#define TAG "UART"
#define UART_BUFFER_SIZE 4096
#define UART_LINE_TIMEOUT_MS 5000  // 5 seconds per line - overall scan has its own timeout
#define UART_LINE_MAX 1024

static void uart_serial_irq(FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context) {
    WiFiApp* app = (WiFiApp*)context;
    if(!app || !app->uart_rx_buffer || !(event & FuriHalSerialRxEventData)) return;

    do {
        uint8_t byte = furi_hal_serial_async_rx(handle);
        furi_stream_buffer_send(app->uart_rx_buffer, &byte, 1, 0);
        app->last_uart_activity = furi_get_tick();
    } while(furi_hal_serial_async_rx_available(handle));
}

//=============================================================================
// CSV Parsing for network scan results
// Format: "index","ssid","vendor","BSSID","channel","auth","rssi","band"
// Quotes inside a field are RFC 4180 doubled quotes. See scan_csv.c.
//=============================================================================

static bool parse_network_line(const char* line, WiFiNetwork* net) {
    if(!line || !net) return false;

    ScanCsvNetwork parsed;
    if(!parse_network_csv(line, &parsed)) return false;

    memset(net, 0, sizeof(*net));
    memcpy(net->ssid, parsed.ssid, sizeof(net->ssid));
    memcpy(net->vendor, parsed.vendor, sizeof(net->vendor));
    memcpy(net->bssid, parsed.bssid, sizeof(net->bssid));
    memcpy(net->auth, parsed.auth, sizeof(net->auth));
    memcpy(net->band, parsed.band, sizeof(net->band));
    net->channel = parsed.channel;
    int rssi = parsed.rssi;
    if(rssi > 127) rssi = 127;
    if(rssi < -128) rssi = -128;
    net->rssi = (int8_t)rssi;
    return true;
}

//=============================================================================
// UART Worker Thread - handles scanning in background
//=============================================================================

static bool uart_read_line_internal(WiFiApp* app, FuriString* line) {
    if(!app || !line) return false;
    
    furi_string_reset(line);
    uint32_t timeout = furi_get_tick() + UART_LINE_TIMEOUT_MS;
    bool has_content = false;
    bool discard = false;
    
    while(furi_get_tick() < timeout) {
        uint8_t byte;
        size_t received = furi_stream_buffer_receive(app->uart_rx_buffer, &byte, 1, 10);
        
        if(received == 1) {
            if(byte == '\n' || byte == '\r') {
                if(has_content && !discard) {
                    return true;
                }
                furi_string_reset(line);
                has_content = false;
                discard = false;
                continue;
            } else if(byte >= 32 && byte < 127) {
                if(discard) continue;
                if(furi_string_size(line) + 1 >= UART_LINE_MAX) {
                    furi_string_reset(line);
                    has_content = false;
                    discard = true;
                    continue;
                }
                furi_string_push_back(line, (char)byte);
                has_content = true;
                timeout = furi_get_tick() + UART_LINE_TIMEOUT_MS;
            }
        }
    }
    return false;
}

#define SCAN_TIMEOUT_MS 60000  // 60 seconds max for entire scan

static int32_t uart_worker(void* context) {
    WiFiApp* app = (WiFiApp*)context;
    if(!app) return -1;
    
    while(app->uart_running) {
        // If scanning, try to read results
        if(app->scanning_in_progress) {
            // Check for overall scan timeout
            if((furi_get_tick() - app->scan_start_time) > SCAN_TIMEOUT_MS) {
                // Timeout - mark as failed if no results
                if(app->scan_result_count == 0) {
                    app->scan_failed = true;
                }
                app->scanning_in_progress = false;
                continue;
            }
            
            FuriString* line = furi_string_alloc();
            
            if(uart_read_line_internal(app, line)) {
                const char* line_str = furi_string_get_cstr(line);
                size_t line_len = furi_string_size(line);
                
                // Count bytes received
                app->scan_bytes_received += line_len + 1;
                
                // Save first network line for debugging
                if(line_str[0] == '"' && furi_string_size(app->last_scan_line) == 0) {
                    furi_string_set(app->last_scan_line, line_str);
                }
                
                // Check for end of results marker
                if(strstr(line_str, "Scan results printed")) {
                    app->scanning_in_progress = false;
                } else if(strstr(line_str, "No networks found") ||
                          strstr(line_str, "Scan still in progress")) {
                    app->scanning_in_progress = false;
                } else if(line_str[0] == '"') {
                    // Parse network CSV line
                    if(app->scan_results && app->scan_result_count < app->scan_result_capacity) {
                        if(parse_network_line(line_str, &app->scan_results[app->scan_result_count])) {
                            app->scan_result_count++;
                        }
                    }
                }
            }
            
            furi_string_free(line);
        } else {
            furi_delay_ms(100);
        }
    }
    return 0;
}

//=============================================================================
// Board Connection Check
//=============================================================================

bool uart_check_board_connection(WiFiApp* app) {
    if(!app || !app->serial) return false;
    
    uart_clear_buffer(app);
    uart_send_command(app, "ping");
    
    uint32_t timeout = furi_get_tick() + 1000; // 1 second timeout
    FuriString* line = furi_string_alloc();
    
    while(furi_get_tick() < timeout) {
        if(uart_read_line_internal(app, line)) {
            const char* line_str = furi_string_get_cstr(line);
            if(strstr(line_str, "pong")) {
                furi_string_free(line);
                FURI_LOG_I(TAG, "Board connected");
                return true;
            }
        }
    }
    
    furi_string_free(line);
    return false;
}

//=============================================================================
// SD Card Check
//=============================================================================

bool uart_check_sd_card(WiFiApp* app) {
    if(!app || !app->serial) return false;
    
    uart_clear_buffer(app);
    uart_send_command(app, "list_sd");
    
    uint32_t timeout = furi_get_tick() + 3000; // 3 second timeout
    FuriString* line = furi_string_alloc();
    bool sd_ok = false;
    
    while(furi_get_tick() < timeout) {
        if(uart_read_line_internal(app, line)) {
            const char* line_str = furi_string_get_cstr(line);
            FURI_LOG_I(TAG, "SD check: %s", line_str);
            
            // If we see "Failed to initialize SD card" - no SD
            if(strstr(line_str, "Failed to initialize SD card")) {
                FURI_LOG_W(TAG, "SD card not found");
                furi_string_free(line);
                return false;
            }
            // If we see "HTML files" header or a numbered file - SD is OK
            if(strstr(line_str, "HTML files") || (line_str[0] >= '1' && line_str[0] <= '9')) {
                sd_ok = true;
            }
        }
    }
    
    furi_string_free(line);
    FURI_LOG_I(TAG, "SD card check result: %s", sd_ok ? "OK" : "not detected");
    return sd_ok;
}

//=============================================================================
// UART Init / Deinit
//=============================================================================

void uart_comm_init(WiFiApp* app) {
    if(!app) return;
    
    app->serial = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!app->serial) return;
    
    furi_hal_serial_init(app->serial, 115200);
    
    app->uart_rx_buffer = furi_stream_buffer_alloc(UART_BUFFER_SIZE, 1);
    app->uart_line_buffer = furi_string_alloc();
    app->uart_running = true;
    app->last_uart_activity = furi_get_tick();
    app->board_connected = false;
    
    furi_stream_buffer_reset(app->uart_rx_buffer);
    furi_hal_serial_async_rx_start(app->serial, uart_serial_irq, app, true);
    
    // Start UART worker thread for scanning
    app->uart_thread = furi_thread_alloc();
    furi_thread_set_name(app->uart_thread, "WiFiUART");
    furi_thread_set_stack_size(app->uart_thread, 2048);
    furi_thread_set_callback(app->uart_thread, uart_worker);
    furi_thread_set_context(app->uart_thread, app);
    furi_thread_start(app->uart_thread);
}

void uart_comm_deinit(WiFiApp* app) {
    if(!app) return;
    
    app->uart_running = false;
    
    if(app->uart_thread) {
        furi_thread_join(app->uart_thread);
        furi_thread_free(app->uart_thread);
        app->uart_thread = NULL;
    }
    
    if(app->serial) {
        furi_hal_serial_deinit(app->serial);
        furi_hal_serial_control_release(app->serial);
        app->serial = NULL;
    }
    
    if(app->uart_rx_buffer) {
        furi_stream_buffer_free(app->uart_rx_buffer);
        app->uart_rx_buffer = NULL;
    }
    if(app->uart_line_buffer) {
        furi_string_free(app->uart_line_buffer);
        app->uart_line_buffer = NULL;
    }
}

void uart_send_command(WiFiApp* app, const char* command) {
    if(!app || !app->serial) {
        FURI_LOG_E(TAG, "uart_send_command: app or serial is NULL");
        return;
    }
    FURI_LOG_I(TAG, "TX: %s", command);
    furi_hal_serial_tx(app->serial, (const uint8_t*)command, strlen(command));
    furi_hal_serial_tx(app->serial, (const uint8_t*)"\n", 1);
    furi_hal_serial_tx_wait_complete(app->serial);
}

void uart_send_select_networks(WiFiApp* app) {
    if(!app || app->selected_count == 0) return;

    char cmd[640];
    int wrote = snprintf(cmd, sizeof(cmd), "select_networks");
    if(wrote < 0) return;
    size_t pos = (size_t)wrote;

    for(uint32_t i = 0; i < app->selected_count; i++) {
        if(pos >= sizeof(cmd)) return;
        wrote = snprintf(
            cmd + pos,
            sizeof(cmd) - pos,
            " %lu",
            (unsigned long)app->selected_networks[i]);
        if(wrote < 0 || (size_t)wrote >= sizeof(cmd) - pos) return;
        pos += (size_t)wrote;
    }

    uart_send_command(app, cmd);
}

const char* uart_read_line(WiFiApp* app, uint32_t timeout_ms) {
    uint32_t start = furi_get_tick();
    furi_string_reset(app->uart_line_buffer);
    bool discard = false;
    
    while((furi_get_tick() - start) < timeout_ms) {
        uint8_t data = 0;
        if(furi_stream_buffer_receive(app->uart_rx_buffer, &data, 1, 10) == 1) {
            if(data == '\n') {
                if(furi_string_size(app->uart_line_buffer) > 0 &&
                   furi_string_get_char(app->uart_line_buffer, furi_string_size(app->uart_line_buffer) - 1) == '\r') {
                    furi_string_left(app->uart_line_buffer, furi_string_size(app->uart_line_buffer) - 1);
                }
                if(discard) {
                    furi_string_reset(app->uart_line_buffer);
                    discard = false;
                    continue;
                }
                if(furi_string_size(app->uart_line_buffer) > 0) {
                    return furi_string_get_cstr(app->uart_line_buffer);
                }
            } else if(data != '\r') {
                if(discard) continue;
                if(furi_string_size(app->uart_line_buffer) + 1 >= UART_LINE_MAX) {
                    furi_string_reset(app->uart_line_buffer);
                    discard = true;
                    continue;
                }
                furi_string_push_back(app->uart_line_buffer, data);
            }
        }
    }
    
    return NULL;
}

void uart_clear_buffer(WiFiApp* app) {
    uint8_t data = 0;
    while(furi_stream_buffer_receive(app->uart_rx_buffer, &data, 1, 1) == 1) {
        // Clear
    }
    furi_string_reset(app->uart_line_buffer);
}

//=============================================================================
// Scanning helpers
//=============================================================================

void uart_start_scan(WiFiApp* app) {
    if(!app) return;
    
    // Clear previous results
    if(app->scan_results) {
        free(app->scan_results);
        app->scan_results = NULL;
    }
    app->scan_result_count = 0;
    app->scan_bytes_received = 0;
    app->scan_failed = false;
    if(app->last_scan_line) {
        furi_string_reset(app->last_scan_line);
    }
    
    // Allocate space for scan results
    app->scan_result_capacity = MAX_SCAN_RESULTS;
    app->scan_results = (WiFiNetwork*)malloc(sizeof(WiFiNetwork) * MAX_SCAN_RESULTS);
    
    // CRITICAL: Clear UART buffer before sending command
    uart_clear_buffer(app);
    furi_delay_ms(50);  // Small delay to ensure buffer is flushed
    
    // Set scanning flag and record start time
    app->scan_start_time = furi_get_tick();
    app->scanning_in_progress = true;
    uart_send_command(app, "scan_networks");
}

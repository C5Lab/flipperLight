#pragma once

#include "app.h"

// UART communication functions
void uart_comm_init(WiFiApp* app);
void uart_comm_deinit(WiFiApp* app);
void uart_send_command(WiFiApp* app, const char* command);
const char* uart_read_line(WiFiApp* app, uint32_t timeout_ms);
void uart_clear_buffer(WiFiApp* app);
bool uart_check_board_connection(WiFiApp* app);
bool uart_check_sd_card(WiFiApp* app);

// CSV parsing
bool csv_next_quoted_field(const char** p, char* out, size_t out_size);

// Scanning
void uart_start_scan(WiFiApp* app);

// =====================================================================
// Password cache (shared between attack screens)
// =====================================================================

// Look up a password by SSID in the in-RAM cache. Returns true if found and
// writes it to `out`. Does NOT touch UART.
bool password_cache_lookup(WiFiApp* app, const char* ssid, char* out, size_t out_size);

// Insert or update a (ssid, password) pair in the cache. Safe to call
// from any context. Older entries are overwritten when full.
void password_cache_put(WiFiApp* app, const char* ssid, const char* password);

// Synchronize the cache with the firmware via `show_pass evil`.
// Idempotent unless `force` is true. Cancellable via `cancel` flag.
// Uses short timeouts to keep the UI responsive.
// Returns true on a successful sync (even if the list was empty).
bool password_cache_refresh(WiFiApp* app, bool force, volatile bool* cancel);

// High-level helper: try cache, refresh from firmware if needed, try cache again.
// Writes the password to `out` and returns true if the SSID is known.
bool attack_resolve_password(
    WiFiApp* app,
    const char* ssid,
    char* out,
    size_t out_size,
    volatile bool* cancel);

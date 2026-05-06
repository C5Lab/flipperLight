#pragma once

#include "app.h"

// Custom event ids posted by the boot screen worker thread to the
// app-level ViewDispatcher custom event handler.
#define BOOT_EVENT_DONE      0xB0010001u
#define BOOT_EVENT_FAILED    0xB0010002u
#define BOOT_EVENT_CANCELLED 0xB0010003u
#define BOOT_EVENT_CONTINUE  0xB0010004u // user chose to continue without board

View* screen_boot_create(WiFiApp* app, void** out_data);
void screen_boot_cleanup_internal(View* view, void* data);

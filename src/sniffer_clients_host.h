#ifndef SNIFFER_CLIENTS_HOST_H
#define SNIFFER_CLIENTS_HOST_H

#include "janos_sniffer_session.h"
#include "uart_comm.h"
#include "app.h"
#include <gui/canvas.h>
#include <stdio.h>

static inline bool fl_js_send(void* context, const char* command) {
    uart_send_command((WiFiApp*)context, command);
    return true;
}

static inline uint32_t fl_now_ms(void) {
    return furi_get_tick();
}

static inline void fl_js_pump_loading(JsSession* s, WiFiApp* app) {
    while(s->phase == JS_LOADING) {
        const char* line = uart_read_line(app, 200);
        uint32_t now = fl_now_ms();
        if(line) js_line(s, line, now);
        js_tick(s, now);
    }
}

static inline bool fl_js_pump_start(JsSession* s, WiFiApp* app, unsigned idx) {
    uint32_t now = fl_now_ms();
    if(!js_start(s, idx, now)) return false;
    while(s->phase == JS_STARTING) {
        const char* line = uart_read_line(app, 200);
        now = fl_now_ms();
        if(line) js_line(s, line, now);
        js_tick(s, now);
    }
    return s->phase == JS_ACTIVE;
}

static inline void fl_draw_client_rows(
    Canvas* canvas,
    const sc_model_t* model,
    unsigned selected,
    unsigned* scroll,
    const char* error) {
    canvas_set_font(canvas, FontSecondary);
    if(error && error[0]) {
        canvas_draw_str(canvas, 2, 32, error);
        return;
    }
    if(!model || !model->complete || model->failed) {
        canvas_draw_str(canvas, 2, 32, "No clients found");
        return;
    }
    if(model->client_count == 0) {
        canvas_draw_str(canvas, 2, 32, "No clients found");
        return;
    }

    const unsigned max_visible = 4;
    unsigned rows = 0;
    unsigned selected_row = 0;
    int previous_ap = -1;
    for(unsigned i = 0; i < model->client_count; i++) {
        unsigned ap = model->clients[i].ap;
        if(ap < model->ap_count && (int)ap != previous_ap) {
            previous_ap = (int)ap;
            rows++;
        }
        if(i == selected) selected_row = rows;
        rows++;
    }
    if(selected_row < *scroll) {
        *scroll = selected_row;
    } else if(selected_row >= *scroll + max_visible) {
        *scroll = selected_row - max_visible + 1;
    }
    if(*scroll > 0 && selected_row == *scroll) *scroll -= 1;

    uint8_t y = 21;
    unsigned row = 0;
    previous_ap = -1;
    for(unsigned i = 0; i < model->client_count && row < *scroll + max_visible; i++) {
        unsigned ap = model->clients[i].ap;
        if(ap < model->ap_count && (int)ap != previous_ap) {
            previous_ap = (int)ap;
            if(row >= *scroll) {
                char label[22];
                sc_ap_label(&model->aps[ap], label, sizeof(label));
                canvas_set_color(canvas, ColorBlack);
                canvas_draw_str(canvas, 2, y + (uint8_t)((row - *scroll) * 9), label);
            }
            row++;
        }
        if(row >= *scroll && row < *scroll + max_visible) {
            char mac[18];
            uint8_t display_y = y + (uint8_t)((row - *scroll) * 9);
            sc_mac_text(mac, model->clients[i].mac);
            if(i == selected) {
                canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                canvas_set_color(canvas, ColorWhite);
            }
            canvas_draw_str(canvas, 10, display_y, mac);
            canvas_set_color(canvas, ColorBlack);
        }
        row++;
    }
}

#endif

#pragma once

#include "../libOs/include/shared.h"

typedef enum {
    KEY_NONE = 0,
    KEY_ESC, KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, KEY_7, KEY_8, KEY_9, KEY_0,
    KEY_MINUS, KEY_EQUALS, KEY_BACKSPACE, KEY_TAB,
    KEY_Q, KEY_W, KEY_E, KEY_R, KEY_T, KEY_Y, KEY_U, KEY_I, KEY_O, KEY_P,
    KEY_LBRACKET, KEY_RBRACKET, KEY_ENTER, KEY_LCTRL,
    KEY_A, KEY_S, KEY_D, KEY_F, KEY_G, KEY_H, KEY_J, KEY_K, KEY_L,
    KEY_SEMICOLON, KEY_QUOTE, KEY_BACKTICK, KEY_LSHIFT, KEY_BACKSLASH,
    KEY_Z, KEY_X, KEY_C, KEY_V, KEY_B, KEY_N, KEY_M,
    KEY_COMMA, KEY_DOT, KEY_SLASH, KEY_RSHIFT,
    KEY_KP_STAR, KEY_LALT, KEY_SPACE, KEY_CAPSLOCK,
    KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5,
    KEY_F6, KEY_F7, KEY_F8, KEY_F9, KEY_F10,
    KEY_NUMLOCK, KEY_SCROLLLOCK,
    KEY_KP_7, KEY_KP_8, KEY_KP_9, KEY_KP_MINUS,
    KEY_KP_4, KEY_KP_5, KEY_KP_6, KEY_KP_PLUS,
    KEY_KP_1, KEY_KP_2, KEY_KP_3, KEY_KP_0, KEY_KP_DOT,
    KEY_F11, KEY_F12,
    KEY_RCTRL, KEY_RALT,
    KEY_HOME, KEY_UP, KEY_PGUP,
    KEY_LEFT, KEY_RIGHT,
    KEY_END, KEY_DOWN, KEY_PGDN,
    KEY_INSERT, KEY_DELETE,
    KEY_KP_ENTER, KEY_KP_SLASH,
    KEY_PRTSCR, KEY_PAUSE,
    KEY_LMETA, KEY_RMETA, KEY_MENU,
    KEY_COUNT
} KeyCode;

typedef enum {
    KEY_EVENT_PRESS,
    KEY_EVENT_RELEASE,
} KeyEventType;

typedef struct {
    KeyCode   key;
    KeyEventType type;
    bool      ctrl;
    bool      alt;
    bool      shift;
    bool      capslock;
    bool      numlock;
} KeyEvent;

static const KeyCode _sc1_normal[0x80] = {
    [0x01] = KEY_ESC,
    [0x02] = KEY_1,       [0x03] = KEY_2,   [0x04] = KEY_3,
    [0x05] = KEY_4,       [0x06] = KEY_5,   [0x07] = KEY_6,
    [0x08] = KEY_7,       [0x09] = KEY_8,   [0x0A] = KEY_9,
    [0x0B] = KEY_0,       [0x0C] = KEY_MINUS, [0x0D] = KEY_EQUALS,
    [0x0E] = KEY_BACKSPACE,[0x0F] = KEY_TAB,
    [0x10] = KEY_Q,       [0x11] = KEY_W,   [0x12] = KEY_E,
    [0x13] = KEY_R,       [0x14] = KEY_T,   [0x15] = KEY_Y,
    [0x16] = KEY_U,       [0x17] = KEY_I,   [0x18] = KEY_O,
    [0x19] = KEY_P,       [0x1A] = KEY_LBRACKET, [0x1B] = KEY_RBRACKET,
    [0x1C] = KEY_ENTER,   [0x1D] = KEY_LCTRL,
    [0x1E] = KEY_A,       [0x1F] = KEY_S,   [0x20] = KEY_D,
    [0x21] = KEY_F,       [0x22] = KEY_G,   [0x23] = KEY_H,
    [0x24] = KEY_J,       [0x25] = KEY_K,   [0x26] = KEY_L,
    [0x27] = KEY_SEMICOLON,[0x28] = KEY_QUOTE, [0x29] = KEY_BACKTICK,
    [0x2A] = KEY_LSHIFT,  [0x2B] = KEY_BACKSLASH,
    [0x2C] = KEY_Z,       [0x2D] = KEY_X,   [0x2E] = KEY_C,
    [0x2F] = KEY_V,       [0x30] = KEY_B,   [0x31] = KEY_N,
    [0x32] = KEY_M,       [0x33] = KEY_COMMA,[0x34] = KEY_DOT,
    [0x35] = KEY_SLASH,   [0x36] = KEY_RSHIFT,
    [0x37] = KEY_KP_STAR, [0x38] = KEY_LALT,[0x39] = KEY_SPACE,
    [0x3A] = KEY_CAPSLOCK,
    [0x3B] = KEY_F1,  [0x3C] = KEY_F2,  [0x3D] = KEY_F3,
    [0x3E] = KEY_F4,  [0x3F] = KEY_F5,  [0x40] = KEY_F6,
    [0x41] = KEY_F7,  [0x42] = KEY_F8,  [0x43] = KEY_F9,
    [0x44] = KEY_F10,
    [0x45] = KEY_NUMLOCK, [0x46] = KEY_SCROLLLOCK,
    [0x47] = KEY_KP_7, [0x48] = KEY_KP_8, [0x49] = KEY_KP_9,
    [0x4A] = KEY_KP_MINUS,
    [0x4B] = KEY_KP_4, [0x4C] = KEY_KP_5, [0x4D] = KEY_KP_6,
    [0x4E] = KEY_KP_PLUS,
    [0x4F] = KEY_KP_1, [0x50] = KEY_KP_2, [0x51] = KEY_KP_3,
    [0x52] = KEY_KP_0, [0x53] = KEY_KP_DOT,
    [0x57] = KEY_F11, [0x58] = KEY_F12,
};

static const KeyCode _sc1_e0[0x80] = {
    [0x1C] = KEY_KP_ENTER,
    [0x1D] = KEY_RCTRL,
    [0x35] = KEY_KP_SLASH,
    [0x37] = KEY_PRTSCR,
    [0x38] = KEY_RALT,
    [0x47] = KEY_HOME,
    [0x48] = KEY_UP,
    [0x49] = KEY_PGUP,
    [0x4B] = KEY_LEFT,
    [0x4D] = KEY_RIGHT,
    [0x4F] = KEY_END,
    [0x50] = KEY_DOWN,
    [0x51] = KEY_PGDN,
    [0x52] = KEY_INSERT,
    [0x53] = KEY_DELETE,
    [0x5B] = KEY_LMETA,
    [0x5C] = KEY_RMETA,
    [0x5D] = KEY_MENU,
};

typedef struct {
    bool     key_state[KEY_COUNT];  
    bool     e0_prefix;
    bool     capslock;
    bool     numlock;
    bool     scrolllock;
    void   (*on_event)(KeyEvent ev, void *userdata);
    void    *userdata;
} Ps2KeyboardState;

static inline void ps2_keyboard_init(Ps2KeyboardState *kb,
                                     void (*on_event)(KeyEvent, void*),
                                     void *userdata)
{
    for (int i = 0; i < KEY_COUNT; i++) kb->key_state[i] = false;
    kb->e0_prefix  = false;
    kb->capslock   = false;
    kb->numlock    = true;  
    kb->scrolllock = false;
    kb->on_event   = on_event;
    kb->userdata   = userdata;
}

static inline void ps2_keyboard_handle_byte(Ps2KeyboardState *kb, uint8_t byte)
{
    if (byte == 0xE0) {
        kb->e0_prefix = true;
        return;
    }

    if (byte == 0xE1) {
        return;
    }

    bool     release  = (byte & 0x80) != 0;
    uint8_t  sc       = byte & 0x7F;
    bool     e0       = kb->e0_prefix;
    kb->e0_prefix = false;

    if (sc == 0 || sc >= 0x80) return;

    KeyCode key = e0 ? _sc1_e0[sc] : _sc1_normal[sc];
    if (key == KEY_NONE) return;

    if (!release) {
        if (key == KEY_CAPSLOCK)   kb->capslock   = !kb->capslock;
        if (key == KEY_NUMLOCK)    kb->numlock    = !kb->numlock;
        if (key == KEY_SCROLLLOCK) kb->scrolllock = !kb->scrolllock;
    }

    kb->key_state[key] = !release;

    if (kb->on_event) {
        KeyEvent ev = {
            .key      = key,
            .type     = release ? KEY_EVENT_RELEASE : KEY_EVENT_PRESS,
            .ctrl     = kb->key_state[KEY_LCTRL]  || kb->key_state[KEY_RCTRL],
            .alt      = kb->key_state[KEY_LALT]   || kb->key_state[KEY_RALT],
            .shift    = kb->key_state[KEY_LSHIFT] || kb->key_state[KEY_RSHIFT],
            .capslock = kb->capslock,
            .numlock  = kb->numlock,
        };
        kb->on_event(ev, kb->userdata);
    }
}

static const char _key_to_ascii_normal[KEY_COUNT] = {
    [KEY_1] = '1', [KEY_2] = '2', [KEY_3] = '3', [KEY_4] = '4',
    [KEY_5] = '5', [KEY_6] = '6', [KEY_7] = '7', [KEY_8] = '8',
    [KEY_9] = '9', [KEY_0] = '0',
    [KEY_MINUS]   = '-', [KEY_EQUALS]  = '=',
    [KEY_Q] = 'q', [KEY_W] = 'w', [KEY_E] = 'e', [KEY_R] = 'r',
    [KEY_T] = 't', [KEY_Y] = 'y', [KEY_U] = 'u', [KEY_I] = 'i',
    [KEY_O] = 'o', [KEY_P] = 'p',
    [KEY_LBRACKET] = '[', [KEY_RBRACKET] = ']', [KEY_BACKSLASH] = '\\',
    [KEY_A] = 'a', [KEY_S] = 's', [KEY_D] = 'd', [KEY_F] = 'f',
    [KEY_G] = 'g', [KEY_H] = 'h', [KEY_J] = 'j', [KEY_K] = 'k',
    [KEY_L] = 'l',
    [KEY_SEMICOLON] = ';', [KEY_QUOTE] = '\'', [KEY_BACKTICK] = '`',
    [KEY_Z] = 'z', [KEY_X] = 'x', [KEY_C] = 'c', [KEY_V] = 'v',
    [KEY_B] = 'b', [KEY_N] = 'n', [KEY_M] = 'm',
    [KEY_COMMA] = ',', [KEY_DOT] = '.', [KEY_SLASH] = '/',
    [KEY_SPACE]  = ' ', [KEY_ENTER] = '\n', [KEY_BACKSPACE] = '\b',
    [KEY_TAB]    = '\t',
    [KEY_KP_0] = '0', [KEY_KP_1] = '1', [KEY_KP_2] = '2',
    [KEY_KP_3] = '3', [KEY_KP_4] = '4', [KEY_KP_5] = '5',
    [KEY_KP_6] = '6', [KEY_KP_7] = '7', [KEY_KP_8] = '8',
    [KEY_KP_9] = '9', [KEY_KP_DOT] = '.', [KEY_KP_STAR] = '*',
    [KEY_KP_MINUS] = '-', [KEY_KP_PLUS] = '+', [KEY_KP_SLASH] = '/',
    [KEY_KP_ENTER] = '\n',
};

static const char _key_to_ascii_shift[KEY_COUNT] = {
    [KEY_1] = '!', [KEY_2] = '@', [KEY_3] = '#', [KEY_4] = '$',
    [KEY_5] = '%', [KEY_6] = '^', [KEY_7] = '&', [KEY_8] = '*',
    [KEY_9] = '(', [KEY_0] = ')',
    [KEY_MINUS]   = '_', [KEY_EQUALS]  = '+',
    [KEY_Q] = 'Q', [KEY_W] = 'W', [KEY_E] = 'E', [KEY_R] = 'R',
    [KEY_T] = 'T', [KEY_Y] = 'Y', [KEY_U] = 'U', [KEY_I] = 'I',
    [KEY_O] = 'O', [KEY_P] = 'P',
    [KEY_LBRACKET] = '{', [KEY_RBRACKET] = '}', [KEY_BACKSLASH] = '|',
    [KEY_A] = 'A', [KEY_S] = 'S', [KEY_D] = 'D', [KEY_F] = 'F',
    [KEY_G] = 'G', [KEY_H] = 'H', [KEY_J] = 'J', [KEY_K] = 'K',
    [KEY_L] = 'L',
    [KEY_SEMICOLON] = ':', [KEY_QUOTE] = '"', [KEY_BACKTICK] = '~',
    [KEY_Z] = 'Z', [KEY_X] = 'X', [KEY_C] = 'C', [KEY_V] = 'V',
    [KEY_B] = 'B', [KEY_N] = 'N', [KEY_M] = 'M',
    [KEY_COMMA] = '<', [KEY_DOT] = '>', [KEY_SLASH] = '?',
    [KEY_SPACE]  = ' ', [KEY_ENTER] = '\n', [KEY_BACKSPACE] = '\b',
    [KEY_TAB]    = '\t',
};

static inline char ps2_key_to_ascii(KeyEvent ev)
{
    if (ev.key >= KEY_COUNT) return 0;

    bool shifted = ev.shift;
    if (ev.capslock) {
        char c = _key_to_ascii_normal[ev.key];
        if (c >= 'a' && c <= 'z') shifted = !shifted;
    }

    char c = shifted ? _key_to_ascii_shift[ev.key] : _key_to_ascii_normal[ev.key];
    return c;
}

#import <ApplicationServices/ApplicationServices.h>
#import <Foundation/Foundation.h>
#import <arpa/inet.h>
#import <errno.h>
#import <limits.h>
#import <netdb.h>
#import <signal.h>
#import <stdbool.h>
#import <stdio.h>
#import <stdlib.h>
#import <stdarg.h>
#import <string.h>
#import <sys/socket.h>
#import <unistd.h>

typedef struct {
    const char *host;
    int port;
    const char *edge;
    int remote_width;
    int remote_height;
    int threshold;
    bool always_grab;
    bool dry_run;
    bool self_test;
} Config;

typedef struct {
    Config config;
    int fd;
    bool active;
    int remote_x;
    int remote_y;
    CGRect desktop;
} State;

static volatile sig_atomic_t g_stop = 0;

static bool send_line(State *state, const char *fmt, ...);

static void handle_signal(int signo) {
    (void)signo;
    g_stop = 1;
    CFRunLoopStop(CFRunLoopGetMain());
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s --host HOST --port PORT [--edge right|left] "
            "[--remote-width PX] [--remote-height PX] [--threshold PX] "
            "[--always-grab] [--dry-run] [--self-test]\n",
            argv0);
}

static bool parse_int(const char *text, int *out) {
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (end == text || *end != '\0' || value < INT_MIN || value > INT_MAX) {
        return false;
    }
    *out = (int)value;
    return true;
}

static bool parse_config(int argc, char **argv, Config *config) {
    *config = (Config){
        .host = NULL,
        .port = 4720,
        .edge = "right",
        .remote_width = 1920,
        .remote_height = 1080,
        .threshold = 2,
        .always_grab = false,
        .dry_run = false,
        .self_test = false,
    };

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--host") == 0 && i + 1 < argc) {
            config->host = argv[++i];
        } else if (strcmp(arg, "--port") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &config->port)) {
                fprintf(stderr, "invalid --port\n");
                return false;
            }
        } else if (strcmp(arg, "--edge") == 0 && i + 1 < argc) {
            config->edge = argv[++i];
            if (strcmp(config->edge, "right") != 0 && strcmp(config->edge, "left") != 0) {
                fprintf(stderr, "invalid --edge: %s\n", config->edge);
                return false;
            }
        } else if (strcmp(arg, "--remote-width") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &config->remote_width) || config->remote_width <= 0) {
                fprintf(stderr, "invalid --remote-width\n");
                return false;
            }
        } else if (strcmp(arg, "--remote-height") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &config->remote_height) || config->remote_height <= 0) {
                fprintf(stderr, "invalid --remote-height\n");
                return false;
            }
        } else if (strcmp(arg, "--threshold") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &config->threshold) || config->threshold < 1) {
                fprintf(stderr, "invalid --threshold\n");
                return false;
            }
        } else if (strcmp(arg, "--always-grab") == 0) {
            config->always_grab = true;
        } else if (strcmp(arg, "--dry-run") == 0) {
            config->dry_run = true;
        } else if (strcmp(arg, "--self-test") == 0) {
            config->self_test = true;
        } else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            return false;
        } else {
            fprintf(stderr, "unknown option: %s\n", arg);
            return false;
        }
    }

    if (!config->host && !config->dry_run) {
        fprintf(stderr, "missing --host\n");
        return false;
    }
    return true;
}

static bool run_self_test(State *state) {
    bool ok = true;
    ok = send_line(state, "MOVE 8 0\n") && ok;
    ok = send_line(state, "MOVE -8 0\n") && ok;
    ok = send_line(state, "BTN left down\n") && ok;
    ok = send_line(state, "BTN left up\n") && ok;
    ok = send_line(state, "KEY 30 down\n") && ok;
    ok = send_line(state, "KEY 30 up\n") && ok;
    ok = send_line(state, "SCROLL 1 0\n") && ok;
    ok = send_line(state, "SCROLL -1 0\n") && ok;
    return ok;
}

static int connect_tcp(const char *host, int port) {
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *results = NULL;
    int err = getaddrinfo(host, port_text, &hints, &results);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo(%s:%d): %s\n", host, port, gai_strerror(err));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = results; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(results);
    return fd;
}

static CGRect desktop_bounds(void) {
    uint32_t count = 0;
    if (CGGetActiveDisplayList(0, NULL, &count) != kCGErrorSuccess || count == 0) {
        return CGDisplayBounds(CGMainDisplayID());
    }

    CGDirectDisplayID displays[count];
    if (CGGetActiveDisplayList(count, displays, &count) != kCGErrorSuccess || count == 0) {
        return CGDisplayBounds(CGMainDisplayID());
    }

    CGRect bounds = CGDisplayBounds(displays[0]);
    for (uint32_t i = 1; i < count; i++) {
        bounds = CGRectUnion(bounds, CGDisplayBounds(displays[i]));
    }
    return bounds;
}

static int clamp_int(int value, int min, int max) {
    if (value < min) return min;
    if (value > max) return max;
    return value;
}

static bool send_line(State *state, const char *fmt, ...) {
    char line[128];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    if (len < 0 || len >= (int)sizeof(line)) {
        fprintf(stderr, "line too long\n");
        return false;
    }

    if (state->config.dry_run) {
        fputs(line, stdout);
        fflush(stdout);
        return true;
    }

    const char *ptr = line;
    int remaining = len;
    while (remaining > 0) {
        ssize_t written = write(state->fd, ptr, (size_t)remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            perror("write");
            return false;
        }
        ptr += written;
        remaining -= (int)written;
    }
    return true;
}

static uint16_t linux_key_for_mac(int mac_key) {
    switch (mac_key) {
        case 0: return 30;   // A
        case 1: return 31;   // S
        case 2: return 32;   // D
        case 3: return 33;   // F
        case 4: return 35;   // H
        case 5: return 34;   // G
        case 6: return 44;   // Z
        case 7: return 45;   // X
        case 8: return 46;   // C
        case 9: return 47;   // V
        case 11: return 48;  // B
        case 12: return 16;  // Q
        case 13: return 17;  // W
        case 14: return 18;  // E
        case 15: return 19;  // R
        case 16: return 21;  // Y
        case 17: return 20;  // T
        case 18: return 2;   // 1
        case 19: return 3;   // 2
        case 20: return 4;   // 3
        case 21: return 5;   // 4
        case 22: return 7;   // 6
        case 23: return 6;   // 5
        case 24: return 13;  // =
        case 25: return 10;  // 9
        case 26: return 8;   // 7
        case 27: return 12;  // -
        case 28: return 9;   // 8
        case 29: return 11;  // 0
        case 30: return 27;  // ]
        case 31: return 24;  // O
        case 32: return 22;  // U
        case 33: return 26;  // [
        case 34: return 23;  // I
        case 35: return 25;  // P
        case 36: return 28;  // Return
        case 37: return 38;  // L
        case 38: return 36;  // J
        case 39: return 40;  // '
        case 40: return 37;  // K
        case 41: return 39;  // ;
        case 42: return 43;  // backslash
        case 43: return 51;  // ,
        case 44: return 53;  // /
        case 45: return 49;  // N
        case 46: return 50;  // M
        case 47: return 52;  // .
        case 48: return 15;  // Tab
        case 49: return 57;  // Space
        case 50: return 41;  // `
        case 51: return 14;  // Backspace
        case 53: return 1;   // Escape
        case 55: return 125; // Left command -> left meta
        case 56: return 42;  // Left shift
        case 57: return 58;  // Caps lock
        case 58: return 56;  // Left option -> left alt
        case 59: return 29;  // Left control
        case 60: return 54;  // Right shift
        case 61: return 100; // Right option -> right alt
        case 62: return 97;  // Right control
        case 69: return 78;  // keypad plus
        case 71: return 69;  // num lock / clear
        case 75: return 98;  // keypad divide
        case 76: return 96;  // keypad enter
        case 78: return 74;  // keypad minus
        case 81: return 13;  // keypad =
        case 82: return 82;  // keypad 0
        case 83: return 79;  // keypad 1
        case 84: return 80;  // keypad 2
        case 85: return 81;  // keypad 3
        case 86: return 75;  // keypad 4
        case 87: return 76;  // keypad 5
        case 88: return 77;  // keypad 6
        case 89: return 71;  // keypad 7
        case 91: return 72;  // keypad 8
        case 92: return 73;  // keypad 9
        case 96: return 63;  // F5
        case 97: return 64;  // F6
        case 98: return 65;  // F7
        case 99: return 61;  // F3
        case 100: return 66; // F8
        case 101: return 67; // F9
        case 103: return 87; // F11
        case 109: return 68; // F10
        case 111: return 88; // F12
        case 114: return 110; // Insert/help
        case 115: return 102; // Home
        case 116: return 104; // Page up
        case 117: return 111; // Delete forward
        case 118: return 59;  // F1
        case 119: return 107; // End
        case 120: return 60;  // F2
        case 121: return 109; // Page down
        case 122: return 62;  // F4
        case 123: return 105; // Left
        case 124: return 106; // Right
        case 125: return 108; // Down
        case 126: return 103; // Up
        default: return 0;
    }
}

static const char *button_name_for_event(CGEventType type) {
    switch (type) {
        case kCGEventLeftMouseDown:
        case kCGEventLeftMouseUp:
            return "left";
        case kCGEventRightMouseDown:
        case kCGEventRightMouseUp:
            return "right";
        case kCGEventOtherMouseDown:
        case kCGEventOtherMouseUp:
            return "middle";
        default:
            return NULL;
    }
}

static bool event_is_down(CGEventType type) {
    return type == kCGEventLeftMouseDown || type == kCGEventRightMouseDown ||
           type == kCGEventOtherMouseDown || type == kCGEventKeyDown ||
           type == kCGEventFlagsChanged;
}

static bool should_enter(State *state, CGPoint loc, int dx) {
    if (state->config.always_grab) {
        return true;
    }
    CGFloat min_x = CGRectGetMinX(state->desktop);
    CGFloat max_x = CGRectGetMaxX(state->desktop);
    if (strcmp(state->config.edge, "right") == 0) {
        return loc.x >= max_x - state->config.threshold && dx > 0;
    }
    return loc.x <= min_x + state->config.threshold && dx < 0;
}

static void enter_remote(State *state, CGPoint loc) {
    state->active = true;
    if (strcmp(state->config.edge, "right") == 0) {
        state->remote_x = 0;
    } else {
        state->remote_x = state->config.remote_width - 1;
    }
    int y = (int)(loc.y - CGRectGetMinY(state->desktop));
    state->remote_y = clamp_int(y, 0, state->config.remote_height - 1);
    fprintf(stderr, "entered remote input region edge=%s remote=%d,%d\n",
            state->config.edge, state->remote_x, state->remote_y);
}

static bool should_leave(State *state, int dx) {
    if (state->config.always_grab) {
        return false;
    }
    if (strcmp(state->config.edge, "right") == 0) {
        return state->remote_x <= 0 && dx < 0;
    }
    return state->remote_x >= state->config.remote_width - 1 && dx > 0;
}

static void leave_remote(State *state) {
    CGFloat x;
    if (strcmp(state->config.edge, "right") == 0) {
        x = CGRectGetMaxX(state->desktop) - state->config.threshold - 3;
    } else {
        x = CGRectGetMinX(state->desktop) + state->config.threshold + 3;
    }
    CGFloat y = CGRectGetMinY(state->desktop) + state->remote_y;
    CGWarpMouseCursorPosition(CGPointMake(x, y));
    state->active = false;
    fprintf(stderr, "left remote input region\n");
}

static CGEventRef event_callback(CGEventTapProxy proxy,
                                 CGEventType type,
                                 CGEventRef event,
                                 void *user_info) {
    (void)proxy;
    State *state = (State *)user_info;
    if (type == kCGEventTapDisabledByTimeout || type == kCGEventTapDisabledByUserInput) {
        fprintf(stderr, "event tap disabled by system\n");
        return event;
    }

    int64_t raw_dx = CGEventGetIntegerValueField(event, kCGMouseEventDeltaX);
    int64_t raw_dy = CGEventGetIntegerValueField(event, kCGMouseEventDeltaY);
    int dx = clamp_int((int)raw_dx, -10000, 10000);
    int dy = clamp_int((int)raw_dy, -10000, 10000);
    CGPoint loc = CGEventGetLocation(event);

    if (!state->active && (type == kCGEventMouseMoved ||
                           type == kCGEventLeftMouseDragged ||
                           type == kCGEventRightMouseDragged ||
                           type == kCGEventOtherMouseDragged) &&
        should_enter(state, loc, dx)) {
        enter_remote(state, loc);
        return NULL;
    }

    if (!state->active) {
        return event;
    }

    switch (type) {
        case kCGEventMouseMoved:
        case kCGEventLeftMouseDragged:
        case kCGEventRightMouseDragged:
        case kCGEventOtherMouseDragged: {
            if (should_leave(state, dx)) {
                leave_remote(state);
                return NULL;
            }
            int next_x = clamp_int(state->remote_x + dx, 0, state->config.remote_width - 1);
            int next_y = clamp_int(state->remote_y + dy, 0, state->config.remote_height - 1);
            int send_dx = next_x - state->remote_x;
            int send_dy = next_y - state->remote_y;
            state->remote_x = next_x;
            state->remote_y = next_y;
            if (send_dx != 0 || send_dy != 0) {
                send_line(state, "MOVE %d %d\n", send_dx, send_dy);
            }
            return NULL;
        }
        case kCGEventScrollWheel: {
            int vertical = (int)CGEventGetIntegerValueField(event, kCGScrollWheelEventDeltaAxis1);
            int horizontal = (int)CGEventGetIntegerValueField(event, kCGScrollWheelEventDeltaAxis2);
            if (vertical != 0 || horizontal != 0) {
                send_line(state, "SCROLL %d %d\n", vertical, horizontal);
            }
            return NULL;
        }
        case kCGEventLeftMouseDown:
        case kCGEventLeftMouseUp:
        case kCGEventRightMouseDown:
        case kCGEventRightMouseUp:
        case kCGEventOtherMouseDown:
        case kCGEventOtherMouseUp: {
            const char *button = button_name_for_event(type);
            if (button) {
                send_line(state, "BTN %s %s\n", button, event_is_down(type) ? "down" : "up");
            }
            return NULL;
        }
        case kCGEventKeyDown:
        case kCGEventKeyUp: {
            int mac_key = (int)CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);
            uint16_t linux_key = linux_key_for_mac(mac_key);
            if (linux_key != 0) {
                send_line(state, "KEY %u %s\n", linux_key, type == kCGEventKeyDown ? "down" : "up");
            } else {
                fprintf(stderr, "unmapped mac keycode=%d\n", mac_key);
            }
            return NULL;
        }
        case kCGEventFlagsChanged: {
            int mac_key = (int)CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);
            uint16_t linux_key = linux_key_for_mac(mac_key);
            if (linux_key != 0) {
                CGEventFlags flags = CGEventGetFlags(event);
                bool down = false;
                if (mac_key == 55) down = (flags & kCGEventFlagMaskCommand) != 0;
                else if (mac_key == 56 || mac_key == 60) down = (flags & kCGEventFlagMaskShift) != 0;
                else if (mac_key == 58 || mac_key == 61) down = (flags & kCGEventFlagMaskAlternate) != 0;
                else if (mac_key == 59 || mac_key == 62) down = (flags & kCGEventFlagMaskControl) != 0;
                else down = event_is_down(type);
                send_line(state, "KEY %u %s\n", linux_key, down ? "down" : "up");
            }
            return NULL;
        }
        default:
            return NULL;
    }
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    Config config;
    if (!parse_config(argc, argv, &config)) {
        usage(argv[0]);
        return 2;
    }

    State state;
    memset(&state, 0, sizeof(state));
    state.config = config;
    state.fd = -1;
    state.desktop = desktop_bounds();

    if (!config.dry_run) {
        state.fd = connect_tcp(config.host, config.port);
        if (state.fd < 0) {
            fprintf(stderr, "failed to connect to %s:%d\n", config.host, config.port);
            return 1;
        }
    }

    if (config.self_test) {
        bool ok = run_self_test(&state);
        if (state.fd >= 0) close(state.fd);
        return ok ? 0 : 1;
    }

    NSDictionary *options = @{(__bridge id)kAXTrustedCheckOptionPrompt: @YES};
    if (!AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options)) {
        fprintf(stderr,
                "Accessibility permission is required. Grant it to this binary or its parent "
                "terminal/app, then run the command again.\n");
        if (state.fd >= 0) close(state.fd);
        return 1;
    }

    if (config.always_grab) {
        state.active = true;
        state.remote_x = config.remote_width / 2;
        state.remote_y = config.remote_height / 2;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    CGEventMask mask =
        CGEventMaskBit(kCGEventMouseMoved) |
        CGEventMaskBit(kCGEventLeftMouseDragged) |
        CGEventMaskBit(kCGEventRightMouseDragged) |
        CGEventMaskBit(kCGEventOtherMouseDragged) |
        CGEventMaskBit(kCGEventLeftMouseDown) |
        CGEventMaskBit(kCGEventLeftMouseUp) |
        CGEventMaskBit(kCGEventRightMouseDown) |
        CGEventMaskBit(kCGEventRightMouseUp) |
        CGEventMaskBit(kCGEventOtherMouseDown) |
        CGEventMaskBit(kCGEventOtherMouseUp) |
        CGEventMaskBit(kCGEventScrollWheel) |
        CGEventMaskBit(kCGEventKeyDown) |
        CGEventMaskBit(kCGEventKeyUp) |
        CGEventMaskBit(kCGEventFlagsChanged);

    CFMachPortRef tap = CGEventTapCreate(kCGHIDEventTap,
                                         kCGHeadInsertEventTap,
                                         kCGEventTapOptionDefault,
                                         mask,
                                         event_callback,
                                         &state);
    if (!tap) {
        fprintf(stderr, "failed to create event tap; check Accessibility/Input Monitoring permissions\n");
        if (state.fd >= 0) close(state.fd);
        return 1;
    }

    CFRunLoopSourceRef source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0);
    CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopCommonModes);
    CGEventTapEnable(tap, true);

    fprintf(stderr,
            "macOS input forwarder ready: host=%s port=%d edge=%s dry_run=%s always_grab=%s\n",
            config.host ? config.host : "(none)",
            config.port,
            config.edge,
            config.dry_run ? "true" : "false",
            config.always_grab ? "true" : "false");
    CFRunLoopRun();

    CGEventTapEnable(tap, false);
    CFRunLoopRemoveSource(CFRunLoopGetMain(), source, kCFRunLoopCommonModes);
    CFRelease(source);
    CFRelease(tap);
    if (state.fd >= 0) close(state.fd);
    return g_stop ? 130 : 0;
}

int vsnprintf_simple(char *buf, int size, const char *fmt, __builtin_va_list ap) {
    int pos = 0;

#define PUT(c) do { if (pos < size - 1) buf[pos++] = (c); } while(0)

    while (*fmt) {
        if (*fmt != '%') {
            PUT(*fmt++);
            continue;
        }
        fmt++; // skip '%'

        // флаги
        int zero_pad = 0;
        int width = 0;
        if (*fmt == '0') { zero_pad = 1; fmt++; }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt++ - '0');
        }

        switch (*fmt++) {
            case 'd': case 'i': {
                long val = __builtin_va_arg(ap, long);
                char tmp[32];
                int neg = 0, i = 30;
                tmp[31] = '\0';
                if (val < 0) { neg = 1; val = -val; }
                if (val == 0) tmp[i--] = '0';
                while (val > 0) { tmp[i--] = '0' + (val % 10); val /= 10; }
                if (neg) tmp[i--] = '-';
                const char *s = &tmp[i + 1];
                int len = 30 - i;
                for (int p = len; p < width; p++) PUT(zero_pad ? '0' : ' ');
                while (*s) PUT(*s++);
                break;
            }
            case 'u': {
                unsigned long val = __builtin_va_arg(ap, unsigned long);
                char tmp[32];
                int i = 30;
                tmp[31] = '\0';
                if (val == 0) tmp[i--] = '0';
                while (val > 0) { tmp[i--] = '0' + (val % 10); val /= 10; }
                const char *s = &tmp[i + 1];
                int len = 30 - i;
                for (int p = len; p < width; p++) PUT(zero_pad ? '0' : ' ');
                while (*s) PUT(*s++);
                break;
            }
            case 'x': case 'X': {
                unsigned long val = __builtin_va_arg(ap, unsigned long);
                const char *hex = (*( fmt - 1) == 'X') ? "0123456789ABCDEF" : "0123456789abcdef";
                char tmp[32];
                int i = 30;
                tmp[31] = '\0';
                if (val == 0) tmp[i--] = '0';
                while (val > 0) { tmp[i--] = hex[val & 0xf]; val >>= 4; }
                const char *s = &tmp[i + 1];
                int len = 30 - i;
                for (int p = len; p < width; p++) PUT(zero_pad ? '0' : ' ');
                while (*s) PUT(*s++);
                break;
            }
            case 's': {
                const char *s = __builtin_va_arg(ap, const char *);
                if (!s) s = "(null)";
                int len = 0;
                const char *t = s;
                while (*t++) len++;
                for (int p = len; p < width; p++) PUT(' ');
                while (*s) PUT(*s++);
                break;
            }
            case 'c': {
                char c = (char)__builtin_va_arg(ap, int);
                PUT(c);
                break;
            }
            case 'p': {
                unsigned long val = __builtin_va_arg(ap, unsigned long);
                PUT('0'); PUT('x');
                char tmp[32];
                int i = 30;
                tmp[31] = '\0';
                if (val == 0) tmp[i--] = '0';
                while (val > 0) { tmp[i--] = "0123456789abcdef"[val & 0xf]; val >>= 4; }
                const char *s = &tmp[i + 1];
                while (*s) PUT(*s++);
                break;
            }
            case '%': PUT('%'); break;
            default:  PUT('?'); break;
        }
    }

#undef PUT
    buf[pos] = '\0';
    return pos;
}

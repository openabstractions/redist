#include <native_windows.h>
/* Shared bounded JSON reads and native folder identity; product inputs stay with callers. */
#pragma once
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CONFIG (1u << 20)
#define MAX_DEPTH 64

static char *read_config(const WCHAR *path, size_t *size)
{
    OA_NATIVE_FILE held={0};
    if (!oa_native_open(path, GENERIC_READ, FILE_SHARE_READ, FALSE, FALSE, &held))
        return NULL;
    HANDLE file=held.file;
    LARGE_INTEGER length;
    char *data = NULL;
    DWORD got = 0;
    if (GetFileSizeEx(file, &length) && length.QuadPart >= 0 && length.QuadPart <= MAX_CONFIG) {
        data = malloc((size_t)length.QuadPart + 1);
        if (data != NULL && (!ReadFile(file, data, (DWORD)length.QuadPart, &got, NULL) || got != length.QuadPart)) {
            free(data);
            data = NULL;
        }
    }
    oa_native_close(&held);
    if (data != NULL) {
        data[got] = '\0';
        *size = got;
    }
    return data;
}

typedef struct {
    const char *p;
    const char *end;
} scanner;

static void blank(scanner *s)
{
    while (s->p < s->end && (*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r'))
        s->p++;
}

static int hex4(scanner *s, unsigned *out)
{
    unsigned value = 0;
    if (s->end - s->p < 4)
        return 0;
    for (int i = 0; i < 4; i++) {
        char c = *s->p++;
        value <<= 4;
        if (c >= '0' && c <= '9')
            value |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            value |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            value |= (unsigned)(c - 'A' + 10);
        else
            return 0;
    }
    *out = value;
    return 1;
}

static void put_utf8(char *out, size_t *n, unsigned cp)
{
    if (cp < 0x80) {
        out[(*n)++] = (char)cp;
    } else if (cp < 0x800) {
        out[(*n)++] = (char)(0xC0 | (cp >> 6));
        out[(*n)++] = (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out[(*n)++] = (char)(0xE0 | (cp >> 12));
        out[(*n)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[(*n)++] = (char)(0x80 | (cp & 0x3F));
    } else {
        out[(*n)++] = (char)(0xF0 | (cp >> 18));
        out[(*n)++] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[(*n)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[(*n)++] = (char)(0x80 | (cp & 0x3F));
    }
}

/* One JSON string at s->p. With out, its decoded UTF-8 bytes and a closing
   NUL are written there; out holds at least as many bytes as the text left,
   which no decoded string exceeds. */
static int string(scanner *s, char *out)
{
    size_t n = 0;
    if (s->p >= s->end || *s->p != '"')
        return 0;
    s->p++;
    while (s->p < s->end) {
        unsigned char c = (unsigned char)*s->p++;
        if (c == '"') {
            if (out != NULL)
                out[n] = '\0';
            return 1;
        }
        if (c < 0x20)
            return 0;
        if (c != '\\') {
            if (out != NULL)
                out[n++] = (char)c;
            continue;
        }
        if (s->p >= s->end)
            return 0;
        unsigned cp;
        switch (*s->p++) {
        case '"': cp = '"'; break;
        case '\\': cp = '\\'; break;
        case '/': cp = '/'; break;
        case 'b': cp = 8; break;
        case 'f': cp = 12; break;
        case 'n': cp = 10; break;
        case 'r': cp = 13; break;
        case 't': cp = 9; break;
        case 'u':
            if (!hex4(s, &cp))
                return 0;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                unsigned low;
                if (s->end - s->p < 6 || s->p[0] != '\\' || s->p[1] != 'u')
                    return 0;
                s->p += 2;
                if (!hex4(s, &low) || low < 0xDC00 || low > 0xDFFF)
                    return 0;
                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                return 0;
            }
            if (cp == 0) /* a NUL would end the decoded text early */
                return 0;
            break;
        default:
            return 0;
        }
        if (out != NULL)
            put_utf8(out, &n, cp);
    }
    return 0;
}

static int literal(scanner *s, const char *word)
{
    size_t length = strlen(word);
    if ((size_t)(s->end - s->p) < length || memcmp(s->p, word, length) != 0)
        return 0;
    s->p += length;
    return 1;
}

static int number(scanner *s)
{
    const char *start = s->p;
    if (s->p < s->end && *s->p == '-')
        s->p++;
    if (s->p >= s->end) return 0;
    if (*s->p == '0') s->p++;
    else {
        if (*s->p < '1' || *s->p > '9') return 0;
        while (s->p < s->end && *s->p >= '0' && *s->p <= '9') s->p++;
    }
    if (s->p < s->end && *s->p == '.') {
        s->p++;
        const char *digits = s->p;
        while (s->p < s->end && *s->p >= '0' && *s->p <= '9') s->p++;
        if (s->p == digits) return 0;
    }
    if (s->p < s->end && (*s->p == 'e' || *s->p == 'E')) {
        s->p++;
        if (s->p < s->end && (*s->p == '+' || *s->p == '-')) s->p++;
        const char *digits = s->p;
        while (s->p < s->end && *s->p >= '0' && *s->p <= '9') s->p++;
        if (s->p == digits) return 0;
    }
    return s->p > start;
}

static int value(scanner *s, int depth)
{
    blank(s);
    if (s->p >= s->end)
        return 0;
    char c = *s->p;
    if (c == '"')
        return string(s, NULL);
    if (c == 't')
        return literal(s, "true");
    if (c == 'f')
        return literal(s, "false");
    if (c == 'n')
        return literal(s, "null");
    if (c != '{' && c != '[')
        return number(s);
    if (depth >= MAX_DEPTH)
        return 0;
    char close = c == '{' ? '}' : ']';
    s->p++;
    blank(s);
    if (s->p < s->end && *s->p == close) {
        s->p++;
        return 1;
    }
    for (;;) {
        if (c == '{') {
            blank(s);
            if (!string(s, NULL))
                return 0;
            blank(s);
            if (s->p >= s->end || *s->p != ':')
                return 0;
            s->p++;
        }
        if (!value(s, depth + 1))
            return 0;
        blank(s);
        if (s->p >= s->end)
            return 0;
        if (*s->p == ',') {
            s->p++;
            continue;
        }
        if (*s->p == close) {
            s->p++;
            return 1;
        }
        return 0;
    }
}

/* The last top-level string value of key, decoded into found (as large as the
   text). Returns 1 when found, 0 when absent or not a string, -1 when the
   text is not one JSON object. */
static int top_level(const char *text, size_t size, const char *key, char *found)
{
    scanner s = {text, text + size};
    char *name = malloc(size + 1);
    int result = 0;
    if (name == NULL)
        return -1;
    if (size >= 3 && memcmp(text, "\xEF\xBB\xBF", 3) == 0)
        s.p += 3;
    blank(&s);
    if (s.p >= s.end || *s.p != '{')
        goto invalid;
    s.p++;
    blank(&s);
    if (s.p < s.end && *s.p == '}') {
        s.p++;
        goto done;
    }
    for (;;) {
        blank(&s);
        if (!string(&s, name))
            goto invalid;
        blank(&s);
        if (s.p >= s.end || *s.p != ':')
            goto invalid;
        s.p++;
        blank(&s);
        if (strcmp(name, key) == 0) {
            if (s.p < s.end && *s.p == '"') {
                if (!string(&s, found))
                    goto invalid;
                result = 1;
            } else {
                if (!value(&s, 1))
                    goto invalid;
                result = 0;
            }
        } else if (!value(&s, 1)) {
            goto invalid;
        }
        blank(&s);
        if (s.p >= s.end)
            goto invalid;
        if (*s.p == ',') {
            s.p++;
            continue;
        }
        if (*s.p != '}')
            goto invalid;
        s.p++;
        break;
    }
done:
    blank(&s);
    if (s.p != s.end)
        goto invalid;
    free(name);
    return result;
invalid:
    free(name);
    return -1;
}

/* Bounded object spans from one JSON array; callbacks never receive a copy
   or an unterminated allocation. A callback failure refuses the whole input. */
typedef int (*object_visitor)(const char *, size_t, void *);
static int object_array(const char *text, size_t size, size_t limit,
                        object_visitor visit, void *context)
{
    if (size > MAX_CONFIG) return 0;
    scanner s = {text, text + size};
    if (size >= 3 && memcmp(text, "\xEF\xBB\xBF", 3) == 0) s.p += 3;
    blank(&s);
    if (s.p == s.end || *s.p++ != '[') return 0;
    blank(&s);
    size_t count = 0;
    if (s.p < s.end && *s.p == ']') s.p++;
    else for (;;) {
        blank(&s);
        const char *start = s.p;
        if (++count > limit || s.p == s.end || *s.p != '{' || !value(&s, 1) ||
            !visit(start, (size_t)(s.p - start), context)) return 0;
        blank(&s);
        if (s.p == s.end) return 0;
        if (*s.p == ']') { s.p++; break; }
        if (*s.p++ != ',') return 0;
    }
    blank(&s);
    return s.p == s.end;
}

static WCHAR *wide(const char *utf8)
{
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
    if (length <= 0)
        return NULL;
    WCHAR *text = calloc((size_t)length, sizeof(WCHAR));
    if (text != NULL && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, text, length) != length) {
        free(text);
        text = NULL;
    }
    return text;
}

static int is_separator(WCHAR c)
{
    return c == L'\\' || c == L'/';
}

/* <path>\<sub>\ as a full path, when path is drive-absolute on a local drive
   and holds no control character; NULL otherwise. */
static WCHAR *host_folder(const WCHAR *path, const WCHAR *sub)
{
    size_t length = wcslen(path);
    if (length < 3 || !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || !is_separator(path[2]))
        return NULL;
    for (size_t i = 0; i < length; i++)
        if (path[i] < 0x20)
            return NULL;
    WCHAR root[4] = {path[0], L':', L'\\', L'\0'};
    UINT drive = GetDriveTypeW(root);
    if (drive != DRIVE_FIXED && drive != DRIVE_REMOVABLE)
        return NULL;
    size_t joined_length = length + wcslen(sub) + 3;
    WCHAR *joined = calloc(joined_length, sizeof(WCHAR));
    if (joined == NULL)
        return NULL;
    wcscpy_s(joined, joined_length, path);
    while (wcslen(joined) > 3 && is_separator(joined[wcslen(joined) - 1]))
        joined[wcslen(joined) - 1] = L'\0';
    if (!is_separator(joined[wcslen(joined) - 1]))
        wcscat_s(joined, joined_length, L"\\");
    wcscat_s(joined, joined_length, sub);
    DWORD full_length = GetFullPathNameW(joined, 0, NULL, NULL);
    WCHAR *full = full_length ? calloc((size_t)full_length + 1, sizeof(WCHAR)) : NULL;
    if (full == NULL || GetFullPathNameW(joined, full_length + 1, full, NULL) == 0) {
        free(joined);
        free(full);
        return NULL;
    }
    free(joined);
    DWORD attributes = GetFileAttributesW(full);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        free(full);
        return NULL;
    }
    if (!is_separator(full[wcslen(full) - 1]))
        wcscat_s(full, (size_t)full_length + 1, L"\\");
    return full;
}

/* The file system's identity of an existing folder: its volume and file ID. */
static __inline int folder_id(const WCHAR *path, FILE_ID_INFO *id)
{
    OA_NATIVE_FILE held={0};OA_NATIVE_FILE_ID value;int ok=0;
    if(oa_native_open(path,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,TRUE,FALSE,&held)&&oa_native_id(held.file,&value)) {
        id->VolumeSerialNumber=value.volume;memcpy(id->FileId.Identifier,value.id,sizeof(value.id));ok=1;
    }
    oa_native_close(&held);return ok;
}

/* Whether <a><name> and <b><name> are one folder, asked of the file system;
   an empty or missing b is never the same. */
static int same_folder(const WCHAR *a, const WCHAR *b, const WCHAR *name)
{
    if (*b == L'\0')
        return 0;
    size_t la = wcslen(a) + wcslen(name) + 2, lb = wcslen(b) + wcslen(name) + 2;
    WCHAR *pa = calloc(la, sizeof(WCHAR)), *pb = calloc(lb, sizeof(WCHAR));
    int same = 0;
    if (pa != NULL && pb != NULL) {
        wcscpy_s(pa, la, a);
        if (!is_separator(pa[wcslen(pa) - 1]))
            wcscat_s(pa, la, L"\\");
        wcscat_s(pa, la, name);
        wcscpy_s(pb, lb, b);
        if (!is_separator(pb[wcslen(pb) - 1]))
            wcscat_s(pb, lb, L"\\");
        wcscat_s(pb, lb, name);
        same = oa_native_same_paths(pa, pb, TRUE, FALSE);
    }
    free(pa);
    free(pb);
    return same;
}


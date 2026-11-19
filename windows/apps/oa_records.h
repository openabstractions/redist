/*
 * oa_records.h: FindRecords, the immediate Windows Installer custom action
 * that reads what OpenAbstractions recorded in the registry. app.wxs and
 * extension.wxs run it in the execute sequence before the launch conditions.
 * Each package's own action library includes this file: installer/apps/
 * hostfolder.c, the ComfyUI host-folder action and the OpenCode installer
 * host.
 *
 *   OaPanel            (out) the Panel's program: the `program` value under
 *                            HKLM\Software\OpenAbstractions\Abstraction\Panel
 *                            (64-bit view), else the same value under the
 *                            installing account's HKCU. A value counts when
 *                            it is a string naming an existing file by a
 *                            drive-absolute path. Empty when none counts.
 *   OaExtensionId      (in)  an extension's identifier, or empty
 *   OaRecordedFolder   (out) the `folder` value under
 *                            HKCU\Software\OpenAbstractions\Extensions\<id>,
 *                            the folder an earlier install of the extension
 *                            recorded. Empty when there is none.
 *
 * The action sets both properties on every run, whatever value they held
 * before. Both are private, so only this action fills them.
 *
 * Windows Installer skips AppSearch in the execute sequence whenever the UI
 * sequence has run, so a full-UI install never searches on the server side.
 * A custom action runs in every sequence it is scheduled in, and this one
 * gives the server the same answer under full UI, basic UI and no UI.
 *
 * It returns success unless Windows Installer refuses a property; the
 * package's launch conditions say what was not found.
 */
#ifndef OA_RECORDS_H
#define OA_RECORDS_H

#include <windows.h>
#include <msiquery.h>
#include <wchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "msi.lib")

#ifndef OA_RECORDS_MACHINE_ROOT
#define OA_RECORDS_MACHINE_ROOT HKEY_LOCAL_MACHINE
#endif
#ifndef OA_RECORDS_PANEL_KEY
#define OA_RECORDS_PANEL_KEY L"Software\\OpenAbstractions\\Abstraction\\Panel"
#endif
#ifndef OA_RECORDS_EXTENSIONS_KEY
#define OA_RECORDS_EXTENSIONS_KEY L"Software\\OpenAbstractions\\Extensions\\"
#endif

#define OA_RECORDS_MAX 32768

static void oa_records_say(MSIHANDLE install, const WCHAR *what, const WCHAR *value)
{
    MSIHANDLE record = MsiCreateRecord(2);
    if (record == 0)
        return;
    MsiRecordSetStringW(record, 0, L"OpenAbstractions records: [1]: [2]");
    MsiRecordSetStringW(record, 1, what);
    MsiRecordSetStringW(record, 2, value);
    MsiProcessMessage(install, INSTALLMESSAGE_INFO, record);
    MsiCloseHandle(record);
}

/* The string value `name` of root\key into out, or FALSE. */
static BOOL oa_records_string(HKEY root, const WCHAR *key, const WCHAR *name, REGSAM view, WCHAR *out)
{
    HKEY opened = NULL;
    DWORD type = 0, size = (OA_RECORDS_MAX - 1) * sizeof(WCHAR);
    BOOL ok = FALSE;
    out[0] = L'\0';
    if (RegOpenKeyExW(root, key, 0, KEY_QUERY_VALUE | view, &opened) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(opened, name, NULL, &type, (BYTE *)out, &size) == ERROR_SUCCESS &&
        type == REG_SZ && size >= sizeof(WCHAR) && size % sizeof(WCHAR) == 0) {
        out[size / sizeof(WCHAR)] = L'\0';
        ok = out[0] != L'\0';
    }
    RegCloseKey(opened);
    if (!ok)
        out[0] = L'\0';
    return ok;
}

/* X:\... naming an existing file. */
static BOOL oa_records_program(const WCHAR *path)
{
    if (!(((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
          path[1] == L':' && path[2] == L'\\'))
        return FALSE;
    DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL oa_records_panel(WCHAR *panel)
{
    HKEY user = NULL;
    if (oa_records_string(OA_RECORDS_MACHINE_ROOT, OA_RECORDS_PANEL_KEY, L"program", KEY_WOW64_64KEY, panel) &&
        oa_records_program(panel))
        return TRUE;
    /* The installing account's own hive, also when the action runs
       impersonated in the Windows Installer service. */
    if (RegOpenCurrentUser(KEY_READ, &user) == ERROR_SUCCESS) {
        BOOL found = oa_records_string(user, OA_RECORDS_PANEL_KEY, L"program", 0, panel) && oa_records_program(panel);
        RegCloseKey(user);
        if (found)
            return TRUE;
    }
    panel[0] = L'\0';
    return FALSE;
}

static void oa_records_folder(MSIHANDLE install, WCHAR *folder, WCHAR *key)
{
    DWORD size = 64;
    WCHAR id[64] = L"";
    HKEY user = NULL;
    folder[0] = L'\0';
    if (MsiGetPropertyW(install, L"OaExtensionId", id, &size) != ERROR_SUCCESS || !id[0])
        return;
    if (wcscpy_s(key, OA_RECORDS_MAX, OA_RECORDS_EXTENSIONS_KEY) || wcscat_s(key, OA_RECORDS_MAX, id))
        return;
    if (RegOpenCurrentUser(KEY_READ, &user) != ERROR_SUCCESS)
        return;
    oa_records_string(user, key, L"folder", 0, folder);
    RegCloseKey(user);
}

__declspec(dllexport) UINT __stdcall FindRecords(MSIHANDLE install)
{
    UINT result = ERROR_INSTALL_FAILURE;
    WCHAR *panel = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, OA_RECORDS_MAX * sizeof(WCHAR));
    WCHAR *folder = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, OA_RECORDS_MAX * sizeof(WCHAR));
    WCHAR *key = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, OA_RECORDS_MAX * sizeof(WCHAR));
    if (panel == NULL || folder == NULL || key == NULL)
        goto out;
    oa_records_panel(panel);
    oa_records_folder(install, folder, key);
    if (MsiSetPropertyW(install, L"OaPanel", panel) != ERROR_SUCCESS ||
        MsiSetPropertyW(install, L"OaRecordedFolder", folder) != ERROR_SUCCESS)
        goto out;
    oa_records_say(install, L"Panel", panel[0] ? panel : L"none");
    oa_records_say(install, L"recorded folder", folder[0] ? folder : L"none");
    result = ERROR_SUCCESS;
out:
    if (panel)
        HeapFree(GetProcessHeap(), 0, panel);
    if (folder)
        HeapFree(GetProcessHeap(), 0, folder);
    if (key)
        HeapFree(GetProcessHeap(), 0, key);
    return result;
}

#endif

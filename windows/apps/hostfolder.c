/*
 * hostfolder.c: the Windows Installer custom action of installer/apps/extension.wxs.
 *
 * An extension's per-user package places a folder inside another
 * application's own folder, which that application records in a JSON
 * configuration file. Windows Installer reads no JSON, so this immediate
 * custom action does, before the launch conditions:
 *
 *   OaHostConfig     (in)  the configuration file's full path
 *   OaHostKey        (in)  a top-level key whose string value is the
 *                          application's folder
 *   OaHostSubfolder  (in)  the folder under it that receives the extension
 *   OaExtensionName  (in)  the extension's folder name inside the subfolder
 *   OAEXTENSION_FOLDER (in) the subfolder an earlier version of this
 *                          package recorded, or empty
 *   HostFolder       (out) <value>\<subfolder>\ when the value is a
 *                          drive-absolute path on a local drive and the
 *                          subfolder is a directory
 *   OaHostFound      (out) 1 when HostFolder was set
 *   OaHostTaken      (out) 1 when <HostFolder><name> already exists and is
 *                          not the folder an earlier version recorded
 *
 * The file is read up to 1 MiB and must be one JSON object; a key given more
 * than once takes its last value, as JSON.parse does. The action changes
 * nothing on disk and names no application: every name comes from the
 * package's properties. It always returns success unless Windows Installer
 * itself fails; the package's launch conditions say what was not found.
 *
 * Build (a Visual Studio x64 developer environment):
 *   cl /nologo /W4 /WX /O2 /MT /GS /guard:cf /Brepro /LD hostfolder.c
 *      /link /guard:cf /Brepro /DYNAMICBASE /NXCOMPAT msi.lib
 */
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <stdlib.h>
#include <string.h>

static WCHAR *property(MSIHANDLE install, const WCHAR *name)
{
    WCHAR empty[1] = L"";
    DWORD size = 0;
    UINT result = MsiGetPropertyW(install, name, empty, &size);
    if (result != ERROR_MORE_DATA && result != ERROR_SUCCESS)
        return NULL;
    size += 1;
    WCHAR *value = calloc(size, sizeof(WCHAR));
    if (value == NULL)
        return NULL;
    if (MsiGetPropertyW(install, name, value, &size) != ERROR_SUCCESS) {
        free(value);
        return NULL;
    }
    return value;
}

static void say(MSIHANDLE install, const WCHAR *text)
{
    MSIHANDLE record = MsiCreateRecord(1);
    if (record == 0)
        return;
    MsiRecordSetStringW(record, 0, L"OpenAbstractions extension folder: [1]");
    MsiRecordSetStringW(record, 1, text);
    MsiProcessMessage(install, INSTALLMESSAGE_INFO, record);
    MsiCloseHandle(record);
}

#include "hostfolder_io.h"

__declspec(dllexport) UINT __stdcall FindHostFolder(MSIHANDLE install)
{
    UINT result = ERROR_INSTALL_FAILURE;
    WCHAR *config = property(install, L"OaHostConfig");
    WCHAR *key = property(install, L"OaHostKey");
    WCHAR *sub = property(install, L"OaHostSubfolder");
    WCHAR *name = property(install, L"OaExtensionName");
    WCHAR *recorded = property(install, L"OAEXTENSION_FOLDER");
    char *data = NULL, *found = NULL, *key_utf8 = NULL;
    WCHAR *base = NULL, *folder = NULL, *target = NULL;
    if (config == NULL || key == NULL || sub == NULL || name == NULL || recorded == NULL ||
        !*config || !*key || !*sub || !*name)
        goto out;
    result = ERROR_SUCCESS;
    MsiSetPropertyW(install, L"OaHostFound", L"");
    MsiSetPropertyW(install, L"OaHostTaken", L"");
    size_t size = 0;
    data = read_config(config, &size);
    if (data == NULL) {
        say(install, L"the configuration file could not be read");
        goto out;
    }
    int key_length = WideCharToMultiByte(CP_UTF8, 0, key, -1, NULL, 0, NULL, NULL);
    key_utf8 = key_length > 0 ? malloc((size_t)key_length) : NULL;
    found = malloc(size + 1);
    if (key_utf8 == NULL || found == NULL ||
        WideCharToMultiByte(CP_UTF8, 0, key, -1, key_utf8, key_length, NULL, NULL) != key_length)
        goto out;
    int state = top_level(data, size, key_utf8, found);
    if (state != 1) {
        say(install, state < 0 ? L"the configuration file is not one JSON object" : L"the configuration names no folder");
        goto out;
    }
    base = wide(found);
    folder = base ? host_folder(base, sub) : NULL;
    if (folder == NULL) {
        say(install, L"the configured folder is not a local folder holding the extension folder's parent");
        goto out;
    }
    size_t target_length = wcslen(folder) + wcslen(name) + 1;
    target = calloc(target_length, sizeof(WCHAR));
    if (target == NULL)
        goto out;
    wcscpy_s(target, target_length, folder);
    wcscat_s(target, target_length, name);
    if (GetFileAttributesW(target) != INVALID_FILE_ATTRIBUTES && !same_folder(folder, recorded, name)) {
        MsiSetPropertyW(install, L"OaHostTaken", L"1");
        say(install, target);
    }
    MsiSetPropertyW(install, L"HostFolder", folder);
    MsiSetPropertyW(install, L"OaHostFound", L"1");
    say(install, folder);
out:
    free(config);
    free(key);
    free(sub);
    free(name);
    free(recorded);
    free(data);
    free(found);
    free(key_utf8);
    free(base);
    free(folder);
    free(target);
    return result;
}

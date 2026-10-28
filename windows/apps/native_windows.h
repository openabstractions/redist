/* Internal native Windows fileid adapter. No exported ABI or persisted key.
 * File identity: volume +128-bit ID. Installer opens refuse every reparse point.
 * Relative single-component opens follow fileid/resolve_windows.go's held-parent
 * walk. NtCreateFile RootDirectory/FILE_OPEN_REPARSE_POINT and FILE_ID_INFO:
 * https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntcreatefile
 * https://learn.microsoft.com/windows/win32/api/winbase/ns-winbase-file_id_info
 */
#pragma once
#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

typedef struct { ULONGLONG volume; BYTE id[16]; } OA_NATIVE_FILE_ID;
typedef struct { HANDLE *chain; size_t count; HANDLE file; WCHAR *tail; } OA_NATIVE_FILE;
typedef NTSTATUS (NTAPI *OA_NATIVE_CREATE)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
typedef ULONG (WINAPI *OA_NATIVE_ERROR)(NTSTATUS);
typedef NTSTATUS (NTAPI *OA_NATIVE_SET)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);

static __inline BOOL oa_native_id(HANDLE file,OA_NATIVE_FILE_ID *id) {
    return GetFileInformationByHandleEx(file,(FILE_INFO_BY_HANDLE_CLASS)18,id,sizeof(*id));
}
static __inline BOOL oa_native_id_equal(const OA_NATIVE_FILE_ID *a,const OA_NATIVE_FILE_ID *b) {
    return a->volume==b->volume&&!memcmp(a->id,b->id,sizeof(a->id));
}
static __inline BOOL oa_native_same_handles(HANDLE a,HANDLE b) {
    OA_NATIVE_FILE_ID left,right;
    return oa_native_id(a,&left)&&oa_native_id(b,&right)&&oa_native_id_equal(&left,&right);
}
static __inline void oa_native_close(OA_NATIVE_FILE *file) {
    DWORD saved=GetLastError();
    for(size_t n=file->count;n;n--)CloseHandle(file->chain[n-1]);
    if(file->chain)HeapFree(GetProcessHeap(),0,file->chain);if(file->tail)HeapFree(GetProcessHeap(),0,file->tail);ZeroMemory(file,sizeof(*file));SetLastError(saved);
}
static __inline BOOL oa_native_add(OA_NATIVE_FILE *file,HANDLE handle) {
    HANDLE *next=file->chain?(HANDLE*)HeapReAlloc(GetProcessHeap(),0,file->chain,(file->count+1)*sizeof(HANDLE)):(HANDLE*)HeapAlloc(GetProcessHeap(),0,(file->count+1)*sizeof(HANDLE));
    if(!next){CloseHandle(handle);SetLastError(ERROR_NOT_ENOUGH_MEMORY);return FALSE;}
    file->chain=next;file->chain[file->count++]=handle;file->file=handle;return TRUE;
}
static __inline BOOL oa_native_safe_name(const WCHAR *part) {
    size_t n=wcslen(part);
    if(!n||n>32766||wcspbrk(part,L"\\/:")||!wcscmp(part,L".")||!wcscmp(part,L"..")||part[n-1]==L'.'||part[n-1]==L' '){SetLastError(ERROR_INVALID_NAME);return FALSE;}
    for(size_t i=0;i<n;i++)if(part[i]<32){SetLastError(ERROR_INVALID_NAME);return FALSE;}
    /* Device syntax is refused before any component open. */
    WCHAR stem[9];size_t sn=0;while(sn<n&&sn<8&&part[sn]!=L'.') {stem[sn]=part[sn];sn++;}stem[sn]=0;
    const WCHAR *devices[]={L"CON",L"PRN",L"AUX",L"NUL",L"CONIN$",L"CONOUT$",L"COM0",L"COM1",L"COM2",L"COM3",L"COM4",L"COM5",L"COM6",L"COM7",L"COM8",L"COM9",L"LPT0",L"LPT1",L"LPT2",L"LPT3",L"LPT4",L"LPT5",L"LPT6",L"LPT7",L"LPT8",L"LPT9",L"COM\u00b9",L"COM\u00b2",L"COM\u00b3",L"LPT\u00b9",L"LPT\u00b2",L"LPT\u00b3"};
    for(size_t d=0;d<sizeof(devices)/sizeof(devices[0]);d++)if(CompareStringOrdinal(stem,-1,devices[d],-1,TRUE)==CSTR_EQUAL){SetLastError(ERROR_INVALID_NAME);return FALSE;}
    return TRUE;
}
/* One component relative to a held parent. Callers retain that parent. */
static __inline HANDLE oa_native_at_checked(HANDLE parent,const WCHAR *name,DWORD access,DWORD share,BOOL directory,ULONG disposition,BOOL *missing) {
    size_t length=wcslen(name);HANDLE result=INVALID_HANDLE_VALUE;
    if(missing)*missing=FALSE;
    if(!oa_native_safe_name(name))return result;
    union {FARPROC raw;OA_NATIVE_CREATE create;} fn;
    union {FARPROC raw;OA_NATIVE_ERROR error;} convert;
    HMODULE module=GetModuleHandleW(L"ntdll.dll");fn.raw=module?GetProcAddress(module,"NtCreateFile"):NULL;convert.raw=module?GetProcAddress(module,"RtlNtStatusToDosError"):NULL;
    if(!fn.raw||!convert.raw){SetLastError(ERROR_NOT_SUPPORTED);return result;}
    DWORD caseFlags=0;
    if(!GetFileInformationByHandleEx(parent,(FILE_INFO_BY_HANDLE_CLASS)23,&caseFlags,sizeof(caseFlags))){
        DWORD error=GetLastError();if(error!=ERROR_INVALID_PARAMETER&&error!=ERROR_NOT_SUPPORTED)return result;
        /* Older volumes lack per-directory case flags; ordinary NT lookup applies. */
        caseFlags=0;
    }
    UNICODE_STRING stringName;stringName.Buffer=(PWSTR)name;stringName.Length=(USHORT)(length*sizeof(WCHAR));stringName.MaximumLength=stringName.Length;
    SECURITY_QUALITY_OF_SERVICE qos={sizeof(qos),SecurityIdentification,SECURITY_STATIC_TRACKING,FALSE};
    OBJECT_ATTRIBUTES attributes;ZeroMemory(&attributes,sizeof(attributes));attributes.Length=sizeof(attributes);attributes.RootDirectory=parent;attributes.ObjectName=&stringName;attributes.Attributes=(caseFlags&1)?0:0x40;attributes.SecurityQualityOfService=&qos;
    IO_STATUS_BLOCK io;ULONG options=0x00200000|0x20|0x4000; /* canonical walk: reparse,synchronous,backup; kind checked on held handle */
    if(disposition!=1)options|=directory?1:0x40; /* creation requires an explicit kind */
    if(disposition==1&&!(access&(GENERIC_READ|GENERIC_WRITE|GENERIC_ALL|FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA)))options|=0x00400000; /* identity-only opens recall no data */
    NTSTATUS status=fn.create(&result,access|FILE_READ_ATTRIBUTES|SYNCHRONIZE,&attributes,&io,NULL,0,share,disposition,options,NULL,0);
    if(status<0){DWORD error=convert.error(status);if(missing)*missing=error==ERROR_FILE_NOT_FOUND||error==ERROR_PATH_NOT_FOUND;SetLastError(error);return INVALID_HANDLE_VALUE;}
    BY_HANDLE_FILE_INFORMATION info;
    DWORD error=ERROR_SUCCESS;
    if(GetFileType(result)!=FILE_TYPE_DISK)error=ERROR_INVALID_HANDLE;
    else if(!GetFileInformationByHandle(result,&info)){error=GetLastError();if(!error)error=ERROR_INVALID_DATA;}
    else if(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)error=ERROR_REPARSE_TAG_INVALID;
    else if(((info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0)!=directory)error=ERROR_DIRECTORY;
    if(error){CloseHandle(result);SetLastError(error);return INVALID_HANDLE_VALUE;}
    return result;
}
static __inline HANDLE oa_native_at(HANDLE parent,const WCHAR *name,DWORD access,DWORD share,BOOL directory,ULONG disposition) {
    return oa_native_at_checked(parent,name,access,share,directory,disposition,NULL);
}
/* Publish a plain leaf beneath the same held directory, without replacement.
 * NtSetInformationFile FileRenameInformation (10) consumes RootDirectory;
 * the Win32 wrapper can reject that relative form on supported Windows builds.
 * https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile
 */
static __inline BOOL oa_native_rename_at(HANDLE file,HANDLE parent,const WCHAR *leaf) {
    if(!oa_native_safe_name(leaf))return FALSE;
    union {FARPROC raw;OA_NATIVE_SET set;} fn;
    union {FARPROC raw;OA_NATIVE_ERROR error;} convert;
    HMODULE module=GetModuleHandleW(L"ntdll.dll");fn.raw=module?GetProcAddress(module,"NtSetInformationFile"):NULL;convert.raw=module?GetProcAddress(module,"RtlNtStatusToDosError"):NULL;
    if(!fn.raw||!convert.raw){SetLastError(ERROR_NOT_SUPPORTED);return FALSE;}
    size_t bytes=wcslen(leaf)*sizeof(WCHAR);ULONG size=(ULONG)(sizeof(FILE_RENAME_INFO)+bytes);
    FILE_RENAME_INFO *rename=(FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,size);
    if(!rename){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return FALSE;}
    rename->RootDirectory=parent;rename->FileNameLength=(DWORD)bytes;memcpy(rename->FileName,leaf,bytes);
    IO_STATUS_BLOCK io;NTSTATUS status=fn.set(file,&io,rename,size,10);HeapFree(GetProcessHeap(),0,rename);
    if(status<0){SetLastError(convert.error(status));return FALSE;}return TRUE;
}
/* Absolute local-drive installer subset. No streams, dot components, reserved
 * device names or trailing-dot/space names. Existing literal-name public APIs
 * retain their separate spelling policy. Pending captures a missing safe tail. */
static __inline BOOL oa_native_open(const WCHAR *input,DWORD access,DWORD share,BOOL directory,BOOL pending,OA_NATIVE_FILE *out) {
    ZeroMemory(out,sizeof(*out));
    const WCHAR *path=input;
    if(!path){SetLastError(ERROR_INVALID_NAME);return FALSE;}
    if(!wcsncmp(path,L"\\\\?\\",4))path+=4;
    size_t length=wcslen(path);
    if(length<3||length>=32768||path[1]!=L':'||path[2]!=L'\\'||!((path[0]>=L'A'&&path[0]<=L'Z')||(path[0]>=L'a'&&path[0]<=L'z'))){SetLastError(ERROR_INVALID_NAME);return FALSE;}
    WCHAR root[8]={L'\\',L'\\',L'?',L'\\',path[0],L':',L'\\',0};
    WCHAR drive[4]={path[0],L':',L'\\',0};UINT type=GetDriveTypeW(drive);
    if(type!=DRIVE_FIXED&&type!=DRIVE_RAMDISK){SetLastError(ERROR_NOT_SUPPORTED);return FALSE;}
    for(size_t i=3;i<length;i++)if(path[i]<32||path[i]==L'/'||path[i]==L':'){SetLastError(ERROR_INVALID_NAME);return FALSE;}
    WCHAR *copy=(WCHAR*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(length+1)*sizeof(WCHAR));if(!copy){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return FALSE;}memcpy(copy,path,(length+1)*sizeof(WCHAR));
    for(WCHAR *part=copy+3;*part;) {
        WCHAR *end=wcschr(part,L'\\');if(end)*end=0;
        BOOL safe=oa_native_safe_name(part);if(end)*end=L'\\';
        if(!safe){HeapFree(GetProcessHeap(),0,copy);return FALSE;}if(!end)break;part=end+1;
    }
    HANDLE parent=CreateFileW(root,FILE_READ_ATTRIBUTES|SYNCHRONIZE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,NULL);
    if(parent==INVALID_HANDLE_VALUE||!oa_native_add(out,parent))goto failed;
    for(WCHAR *part=copy+3;*part;) {
        WCHAR *end=wcschr(part,L'\\');if(end)*end=0;
        BOOL last=!end||!end[1];size_t n=wcslen(part);
        if(!n||!wcscmp(part,L".")||!wcscmp(part,L"..")||part[n-1]==L'.'||part[n-1]==L' '){SetLastError(ERROR_INVALID_NAME);goto failed;}
        BOOL missing=FALSE;HANDLE child=oa_native_at_checked(out->file,part,last?access:FILE_READ_ATTRIBUTES,last?share:(FILE_SHARE_READ|FILE_SHARE_WRITE),last?directory:TRUE,1,&missing);
        if(child==INVALID_HANDLE_VALUE){
            DWORD error=GetLastError();
            if(end)*end=L'\\';
            if(pending&&missing) {
                /* Validate all remaining components without opening names. */
                for(const WCHAR *p=part;*p;p++)if(*p==L':'||*p==L'/'||*p<32){SetLastError(ERROR_INVALID_NAME);goto failed;}
                size_t bytes=(wcslen(part)+1)*sizeof(WCHAR);out->tail=(WCHAR*)HeapAlloc(GetProcessHeap(),0,bytes);if(!out->tail){SetLastError(ERROR_NOT_ENOUGH_MEMORY);goto failed;}memcpy(out->tail,part,bytes);HeapFree(GetProcessHeap(),0,copy);return TRUE;
            }
            SetLastError(error);goto failed;
        }
        if(!oa_native_add(out,child))goto failed;
        if(!end)break;part=end+1;
    }
    if(out->count==1&&!directory){SetLastError(ERROR_DIRECTORY);goto failed;}
    HeapFree(GetProcessHeap(),0,copy);return TRUE;
failed:{DWORD error=GetLastError();HeapFree(GetProcessHeap(),0,copy);oa_native_close(out);SetLastError(error);return FALSE;}
}
/* A checked comparison keeps a known different object distinct from failure. */
static __inline BOOL oa_native_compare_paths(const WCHAR *a,const WCHAR *b,BOOL directory,BOOL pending,BOOL *sameOut) {
    OA_NATIVE_FILE left={0},right={0};OA_NATIVE_FILE_ID leftId,rightId;BOOL same=FALSE,checked=FALSE;*sameOut=FALSE;
    if(!oa_native_open(a,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,directory,pending,&left)||!oa_native_open(b,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,directory,pending,&right))goto done;
    if(!oa_native_id(left.file,&leftId)||!oa_native_id(right.file,&rightId))goto done;
    same=oa_native_id_equal(&leftId,&rightId);
    if(same&&(left.tail||right.tail)) {
        DWORD caseFlags=0;
        if(!GetFileInformationByHandleEx(left.file,(FILE_INFO_BY_HANDLE_CLASS)23,&caseFlags,sizeof(caseFlags))) {
            DWORD error=GetLastError();if(error!=ERROR_INVALID_PARAMETER&&error!=ERROR_NOT_SUPPORTED)goto done;
        }
        /* ID-F7: unresolved names under the SAME held root use that folder's
           case rule and the system NT name table; existing objects use IDs. */
        if(left.tail&&right.tail){int order=CompareStringOrdinal(left.tail,-1,right.tail,-1,(caseFlags&1)?FALSE:TRUE);if(!order)goto done;same=order==CSTR_EQUAL;}
        else same=FALSE;
    }
    *sameOut=same;checked=TRUE;
done:oa_native_close(&left);oa_native_close(&right);return checked;
}
static __inline BOOL oa_native_same_paths(const WCHAR *a,const WCHAR *b,BOOL directory,BOOL pending) {
    BOOL same=FALSE;return oa_native_compare_paths(a,b,directory,pending,&same)&&same;
}
#endif

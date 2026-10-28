/* Receiving user token facts shared by native app installer owners. */
#pragma once
#include <windows.h>

typedef struct {BYTE sid[SECURITY_MAX_SID_SIZE];LUID authentication;DWORD session,integrity;BOOL elevated,service;} TOKEN_FACTS;
static BOOL token_facts(HANDLE token,TOKEN_FACTS *facts) {
    BYTE bytes[4096];DWORD size;TOKEN_ELEVATION elevation;TOKEN_STATISTICS statistics;
    ZeroMemory(facts,sizeof(*facts));
    if(!GetTokenInformation(token,TokenUser,bytes,sizeof(bytes),&size)||!IsValidSid(((TOKEN_USER*)bytes)->User.Sid)
       ||!CopySid(sizeof(facts->sid),facts->sid,((TOKEN_USER*)bytes)->User.Sid))return FALSE;
    facts->service=IsWellKnownSid(facts->sid,WinLocalSystemSid)||IsWellKnownSid(facts->sid,WinLocalServiceSid)||IsWellKnownSid(facts->sid,WinNetworkServiceSid);
    if(!GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&size)
       ||!GetTokenInformation(token,TokenStatistics,&statistics,sizeof(statistics),&size)
       ||!GetTokenInformation(token,TokenSessionId,&facts->session,sizeof(facts->session),&size)
       ||!GetTokenInformation(token,TokenIntegrityLevel,bytes,sizeof(bytes),&size))return FALSE;
    PSID integrity=((TOKEN_MANDATORY_LABEL*)bytes)->Label.Sid;
    if(!IsValidSid(integrity)||!*GetSidSubAuthorityCount(integrity))return FALSE;
    facts->integrity=*GetSidSubAuthority(integrity,*GetSidSubAuthorityCount(integrity)-1);
    facts->authentication=statistics.AuthenticationId;facts->elevated=elevation.TokenIsElevated;
    return TRUE;
}
static BOOL ordinary_user(const TOKEN_FACTS *facts) {return !facts->service&&!facts->elevated&&facts->integrity<=SECURITY_MANDATORY_MEDIUM_RID;}
static BOOL same_execution_user(const TOKEN_FACTS *host,const TOKEN_FACTS *user) {
    return ordinary_user(host)&&ordinary_user(user)&&EqualSid((PSID)host->sid,(PSID)user->sid)
       &&host->authentication.LowPart==user->authentication.LowPart&&host->authentication.HighPart==user->authentication.HighPart
       &&host->session==user->session&&host->integrity==user->integrity;
}
static HANDLE user_token(void) {
    HANDLE token=NULL;TOKEN_FACTS facts;
    if(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY|TOKEN_DUPLICATE,TRUE,&token)) {
        if(GetLastError()!=ERROR_NO_TOKEN||!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&token))return NULL;
    }
    /* Per-user writable JavaScript executes only at ordinary user integrity. */
    if(!token_facts(token,&facts)||!ordinary_user(&facts)){CloseHandle(token);return NULL;}
    return token;
}

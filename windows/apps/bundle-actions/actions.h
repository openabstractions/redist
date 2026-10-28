// OpenAbstractions' finite optional-app planning policy. Windows/Burn owns detection.
#pragma once
#include "wix5/BootstrapperEngineTypes.h"

struct OA_BUNDLE_APP
{
    LPCWSTR variable;
    LPCWSTR packages[4]; // integration, host, preflight, preparation
};

inline HRESULT OaBundleRequestedState(BOOTSTRAPPER_ACTION action,
    BOOTSTRAPPER_PACKAGE_STATE state, BOOTSTRAPPER_PACKAGE_CONDITION_RESULT selected,
    BOOTSTRAPPER_REQUEST_STATE* requested)
{
    if (action != BOOTSTRAPPER_ACTION_INSTALL && action != BOOTSTRAPPER_ACTION_MODIFY &&
        action != BOOTSTRAPPER_ACTION_REPAIR)
    {
        if (action == BOOTSTRAPPER_ACTION_UNINSTALL || action == BOOTSTRAPPER_ACTION_UNSAFE_UNINSTALL ||
            action == BOOTSTRAPPER_ACTION_LAYOUT || action == BOOTSTRAPPER_ACTION_CACHE ||
            action == BOOTSTRAPPER_ACTION_UPDATE_REPLACE || action == BOOTSTRAPPER_ACTION_UPDATE_REPLACE_EMBEDDED)
            return S_OK; // Explicit uninstall/layout/update retain Burn's own policy.
        return E_INVALIDARG;
    }
    if (state != BOOTSTRAPPER_PACKAGE_STATE_ABSENT && state != BOOTSTRAPPER_PACKAGE_STATE_PRESENT)
        return E_INVALIDARG;
    if (selected != BOOTSTRAPPER_PACKAGE_CONDITION_TRUE && selected != BOOTSTRAPPER_PACKAGE_CONDITION_FALSE)
        return E_INVALIDARG;
    // A stock BA restart skip is already NONE; never schedule it a second time.
    if (*requested == BOOTSTRAPPER_REQUEST_STATE_NONE)
        return S_OK;
    if (*requested != BOOTSTRAPPER_REQUEST_STATE_ABSENT && *requested != BOOTSTRAPPER_REQUEST_STATE_PRESENT &&
        *requested != BOOTSTRAPPER_REQUEST_STATE_REPAIR)
        return E_INVALIDARG;
    if (selected == BOOTSTRAPPER_PACKAGE_CONDITION_FALSE)
        *requested = BOOTSTRAPPER_REQUEST_STATE_NONE;
    else if (state == BOOTSTRAPPER_PACKAGE_STATE_ABSENT)
        *requested = BOOTSTRAPPER_REQUEST_STATE_PRESENT;
    return S_OK;
}

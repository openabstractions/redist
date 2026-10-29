// OpenAbstractions' finite optional-app planning policy. Windows/Burn owns detection.
#pragma once
#include "wix5/BootstrapperEngineTypes.h"

struct OA_BUNDLE_APP
{
    LPCWSTR variable;
    LPCWSTR packages[4]; // integration, host, preflight, preparation
    BOOL needsMcpGateway;
};
struct OA_BUNDLE_CORE_FEATURE { LPCWSTR id; BOOL defaultLocal; };

// The success page's own controls (build_bundle.theme writes them): Finish
// and the ticked "Open OpenAbstractions" box. BAFunctions assigns their ids
// in its own range, [0x4000, 0x8000).
#define OA_FINISH_BUTTON L"OaFinishButton"
#define OA_OPEN_CHECKBOX L"OaOpenCheckbox"
// 1 while Setup runs elevated; the box's show condition reads it.
#define OA_SETUP_ELEVATED L"OaSetupElevated"
const WORD OA_FINISH_BUTTON_ID = 0x4001;
const WORD OA_OPEN_CHECKBOX_ID = 0x4002;

// Core features every installation carries (Level 1 in abstraction.wxs):
// picture adapters that start nothing and offer no model until Setup's
// approved plan installs their engine, and the MCP gateway an assistant starts. Setup
// never adds a feature later, so each install, upgrade and modify plans them
// local, including over a related core that had them absent.
inline BOOL OaBundleCoreFeatureAlways(LPCWSTR id)
{
    static const LPCWSTR always[] = {L"McpGateway", L"LemonadeImage", L"PyTorchImage"};
    for (SIZE_T i = 0; id && i < sizeof(always) / sizeof(always[0]); ++i)
        if (!wcscmp(id, always[i])) return TRUE;
    return FALSE;
}

// The source-owned unconditional Level1 roster supplies fresh defaults. Burn
// supplies actual installed states; unknown observations never mean absent.
// A feature the related product never registered is fresh (related FALSE).
inline HRESULT OaBundleCoreFeatureState(BOOTSTRAPPER_ACTION action,
    BOOTSTRAPPER_PACKAGE_STATE core, BOOTSTRAPPER_REQUEST_STATE requestedCore,
    BOOL selected, BOOL related, BOOL defaultLocal, BOOL required,
    BOOTSTRAPPER_FEATURE_STATE detected, BOOTSTRAPPER_FEATURE_STATE* requested)
{
    if (!selected || (action != BOOTSTRAPPER_ACTION_INSTALL && action != BOOTSTRAPPER_ACTION_MODIFY) ||
        requestedCore != BOOTSTRAPPER_REQUEST_STATE_PRESENT) return S_OK;
    if (core != BOOTSTRAPPER_PACKAGE_STATE_ABSENT && core != BOOTSTRAPPER_PACKAGE_STATE_PRESENT) return E_INVALIDARG;
    if (detected < BOOTSTRAPPER_FEATURE_STATE_ABSENT || detected > BOOTSTRAPPER_FEATURE_STATE_SOURCE) return E_INVALIDARG;
    if (required) *requested = BOOTSTRAPPER_FEATURE_STATE_LOCAL;
    else if (core == BOOTSTRAPPER_PACKAGE_STATE_PRESENT || related) *requested = detected;
    else *requested = defaultLocal ? BOOTSTRAPPER_FEATURE_STATE_LOCAL : BOOTSTRAPPER_FEATURE_STATE_ABSENT;
    return S_OK;
}

// BeginCoreUpgrade stops the installed runtime and holds the upgrade exclusion
// for this Burn chain; the core MSI's commit releases it. Burn executes the
// core only when its exact product is absent. Over a present (same build) or
// superseded (newer) core nothing releases the exclusion, and every app
// package after it found the runtime "being replaced" (R23 reinstall,
// 2026-11-10). The early stop is planned only while Burn installs the core.
inline HRESULT OaBundleEarlyStopState(BOOTSTRAPPER_PACKAGE_STATE core, BOOTSTRAPPER_REQUEST_STATE* requested)
{
    if (!requested) return E_INVALIDARG;
    if (*requested == BOOTSTRAPPER_REQUEST_STATE_PRESENT && core != BOOTSTRAPPER_PACKAGE_STATE_ABSENT)
        *requested = BOOTSTRAPPER_REQUEST_STATE_NONE;
    return S_OK;
}

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

/*
 * Copyright 2016 Michael Müller
 * Copyright 2017 Andrey Gusev
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define COBJMACROS

#include <stdlib.h>   /* bsearch (bo3-kernelbase-stubs; ntdll exports it) */
#include <string.h>
#include "ntstatus.h"
#include "windows.h"
#include "appmodel.h"
#include "shlwapi.h"
#include "perflib.h"
#include "winternl.h"
#include "winperf.h"

#include "wine/debug.h"
#include "kernelbase.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(kernelbase);


BOOL is_wow64 = FALSE;

/* iOS-Madeira bo3-kernelbase-stubs (Nov 20 2026). kernelbase.spec ends with 497 "@ stub" exports
 * that real Windows kernelbase.dll has and ours lacked. Black Ops III's anti-tamper walks this
 * export table by name hash, finds nothing, and calls a null pointer; with the stubs present the
 * call lands in a stub that logs its own name. Other programs probe exports with GetProcAddress
 * and would take a stub instead of their fallback, so the stubs stay HIDDEN unless the game's own
 * config sets env.MADEIRA_KB_STUBS = 1. Hiding = removing their entries from the sorted name
 * table in place (order kept, so binary search still works) and lowering NumberOfNames. The
 * functions stay reachable by ordinal only, which nothing uses. Runs once in DllMain. Note: the
 * exe's static imports are bound before this runs, so a static import of a hidden name still binds
 * to its stub (today it binds to the loader's own unimplemented stub; both crash on call). */
static const char * const kb_stub_names[] =
{
    "AcquireStateLock",
    "AddDependencyToProcessPackageGraph",
    "AddExtensionProgId",
    "AddPackageToFamilyXref",
    "AddResourceAttributeAce",
    "AddSIDToBoundaryDescriptor",
    "AddScopedPolicyIDAce",
    "AppContainerDeriveSidFromMoniker",
    "AppContainerFreeMemory",
    "AppContainerLookupDisplayNameMrtReference",
    "AppContainerLookupMoniker",
    "AppContainerRegisterSid",
    "AppContainerUnregisterSid",
    "AppPolicyGetClrCompat",
    "AppPolicyGetCreateFileAccess",
    "AppPolicyGetLifecycleManagement",
    "AppXFreeMemory",
    "AppXGetApplicationData",
    "AppXGetDevelopmentMode",
    "AppXGetOSMaxVersionTested",
    "AppXGetOSMinVersion",
    "AppXGetPackageCapabilities",
    "AppXGetPackageSid",
    "AppXLookupDisplayName",
    "AppXLookupMoniker",
    "AppXPostSuccessExtension",
    "AppXPreCreationExtension",
    "AppXReleaseAppXContext",
    "AppXUpdatePackageCapabilities",
    "ApplicationUserModelIdFromProductId",
    "AreThereVisibleLogoffScriptsInternal",
    "AreThereVisibleShutdownScriptsInternal",
    "ArmFeatureUsageSubscriberFlushNotification",
    "BaseCheckAppcompatCacheEx",
    "BaseFormatObjectAttributes",
    "BaseFreeAppCompatDataForProcess",
    "BaseGetConsoleReference",
    "BaseIsAppcompatInfrastructureDisabled",
    "BaseMarkFileForDelete",
    "BaseReadAppCompatDataForProcess",
    "BasepAdjustObjectAttributesForPrivateNamespace",
    "BasepCopyFileCallback",
    "BasepCopyFileExW",
    "BasepNotifyTrackingService",
    "CLOSE_LOCAL_HANDLE_INTERNAL",
    "CallEnclave",
    "CeipIsOptedIn",
    "CheckAllowDecryptedRemoteDestinationPolicy",
    "CheckIfStateChangeNotificationExists",
    "CheckIsMSIXPackage",
    "CheckTokenCapability",
    "CheckTokenMembershipEx",
    "ClosePackageInfo",
    "ClosePrivateNamespace",
    "CloseState",
    "CloseStateAtom",
    "CloseStateChangeNotification",
    "CloseStateContainer",
    "CloseStateLock",
    "CommitStateAtom",
    "CouldMultiUserAppsBehaviorBePossibleForPackage",
    "CreateAppContainerToken",
    "CreateEnclave",
    "CreatePrivateNamespaceW",
    "CreatePseudoConsoleAsUser",
    "CreateStateAtom",
    "CreateStateChangeNotification",
    "CreateStateContainer",
    "CreateStateLock",
    "CreateStateSubcontainer",
    "CveEventWrite",
    "DecodeRemotePointer",
    "DelayLoadFailureHookLookup",
    "DeleteBoundaryDescriptor",
    "DeleteEnclave",
    "DeleteStateAtomValue",
    "DeleteStateContainer",
    "DeleteStateContainerValue",
    "DsBindWithSpnExW",
    "DsCrackNamesW",
    "DsFreeDomainControllerInfoW",
    "DsFreeNameResultW",
    "DsFreeNgcKey",
    "DsFreePasswordCredentials",
    "DsGetDomainControllerInfoW",
    "DsMakePasswordCredentialsW",
    "DsReadNgcKeyW",
    "DsUnBindW",
    "DsWriteNgcKeyW",
    "DuplicateStateContainerHandle",
    "EncodeRemotePointer",
    "EnterCriticalPolicySectionInternal",
    "EnumSystemGeoNames",
    "EnumerateExtensionNames",
    "EnumerateStateAtomValues",
    "EnumerateStateContainerItems",
    "ExtensionProgIdExists",
    "FindPackagesByPackageFamily",
    "ForceSyncFgPolicyInternal",
    "FormatApplicationUserModelId",
    "FormatApplicationUserModelIdA",
    "FreeGPOListInternalA",
    "FreeGPOListInternalW",
    "GenerateGPNotificationInternal",
    "GetAdjustObjectAttributesForPrivateNamespaceRoutine",
    "GetAlternatePackageRoots",
    "GetAppContainerAce",
    "GetAppContainerNamedObjectPath",
    "GetAppDataFolder",
    "GetAppModelVersion",
    "GetApplicationRecoveryCallback",
    "GetApplicationUserModelId",
    "GetApplicationUserModelIdFromToken",
    "GetAppliedGPOListInternalA",
    "GetAppliedGPOListInternalW",
    "GetCachedSigningLevel",
    "GetCommPorts",
    "GetConsoleAliasExesA",
    "GetConsoleAliasExesW",
    "GetConsoleAliasesA",
    "GetConsoleAliasesW",
    "GetConsoleHistoryInfo",
    "GetConsoleSelectionInfo",
    "GetCurrentPackageApplicationContext",
    "GetCurrentPackageApplicationResourcesContext",
    "GetCurrentPackageContext",
    "GetCurrentPackageGlobalizationContext",
    "GetCurrentPackageInfo2",
    "GetCurrentPackageInfo3",
    "GetCurrentPackagePath2",
    "GetCurrentPackageResourcesContext",
    "GetCurrentPackageSecurityContext",
    "GetCurrentTargetPlatformContext",
    "GetDurationFormatEx",
    "GetEffectivePackageStatusForUser",
    "GetEffectivePackageStatusForUserSid",
    "GetEightBitStringToUnicodeSizeRoutine",
    "GetEightBitStringToUnicodeStringRoutine",
    "GetExtensionApplicationUserModelId",
    "GetExtensionProgIds",
    "GetExtensionProperty",
    "GetExtensionProperty2",
    "GetFileVersionInfoByHandle",
    "GetGPOListInternalA",
    "GetGPOListInternalW",
    "GetGamingDeviceModelInformation",
    "GetHivePath",
    "GetIsEdpEnabled",
    "GetIsWdagEnabled",
    "GetMemoryErrorHandlingCapabilities",
    "GetNextFgPolicyRefreshInfoInternal",
    "GetOsManufacturingMode",
    "GetOsSafeBootMode",
    "GetPackageApplicationContext",
    "GetPackageApplicationIds",
    "GetPackageApplicationProperty",
    "GetPackageApplicationPropertyString",
    "GetPackageApplicationResourcesContext",
    "GetPackageContext",
    "GetPackageFamilyNameFromProgId",
    "GetPackageFamilyNameFromToken",
    "GetPackageFullNameFromToken",
    "GetPackageGlobalizationContext",
    "GetPackageGlobalizationProperty",
    "GetPackageId",
    "GetPackageInfo",
    "GetPackageInfo2",
    "GetPackageInfo3",
    "GetPackageInstallTime",
    "GetPackageOSMaxVersionTested",
    "GetPackagePath",
    "GetPackagePathByFullName2",
    "GetPackagePathOnVolume",
    "GetPackageProperty",
    "GetPackagePropertyString",
    "GetPackageResourcesContext",
    "GetPackageResourcesProperty",
    "GetPackageSecurityContext",
    "GetPackageSecurityProperty",
    "GetPackageStatus",
    "GetPackageStatusForUser",
    "GetPackageStatusForUserSid",
    "GetPackageTargetPlatformProperty",
    "GetPackageVolumeSisPath",
    "GetPersistedFileLocationW",
    "GetPersistedRegistryLocationW",
    "GetPersistedRegistryValueW",
    "GetPreviousFgPolicyRefreshInfoInternal",
    "GetProcAddressForCaller",
    "GetProcessDefaultCpuSets",
    "GetProcessorSystemCycleTime",
    "GetProtocolAumid",
    "GetProtocolProperty",
    "GetPublisherCacheFolder",
    "GetPublisherRootFolder",
    "GetRegistryExtensionFlags",
    "GetRegistryValueWithFallbackW",
    "GetRoamingLastObservedChangeTime",
    "GetSecureSystemAppDataFolder",
    "GetSerializedAtomBytes",
    "GetSharedLocalFolder",
    "GetStagedPackageOrigin",
    "GetStagedPackagePathByFullName",
    "GetStagedPackagePathByFullName2",
    "GetStateContainerDepth",
    "GetStateFolder",
    "GetStateRootFolder",
    "GetStateRootFolderBase",
    "GetStateSettingsFolder",
    "GetStateVersion",
    "GetStringScripts",
    "GetSystemAppDataFolder",
    "GetSystemAppDataKey",
    "GetSystemLeapSecondInformation",
    "GetSystemMetadataPath",
    "GetSystemMetadataPathForPackage",
    "GetSystemMetadataPathForPackageFamily",
    "GetSystemStateRootFolder",
    "GetSystemTimeAdjustmentPrecise",
    "GetTargetPlatformContext",
    "GetThreadInformation",
    "GetThreadSelectedCpuSets",
    "GetUnicodeStringToEightBitSizeRoutine",
    "GetUnicodeStringToEightBitStringRoutine",
    "GetUserOverrideString",
    "GetUserOverrideWord",
    "GuardCheckLongJumpTarget",
    "HasPolicyForegroundProcessingCompletedInternal",
    "IncrementPackageStatusVersion",
    "InitializeEnclave",
    "InstallELAMCertificateInfo",
    "InternetTimeFromSystemTimeA",
    "InternetTimeFromSystemTimeW",
    "InternetTimeToSystemTimeA",
    "InternetTimeToSystemTimeW",
    "InvalidateAppModelVersionCache",
    "IsDeveloperModePolicyApplied",
    "IsEnclaveTypeSupported",
    "IsMrtResourceRedirectionEnabled",
    "IsOnDemandRegistrationSupportedForExtensionCategory",
    "IsProcessCritical",
    "IsSideloadingEnabled",
    "IsSideloadingPolicyApplied",
    "IsSyncForegroundPolicyRefresh",
    "IsTimeZoneRedirectionEnabled",
    "IsUserCetAvailableInEnvironment",
    "IsWow64GuestMachineSupported",
    "KernelbasePostInit",
    "LeaveCriticalPolicySectionInternal",
    "LoadEnclaveData",
    "LoadEnclaveImageA",
    "LoadEnclaveImageW",
    "LocalFileTimeToLocalSystemTime",
    "LocalSystemTimeToLocalFileTime",
    "MapPredefinedHandleInternal",
    "MapViewOfFile3FromApp",
    "MapViewOfFileNuma2",
    "MoveFileWithProgressTransactedW",
    "NamedPipeEventEnum",
    "NamedPipeEventSelect",
    "OfferVirtualMemory",
    "OpenCommPort",
    "OpenGlobalizationUserSettingsKey",
    "OpenPackageInfoByFullName",
    "OpenPackageInfoByFullNameForMachine",
    "OpenPackageInfoByFullNameForUser",
    "OpenPrivateNamespaceW",
    "OpenState",
    "OpenStateAtom",
    "OpenStateExplicit",
    "OpenStateExplicitForUserSid",
    "OpenStateExplicitForUserSidString",
    "OverrideRoamingDataModificationTimesInRange",
    "PackageFamilyNameFromFullName",
    "PackageFamilyNameFromFullNameA",
    "PackageFamilyNameFromId",
    "PackageFamilyNameFromIdA",
    "PackageFamilyNameFromProductId",
    "PackageFullNameFromIdA",
    "PackageFullNameFromProductId",
    "PackageIdFromFullNameA",
    "PackageIdFromProductId",
    "PackageNameAndPublisherIdFromFamilyName",
    "PackageNameAndPublisherIdFromFamilyNameA",
    "PackageRelativeApplicationIdFromProductId",
    "PackageSidFromFamilyName",
    "PackageSidFromProductId",
    "ParseApplicationUserModelId",
    "ParseApplicationUserModelIdA",
    "PcwAddQueryItem",
    "PcwClearCounterSetSecurity",
    "PcwCollectData",
    "PcwCompleteNotification",
    "PcwCreateNotifier",
    "PcwCreateQuery",
    "PcwDisconnectCounterSet",
    "PcwEnumerateInstances",
    "PcwIsNotifierAlive",
    "PcwQueryCounterSetSecurity",
    "PcwReadNotificationData",
    "PcwRegisterCounterSet",
    "PcwRemoveQueryItem",
    "PcwSendNotification",
    "PcwSendStatelessNotification",
    "PcwSetCounterSetSecurity",
    "PcwSetQueryItemUserData",
    "PerfDecrementULongCounterValue",
    "PerfDecrementULongLongCounterValue",
    "PerfIncrementULongCounterValue",
    "PerfIncrementULongLongCounterValue",
    "PerfQueryInstance",
    "PoolPerAppKeyStateInternal",
    "ProductIdFromPackageFamilyName",
    "PsmCreateKey",
    "PsmCreateKeyWithDynamicId",
    "PsmEqualApplication",
    "PsmEqualPackage",
    "PsmGetApplicationNameFromKey",
    "PsmGetDynamicIdFromKey",
    "PsmGetKeyFromProcess",
    "PsmGetKeyFromToken",
    "PsmGetPackageFullNameFromKey",
    "PsmIsChildKey",
    "PsmIsDynamicKey",
    "PsmIsValidKey",
    "PssDuplicateSnapshot",
    "PssWalkMarkerCreate",
    "PssWalkMarkerFree",
    "PssWalkMarkerGetPosition",
    "PssWalkMarkerSeekToBeginning",
    "PssWalkMarkerSetPosition",
    "PssWalkSnapshot",
    "PublishStateChangeNotification",
    "PublisherFromPackageFullName",
    "QueryAuxiliaryCounterFrequency",
    "QueryGlobalizationUserSettingsStatus",
    "QueryOptionalDelayLoadedAPI",
    "QueryProtectedPolicy",
    "QueryStateAtomValueInfo",
    "QueryStateContainerCreatedNew",
    "QueryStateContainerItemInfo",
    "QuirkGetData",
    "QuirkGetData2",
    "QuirkIsEnabled2",
    "QuirkIsEnabledForPackage",
    "QuirkIsEnabledForPackage2",
    "QuirkIsEnabledForPackage3",
    "QuirkIsEnabledForPackage4",
    "QuirkIsEnabledForProcess",
    "RaiseCustomSystemEventTrigger",
    "ReadDirectoryChangesExW",
    "ReadStateAtomValue",
    "ReadStateContainerValue",
    "ReclaimVirtualMemory",
    "RecordFeatureUsage2",
    "RefreshPackageInfo",
    "RefreshPolicyExInternal",
    "RefreshPolicyInternal",
    "RegCreateKeyExInternalA",
    "RegCreateKeyExInternalW",
    "RegDeleteKeyExInternalA",
    "RegDeleteKeyExInternalW",
    "RegDisablePredefinedCacheEx",
    "RegKrnGetAppKeyEventAddressInternal",
    "RegKrnGetAppKeyLoaded",
    "RegKrnGetClassesEnumTableAddressInternal",
    "RegKrnGetHKEY_ClassesRootAddress",
    "RegKrnGetTermsrvRegistryExtensionFlags",
    "RegKrnResetAppKeyLoaded",
    "RegKrnSetDllHasThreadStateGlobal",
    "RegKrnSetTermsrvRegistryExtensionFlags",
    "RegOpenKeyExInternalA",
    "RegOpenKeyExInternalW",
    "RegQueryMultipleValuesA",
    "RegQueryMultipleValuesW",
    "RegisterApplicationRestart",
    "RegisterBadMemoryNotification",
    "RegisterGPNotificationInternal",
    "RegisterStateChangeNotification",
    "RegisterStateLock",
    "ReleaseStateLock",
    "RemoveExtensionProgIds",
    "RemovePackageFromFamilyXref",
    "RemovePackageStatus",
    "RemovePackageStatusForUser",
    "ReplaceFileExInternal",
    "ResetState",
    "ResolveDelayLoadsFromDll",
    "RestoreThreadPreferredUILanguages",
    "RsopLoggingEnabledInternal",
    "SHCoCreateInstance",
    "SHLoadIndirectStringInternal",
    "SaveAlternatePackageRootPath",
    "SaveStateRootFolderPath",
    "SetClientDynamicTimeZoneInformation",
    "SetClientTimeZoneInformation",
    "SetComputerNameEx2W",
    "SetConsoleHistoryInfo",
    "SetConsoleNumberOfCommandsA",
    "SetConsoleNumberOfCommandsW",
    "SetDynamicTimeZoneInformation",
    "SetExtensionProperty",
    "SetFileIoOverlappedRange",
    "SetIsDeveloperModeEnabled",
    "SetIsSideloadingEnabled",
    "SetProcessDynamicEHContinuationTargets",
    "SetProcessDynamicEnforcedCetCompatibleRanges",
    "SetProcessValidCallTargets",
    "SetProcessValidCallTargetsForMappedView",
    "SetProtectedPolicy",
    "SetProtocolProperty",
    "SetRoamingLastObservedChangeTime",
    "SetStateVersion",
    "SetSystemTimeAdjustmentPrecise",
    "SetThreadPreferredUILanguages2",
    "SetThreadpoolWaitEx",
    "SharedLocalIsEnabled",
    "StrChrA_MB",
    "StrChrNIW",
    "SubscribeEdpEnabledStateChange",
    "SubscribeFeatureUsageFlush",
    "SubscribeStateChangeNotification",
    "SubscribeWdagEnabledStateChange",
    "TerminateEnclave",
    "TerminateProcessOnMemoryExhaustion",
    "TestClose",
    "TestControlReporting",
    "TestCreate",
    "TestOpen",
    "TestQueryData",
    "TestRecoverResults",
    "TestReport",
    "TestUnlockData",
    "UnregisterApplicationRestart",
    "UnregisterBadMemoryNotification",
    "UnregisterGPNotificationInternal",
    "UnregisterStateChangeNotification",
    "UnregisterStateLock",
    "UnsubscribeEdpEnabledStateChange",
    "UnsubscribeFeatureUsageFlush",
    "UnsubscribeStateChangeNotification",
    "UnsubscribeWdagEnabledStateChange",
    "UpdatePackageStatus",
    "UpdatePackageStatusForUser",
    "UpdatePackageStatusForUserSid",
    "VerifyApplicationUserModelId",
    "VerifyApplicationUserModelIdA",
    "VerifyPackageFamilyName",
    "VerifyPackageFamilyNameA",
    "VerifyPackageFullName",
    "VerifyPackageFullNameA",
    "VerifyPackageId",
    "VerifyPackageIdA",
    "VerifyPackagePublisher",
    "VerifyPackagePublisherA",
    "VerifyPackageRelativeApplicationId",
    "VerifyPackageRelativeApplicationIdA",
    "VerifyScripts",
    "VirtualUnlockEx",
    "WTSGetServiceSessionId",
    "WTSIsServerContainer",
    "WaitForMachinePolicyForegroundProcessingInternal",
    "WaitForUserPolicyForegroundProcessingInternal",
    "WerRegisterAdditionalProcess",
    "WerRegisterAppLocalDump",
    "WerRegisterExcludedMemoryBlock",
    "WerSetMaxProcessHoldMilliseconds",
    "WerUnregisterAdditionalProcess",
    "WerUnregisterAppLocalDump",
    "WerUnregisterExcludedMemoryBlock",
    "WerpNotifyLoadStringResource",
    "WerpNotifyUseStringResource",
    "Wow64SetThreadDefaultGuestMachine",
    "Wow64SuspendThread",
    "WriteStateAtomValue",
    "WriteStateContainerValue",
    "_AddMUIStringToCache",
    "_GetMUIStringFromCache",
    "_OpenMuiStringCache",
    "__dllonexit3",
    "__wgetmainargs",
    "_amsg_exit",
    "_c_exit",
    "_cexit",
    "_exit",
    "_initterm",
    "_initterm_e",
    "_invalid_parameter",
    "_onexit",
    "_purecall",
    "_time64",
    "atexit",
    "exit",
    "hgets",
    "hwprintf",
    "time",
    "wprintf"
};

static int __cdecl kb_stub_cmp( const void *a, const void *b )
{
    return strcmp( *(const char * const *)a, *(const char * const *)b );
}

static void kb_stubs_hide( HINSTANCE hinst )
{
    WCHAR value[4];
    DWORD len = GetEnvironmentVariableW( L"MADEIRA_KB_STUBS", value, ARRAY_SIZE(value) );
    BOOL hide_stubs = !(len == 1 && value[0] == '1');
    BOOL hide_ntcs;
    BYTE *base = (BYTE *)hinst;
    IMAGE_EXPORT_DIRECTORY *exp;
    DWORD *names, *names_end, total_size, old_names, old_ords, old_dir;
    WORD *ords;
    ULONG size, i, kept = 0;
    SIZE_T names_size, ords_size;
    void *addr;

    /* (bo3-kb-ntcreatesection) the NtCreateSection pass-through rides on the same switch, and
     * env.MADEIRA_KB_NTCS = 0 hides it alone */
    len = GetEnvironmentVariableW( L"MADEIRA_KB_NTCS", value, ARRAY_SIZE(value) );
    hide_ntcs = hide_stubs || (len == 1 && value[0] == '0');
    if (!hide_stubs)
        ERR( "[kb-stubs] %u extra kernelbase exports VISIBLE (env.MADEIRA_KB_STUBS = 1)\n",
             (unsigned)ARRAY_SIZE(kb_stub_names) );
    if (!hide_ntcs)
        ERR( "[kb-ntcs] kernelbase NtCreateSection VISIBLE (env.MADEIRA_KB_NTCS = 0 hides it)\n" );
    if (!hide_stubs && !hide_ntcs) return;
    if (!(exp = RtlImageDirectoryEntryToData( hinst, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size )))
    {
        ERR( "[kb-stubs] hide FAILED: no export directory, the extra exports stay visible\n" );
        return;
    }
    names = (DWORD *)(base + exp->AddressOfNames);
    ords = (WORD *)(base + exp->AddressOfNameOrdinals);
    names_size = exp->NumberOfNames * sizeof(DWORD);
    ords_size = exp->NumberOfNames * sizeof(WORD);

    addr = exp;
    total_size = sizeof(*exp);
    if (!VirtualProtect( addr, total_size, PAGE_READWRITE, &old_dir ))
    {
        ERR( "[kb-stubs] hide FAILED: VirtualProtect(dir) error %lu, the extra exports stay visible\n", GetLastError() );
        return;
    }
    if (!VirtualProtect( names, names_size, PAGE_READWRITE, &old_names ))
    {
        ERR( "[kb-stubs] hide FAILED: VirtualProtect(names) error %lu, the extra exports stay visible\n", GetLastError() );
        VirtualProtect( addr, total_size, old_dir, &old_dir );
        return;
    }
    if (!VirtualProtect( ords, ords_size, PAGE_READWRITE, &old_ords ))
    {
        ERR( "[kb-stubs] hide FAILED: VirtualProtect(ordinals) error %lu, the extra exports stay visible\n", GetLastError() );
        VirtualProtect( names, names_size, old_names, &old_names );
        VirtualProtect( addr, total_size, old_dir, &old_dir );
        return;
    }
    names_end = names + exp->NumberOfNames;
    for (i = 0; names + i < names_end; i++)
    {
        const char *name = (const char *)(base + names[i]);
        if (hide_stubs && bsearch( &name, kb_stub_names, ARRAY_SIZE(kb_stub_names), sizeof(kb_stub_names[0]), kb_stub_cmp ))
            continue;
        if (hide_ntcs && !strcmp( name, "NtCreateSection" )) continue;
        names[kept] = names[i];
        ords[kept] = ords[i];
        kept++;
    }
    TRACE( "[kb-stubs] hid %lu of %lu names\n", exp->NumberOfNames - kept, exp->NumberOfNames );
    exp->NumberOfNames = kept;
    VirtualProtect( ords, ords_size, old_ords, &old_ords );
    VirtualProtect( names, names_size, old_names, &old_names );
    VirtualProtect( addr, total_size, old_dir, &old_dir );
}

/* iOS-Madeira bo3-kb-ntcreatesection (Nov 21 2026). Black Ops III's anti-tamper hashes kernelbase's
 * export names (FNV-1a 64, lowercased) looking for "NtCreateSection", finds none, and calls the
 * null result (proven from its block-ring log). This gives kernelbase a real function under that
 * name that just calls ntdll's NtCreateSection. It is a real function, not a forwarder: a manual
 * export walker would call a forwarder's "ntdll.NtCreateSection" string. Exported -private (never in
 * the import library, so no other dll links to it) and HIDDEN by kb_stubs_hide unless
 * env.MADEIRA_KB_STUBS = 1; env.MADEIRA_KB_NTCS = 0 hides it alone. The game's code is not touched. */
NTSTATUS WINAPI kb_NtCreateSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                    const LARGE_INTEGER *size, ULONG protect, ULONG sec_flags, HANDLE file )
{
    static LONG logged;
    NTSTATUS status = NtCreateSection( handle, access, attr, size, protect, sec_flags, file );

    if (!InterlockedExchange( &logged, 1 ))
        ERR( "[kb-ntcs] first call: access %#lx protect %#lx flags %#lx file %p -> status %#lx\n",
             (unsigned long)access, (unsigned long)protect, (unsigned long)sec_flags, file, (unsigned long)status );
    return status;
}

/***********************************************************************
 *           DllMain
 */
BOOL WINAPI DllMain( HINSTANCE hinst, DWORD reason, LPVOID reserved )
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls( hinst );
        IsWow64Process( GetCurrentProcess(), &is_wow64 );
        init_global_data();
        init_locale( hinst );
        init_startup_info( NtCurrentTeb()->Peb->ProcessParameters );
        init_console();
        crash_report_init();   /* (crash-report) reads env.MADEIRA_CRASH_REPORT once */
        kb_stubs_hide( hinst );   /* (bo3-kernelbase-stubs, bo3-kb-ntcreatesection) env.MADEIRA_KB_STUBS = 1 shows the 497 stubs + NtCreateSection */
    }
    return TRUE;
}


/***********************************************************************
 *           IsDeveloperModeEnabled   (kernelbase.@)
 *
 * Windows' Developer Mode switch. Some games' own d3d12.dll delay-loads it
 * (api-ms-win-appmodel-unlock-l1-1-0) during DllMain and aborts when it is
 * missing. Madeira reports Developer Mode as off.
 */
HRESULT WINAPI IsDeveloperModeEnabled( BOOL *enabled )
{
    FIXME( "(%p) stub, reporting off\n", enabled );
    if (enabled) *enabled = FALSE;   /* IsBadWritePtr is kernel32's; kernelbase cannot import it */
    return S_OK;
}


/***********************************************************************
 *           MulDiv   (kernelbase.@)
 */
INT WINAPI MulDiv( INT a, INT b, INT c )
{
    LONGLONG ret;

    if (!c) return -1;

    /* We want to deal with a positive divisor to simplify the logic. */
    if (c < 0)
    {
        a = -a;
        c = -c;
    }

    /* If the result is positive, we "add" to round. else, we subtract to round. */
    if ((a < 0 && b < 0) || (a >= 0 && b >= 0))
        ret = (((LONGLONG)a * b) + (c / 2)) / c;
    else
        ret = (((LONGLONG)a * b) - (c / 2)) / c;

    if (ret > 2147483647 || ret < -2147483647) return -1;
    return ret;
}

/***********************************************************************
 *          AppPolicyGetMediaFoundationCodecLoading (KERNELBASE.@)
 */

LONG WINAPI AppPolicyGetMediaFoundationCodecLoading(HANDLE token, AppPolicyMediaFoundationCodecLoading *policy)
{
    FIXME("%p, %p\n", token, policy);

    if(policy)
        *policy = AppPolicyMediaFoundationCodecLoading_All;

    return ERROR_SUCCESS;
}

/***********************************************************************
 *          AppPolicyGetProcessTerminationMethod (KERNELBASE.@)
 */
LONG WINAPI AppPolicyGetProcessTerminationMethod(HANDLE token, AppPolicyProcessTerminationMethod *policy)
{
    FIXME("%p, %p\n", token, policy);

    if(policy)
        *policy = AppPolicyProcessTerminationMethod_ExitProcess;

    return ERROR_SUCCESS;
}

/***********************************************************************
 *          AppPolicyGetThreadInitializationType (KERNELBASE.@)
 */
LONG WINAPI AppPolicyGetThreadInitializationType(HANDLE token, AppPolicyThreadInitializationType *policy)
{
    FIXME("%p, %p\n", token, policy);

    if(policy)
        *policy = AppPolicyThreadInitializationType_None;

    return ERROR_SUCCESS;
}

/***********************************************************************
 *          AppPolicyGetShowDeveloperDiagnostic (KERNELBASE.@)
 */
LONG WINAPI AppPolicyGetShowDeveloperDiagnostic(HANDLE token, AppPolicyShowDeveloperDiagnostic *policy)
{
    FIXME("%p, %p\n", token, policy);

    if(policy)
        *policy = AppPolicyShowDeveloperDiagnostic_ShowUI;

    return ERROR_SUCCESS;
}

/***********************************************************************
 *          AppPolicyGetWindowingModel (KERNELBASE.@)
 */
LONG WINAPI AppPolicyGetWindowingModel(HANDLE token, AppPolicyWindowingModel *policy)
{
    static int once;

    if(!once++)
        FIXME("%p, %p\n", token, policy);

    if(policy)
        *policy = AppPolicyWindowingModel_ClassicDesktop;

    return ERROR_SUCCESS;
}

struct counterset_template
{
    PERF_COUNTERSET_INFO counterset;
    PERF_COUNTER_INFO counter[1];
};

struct counterset_instance
{
    struct list entry;
    struct counterset_template *template;
    PERF_COUNTERSET_INSTANCE instance;
};

struct perf_provider
{
    GUID guid;
    PERFLIBREQUEST callback;
    struct counterset_template **countersets;
    unsigned int counterset_count;

    struct list instance_list;
};

static struct perf_provider *perf_provider_from_handle(HANDLE prov)
{
    return (struct perf_provider *)prov;
}

/***********************************************************************
 *           PerfCreateInstance   (KERNELBASE.@)
 */
PERF_COUNTERSET_INSTANCE WINAPI *PerfCreateInstance( HANDLE handle, const GUID *guid,
                                                     const WCHAR *name, ULONG id )
{
    struct perf_provider *prov = perf_provider_from_handle( handle );
    struct counterset_template *template;
    struct counterset_instance *inst;
    unsigned int i;
    ULONG size;

    FIXME( "handle %p, guid %s, name %s, id %lu semi-stub.\n", handle, debugstr_guid(guid), debugstr_w(name), id );

    if (!prov || !guid || !name)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return NULL;
    }

    for (i = 0; i < prov->counterset_count; ++i)
        if (IsEqualGUID(guid, &prov->countersets[i]->counterset.CounterSetGuid)) break;

    if (i == prov->counterset_count)
    {
        SetLastError( ERROR_NOT_FOUND );
        return NULL;
    }

    template = prov->countersets[i];

    LIST_FOR_EACH_ENTRY(inst, &prov->instance_list, struct counterset_instance, entry)
    {
        if (inst->template == template && inst->instance.InstanceId == id)
        {
            SetLastError( ERROR_ALREADY_EXISTS );
            return NULL;
        }
    }

    size = (sizeof(PERF_COUNTERSET_INSTANCE) + template->counterset.NumCounters * sizeof(UINT64)
            + (lstrlenW( name ) + 1) * sizeof(WCHAR) + 7) & ~7;
    inst = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY,
                      offsetof(struct counterset_instance, instance) + size );
    if (!inst)
    {
        SetLastError( ERROR_OUTOFMEMORY );
        return NULL;
    }

    inst->template = template;
    inst->instance.CounterSetGuid = *guid;
    inst->instance.dwSize = size;
    inst->instance.InstanceId = id;
    inst->instance.InstanceNameOffset = sizeof(PERF_COUNTERSET_INSTANCE)
                                        + template->counterset.NumCounters * sizeof(UINT64);
    inst->instance.InstanceNameSize = (lstrlenW( name ) + 1) * sizeof(WCHAR);
    memcpy( (BYTE *)&inst->instance + inst->instance.InstanceNameOffset, name, inst->instance.InstanceNameSize );
    list_add_tail( &prov->instance_list, &inst->entry );

    return &inst->instance;
}

/***********************************************************************
 *           PerfDeleteInstance   (KERNELBASE.@)
 */
ULONG WINAPI PerfDeleteInstance(HANDLE provider, PERF_COUNTERSET_INSTANCE *block)
{
    struct perf_provider *prov = perf_provider_from_handle( provider );
    struct counterset_instance *inst;

    TRACE( "provider %p, block %p.\n", provider, block );

    if (!prov || !block) return ERROR_INVALID_PARAMETER;

    inst = CONTAINING_RECORD(block, struct counterset_instance, instance);
    list_remove( &inst->entry );
    HeapFree( GetProcessHeap(), 0, inst );

    return ERROR_SUCCESS;
}

/***********************************************************************
 *           PerfSetCounterSetInfo   (KERNELBASE.@)
 */
ULONG WINAPI PerfSetCounterSetInfo( HANDLE handle, PERF_COUNTERSET_INFO *template, ULONG size )
{
    struct perf_provider *prov = perf_provider_from_handle( handle );
    struct counterset_template **new_array;
    struct counterset_template *new;
    unsigned int i;

    FIXME( "handle %p, template %p, size %lu semi-stub.\n", handle, template, size );

    if (!prov || !template) return ERROR_INVALID_PARAMETER;
    if (!template->NumCounters) return ERROR_INVALID_PARAMETER;
    if (size < sizeof(*template) || (size - (sizeof(*template))) / sizeof(PERF_COUNTER_INFO) < template->NumCounters)
        return ERROR_INVALID_PARAMETER;

    for (i = 0; i < prov->counterset_count; ++i)
    {
        if (IsEqualGUID( &template->CounterSetGuid, &prov->countersets[i]->counterset.CounterSetGuid ))
            return ERROR_ALREADY_EXISTS;
    }

    size = offsetof( struct counterset_template, counter[template->NumCounters] );
    if (!(new = HeapAlloc( GetProcessHeap(), 0, size ))) return ERROR_OUTOFMEMORY;

    if (prov->counterset_count)
        new_array = HeapReAlloc( GetProcessHeap(), 0, prov->countersets,
                                 sizeof(*prov->countersets) * (prov->counterset_count + 1) );
    else
        new_array = HeapAlloc( GetProcessHeap(), 0, sizeof(*prov->countersets) );

    if (!new_array)
    {
        HeapFree( GetProcessHeap(), 0, new );
        return ERROR_OUTOFMEMORY;
    }
    memcpy( new, template, size );
    for (i = 0; i < template->NumCounters; ++i)
        new->counter[i].Offset = i * sizeof(UINT64);
    new_array[prov->counterset_count++] = new;
    prov->countersets = new_array;

    return STATUS_SUCCESS;
}

static PERF_COUNTER_INFO* get_performance_counter_info(PERF_COUNTERSET_INSTANCE *instance, ULONG counter_id)
{
    unsigned int i;
    struct counterset_template *template;
    struct counterset_instance *inst;

    inst = CONTAINING_RECORD(instance, struct counterset_instance, instance);
    template = inst->template;

    for (i = 0; i < template->counterset.NumCounters; ++i)
        if (template->counter[i].CounterId == counter_id) return  &template->counter[i];

    return NULL;
}

/***********************************************************************
 *           PerfSetCounterRefValue   (KERNELBASE.@)
 */
ULONG WINAPI PerfSetCounterRefValue(HANDLE provider, PERF_COUNTERSET_INSTANCE *instance,
                                    ULONG counterid, void *address)
{
    struct perf_provider *prov = perf_provider_from_handle( provider );
    PERF_COUNTER_INFO* counter;

    FIXME( "provider %p, instance %p, counterid %lu, address %p semi-stub.\n",
           provider, instance, counterid, address );

    if (!prov || !instance || !address) return ERROR_INVALID_PARAMETER;

    counter = get_performance_counter_info(instance, counterid);

    if (counter == NULL) return ERROR_NOT_FOUND;
    if (!(counter->Attrib & PERF_ATTRIB_BY_REFERENCE)) return ERROR_INVALID_PARAMETER;

    *(void **)((BYTE *)(instance + 1) + counter->Offset) = address;

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           PerfSetULongCounterValue   (KERNELBASE.@)
 */
ULONG WINAPI PerfSetULongCounterValue(HANDLE provider, PERF_COUNTERSET_INSTANCE *instance,
                                      ULONG counterid, ULONG value)
{
    struct perf_provider *prov = perf_provider_from_handle( provider );
    PERF_COUNTER_INFO* counter;

    TRACE( "provider %p, instance %p, counterid %lu, address %lu semi-stub.\n",
           provider, instance, counterid, value );

    if (!prov || !instance) return ERROR_INVALID_PARAMETER;

    counter = get_performance_counter_info(instance, counterid);

    if (counter == NULL) return ERROR_NOT_FOUND;
    if (counter->Attrib & PERF_ATTRIB_BY_REFERENCE) return ERROR_INVALID_PARAMETER;
    if (counter->Type & PERF_SIZE_LARGE) return ERROR_INVALID_PARAMETER;

    *(ULONG*)((BYTE *)(instance + 1) + counter->Offset) = value;

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           PerfSetULongLongCounterValue   (KERNELBASE.@)
 */
ULONG WINAPI PerfSetULongLongCounterValue(HANDLE provider, PERF_COUNTERSET_INSTANCE *instance,
                                          ULONG counterid, ULONGLONG value)
{
    struct perf_provider *prov = perf_provider_from_handle( provider );
    PERF_COUNTER_INFO* counter;

    TRACE( "provider %p, instance %p, counterid %lu, address %I64u semi-stub.\n",
           provider, instance, counterid, value );

    if (!prov || !instance) return ERROR_INVALID_PARAMETER;

    counter = get_performance_counter_info(instance, counterid);

    if (counter == NULL) return ERROR_NOT_FOUND;
    if (counter->Attrib & PERF_ATTRIB_BY_REFERENCE) return ERROR_INVALID_PARAMETER;
    if (!(counter->Type & PERF_SIZE_LARGE)) return ERROR_INVALID_PARAMETER;

    *(ULONGLONG*)((BYTE *)(instance + 1) + counter->Offset) = value;

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           PerfStartProvider   (KERNELBASE.@)
 */
ULONG WINAPI PerfStartProvider( GUID *guid, PERFLIBREQUEST callback, HANDLE *provider )
{
    PERF_PROVIDER_CONTEXT ctx;

    FIXME( "guid %s, callback %p, provider %p semi-stub.\n", debugstr_guid(guid), callback, provider );

    memset( &ctx, 0, sizeof(ctx) );
    ctx.ContextSize = sizeof(ctx);
    ctx.ControlCallback = callback;

    return PerfStartProviderEx( guid, &ctx, provider );
}

/***********************************************************************
 *           PerfStartProviderEx   (KERNELBASE.@)
 */
ULONG WINAPI PerfStartProviderEx( GUID *guid, PERF_PROVIDER_CONTEXT *context, HANDLE *provider )
{
    struct perf_provider *prov;

    FIXME( "guid %s, context %p, provider %p semi-stub.\n", debugstr_guid(guid), context, provider );

    if (!guid || !context || !provider) return ERROR_INVALID_PARAMETER;
    if (context->ContextSize < sizeof(*context)) return ERROR_INVALID_PARAMETER;

    if (context->MemAllocRoutine || context->MemFreeRoutine)
        FIXME("Memory allocation routine is not supported.\n");

    if (!(prov = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*prov) ))) return ERROR_OUTOFMEMORY;
    list_init( &prov->instance_list );
    memcpy( &prov->guid, guid, sizeof(prov->guid) );
    prov->callback = context->ControlCallback;
    *provider = prov;

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           PerfStopProvider   (KERNELBASE.@)
 */
ULONG WINAPI PerfStopProvider(HANDLE handle)
{
    struct perf_provider *prov = perf_provider_from_handle( handle );
    struct counterset_instance *inst, *next;
    unsigned int i;

    TRACE( "handle %p.\n", handle );

    if (!list_empty( &prov->instance_list ))
        WARN( "Stopping provider with active counter instances.\n" );

    LIST_FOR_EACH_ENTRY_SAFE(inst, next, &prov->instance_list, struct counterset_instance, entry)
    {
        list_remove( &inst->entry );
        HeapFree( GetProcessHeap(), 0, inst );
    }

    for (i = 0; i < prov->counterset_count; ++i)
        HeapFree( GetProcessHeap(), 0, prov->countersets[i] );
    HeapFree( GetProcessHeap(), 0, prov->countersets );
    HeapFree( GetProcessHeap(), 0, prov );
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           QuirkIsEnabled   (KERNELBASE.@)
 */
BOOL WINAPI QuirkIsEnabled(void *arg)
{
    FIXME("(%p): stub\n", arg);
    return FALSE;
}

/***********************************************************************
 *          QuirkIsEnabled3 (KERNELBASE.@)
 */
BOOL WINAPI QuirkIsEnabled3(void *unk1, void *unk2)
{
    static int once;

    if (!once++)
        FIXME("(%p, %p) stub!\n", unk1, unk2);

    return FALSE;
}

HRESULT WINAPI QISearch(void *base, const QITAB *table, REFIID riid, void **obj)
{
    const QITAB *ptr;
    IUnknown *unk;

    TRACE("%p, %p, %s, %p\n", base, table, debugstr_guid(riid), obj);

    if (!obj)
        return E_POINTER;

    for (ptr = table; ptr->piid; ++ptr)
    {
        TRACE("trying (offset %ld) %s\n", ptr->dwOffset, debugstr_guid(ptr->piid));
        if (IsEqualIID(riid, ptr->piid))
        {
            unk = (IUnknown *)((BYTE *)base + ptr->dwOffset);
            TRACE("matched, returning (%p)\n", unk);
            *obj = unk;
            IUnknown_AddRef(unk);
            return S_OK;
        }
    }

    if (IsEqualIID(riid, &IID_IUnknown))
    {
        unk = (IUnknown *)((BYTE *)base + table->dwOffset);
        TRACE("returning first for IUnknown (%p)\n", unk);
        *obj = unk;
        IUnknown_AddRef(unk);
        return S_OK;
    }

    WARN("Not found %s.\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

HRESULT WINAPI GetAcceptLanguagesA(LPSTR langbuf, DWORD *buflen)
{
    DWORD buflenW, convlen;
    WCHAR *langbufW;
    HRESULT hr;

    TRACE("%p, %p, *%p: %ld\n", langbuf, buflen, buflen, buflen ? *buflen : -1);

    if (!langbuf || !buflen || !*buflen)
        return E_FAIL;

    buflenW = *buflen;
    langbufW = HeapAlloc(GetProcessHeap(), 0, sizeof(WCHAR) * buflenW);
    hr = GetAcceptLanguagesW(langbufW, &buflenW);

    if (hr == S_OK)
    {
        convlen = WideCharToMultiByte(CP_ACP, 0, langbufW, -1, langbuf, *buflen, NULL, NULL);
        convlen--;  /* do not count the terminating 0 */
    }
    else  /* copy partial string anyway */
    {
        convlen = WideCharToMultiByte(CP_ACP, 0, langbufW, *buflen, langbuf, *buflen, NULL, NULL);
        if (convlen < *buflen)
        {
            langbuf[convlen] = 0;
            convlen--;  /* do not count the terminating 0 */
        }
        else
        {
            convlen = *buflen;
        }
    }
    *buflen = buflenW ? convlen : 0;

    HeapFree(GetProcessHeap(), 0, langbufW);
    return hr;
}

static HRESULT lcid_to_rfc1766(LCID lcid, WCHAR *rfc1766, INT len)
{
    WCHAR buffer[6 /* MAX_RFC1766_NAME */];
    INT n = GetLocaleInfoW(lcid, LOCALE_SISO639LANGNAME, buffer, ARRAY_SIZE(buffer));
    INT i;

    if (n)
    {
        i = PRIMARYLANGID(lcid);
        if ((((i == LANG_ENGLISH) || (i == LANG_CHINESE) || (i == LANG_ARABIC)) &&
            (SUBLANGID(lcid) == SUBLANG_DEFAULT)) ||
            (SUBLANGID(lcid) > SUBLANG_DEFAULT)) {

            buffer[n - 1] = '-';
            i = GetLocaleInfoW(lcid, LOCALE_SISO3166CTRYNAME, buffer + n, ARRAY_SIZE(buffer) - n);
            if (!i)
                buffer[n - 1] = '\0';
        }
        else
            i = 0;

        LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_LOWERCASE, buffer, n + i, rfc1766, len);
        return ((n + i) > len) ? E_INVALIDARG : S_OK;
    }
    return E_FAIL;
}

HRESULT WINAPI GetAcceptLanguagesW(WCHAR *langbuf, DWORD *buflen)
{
    DWORD mystrlen, mytype;
    WCHAR *mystr;
    LCID mylcid;
    HKEY mykey;
    LONG lres;
    DWORD len;

    TRACE("%p, %p, *%p: %ld\n", langbuf, buflen, buflen, buflen ? *buflen : -1);

    if (!langbuf || !buflen || !*buflen)
        return E_FAIL;

    mystrlen = (*buflen > 20) ? *buflen : 20 ;
    len = mystrlen * sizeof(WCHAR);
    mystr = HeapAlloc(GetProcessHeap(), 0, len);
    mystr[0] = 0;
    RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\International",
                  0, KEY_QUERY_VALUE, &mykey);
    lres = RegQueryValueExW(mykey, L"AcceptLanguage", 0, &mytype, (PBYTE)mystr, &len);
    RegCloseKey(mykey);
    len = lstrlenW(mystr);

    if (!lres && (*buflen > len))
    {
        lstrcpyW(langbuf, mystr);
        *buflen = len;
        HeapFree(GetProcessHeap(), 0, mystr);
        return S_OK;
    }

    /* Did not find a value in the registry or the user buffer is too small */
    mylcid = GetUserDefaultLCID();
    lcid_to_rfc1766(mylcid, mystr, mystrlen);
    len = lstrlenW(mystr);

    memcpy(langbuf, mystr, min(*buflen, len + 1)*sizeof(WCHAR));
    HeapFree(GetProcessHeap(), 0, mystr);

    if (*buflen > len)
    {
        *buflen = len;
        return S_OK;
    }

    *buflen = 0;
    return E_NOT_SUFFICIENT_BUFFER;
}

HRESULT WINAPI GetIntegratedDisplaySize( double *sz_inches )
{
    FIXME( "%p stub.\n", sz_inches );
    return E_NOTIMPL;
}

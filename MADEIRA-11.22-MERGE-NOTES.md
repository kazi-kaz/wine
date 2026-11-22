# Wine 11.22 merge notes (per-file decisions)
- dlls/nsiproxy.sys/ndis.c update_if_table: our `if (!indices) return 0;` DROPPED, covered by upstream 11.22 ("indices = if_nameindex(); if (!indices) { ERR(...); return 0; }"). Our sysctl cursor/bounds fix in ifinfo_fill_dynamic kept.
- dlls/dinput: kept ios_joystick (ml760) beside upstream's new Em/Em2 GUIDs and hid_joystick_refresh_devices; IMPORTS now "cfgmgr32 ... hid win32u" (upstream dropped setupapi).
- dlls/ntdll/process.c: our RtlWow64SuspendThread DROPPED, upstream 11.22 has the identical function (NtSuspendThread wrapper).
- server/*: upstream 11.22 turned object_ops into designated initializers and added an `init` operation (object creation goes through struct object_params + ops->init). Our WINE_IOS hooks were re-homed: semaphore/event add_queue/remove_queue/destroy as designated fields; event ml809 memset + ml805 IOS_EVT_CREATE record moved into event_init (now recorded only for newly created events, not for opens of an existing name); completion [pipe-census] add moved into completion_init; handle.c close_handle keeps ml805 record with upstream's NULL check; winstation virtual-desktop input hack (S2) moved after the exists/new branch in create_desktop.
- dlls/ntdll/unix/debug.c: our ml379 "thread with no TEB must not crash the logger" guards DROPPED, covered by upstream 11.22: get_info() is now "return data ? (struct debug_info *)data->debug_info : &initial_info;" and __wine_dbg_header only prints pid/tid inside "if (data)". Added one Madeira line: the pid in the header comes from the caller's TEB (pseudo-processes share one unix lib, upstream's `pid` is process-global).
- dlls/ntdll/unix/system.c ml1122 cpu-count override: upstream moved "peb->NumberOfProcessors = ..." to env.c (from cpu_count). Override now stored in madeira_peb_cpu_count and applied in env.c; cpu_count keeps the host value as before. TODO Madeira repo: env_ios.c must do the same.
- dlls/ntdll/sync.c RtlpUnWaitCriticalSection: upstream 06c0cb5c5 ("Ignore semaphore errors") no longer raises on a failed NtReleaseSemaphore. BEHAVIOUR CHANGE vs our pin (we raised c0000008). Our ml671 [cs-raise] log kept, now log-only.
- dlls/ntdll/sync.c RtlWaitOnAddress: upstream 81e52628b (queue-removal race) is now in; our pending-prs/wine-waitonaddress-race cherry-pick is therefore covered (verify no double application below).
- dlls/xinput1_3/main.c: upstream rewrote the HID side (xinput_cs, get_current_state, update_controller_list; controller_lock gone). Took upstream's file and re-added our host gamepad path (ml668/ml2114/ml2115/ml2170) function by function. Our keystroke_from_state split + host_last_keystroke DROPPED: upstream's check_for_keystroke now reads through xinput_get_state(), which tries the host slot first, so the host pad gets keystrokes through upstream code.
- dlls/wow64: ProcessExecuteFlags -> BTCpuNotifyProcessExecuteFlagsChange is now ALSO upstream (same hook name); kept our version (adds the len check). token_*_32to64 keep guest_ptr32 plus upstream's NULL checks. NtMapViewOfSection/NtFlushVirtualMemory keep the guest-window conversions with upstream's new range checks / iosb.
- dlls/wow64win/user.c: client_menu_name 32<->64 helpers and the GCLP_MENUNAME special case removed upstream (class menu names changed); our guest_ptr32 variants of them dropped with it.
- dlls/ntdll/signal_arm64ec.c: upstream added XState/AVX (struct xcontext, init_xcontext) and cooperative suspend (SuspendDoorbell in leave_syscall_callback). Our 397-line prepare_exception_arm64ec block kept, now on context->c.AMD64_Context. RISK: ContextAmd64 must now be large enough for struct xcontext (0x670); upstream points it at cpu_area->EmulatorDataInline in unix thread.c, our thread_ios.c twin must match.
- libs/vkd3d/libs/vkd3d-shader/fx.c: RE-PORTED (commit 32a3b8377). 125hz's fx_2_0 work re-done on the 11.22 writer, which already had numeric pass assignments and shader object initializers: added sampler initializers, shader/texture assignments with resource records, zeros for a parameter without initializer, TRUE/FALSE for every fx_2_0 state, all components of a single vector value, uniform-only parameter walk. Dropped as covered upstream: our compile_shader refactor (upstream has the same function), is_type_supported_fx_2 shader classes (upstream returns true), write_fx_2_state_type for numerics. `f32_denorm_mode` no longer exists.
- libs/vkd3d hlsl.h: kept madeira_nonuint_index_logged; the five option bools moved elsewhere upstream.
- dlls/bcrypt/gnutls.c: file DELETED upstream (50c4a503b "bcrypt: Get rid of the unixlib"; bcrypt.dll is now PE-only on the bundled SymCrypt, libs/symcrypt). Both our patches there are DROPPED as moot: (a) the [bcrypt-guard] CBC length check existed only because nettle aborts the process; 11.22 bcrypt_main.c checks "if (input_len & (block_size - 1)) return STATUS_INVALID_BUFFER_SIZE;" itself; (b) the WoW64 thunks' ios_wow_host_ptr conversions, since there are no unix thunks left. TODO Madeira repo: bcrypt no longer needs the gnutls unix side (build/crypto-unix keeps crypt32/secur32); the PE build must now build libs/symcrypt.
- dlls/ntdll/unix/system.c init_shared_data_cpuinfo: NEW upstream behaviour gated. 11.22 sets PF_AVX/PF_AVX2 and an AVX XState configuration for every x86 guest on ARM64. Under WINE_IOS this now happens only with MADEIRA_FEX_AVX=1 (and not MADEIRA_KUSD_AVX=0), which is the rule our ml1310 block in virtual_ios.c already used. Off switch = the existing ones. When virtual_ios.c is ported the ml1310 block becomes redundant (upstream fills the same layout).

## Compile check in the cloud (Nov 19)
Configured for i386, x86_64, aarch64, arm64ec with clang 18 + lld on Linux and built every module the
Madeira tree changes, plus bcrypt, d3dcompiler_47, d3dx9_36 and the wineserver.
- Found and fixed: `dlls/ntdll/loader.c` (`imp_mod` no longer exists, now `context.module`);
  `dlls/wow64/process.c` (two `case PS_ATTRIBUTE_GROUP_AFFINITY`: 11.22 converts the whole structure
  because the mask is 4 bytes for the guest, so our pointer-only case is dropped and upstream's case reads
  the guest address through `guest_ptr32`).
- Not ours: clang 18 crashes on upstream's i386 inline assembly in `dlls/dinput/dinput.c`, and has no
  `-marm64x`. The real toolchain on the PC does not have either limit.
- Cannot be checked here: everything under `WINE_IOS` / `__APPLE__` (no iOS SDK in the cloud), e.g.
  `dlls/ntdll/unix/sync.c` stops at the Apple-only QoS and Mach code.

## Second round (Nov 19): iOS-side interfaces
- dlls/opengl32, dlls/win32u/opengl.c: winios OpenGL patch re-done for 11.22 (commit e26b181dc); see
  TWIN-NOTES in the Madeira delivery for the details and off switches.
- dlls/mmdevapi: MADEIRA_S_PE_TIMER / MADEIRA_UNIX_TIMER_LOOP (commit 3d7f791a3): the timer thread of the
  iOS audio driver is made by mmdevapi, as before Wine 11.5.
- dlls/dnsapi/libresolv.c: new get_hostinfo 32-bit thunk converts guest pointers (8cd65e7f3).
- dlls/ntdll/unix/unix_private.h, dlls/win32u/syscall.c: declarations and per-thread key handling the iOS
  files need (45d86526e).

use detour::static_detour;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{c_void, CString},
    intrinsics::transmute,
    mem::MaybeUninit,
    ptr,
    slice::from_raw_parts,
};
use widestring::U16CString;
use windows_sys::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{GetLastError, BOOL, FARPROC, HANDLE, HINSTANCE},
        Security::SECURITY_ATTRIBUTES,
        System::{
            Diagnostics::Debug::{WriteProcessMemory, PROCESSOR_ARCHITECTURE_INTEL},
            LibraryLoader::{
                GetModuleFileNameA, GetModuleHandleExA, GetProcAddress, LoadLibraryA,
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            },
            Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
            SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
            Threading::{
                CreateRemoteThread, GetCurrentProcess, GetExitCodeThread, GetThreadId,
                IsWow64Process, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED,
                PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
            },
        },
    },
};

pub mod communication;

#[derive(Serialize, Deserialize, Clone)]
pub struct InjectOptions {
    pub server_address: Option<String>,
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct InjectOptionsWrapper {
    pub len: usize,
    pub ptr: u64,
}

#[repr(C)]
pub struct ShellCodeParam {
    pub module_path: [u8; 1024],
    pub enable_hook_name: [u8; 1024],
    pub enable_hook_param_wrapper_ptr: *const c_void,
    pub fp_get_proc_address:
        unsafe extern "system" fn(isize, *const u8) -> unsafe extern "system" fn() -> isize,
    pub fp_load_library: unsafe extern "system" fn(lplibfilename: PCSTR) -> HINSTANCE,
}

type FnCreateProcessW = unsafe extern "system" fn(
    PCWSTR,
    PWSTR,
    *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES,
    BOOL,
    PROCESS_CREATION_FLAGS,
    *const c_void,
    PCWSTR,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> BOOL;

static_detour! {
  static HookCreateProcessW: unsafe extern "system" fn(
      PCWSTR,
      PWSTR,
      *const SECURITY_ATTRIBUTES,
      *const SECURITY_ATTRIBUTES,
      BOOL,
      PROCESS_CREATION_FLAGS,
      *const c_void,
      PCWSTR,
      *const STARTUPINFOW,
      *mut PROCESS_INFORMATION
  ) -> BOOL;
}

static SHELLCODE_X86: &[u8] = include_bytes!("..\\..\\..\\dist\\shellcode-x86.bin");
static SHELLCODE_X64: &[u8] = include_bytes!("..\\..\\..\\dist\\shellcode-x64.bin");

#[allow(clippy::too_many_arguments)]
fn detour_create_process(
    opts: &Option<InjectOptions>,
    app_name: PCWSTR,
    cmd_line: PWSTR,
    proc_attrs: *const SECURITY_ATTRIBUTES,
    th_attrs: *const SECURITY_ATTRIBUTES,
    inherit: BOOL,
    flags: PROCESS_CREATION_FLAGS,
    env: *const c_void,
    cur_dir: PCWSTR,
    startup_info: *const STARTUPINFOW,
    proc_info: *mut PROCESS_INFORMATION,
) -> BOOL {
    unsafe {
        let app_name_string = if app_name.is_null() {
            String::new()
        } else {
            U16CString::from_ptr_str(app_name).to_string().unwrap()
        };
        let cmd_line_string = if cmd_line.is_null() {
            String::new()
        } else {
            U16CString::from_ptr_str(cmd_line).to_string().unwrap()
        };
        info!("CreateProcessW: {} {}", app_name_string, cmd_line_string);
        let flags_with_suspend = CREATE_SUSPENDED | flags;
        let creating_res = HookCreateProcessW.call(
            app_name,
            cmd_line,
            proc_attrs,
            th_attrs,
            inherit,
            flags_with_suspend,
            env,
            cur_dir,
            startup_info,
            proc_info,
        );

        if creating_res != 0 {
            info!("New process id: {:?}", (*proc_info).dwProcessId);
            if let Err(err) = inject_to_process((*proc_info).hProcess, opts) {
                warn!("inject_to_process error: {}", err);
            }
            if flags & CREATE_SUSPENDED == 0 {
                if ResumeThread((*proc_info).hThread) == u32::MAX {
                    warn!("ResumeThread error: {}", GetLastError());
                }
            }
        } else {
            warn!("CreateProcessW failed: {}", GetLastError());
        }

        creating_res
    }
}

pub fn enable_hook(opts: Option<InjectOptions>) {
    info!(
        "Module: {}",
        get_module_file_name(get_self_module_handle().unwrap()).unwrap_or(String::new())
    );
    unsafe {
        let fp_create_process: FnCreateProcessW =
            transmute(get_proc_address("CreateProcessW", "kernel32.dll").unwrap());

        let opts = Box::leak(Box::new(opts));
        HookCreateProcessW
            .initialize(
                fp_create_process,
                |app_name,
                 cmd_line,
                 proc_attrs,
                 th_attrs,
                 inherit,
                 flags,
                 env,
                 cur_dir,
                 startup_info,
                 proc_info| {
                    detour_create_process(
                        opts,
                        app_name,
                        cmd_line,
                        proc_attrs,
                        th_attrs,
                        inherit,
                        flags,
                        env,
                        cur_dir,
                        startup_info,
                        proc_info,
                    )
                },
            )
            .unwrap();
        HookCreateProcessW.enable().unwrap();
    }
}

unsafe fn get_proc_address(proc_name: &str, module_name: &str) -> FARPROC {
    let module_name_cstr = CString::new(module_name).ok()?;
    let proc_name_cstr = CString::new(proc_name).ok()?;
    let h_inst = LoadLibraryA(module_name_cstr.as_ptr() as PCSTR);

    if h_inst == 0 {
        panic!("LoadLibraryA failed: {}", GetLastError());
    }

    GetProcAddress(h_inst, proc_name_cstr.as_ptr() as PCSTR)
}

unsafe fn inject_to_process(
    process_handle: HANDLE,
    opts: &Option<InjectOptions>,
) -> anyhow::Result<()> {
    let is_target_x86 = is_process_x86(process_handle)?;
    let is_self_x86 = is_process_x86(GetCurrentProcess())?;
    if is_target_x86 != is_self_x86 {
        return Err(anyhow::anyhow!(
            "Process architecture mismatch, expect {} got {}",
            if is_target_x86 { "x86" } else { "x64" },
            if is_self_x86 { "x86" } else { "x64" }
        ));
    }

    let library_name_with_null = format!(
        "program_bootstrap_core-{}.dll\0",
        if is_target_x86 { "x86" } else { "x64" }
    );
    let core_module_handle = LoadLibraryA(library_name_with_null.as_ptr() as PCSTR);
    let mut core_full_name_buffer = [0u8; 4096];
    if core_module_handle == 0
        || GetModuleFileNameA(
            core_module_handle,
            core_full_name_buffer.as_mut_ptr(),
            core_full_name_buffer.len() as u32,
        ) == 0
    {
        return Err(anyhow::anyhow!(
            "GetModuleFileNameA failed: {}",
            GetLastError()
        ));
    }
    let library_name_addr = write_process_memory(process_handle, &core_full_name_buffer)?;
    let fp_load_library = get_proc_address("LoadLibraryA", "kernel32.dll")
        .ok_or_else(|| anyhow::anyhow!("No LoadLibraryA function found"))?;
    let load_library_thread = CreateRemoteThread(
        process_handle,
        ptr::null(),
        0,
        Some(transmute(fp_load_library)),
        library_name_addr,
        0,
        ptr::null_mut(),
    );
    if load_library_thread == 0 {
        return Err(anyhow::anyhow!(
            "CreateRemoteThread failed: {}",
            GetLastError()
        ));
    }
    info!(
        "Created LoadLibraryA thread with id: {}",
        GetThreadId(load_library_thread)
    );
    let wait_result = WaitForSingleObject(load_library_thread, 0xFFFFFFFF);
    if wait_result != 0 {
        return Err(anyhow::anyhow!(
            "WaitForSingleObject failed: {}",
            wait_result
        ));
    }
    let mut load_thread_exit_code: u32 = 0;
    if GetExitCodeThread(load_library_thread, &mut load_thread_exit_code as *mut u32) != 0
        && load_thread_exit_code == 0
    {
        return Err(anyhow::anyhow!("Remote LoadLibraryA failed"));
    }

    let enable_hook_param_wrapper_ptr = if let Some(opts) = opts {
        let opts_bytes = bincode::serialize(opts)?;
        let opts_ptr = write_process_memory(process_handle, opts_bytes.as_slice())?;
        info!("Write options to address {:?}", opts_ptr);
        let opts_wrapper = InjectOptionsWrapper {
            len: opts_bytes.len(),
            ptr: opts_ptr as u64,
        };
        let opts_wrapper_bytes = bincode::serialize(&opts_wrapper)?;
        let opts_wrapper_ptr = write_process_memory(process_handle, opts_wrapper_bytes.as_slice())?;
        info!("Write options wrapper to address {:?}", opts_wrapper_ptr);
        opts_wrapper_ptr
    } else {
        ptr::null()
    };
    let mut shellcode_param = ShellCodeParam {
        enable_hook_name: [0; 1024],
        fp_get_proc_address: transmute(
            get_proc_address("GetProcAddress", "kernel32.dll")
                .ok_or_else(|| anyhow::anyhow!("No GetProcAddress function found"))?,
        ),
        fp_load_library: transmute(
            get_proc_address("LoadLibraryA", "kernel32.dll")
                .ok_or_else(|| anyhow::anyhow!("No LoadLibraryA function found"))?,
        ),
        enable_hook_param_wrapper_ptr,
        module_path: [0; 1024],
    };
    let enable_hook_name = "enable_hook\0".as_bytes();
    shellcode_param.enable_hook_name[..enable_hook_name.len()]
        .clone_from_slice("enable_hook\0".as_bytes());
    let library_name_bytes = library_name_with_null.as_bytes();
    shellcode_param.module_path[..library_name_bytes.len()].clone_from_slice(library_name_bytes);
    let shellcode_param_ptr =
        write_process_memory(process_handle, any_as_u8_slice(&shellcode_param))?;
    let shellcode_ptr = write_process_memory(
        process_handle,
        if is_target_x86 {
            SHELLCODE_X86
        } else {
            SHELLCODE_X64
        },
    )?;
    info!("Write shellcode to address 0x{:x}", shellcode_ptr as isize);
    let shellcode_thread_handle = CreateRemoteThread(
        process_handle,
        ptr::null(),
        0,
        Some(transmute(shellcode_ptr)),
        shellcode_param_ptr,
        0,
        ptr::null_mut(),
    );
    if shellcode_thread_handle == 0 {
        return Err(anyhow::anyhow!(
            "CreateRemoteThread failed: {}",
            GetLastError()
        ));
    }
    info!(
        "Created enable_hook thread with id: 0x{:x}",
        GetThreadId(shellcode_thread_handle)
    );
    let wait_result = WaitForSingleObject(shellcode_thread_handle, 0xFFFFFFFF);
    if wait_result != 0 {
        return Err(anyhow::anyhow!(
            "WaitForSingleObject failed: {}",
            wait_result
        ));
    }
    let mut hook_thread_exit_code = 0;
    if GetExitCodeThread(shellcode_thread_handle, &mut hook_thread_exit_code) != 0
        && hook_thread_exit_code != 1
    {
        return Err(anyhow::anyhow!(
            "Remote enable_hook failed with code: 0x{:x}",
            hook_thread_exit_code
        ));
    }

    Ok(())
}

fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe { from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>()) }
}

fn get_module_file_name(instance_handle: HINSTANCE) -> anyhow::Result<String> {
    let mut file_name_buffer = [0u8; 4096];
    let file_name_len = unsafe {
        GetModuleFileNameA(
            instance_handle,
            file_name_buffer.as_mut_ptr(),
            file_name_buffer.len() as u32,
        )
    };
    if file_name_len == 0 {
        return Err(anyhow::anyhow!("GetModuleFileNameA failed: {}", unsafe {
            GetLastError()
        }));
    }
    Ok(String::from_utf8_lossy(&file_name_buffer[..file_name_len as usize]).to_string())
}

fn get_self_module_handle() -> anyhow::Result<HINSTANCE> {
    let mut instance_handle: HINSTANCE = 0;
    let result = unsafe {
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            transmute(get_self_module_handle as *const ()),
            &mut instance_handle,
        )
    };
    if result == 0 {
        return Err(anyhow::anyhow!("GetModuleHandleExA failed: {}", unsafe {
            GetLastError()
        }));
    }
    Ok(instance_handle)
}

fn is_process_x86(process_handle: HANDLE) -> anyhow::Result<bool> {
    let sys_info = unsafe {
        let mut sys_info = MaybeUninit::<SYSTEM_INFO>::uninit();
        GetNativeSystemInfo(sys_info.as_mut_ptr());
        sys_info.assume_init()
    };
    let processor_arch = unsafe { sys_info.Anonymous.Anonymous.wProcessorArchitecture };
    Ok(processor_arch == PROCESSOR_ARCHITECTURE_INTEL || is_wow64_process(process_handle)?)
}

fn is_wow64_process(process_handle: HANDLE) -> anyhow::Result<bool> {
    let mut is_wow64 = 0;
    unsafe {
        if IsWow64Process(process_handle, &mut is_wow64) == 0 {
            return Err(anyhow::anyhow!("IsWow64Process failed: {}", GetLastError()));
        }
    }
    Ok(is_wow64 != 0)
}

unsafe fn write_process_memory(
    process_handle: HANDLE,
    content: &[u8],
) -> anyhow::Result<*mut c_void> {
    let target_address = VirtualAllocEx(
        process_handle,
        ptr::null(),
        content.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if target_address.is_null() {
        return Err(anyhow::anyhow!("VirtualAllocEx failed: {}", GetLastError()));
    }
    let success = WriteProcessMemory(
        process_handle,
        target_address,
        content.as_ptr() as *const c_void,
        content.len(),
        ptr::null_mut(),
    );
    if success == 0 {
        return Err(anyhow::anyhow!(
            "WriteProcessMemory failed: {}",
            GetLastError()
        ));
    }
    Ok(target_address)
}

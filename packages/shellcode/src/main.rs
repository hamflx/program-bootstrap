#![no_std]
#![no_main]

use core::{arch::asm, intrinsics::transmute};

#[panic_handler]
fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

type FnEnableHook = unsafe extern "system" fn(opts_ptr: *const u8);

#[no_mangle]
pub unsafe extern "system" fn main(param: *mut ShellCodeParam) -> bool {
    let mut process_env_block: *const PEB = 0 as *const PEB;
    #[cfg(target_arch = "x86")]
    asm!("mov {peb}, fs:0x30", peb = out(reg) process_env_block);

    #[cfg(target_arch = "x86_64")]
    asm!("mov {peb}, gs:0x60", peb = out(reg) process_env_block);

    let first_entry = &(*(*process_env_block).Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;
    let mut current_entry = (*first_entry).Flink;

    while first_entry != current_entry {
        let module_entry = current_entry as *const LDR_DATA_TABLE_ENTRY;
        current_entry = (*current_entry).Flink;
    }

    let get_proc_address = (*param).fp_get_proc_address;
    let load_library = (*param).fp_load_library;
    let module_handle = load_library(&(*param).module_path as *const [u8] as *const u8);
    let mut enable_hook: FnEnableHook = transmute(get_proc_address(
        module_handle,
        &(*param).enable_hook_name as *const [u8] as *const u8,
    ));

    enable_hook((*param).enable_hook_param_wrapper_ptr);

    true
}

#[repr(C)]
pub struct ShellCodeParam {
    pub module_path: [u8; 1024],
    pub enable_hook_name: [u8; 1024],
    pub enable_hook_param_wrapper_ptr: *const u8,
    pub fp_get_proc_address: unsafe extern "system" fn(isize, *const u8) -> *const (),
    pub fp_load_library: unsafe extern "system" fn(lplibfilename: *const u8) -> isize,
}

#[repr(C)]
pub union CastToFnEnableHook {
    fn_ptr: FnEnableHook,
    ptr: *const (),
}

#[repr(C)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [*mut c_void; 2],
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub Reserved4: [*mut c_void; 3],
    pub AtlThunkSListPtr: *mut c_void,
    pub Reserved5: *mut c_void,
    pub Reserved6: u32,
    pub Reserved7: *mut c_void,
    pub Reserved8: u32,
    pub AtlThunkSListPtr32: u32,
    pub Reserved9: [*mut c_void; 45],
    pub Reserved10: [u8; 96],
    pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
    pub Reserved11: [u8; 128],
    pub Reserved12: [*mut c_void; 1],
    pub SessionId: u32,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [u8; 16],
    pub Reserved2: [*mut c_void; 10],
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: PWSTR,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [u8; 8],
    pub Reserved2: [*mut c_void; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub Reserved1: [*mut c_void; 2],
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: [*mut c_void; 2],
    pub DllBase: *mut c_void,
    pub Reserved3: [*mut c_void; 2],
    pub FullDllName: UNICODE_STRING,
    pub Reserved4: [u8; 8],
    pub Reserved5: [*mut c_void; 3],
    pub Anonymous: LDR_DATA_TABLE_ENTRY_0,
    pub TimeDateStamp: u32,
}

#[repr(C)]
pub union LDR_DATA_TABLE_ENTRY_0 {
    pub CheckSum: u32,
    pub Reserved6: *mut c_void,
}

#[allow(non_camel_case_types)]
type PPS_POST_PROCESS_INIT_ROUTINE = Option<unsafe extern "system" fn()>;

#[allow(non_camel_case_types)]
type c_void = *mut ();
type PWSTR = *mut u16;

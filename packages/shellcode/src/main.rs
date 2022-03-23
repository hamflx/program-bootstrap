#![no_std]
#![no_main]

use core::intrinsics::transmute;

#[panic_handler]
fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

type FnEnableHook = unsafe extern "system" fn(opts_ptr: *const u8);

#[no_mangle]
pub unsafe extern "system" fn main(param: *mut ShellCodeParam) -> bool {
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

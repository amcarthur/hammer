extern crate winapi;
extern crate user32;
extern crate kernel32;
extern crate widestring;
extern crate pe;

use std::env;
use std::mem;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::ffi::CString;
use widestring::WideCString;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::ffi::OsStrExt;
use std::fs::OpenOptions;
use std::io::Read;

fn main() {
    let arguments: Vec<_> = env::args().collect();
    let arguments_length: usize = arguments.len();

    if arguments_length < 2 {
        println!("Invalid syntax. You must specify a command.");
        return;
    }

    let inject_command = WideCString::from_str("inject").unwrap();
    let eject_command = WideCString::from_str("eject").unwrap();
    let create_command = WideCString::from_str("create").unwrap();
    let call_command = WideCString::from_str("call").unwrap();

    let command_arg = WideCString::from_str(&arguments[1]).unwrap();

    if command_arg == inject_command {
        if arguments_length != 4 {
            println!("Invalid number of arguments");
            return;
        }

        let process_arg: WideCString = WideCString::from_str(&arguments[2]).unwrap();
        let dll_arg: WideCString = WideCString::from_str(&arguments[3]).unwrap();
        let dll_arg_os_str: OsString = dll_arg.to_os_string();
        let dll_path: &Path = Path::new(&dll_arg_os_str);

        if !dll_path.exists() {
            println!("DLL file specified does not exist: {:?}", dll_path);
            return;
        }

        let mut process_ids: Vec<u32> = Vec::new();

        match process_arg.to_string().unwrap().parse::<u32>() {
            Ok(n) => {
                process_ids.push(n);
            },
            Err(_) => {
                process_ids = get_process_ids_from_name(&process_arg);
                if process_ids.is_empty() {
                    println!("Process with name {} does not exist.", process_arg.to_string().unwrap());
                    return;
                }
            }
        }

        for p in &process_ids {
            let process_handle: winapi::HANDLE = open_process(
                *p,
                winapi::winnt::PROCESS_CREATE_THREAD
                | winapi::winnt::PROCESS_QUERY_INFORMATION
                | winapi::winnt::PROCESS_VM_OPERATION
                | winapi::winnt::PROCESS_VM_WRITE
                | winapi::winnt::PROCESS_VM_READ
            );

            if process_handle == null_mut() {
                println!("Process with id {:?} does not exist or is not accessible.", p);
                continue;
            }

            let remote_module: winapi::minwindef::HMODULE = find_remote_module_by_path(*p, dll_path);
            if remote_module != null_mut() {
                println!("DLL already exists in process. HMODULE: {:?}.", remote_module);
                println!("Injection failed.");
            } else {
                if inject_library(process_handle, &dll_path) {
                    println!("Successfully injected {:?} into {:?}.", dll_path, p);
                } else {
                    println!("Injection failed.");
                }
            }

            if process_handle != null_mut() {
               unsafe { kernel32::CloseHandle( process_handle ); }
            }
        }
    } else if command_arg == eject_command {
        if arguments_length != 4 {
            println!("Invalid number of arguments");
            return;
        }

        let process_arg: WideCString = WideCString::from_str(&arguments[2]).unwrap();
        let dll_arg: WideCString = WideCString::from_str(&arguments[3]).unwrap();
        let dll_arg_os_str: OsString = dll_arg.to_os_string();
        let dll_path: &Path = Path::new(&dll_arg_os_str);

        let mut process_ids: Vec<u32> = Vec::new();

        match process_arg.to_string().unwrap().parse::<u32>() {
            Ok(n) => {
                process_ids.push(n);
            },
            Err(_) => {
                process_ids = get_process_ids_from_name(&process_arg);
                if process_ids.is_empty() {
                    println!("Process with name {} does not exist.", process_arg.to_string().unwrap());
                    return;
                }
            }
        }

        for p in &process_ids {
            let process_handle: winapi::HANDLE = open_process(
                *p,
                winapi::winnt::PROCESS_CREATE_THREAD
                | winapi::winnt::PROCESS_QUERY_INFORMATION
                | winapi::winnt::PROCESS_VM_OPERATION
                | winapi::winnt::PROCESS_VM_WRITE
                | winapi::winnt::PROCESS_VM_READ
            );

            if process_handle == null_mut() {
                println!("Process does not exist or is not accessible.");
                continue;
            }

            let module_handle: winapi::minwindef::HMODULE;
            if !dll_path.exists() {
                let module_name: WideCString = WideCString::from_str(dll_path.file_name().unwrap()).unwrap();
                module_handle = find_remote_module_by_name(*p, &module_name);
            } else {
                module_handle = find_remote_module_by_path(*p, &dll_path);
            }

            if module_handle == null_mut() {
                println!("Failed to find the remote module {:?}.", dll_path);
                println!("Ejection failed.");
            } else {
                if eject_library(process_handle, module_handle) {
                    println!("Successfully ejected {:?} from {:?}.", dll_path, p);
                } else {
                    println!("Ejection failed.");
                }
            }

            if process_handle != null_mut() {
               unsafe { kernel32::CloseHandle( process_handle ); }
            }
        }

    } else if command_arg == create_command {
        if arguments_length < 4 {
            println!("Invalid number of arguments");
            return;
        }

        let exe_arg: WideCString = WideCString::from_str(&arguments[2]).unwrap();
        let dll_arg: WideCString = WideCString::from_str(&arguments[3]).unwrap();
        let exe_arg_os_str: OsString = exe_arg.to_os_string();
        let exe_path: &Path = Path::new(&exe_arg_os_str);
        let dll_arg_os_str: OsString = dll_arg.to_os_string();
        let dll_path: &Path = Path::new(&dll_arg_os_str);

        if !exe_path.exists() {
            println!("Executable file specified does not exist: {:?}", exe_path);
            return;
        }

        if !dll_path.exists() {
            println!("DLL file specified does not exist: {:?}", dll_path);
            return;
        }

        let command_line: WideCString;
        if arguments_length > 4 {
            command_line = WideCString::from_str(&arguments[4]).unwrap();
        } else {
            command_line = WideCString::new();
        }

        let working_dir_arg: WideCString;
        if arguments_length > 5 {
            working_dir_arg = WideCString::from_str(&arguments[5]).unwrap();
        } else {
            working_dir_arg = WideCString::new();
        }
        let working_dir_arg_os_str = working_dir_arg.to_os_string();
        let working_dir_path: &Path = Path::new(&working_dir_arg_os_str);

        let mut create_proc_id: u32 = 0;
        create_process_and_inject_library(&exe_path, &dll_path, &command_line, &working_dir_path, &mut create_proc_id);
        println!("Created and injected into process successfully. New process id: {:?}", create_proc_id);

    } else if command_arg == call_command {
        if arguments_length < 5 {
            println!("Invalid number of arguments");
            return;
        }

        let process_arg: WideCString = WideCString::from_str(&arguments[2]).unwrap();
        let module_arg: WideCString = WideCString::from_str(&arguments[3]).unwrap();
        let function_name_arg: WideCString = WideCString::from_str(&arguments[4]).unwrap();
        let function_name_cstr: CString = CString::new(function_name_arg.to_string().unwrap()).unwrap();
        let argument_arg: WideCString;
        if arguments_length > 5 {
            argument_arg = WideCString::from_str(&arguments[5]).unwrap();
        } else {
            argument_arg = WideCString::new();
        }

        let mut process_ids: Vec<u32> = Vec::new();

        match process_arg.to_string().unwrap().parse::<u32>() {
            Ok(n) => {
                process_ids.push(n);
            },
            Err(_) => {
                process_ids = get_process_ids_from_name(&process_arg);
                if process_ids.is_empty() {
                    println!("Process with name {} does not exist.", process_arg.to_string().unwrap());
                    return;
                }
            }
        }

        for p in &process_ids {
            let process_handle: winapi::HANDLE = open_process(
                *p,
                winapi::winnt::PROCESS_CREATE_THREAD
                | winapi::winnt::PROCESS_QUERY_INFORMATION
                | winapi::winnt::PROCESS_VM_OPERATION
                | winapi::winnt::PROCESS_VM_WRITE
                | winapi::winnt::PROCESS_VM_READ
            );

            if process_handle == null_mut() {
                println!("Process with id {:?} does not exist or is not accessible.", p);
                continue;
            }

            let module_handle: winapi::minwindef::HMODULE = find_remote_module_by_name(*p, &module_arg);

            if module_handle == null_mut() {
                println!("Failed to find the remote module {:?}.", module_arg.to_string().unwrap());
                println!("Remote call failed.");
                continue;
            }

            let argument_ptr: winapi::minwindef::LPVOID;
            let argument_size: u64;
            if argument_arg.len() > 0 {
                argument_ptr = argument_arg.as_ptr() as *mut winapi::c_void;
                argument_size = ((argument_arg.len() + 1) * mem::size_of::<u16>()) as u64;
            } else {
                argument_ptr = null_mut();
                argument_size = 0;
            }

            if call_remote_function(process_handle, module_handle, &function_name_cstr, argument_ptr, argument_size) {
                println!("Successfully called function {:?}.", function_name_arg.to_string().unwrap());
            } else {
                println!("Remote call failed.");
            }

            if process_handle != null_mut() {
               unsafe { kernel32::CloseHandle( process_handle ); }
            }
        }
    } else {
       println!("Invalid command entered {:?}", command_arg.to_string().unwrap());
    }
}

fn get_process_ids_from_name(process_name: &WideCString) -> Vec<u32> {

    let snapshot: winapi::HANDLE;
    let mut process_entry = winapi::tlhelp32::PROCESSENTRY32W {
        dwSize: mem::size_of::<winapi::tlhelp32::PROCESSENTRY32W>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; winapi::minwindef::MAX_PATH]
    };

    unsafe { snapshot = kernel32::CreateToolhelp32Snapshot(winapi::tlhelp32::TH32CS_SNAPPROCESS, 0); }

    let mut process_ids: Vec<u32> = Vec::new();

    unsafe {
             if kernel32::Process32FirstW(snapshot, &mut process_entry) == winapi::minwindef::TRUE {
                while kernel32::Process32NextW(snapshot, &mut process_entry) == winapi::minwindef::TRUE {
                    let wide_str:OsString = OsStringExt::from_wide(&process_entry.szExeFile);
                    let exe_str:WideCString = WideCString::from_str_with_nul(wide_str).unwrap();
                    if exe_str == *process_name {
                        process_ids.push(process_entry.th32ProcessID);
                    }
                }
	       }
    }

	if snapshot != winapi::INVALID_HANDLE_VALUE {
		unsafe { kernel32::CloseHandle( snapshot ); }
    }

	return process_ids;
}

fn find_remote_module_by_path(process_id: u32, dll_path: &Path) -> winapi::minwindef::HMODULE {
    let snapshot: winapi::HANDLE;
    let mut module_entry = winapi::tlhelp32::MODULEENTRY32W {
        dwSize: mem::size_of::<winapi::tlhelp32::MODULEENTRY32W>() as u32,
        th32ModuleID: 0,
        th32ProcessID: 0,
        GlblcntUsage: 0,
        ProccntUsage: 0,
        modBaseAddr: null_mut(),
        modBaseSize: 0,
        hModule: null_mut(),
        szModule: [0; winapi::tlhelp32::MAX_MODULE_NAME32 + 1],
        szExePath: [0; winapi::minwindef::MAX_PATH]
    };

    unsafe { snapshot = kernel32::CreateToolhelp32Snapshot(winapi::tlhelp32::TH32CS_SNAPMODULE, process_id); }

    let mut module_handle: winapi::minwindef::HMODULE = null_mut();
    unsafe {
             if kernel32::Module32FirstW(snapshot, &mut module_entry) == winapi::minwindef::TRUE {

                while kernel32::Module32NextW(snapshot, &mut module_entry) == winapi::minwindef::TRUE {
                    let wide_str:OsString = OsStringExt::from_wide(&module_entry.szExePath);
                    let exe_str:WideCString = WideCString::from_str_with_nul(wide_str).unwrap();
                    if exe_str.to_os_string() == dll_path.as_os_str() {
                        module_handle = module_entry.hModule;
                        break;
                    }
                }
	       }
    }

	if snapshot != winapi::INVALID_HANDLE_VALUE {
		unsafe { kernel32::CloseHandle( snapshot ); }
    }

	return module_handle;
}

fn find_remote_module_by_name(process_id: u32, module_name: &WideCString) -> winapi::minwindef::HMODULE {
    let snapshot: winapi::HANDLE;
    let mut module_entry = winapi::tlhelp32::MODULEENTRY32W {
        dwSize: mem::size_of::<winapi::tlhelp32::MODULEENTRY32W>() as u32,
        th32ModuleID: 0,
        th32ProcessID: 0,
        GlblcntUsage: 0,
        ProccntUsage: 0,
        modBaseAddr: null_mut(),
        modBaseSize: 0,
        hModule: null_mut(),
        szModule: [0; winapi::tlhelp32::MAX_MODULE_NAME32 + 1],
        szExePath: [0; winapi::minwindef::MAX_PATH]
    };

    unsafe { snapshot = kernel32::CreateToolhelp32Snapshot(winapi::tlhelp32::TH32CS_SNAPMODULE, process_id); }

    let mut module_handle: winapi::minwindef::HMODULE = null_mut();
    unsafe {
             if kernel32::Module32FirstW(snapshot, &mut module_entry) == winapi::minwindef::TRUE {

                while kernel32::Module32NextW(snapshot, &mut module_entry) == winapi::minwindef::TRUE {
                    let wide_str:OsString = OsStringExt::from_wide(&module_entry.szExePath);
                    let exe_str:String = WideCString::from_str_with_nul(wide_str).unwrap().to_string().unwrap();
                    let path = Path::new(&exe_str);
                    if path.file_name().unwrap() == module_name.to_os_string() {
                        module_handle = module_entry.hModule;
                        break;
                    }
                }
	       }
    }

	if snapshot != winapi::INVALID_HANDLE_VALUE {
		unsafe { kernel32::CloseHandle( snapshot ); }
    }

	return module_handle;
}

fn find_remote_module_path_by_handle(process_id: u32, module_handle: winapi::minwindef::HMODULE) -> PathBuf {
    let snapshot: winapi::HANDLE;
    let mut module_entry = winapi::tlhelp32::MODULEENTRY32W {
        dwSize: mem::size_of::<winapi::tlhelp32::MODULEENTRY32W>() as u32,
        th32ModuleID: 0,
        th32ProcessID: 0,
        GlblcntUsage: 0,
        ProccntUsage: 0,
        modBaseAddr: null_mut(),
        modBaseSize: 0,
        hModule: null_mut(),
        szModule: [0; winapi::tlhelp32::MAX_MODULE_NAME32 + 1],
        szExePath: [0; winapi::minwindef::MAX_PATH]
    };

    unsafe { snapshot = kernel32::CreateToolhelp32Snapshot(winapi::tlhelp32::TH32CS_SNAPMODULE, process_id); }

    let mut module_path: PathBuf = PathBuf::new();
    unsafe {
             if kernel32::Module32FirstW(snapshot, &mut module_entry) == winapi::minwindef::TRUE {

                while kernel32::Module32NextW(snapshot, &mut module_entry) == winapi::minwindef::TRUE {
                    if module_entry.hModule == module_handle {
                        let wide_str:OsString = OsStringExt::from_wide(&module_entry.szExePath);
                        let exe_str:String = WideCString::from_str_with_nul(wide_str).unwrap().to_string().unwrap();
                        module_path = PathBuf::from(&exe_str);
                        break;
                    }
                }
	       }
    }

	if snapshot != winapi::INVALID_HANDLE_VALUE {
		unsafe { kernel32::CloseHandle( snapshot ); }
    }

	return module_path;
}

fn find_remote_module_base_address_by_handle(process_id: u32, module_handle: winapi::minwindef::HMODULE) -> *mut winapi::BYTE {
    let snapshot: winapi::HANDLE;
    let mut module_entry = winapi::tlhelp32::MODULEENTRY32W {
        dwSize: mem::size_of::<winapi::tlhelp32::MODULEENTRY32W>() as u32,
        th32ModuleID: 0,
        th32ProcessID: 0,
        GlblcntUsage: 0,
        ProccntUsage: 0,
        modBaseAddr: null_mut(),
        modBaseSize: 0,
        hModule: null_mut(),
        szModule: [0; winapi::tlhelp32::MAX_MODULE_NAME32 + 1],
        szExePath: [0; winapi::minwindef::MAX_PATH]
    };

    unsafe { snapshot = kernel32::CreateToolhelp32Snapshot(winapi::tlhelp32::TH32CS_SNAPMODULE, process_id); }

    let mut base_address: *mut winapi::BYTE = null_mut();
    unsafe {
             if kernel32::Module32FirstW(snapshot, &mut module_entry) == winapi::minwindef::TRUE {

                while kernel32::Module32NextW(snapshot, &mut module_entry) == winapi::minwindef::TRUE {
                    if module_entry.hModule == module_handle {
                        base_address = module_entry.modBaseAddr;
                        break;
                    }
                }
	       }
    }

	if snapshot != winapi::INVALID_HANDLE_VALUE {
		unsafe { kernel32::CloseHandle( snapshot ); }
    }

	return base_address;
}

fn open_process(process_id: u32, desired_access: winapi::minwindef::DWORD) -> winapi::HANDLE {
    let process_handle: winapi::HANDLE;
    unsafe {
        process_handle = kernel32::OpenProcess(desired_access, winapi::minwindef::FALSE, process_id);
    }

    return process_handle;
}

fn inject_library(process_handle: winapi::HANDLE, dll_path: &Path) -> bool {

    if process_handle == null_mut() {
        println!("Process does not exist or is not accessible.");
        return false;
    }

    let kernel32_module: winapi::minwindef::HMODULE;
    let load_library_address: winapi::minwindef::FARPROC;
    let remote_string: *mut winapi::c_void;

    let kernel32_str = WideCString::from_str("Kernel32.dll").unwrap();
    let load_library_str = CString::new("LoadLibraryW").unwrap();

    unsafe {
        kernel32_module = kernel32::GetModuleHandleW(kernel32_str.as_ptr());
    }

    if kernel32_module == null_mut() {
        println!("Failed to find {:?}.", kernel32_str.to_string().unwrap());
        return false;
    }

    unsafe {
        load_library_address = kernel32::GetProcAddress(kernel32_module, load_library_str.as_ptr());
    }

    if load_library_address == null_mut() {
        println!("Failed to find {:?}.", load_library_str);
        return false;
    }

    let dll_path_str = dll_path.as_os_str();
    let dll_path_size: u64 = ((dll_path_str.len() + 1) * mem::size_of::<u16>()) as u64;

    unsafe {
        remote_string = kernel32::VirtualAllocEx(process_handle, null_mut(), dll_path_size, winapi::winnt::MEM_RESERVE | winapi::winnt::MEM_COMMIT, winapi::winnt::PAGE_READWRITE);
    }

    if remote_string == null_mut() {
        println!("Failed to allocate memory in the target process.");
        return false;
    }

    let mut bytes_written: winapi::basetsd::SIZE_T = 0;
    let bytes_written_ptr: *mut winapi::basetsd::SIZE_T = &mut bytes_written as *mut _ as *mut winapi::basetsd::SIZE_T;
    let wpm_ret: winapi::minwindef::BOOL;

    unsafe {
        wpm_ret = kernel32::WriteProcessMemory(process_handle, remote_string, dll_path_str.encode_wide().collect::<Vec<_>>().as_ptr() as *const winapi::c_void, dll_path_size, bytes_written_ptr);
    }

    if wpm_ret == winapi::minwindef::FALSE || bytes_written < dll_path_size {
        println!("Failed to write memory to the target process.");
        unsafe {
            kernel32::VirtualFreeEx(process_handle, remote_string, dll_path_size, winapi::winnt::MEM_RELEASE);
        }
        return false;
    }

    let mut thread_id: winapi::minwindef::DWORD = 0;
    let thread_id_ptr: *mut winapi::minwindef::DWORD = &mut thread_id as *mut _ as *mut winapi::minwindef::DWORD;

    let start_routine = if load_library_address.is_null() { None } else { unsafe {Some(::std::mem::transmute::<*const winapi::c_void, unsafe extern "system" fn(lpThreadParameter: winapi::minwindef::LPVOID) -> winapi::minwindef::DWORD>(load_library_address)) } };

    let thread_handle: winapi::winnt::HANDLE;
    unsafe {
        thread_handle = kernel32::CreateRemoteThread(process_handle, null_mut(), 0, start_routine, remote_string, 0, thread_id_ptr);
    }

    if thread_handle == null_mut() {
        println!("Failed to inject the dll.");
        unsafe {
            kernel32::VirtualFreeEx(process_handle, remote_string, dll_path_size, winapi::winnt::MEM_RELEASE);
        }
        return false;
    }

    unsafe {
        kernel32::WaitForSingleObject(thread_handle, winapi::winbase::INFINITE);
        kernel32::CloseHandle(thread_handle);
        kernel32::VirtualFreeEx(process_handle, remote_string, dll_path_size, winapi::winnt::MEM_RELEASE);
    }
    return true;
}

fn eject_library(process_handle: winapi::HANDLE, module_handle: winapi::minwindef::HMODULE) -> bool {
    if process_handle == null_mut() {
        println!("Process does not exist or is not accessible.");
        return false;
    }

    let kernel32_module: winapi::minwindef::HMODULE;
    let free_library_address: winapi::minwindef::FARPROC;

    let kernel32_str = WideCString::from_str("Kernel32.dll").unwrap();
    let free_library_str = CString::new("FreeLibrary").unwrap();

    unsafe {
        kernel32_module = kernel32::GetModuleHandleW(kernel32_str.as_ptr());
    }

    if kernel32_module == null_mut() {
        println!("Failed to find {:?}.", kernel32_str);
        return false;
    }

    unsafe {
        free_library_address = kernel32::GetProcAddress(kernel32_module, free_library_str.as_ptr());
    }

    if free_library_address == null_mut() {
        println!("Failed to find {:?}.", free_library_str);
        return false;
    }

    let mut thread_id: winapi::minwindef::DWORD = 0;
    let thread_id_ptr: *mut winapi::minwindef::DWORD = &mut thread_id as *mut _ as *mut winapi::minwindef::DWORD;

    let start_routine = if free_library_address.is_null() { None } else { unsafe {Some(::std::mem::transmute::<*const winapi::c_void, unsafe extern "system" fn(lpThreadParameter: winapi::minwindef::LPVOID) -> winapi::minwindef::DWORD>(free_library_address)) } };

    let thread_handle: winapi::winnt::HANDLE;
    unsafe {
        thread_handle = kernel32::CreateRemoteThread(process_handle, null_mut(), 0, start_routine, module_handle as *mut winapi::c_void, 0, thread_id_ptr);
    }

    if thread_handle == null_mut() {
        println!("Failed to free the module.");
        return false;
    }

    unsafe {
        kernel32::WaitForSingleObject(thread_handle, winapi::winbase::INFINITE);
        kernel32::CloseHandle(thread_handle);
    }
    return true;
}

fn create_process_and_inject_library(exe_path: &Path, dll_path: &Path, command_line: &WideCString, working_directory: &Path, process_id: &mut u32) -> bool {
    if !exe_path.exists() {
        println!("Executable {:?} does not exist.", exe_path);
        return false;
    }

    if !dll_path.exists() {
        println!("DLL {:?} does not exist.", dll_path);
        return false;
    }

    let exe_str: WideCString = WideCString::from_str(exe_path.to_str().unwrap()).unwrap();
    let working_directory_str: WideCString = WideCString::from_str(working_directory.to_str().unwrap()).unwrap();
    let working_dir_opt: winapi::winnt::LPCWSTR = if working_directory_str.len() > 0 { working_directory_str.as_ptr() } else { null_mut() };

    let mut startup_info = winapi::processthreadsapi::STARTUPINFOW {
        cb: mem::size_of::<winapi::processthreadsapi::STARTUPINFOW>() as u32,
        lpReserved: null_mut(),
        lpDesktop: null_mut(),
        lpTitle: null_mut(),
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: 0,
        wShowWindow: 0,
        cbReserved2: 0,
        lpReserved2: null_mut(),
        hStdInput: null_mut(),
        hStdOutput: null_mut(),
        hStdError: null_mut(),
    };

    let mut process_info = winapi::processthreadsapi::PROCESS_INFORMATION {
        hProcess: null_mut(),
        hThread: null_mut(),
        dwProcessId: 0,
        dwThreadId: 0,
    };

    let success: winapi::minwindef::BOOL;

    unsafe {
        success = kernel32::CreateProcessW(
            exe_str.as_ptr(),
            command_line.as_ptr() as *mut _,
            null_mut(),
            null_mut(),
            winapi::minwindef::FALSE,
            winapi::winbase::NORMAL_PRIORITY_CLASS | winapi::winbase::CREATE_SUSPENDED,
            null_mut(),
            working_dir_opt,
            &mut startup_info,
            &mut process_info
         );
    }

    if success == winapi::minwindef::TRUE {
        *process_id = process_info.dwProcessId;
        let injected: bool = inject_library(process_info.hProcess, dll_path);

        unsafe {
            kernel32::ResumeThread(process_info.hThread);
        }

        return injected;
    } else {
        println!("Failed to create the process.");
    }

    *process_id = 0;
    return false;
}

fn call_remote_function(process_handle: winapi::HANDLE, module_handle: winapi::minwindef::HMODULE, function_name: &CString, argument: winapi::minwindef::LPVOID, argument_size: u64) -> bool {
    if process_handle == null_mut() {
        println!("Process does not exist or is not accessible.");
        return false;
    }

    if module_handle == null_mut() {
        println!("Failed to find {:?}.", module_handle);
        return false;
    }

    let process_id: u32 = unsafe { kernel32::GetProcessId(process_handle) };

    let module_path: PathBuf = find_remote_module_path_by_handle(process_id, module_handle);
    if !module_path.exists() {
    }

    let mut file = OpenOptions::new().read(true).write(false).truncate(false).append(false).open(module_path).unwrap();
	let mut buf=vec![];
	file.read_to_end(&mut buf).unwrap();
	let pe_file = pe::Pe::new(&buf).unwrap();
    let export_dir = pe_file.get_exports().unwrap();
    let remote_fn = export_dir.lookup_symbol(function_name.to_str().unwrap());
    let remote_fn_rva: pe::ExportAddress;

    match remote_fn {
        Ok(rva) => { remote_fn_rva = rva; },
        Err(_) => { 
            println!("Could not find the remote function {:?}.", function_name);
            return false;
        }
    };

    use pe::ExportAddress as EA;
	let offset = match remote_fn_rva {
		EA::Export(rva) => rva.get(),
		EA::Forwarder(rva) => rva.get(),
	};

    let module_base_addr = find_remote_module_base_address_by_handle(process_id, module_handle);
    let resolved_fn = (module_base_addr as usize + offset as usize) as *const winapi::c_void;

    if resolved_fn == null_mut() {
        println!("Failed to find {:?}.", function_name);
        return false;
    }

    let mut remote_arg: *mut winapi::c_void = null_mut();
    if argument_size > 0 {
        unsafe {
            remote_arg = kernel32::VirtualAllocEx(process_handle, null_mut(), argument_size, winapi::winnt::MEM_RESERVE | winapi::winnt::MEM_COMMIT, winapi::winnt::PAGE_READWRITE);
        }

        if remote_arg == null_mut() {
            println!("Failed to allocate memory in the target process.");
            return false;
        }

        let mut bytes_written: winapi::basetsd::SIZE_T = 0;
        let bytes_written_ptr: *mut winapi::basetsd::SIZE_T = &mut bytes_written as *mut _ as *mut winapi::basetsd::SIZE_T;
        let wpm_ret: winapi::minwindef::BOOL;

        unsafe {
            wpm_ret = kernel32::WriteProcessMemory(process_handle, remote_arg, argument, argument_size, bytes_written_ptr);
        }

        if wpm_ret == winapi::minwindef::FALSE || bytes_written < argument_size {
            println!("Failed to write memory to the target process.");
            unsafe {
                kernel32::VirtualFreeEx(process_handle, remote_arg, argument_size, winapi::winnt::MEM_RELEASE);
            }
            return false;
        }
    }

    let mut thread_id: winapi::minwindef::DWORD = 0;
    let thread_id_ptr: *mut winapi::minwindef::DWORD = &mut thread_id as *mut _ as *mut winapi::minwindef::DWORD;

    let start_routine = if resolved_fn.is_null() { None } else { unsafe {Some(::std::mem::transmute::<*const winapi::c_void, unsafe extern "system" fn(lpParameter: winapi::minwindef::LPVOID) -> winapi::minwindef::DWORD>(resolved_fn)) } };

    let thread_handle: winapi::winnt::HANDLE;
    unsafe {
        thread_handle = kernel32::CreateRemoteThread(process_handle, null_mut(), 0, start_routine, remote_arg, 0, thread_id_ptr);
    }

    if thread_handle == null_mut() {
        println!("Failed to call the remote function.");
        unsafe {
            kernel32::VirtualFreeEx(process_handle, remote_arg, argument_size, winapi::winnt::MEM_RELEASE);
        }
        return false;
    }

    unsafe {
        kernel32::WaitForSingleObject(thread_handle, winapi::winbase::INFINITE);
        kernel32::CloseHandle(thread_handle);
        kernel32::VirtualFreeEx(process_handle, remote_arg, argument_size, winapi::winnt::MEM_RELEASE);
    }
    return true;
}

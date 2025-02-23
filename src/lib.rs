mod remote_mem;
mod remote_module;
mod remote_proc;
mod shellcode;
mod utils;

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use log::{error, info, warn, LevelFilter};
use android_logger::Config;
use simple_logger::SimpleLogger;


#[macro_use]
extern crate log;

#[derive(Debug)]
pub enum InjectionError {
    RemoteProcessError,
    RemoteMemoryError,
    RemoteModuleError,
    ModuleNotFound,
    SymbolNotFound,
    FileError,
    CommandError,
    ShellcodeError,
    PidNotFound,
}

pub struct Injector {
    pid: i32,
    remote_proc: remote_proc::RemoteProc,
    file_path: String,
    injection_type: InjectionType,
    target_func_sym_name: String,
    target_func_sym_addr: usize,
    target_var_sym_name: String,
    target_var_sym_addr: usize,
    module_cache: HashMap<String, remote_module::RemoteModule>,
    sym_cache: HashMap<String, usize>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum InjectionType {
    /// Use dlopen to inject a library
    RawDlopen,
    /// Use memfd_create and dlopen to inject a library
    MemFdDlopen,
    /// Inject raw shellcode
    RawShellcode,
}

impl Injector {
    pub fn new(pid: i32) -> Result<Injector, InjectionError> {
        info!("new injector for pid: {}", pid);
        Ok(Injector {
            pid,
            remote_proc: remote_proc::RemoteProc::new(pid)?,
            file_path: String::new(),
            injection_type: InjectionType::RawDlopen,
            target_func_sym_name: String::new(),
            target_func_sym_addr: 0,
            target_var_sym_name: String::new(),
            target_var_sym_addr: 0,
            module_cache: HashMap::new(),
            sym_cache: HashMap::new(),
        })
    }

    pub fn set_file_path(&mut self, file_path: String) -> Result<&mut Self, InjectionError> {
        let file = std::fs::File::open(&file_path);
        if file.is_err() {
            error!("File not found: {}", file_path);
            return Err(InjectionError::FileError);
        }

        self.file_path = file_path;
        Ok(self)
    }

    fn prepare_file(&self) -> Result<String, InjectionError> {
        if self.injection_type == InjectionType::RawDlopen
            || self.injection_type == InjectionType::MemFdDlopen
        {
            utils::verify_elf_file(self.file_path.as_str())?;
        }

        let tmp_file_path = utils::copy_file_to_tmp(self.file_path.as_str())?;
        utils::fix_file_context(tmp_file_path.as_str())?;
        utils::fix_file_permissions(tmp_file_path.as_str())?;
        utils::print_file_hexdump(tmp_file_path.as_str())?;
        Ok(tmp_file_path)
    }

    fn add_sym(&mut self, module_name: &str, sym_name: &str) -> Result<usize, InjectionError> {
        debug!("add_sym: {}!{}", module_name, sym_name);

        if !self.module_cache.contains_key(module_name) {
            let module = self.remote_proc.module(module_name)?;
            self.module_cache.insert(module_name.to_string(), module);
        }

        let module = self.module_cache.get(module_name).unwrap();
        debug!("add_sym: {} 0x{:x}", module_name, module.vm_addr);

        if !self.sym_cache.contains_key(sym_name) {
            let sym = module.dlsym_from_fs(sym_name)?;
            self.sym_cache.insert(sym_name.to_string(), sym);
        }

        debug!(
            "add_sym: {} 0x{:x}",
            sym_name,
            self.sym_cache.get(sym_name).unwrap()
        );
        Ok(*self.sym_cache.get(sym_name).unwrap())
    }

    pub fn set_func_sym(
        &mut self,
        module_name: &str,
        sym_name: &str,
    ) -> Result<&mut Self, InjectionError> {
        let sym_addr = self.add_sym(module_name, sym_name)?;
        self.target_func_sym_name = sym_name.to_string();
        self.target_func_sym_addr = sym_addr;
        debug!("set_func_sym: {} 0x{:x}", sym_name, sym_addr);
        Ok(self)
    }

    pub fn set_var_sym(
        &mut self,
        module_name: &str,
        sym_name: &str,
    ) -> Result<&mut Self, InjectionError> {
        let sym_addr = self.add_sym(module_name, sym_name)?;
        self.target_var_sym_name = sym_name.to_string();
        self.target_var_sym_addr = sym_addr;
        debug!("set_var_sym: {} 0x{:x}", sym_name, sym_addr);
        Ok(self)
    }

    pub fn set_default_syms(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_func_sym("libc.so", "malloc")?;
        self.set_var_sym("libc.so", "timezone")?;
        Ok(self)
    }

    pub fn set_test_syms(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_func_sym(
            "liblasso.so",
            "Java_com_github_erfur_lasso_MainActivity_testFunction",
        )?;
        self.set_var_sym("liblasso.so", "test_var")?;
        Ok(self)
    }

    pub fn use_raw_dlopen(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_func_sym("libdl.so", "dlopen")?;
        self.injection_type = InjectionType::RawDlopen;
        Ok(self)
    }

    pub fn use_memfd_dlopen(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_func_sym("libdl.so", "dlopen")?;
        self.set_func_sym("libc.so", "sprintf")?;
        self.injection_type = InjectionType::MemFdDlopen;
        Ok(self)
    }

    pub fn use_raw_shellcode(&mut self) -> Result<&mut Self, InjectionError> {
        self.injection_type = InjectionType::RawShellcode;
        Ok(self)
    }

    pub fn restart_app_and_get_pid(package_name: &str) -> Result<u32, InjectionError> {
        let pid = utils::restart_app_and_get_pid(package_name);
        if pid > 0 {
            Ok(pid)
        } else {
            Err(InjectionError::PidNotFound)
        }
    }

    pub fn inject(&mut self) -> Result<(), InjectionError> {
        let file_path = self.prepare_file()?;
        let proc = remote_proc::RemoteProc::new(self.pid)?;

        if self.target_func_sym_name.is_empty() || self.target_var_sym_name.is_empty() {
            warn!("target_func_sym or target_var_sym is empty, using defaults");
            self.set_default_syms()?;
        }

        info!("build second stage shellcode");
        let second_stage = match self.injection_type {
            InjectionType::RawDlopen => shellcode::raw_dlopen_shellcode(
                *self.sym_cache.get("dlopen").unwrap(),
                file_path,
                *self.sym_cache.get("malloc").unwrap(),
            )
            .unwrap(),
            InjectionType::MemFdDlopen => shellcode::memfd_dlopen_shellcode(
                *self.sym_cache.get("dlopen").unwrap(),
                *self.sym_cache.get("malloc").unwrap(),
                &std::fs::read(file_path.as_str()).unwrap(),
                *self.sym_cache.get("sprintf").unwrap(),
            )
            .unwrap(),
            InjectionType::RawShellcode => shellcode::raw_shellcode().unwrap(),
        };

        info!("build first stage shellcode");
        let first_stage =
            shellcode::main_shellcode(self.target_var_sym_addr, second_stage.len()).unwrap();

        info!("read original bytes");
        let func_original_bytes = proc
            .mem
            .read(self.target_func_sym_addr, first_stage.len())
            .unwrap();
        let var_original_bytes = proc.mem.read(self.target_var_sym_addr, 0x8).unwrap();

        info!("write first stage shellcode");
        proc.mem
            .write(self.target_var_sym_addr, &vec![0x0; 0x8])
            .unwrap();
        proc.mem
            .write(self.target_func_sym_addr, &first_stage)
            .unwrap();

        info!("wait for shellcode to trigger");
        let mut new_map: u64;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(10));
            let data = proc.mem.read(self.target_var_sym_addr, 0x8).unwrap();
            // u64 from val
            new_map = u64::from_le_bytes(data[0..8].try_into().unwrap());
            if (new_map & 0x1 != 0) && (new_map & 0xffff_ffff_ffff_fff0 != 0) {
                break;
            }
        }

        new_map &= 0xffff_ffff_ffff_fff0;
        info!("new map: 0x{:x}", new_map);

        info!("overwrite malloc with loop");
        proc.mem
            .write(self.target_func_sym_addr, &shellcode::self_jmp().unwrap())
            .unwrap();

        // wait for 100ms
        std::thread::sleep(std::time::Duration::from_millis(100));

        info!("restore original bytes");
        proc.mem
            .write_code(self.target_func_sym_addr, &func_original_bytes, 1)
            .unwrap();
        proc.mem
            .write(self.target_var_sym_addr, &var_original_bytes)
            .unwrap();

        info!("overwrite new map");
        proc.mem
            .write_code(new_map as usize, &second_stage, 1)
            .unwrap();

        info!("injection done.");
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn inject(
    pid: i32,
    file_path: *const c_char,
    injection_type: i32,
    func_sym: *const c_char,
    var_sym: *const c_char,
    debug: bool,
    logcat: bool,
) -> i32 {
    // 初始化日志
    if logcat {
        if debug {
            android_logger::init_once(Config::default().with_max_level(LevelFilter::Debug));
        } else {
            android_logger::init_once(Config::default().with_max_level(LevelFilter::Info));
        }
    } else if debug {
        SimpleLogger::new()
           .with_level(LevelFilter::Debug)
           .init()
           .unwrap();
    } else {
        SimpleLogger::new()
           .with_level(LevelFilter::Info)
           .init()
           .unwrap();
    }

    let file_path = unsafe { CStr::from_ptr(file_path).to_string_lossy().into_owned() };
    let func_sym_str = if func_sym.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(func_sym).to_string_lossy().into_owned() })
    };
    let var_sym_str = if var_sym.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(var_sym).to_string_lossy().into_owned() })
    };

    info!("target process pid: {}", pid);

    let mut injector = match Injector::new(pid) {
        Ok(injector) => injector,
        Err(e) => {
            error!("Error creating injector: {:?}", e);
            return -1;
        }
    };

    match injector.set_file_path(file_path) {
        Ok(_) => {}
        Err(e) => {
            error!("Error setting file path: {:?}", e);
            return -1;
        }
    }

    // 根据 injection_type 设置注入方式
    let result = match injection_type {
        0 => injector.use_raw_dlopen(),       // 使用 RawDlopen
        1 => injector.use_memfd_dlopen(),    // 使用 MemFdDlopen
        2 => injector.use_raw_shellcode(),   // 使用 RawShellcode
        _ => {
            error!("Invalid injection type: {}", injection_type);
            return -1;
        }
    };

    // 检查注入方式是否设置成功
    if result.is_err() {
        error!("Error setting injection type: {:?}", result.err());
        return -1;
    }

    // 处理函数符号
    if let Some(ref func_sym) = func_sym_str {
        let sym_pair: Vec<&str> = func_sym.split('!').collect();
        if sym_pair.len() != 2 {
            error!("Invalid function symbol format, use lib.so!symbol_name");
            return -1;
        }
        match injector.set_func_sym(sym_pair[0], sym_pair[1]) {
            Ok(_) => {}
            Err(e) => {
                error!("Error setting function symbol: {:?}", e);
                return -1;
            }
        };
    }

    // 处理变量符号
    if let Some(ref var_sym) = var_sym_str {
        let sym_pair: Vec<&str> = var_sym.split('!').collect();
        if sym_pair.len() != 2 {
            error!("Invalid variable symbol format, use lib.so!symbol_name");
            return -1;
        }
        match injector.set_var_sym(sym_pair[0], sym_pair[1]) {
            Ok(_) => {}
            Err(e) => {
                error!("Error setting variable symbol: {:?}", e);
                return -1;
            }
        };
    }

    // if either func_sym or var_sym is not provided, use default symbols
    if func_sym_str.is_none() || var_sym_str.is_none() {
        warn!("function or variable symbol not specified, using defaults");
        match injector.set_default_syms() {
            Ok(_) => {}
            Err(e) => {
                error!("Error setting default symbols: {:?}", e);
                return -1;
            }
        };
    }

    match injector.inject() {
        Ok(_) => {
            info!("injection successful");
            0
        }
        Err(e) => {
            error!("Error injecting: {:?}", e);
            -1
        }
    }
}

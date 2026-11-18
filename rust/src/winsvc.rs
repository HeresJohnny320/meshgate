//! The Windows service (Go: cmd/meshgate/service_windows.go): runs the agent
//! under the Service Control Manager, and `meshgate service install|uninstall`.

#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const NAME: &str = "meshgate";

/// Whether the Service Control Manager started this process (its parent is
/// services.exe), like Go's svc.IsWindowsService.
pub fn is_service() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
    };
    let me = std::process::id();
    // SAFETY: a process snapshot walked with a correctly sized entry.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut procs: Vec<(u32, u32, String)> = vec![];
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e) != 0;
        while ok {
            let n = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            procs.push((e.th32ProcessID, e.th32ParentProcessID, String::from_utf16_lossy(&e.szExeFile[..n])));
            ok = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
        let Some(parent) = procs.iter().find(|p| p.0 == me).map(|p| p.1) else { return false };
        procs.iter().any(|p| p.0 == parent && p.2.eq_ignore_ascii_case("services.exe"))
    }
}

/// Handoff between the agent (on the tokio runtime) and the service thread.
struct Shared {
    stop: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// The agent's result once it returned: Some(failed).
    done: Mutex<Option<bool>>,
    cv: Condvar,
}

static SHARED: Mutex<Option<Arc<Shared>>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    let Some(sh) = SHARED.lock().unwrap().clone() else { return };
    let sh2 = sh.clone();
    let handler = move |c: ServiceControl| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = sh2.stop.lock().unwrap().take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(h) = service_control_handler::register(NAME, handler) else { return };
    let status = |state, accept, exit, wait| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: exit,
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    };
    let _ = h.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
        Duration::ZERO,
    ));
    // Wait for the agent to return (after a stop request, or on its own).
    let failed = {
        let mut d = sh.done.lock().unwrap();
        loop {
            if let Some(f) = *d {
                break f;
            }
            if sh.stop.lock().unwrap().is_none() {
                // Stopping: tell the SCM to wait (Go waited up to 10 s).
                let _ = h.set_service_status(status(
                    ServiceState::StopPending,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::Win32(0),
                    Duration::from_secs(10),
                ));
                let (g, t) = sh.cv.wait_timeout_while(d, Duration::from_secs(10), |d| d.is_none()).unwrap();
                d = g;
                if t.timed_out() {
                    break false;
                }
                continue;
            }
            d = sh.cv.wait_timeout(d, Duration::from_millis(500)).unwrap().0;
        }
    };
    // A failing agent ends with an error so the recovery actions restart it.
    let exit = if failed { ServiceExitCode::ServiceSpecific(1) } else { ServiceExitCode::Win32(0) };
    let _ = h.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), exit, Duration::ZERO));
}

/// Runs the agent as the service until the SCM stops it.
pub async fn run(a: Arc<crate::agent::Agent>) -> Result<(), String> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let sh = Arc::new(Shared { stop: Mutex::new(Some(tx)), done: Mutex::new(None), cv: Condvar::new() });
    *SHARED.lock().unwrap() = Some(sh.clone());
    let dispatcher = std::thread::spawn(|| service_dispatcher::start(NAME, ffi_service_main));
    let res = a
        .run(async {
            let _ = rx.await;
        })
        .await;
    *sh.done.lock().unwrap() = Some(res.is_err());
    sh.cv.notify_all();
    let _ = tokio::task::spawn_blocking(move || dispatcher.join()).await;
    res
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager, String> {
    ServiceManager::local_computer(None::<&str>, access).map_err(|e| format!("service manager (run as Administrator): {e}"))
}

/// `meshgate service install|uninstall`.
pub fn cmd_service(cfg_path: &str, args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("install") => {
            let m = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let cfg = std::path::absolute(cfg_path).map_err(|e| e.to_string())?;
            let info = ServiceInfo {
                name: NAME.into(),
                display_name: "meshgate".into(),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::AutoStart,
                error_control: ServiceErrorControl::Normal,
                executable_path: exe,
                launch_arguments: vec!["-config".into(), cfg.into_os_string(), "agent".into()],
                dependencies: vec![],
                account_name: None, // LocalSystem
                account_password: None,
            };
            let s = m
                .create_service(&info, ServiceAccess::START | ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS)
                .map_err(|e| e.to_string())?;
            let _ = s.set_description("meshgate WireGuard mesh node");
            let restart = |secs| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(secs) };
            let _ = s.update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(3600)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![restart(3), restart(10), restart(30)]),
            });
            s.start::<&OsStr>(&[]).map_err(|e| e.to_string())?;
            println!("meshgate service installed and started.");
            Ok(())
        }
        Some("uninstall") => {
            stop_for_leave();
            println!("meshgate service removed.");
            Ok(())
        }
        _ => Err("usage: meshgate service install|uninstall".into()),
    }
}

fn wait_stopped(s: &windows_service::service::Service) {
    for _ in 0..50 {
        if s.query_status().map(|st| st.current_state == ServiceState::Stopped).unwrap_or(true) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Restarts meshgate if it runs; a stopped one stays stopped.
pub fn restart() -> Result<(), String> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let s = m.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START).map_err(|e| e.to_string())?;
    if s.query_status().map(|st| st.current_state == ServiceState::Stopped).unwrap_or(false) {
        return Ok(());
    }
    let _ = s.stop();
    wait_stopped(&s);
    s.start::<&OsStr>(&[]).map_err(|e| e.to_string())
}

/// Starts or stops meshgate and makes that survive reboots (automatic vs
/// manual start).
pub fn set(on: bool) -> Result<(), String> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let s = m
        .open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START | ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| format!("meshgate service not installed (meshgate service install): {e}"))?;
    let o = crate::util::run("sc.exe", &["config", NAME, "start=", if on { "auto" } else { "demand" }], None);
    if !o.ok {
        return Err(format!("sc config: {} {}", o.err, o.out.trim()));
    }
    if on {
        if s.query_status().map(|st| st.current_state == ServiceState::Running).unwrap_or(false) {
            return Ok(());
        }
        return s.start::<&OsStr>(&[]).map_err(|e| e.to_string());
    }
    let _ = s.stop();
    Ok(())
}

/// Stops and removes the service.
pub fn stop_for_leave() {
    let Ok(m) = manager(ServiceManagerAccess::CONNECT) else { return };
    let Ok(s) = m.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE) else { return };
    let _ = s.stop();
    let _ = s.delete();
}

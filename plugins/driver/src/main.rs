//! v1.9 driver 插件主入口。
//!
//! 变更点（相对 v1.7）：
//! 1. 事件读取改用 `ringslot::RingSlot`（`/sys/module/elkeid/parameters/control_trace`），
//!    不再读 `/proc/elkeid-endpoint`。
//! 2. 控制改用 `kmod::Kmod`（封装 `ringslot::SmithControl`），不再写 `/dev/hids_driver_allowlist`。
//! 3. 事件为二进制 sd_event 格式，解析由 `event` 模块（待实现）完成。

use driver::{config::*, event, kmod::Kmod};
use log::*;
use plugins::{logger::*, Client, Task};
use ringslot::RingSlot;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

// 控制任务 data_type 约定（Manager/Console 下发到本插件）
const TASK_ADD_ALLOW_EXE: i32 = 9001;
const TASK_ADD_ALLOW_ARGV: i32 = 9002;
const TASK_DEL_ALLOW_EXE: i32 = 9003;
const TASK_DEL_ALLOW_ARGV: i32 = 9004;
const TASK_SET_BLOCK_EXE_ARGV: i32 = 9005; // data = 阻断规则 JSON 文件路径
const TASK_SET_BLOCK_MD5: i32 = 9006; // data = md5 阻断 JSON 文件路径
const TASK_ENABLE_SELF_PROTECTION: i32 = 9007;
const TASK_DISABLE_SELF_PROTECTION: i32 = 9008;
const TASK_ENABLE_PSAD: i32 = 9009;

fn handle_task(kmod: &Kmod, t: Task) {
    match t.data_type {
        TASK_ADD_ALLOW_EXE => {
            if let Err(e) = kmod.add_allow_exe(&t.data) {
                error!("add_allow_exe({}) failed: {}", t.data, e);
            }
        }
        TASK_ADD_ALLOW_ARGV => {
            if let Err(e) = kmod.add_allow_argv(&t.data) {
                error!("add_allow_argv({}) failed: {}", t.data, e);
            }
        }
        TASK_DEL_ALLOW_EXE => {
            if let Err(e) = kmod.del_allow_exe(&t.data) {
                error!("del_allow_exe({}) failed: {}", t.data, e);
            }
        }
        TASK_DEL_ALLOW_ARGV => {
            if let Err(e) = kmod.del_allow_argv(&t.data) {
                error!("del_allow_argv({}) failed: {}", t.data, e);
            }
        }
        TASK_SET_BLOCK_EXE_ARGV => {
            if let Err(e) = kmod.set_block_exe_argv(&t.data) {
                error!("set_block_exe_argv({}) failed: {}", t.data, e);
            }
        }
        TASK_SET_BLOCK_MD5 => {
            if let Err(e) = kmod.set_block_md5(&t.data) {
                error!("set_block_md5({}) failed: {}", t.data, e);
            }
        }
        TASK_ENABLE_SELF_PROTECTION => {
            if let Err(e) = kmod.enable_self_protection() {
                error!("enable_self_protection failed: {}", e);
            }
        }
        TASK_DISABLE_SELF_PROTECTION => {
            if let Err(e) = kmod.disable_self_protection() {
                error!("disable_self_protection failed: {}", e);
            }
        }
        TASK_ENABLE_PSAD => {
            if let Err(e) = kmod.enable_psad() {
                error!("enable_psad failed: {}", e);
            }
        }
        other => warn!("unknown task data_type: {}", other),
    }
}

fn main() {
    let mut client = Client::new(true);

    let logger = Logger::new(Config {
        max_size: 1024 * 1024 * 5,
        path: PathBuf::from("./driver.log"),
        file_level: LevelFilter::Info,
        remote_level: LevelFilter::Error,
        max_backups: 10,
        compress: true,
        client: Some(client.clone()),
    });
    set_boxed_logger(Box::new(logger)).unwrap();

    // 控制层初始化（连接到 elkeid 内核模块）
    let kmod = match Kmod::new() {
        Ok(k) => k,
        Err(err) => {
            error!("init kmod control failed: {}", err);
            return;
        }
    };
    if let Err(e) = kmod.apply_static_allowlist() {
        warn!("apply_static_allowlist failed: {}", e);
    }
    let kmod = Arc::new(kmod);

    // 控制任务接收线程
    let kmod_t = kmod.clone();
    let mut client_c = client.clone();
    let control_s = Arc::new(AtomicBool::new(false));
    let control_l = control_s.clone();
    let _task_thread = thread::Builder::new()
        .name("task_receive".to_owned())
        .spawn(move || loop {
            match client_c.receive() {
                Ok(t) => handle_task(&*kmod_t, t),
                Err(e) => {
                    error!("when receiving task, an error occurred: {}", e);
                    control_s.store(true, Ordering::Relaxed);
                    return;
                }
            }
        });

    // 事件读取线程（RingSlot）
    let mut client_r = client.clone();
    let record_send = thread::Builder::new()
        .name("record_send".to_string())
        .spawn(move || {
            let (mut rs, _cancel) = match RingSlot::new(RING_KMOD_V1_9, CONTROL_PATH) {
                Ok(r) => r,
                Err(e) => {
                    error!("RingSlot::new failed: {}", e);
                    return;
                }
            };
            info!("init ringslot successfully");

            loop {
                if control_l.load(Ordering::Relaxed) {
                    break;
                }
                match rs.read_record() {
                    Ok(rec) => {
                        if let Some(record) = event::parse_record(rec) {
                            if let Err(e) = client_r.send_record(&record) {
                                error!("send record failed: {}", e);
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("read ringslot record: {}", e);
                        continue;
                    }
                }
            }
        })
        .unwrap();

    let _ = record_send.join();
    info!("plugin will exit");
}

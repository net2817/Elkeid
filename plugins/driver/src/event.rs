//! v1.9 事件解析（文本映射器）。
//!
//! 关键事实：二进制 sd_event 的反序列化已在 C 层完成
//! （`driver/ring/kmod.c` 的 `tb_read_kmod_v1_9` → `sd_unpack(..., sd_query_event_v1_9)`），
//! `RingSlot::read_record()` 返回的是 **\0 分隔的文本字段**，本模块只做「切分 + 按 schema 映射」。
//!
//! ⚠️ 需在 Linux 上用 `driver/test` 二进制观察实际输出后，确认：
//!    1) 第一个字段是 data_type(xid) 还是 timestamp；
//!    2) 是否带 SD_REC_ENDIAN(0xFFFE00) 记录尾；
//!    再据此微调 `parse_record` 的字段索引。

use plugins::{Payload, Record};
use std::collections::HashMap;

/// 公共头字段顺序（ENTRY_COMMON，见 kprobe_print.h），不含 xid。
/// 注：v1.9 字段名与 v1.7 schema.rs 有差异，见 V19_ADAPTATION.md。
pub const COMMON_FIELDS: &[&str] = &[
    "uid", "exe_path", "pid", "ppid", "pgid", "tgid", "sid", "epoch",
    "comm", "nodename", "mntns_id", "root_mntns_id",
];

/// 事件私有字段（按 data_type）。此处列出核心事件；完整表需按 kprobe_print.h /
/// anti_rootkit_print.h 的 XFER(...) 顺序补齐（含 execve/connect/dns 的 v4/v6/nosocket 变体）。
fn event_fields(data_type: u32) -> &'static [&'static str] {
    match data_type {
        1 => &["file", "buf"],                             // write
        2 => &["flags", "mode", "filename"],              // open
        10 => &["prot", "owner_pid", "owner_file", "vm_file", "pid_tree"], // mprotect
        35 => &["sec", "nsec"],                           // nanosleep
        42 => &["sa_family", "dip", "dport", "sip", "sport", "retval", "pid_tree"], // connect4
        43 => &["sa_family", "dip", "dport", "sip", "sport", "retval"],  // accept
        49 => &["sa_family", "sip", "sport", "retval", "pid_tree"],      // bind4
        59 => &[
            "argv", "pname", "tmp_stdin", "tmp_stdout", "dip", "dport",
            "sip", "sport", "sa_family", "pid_tree", "tty_name", "socket_pid",
            "ssh_connection", "ld_preload", "ld_library_path", "retval", "size", "md5",
        ], // execve
        60 => &[],                                        // exit
        62 => &["killpid", "killsig", "killret"],         // kill
        82 => &["oldname", "newname", "s_id"],            // rename
        86 => &["oldname", "newname", "s_id"],            // link
        90 => &["pid_tree", "file_path", "fsid", "mode", "retval"], // chmod
        101 => &["request", "owner_pid", "addr", "data_res", "pid_tree"], // ptrace
        112 => &["newsid", "pid_tree"],                   // setsid
        157 => &["option", "newname"],                    // prctl
        165 => &["pid_tree", "dev_name", "file_path", "fsid", "fstype", "flags", "option"], // mount
        200 => &["killtid", "killsig", "killret"],        // tkill
        201 => &["kiltgid", "killtid", "killsig", "killret"], // tgkill
        231 => &[],                                       // exit_group
        356 => &["fdname", "flags"],                      // memfd_create
        601 => &["query", "sa_family", "dip", "dport", "sip", "sport", "opcode", "rcode", "type", "pid_tree"], // dns
        602 => &["pathstr", "dip", "dport", "sip", "sport", "sa_family", "socket_pid", "s_id", "pid_tree"],    // create
        603 => &["mod_name", "pid_tree", "pwd"],          // init_module
        604 => &["pid_tree", "old_uid", "retval"],        // update_cred
        605 => &["file"],                                 // unlink
        606 => &["file"],                                 // rmdir
        607 => &["exe", "argv", "wait"],                  // call_usermodehelper_exec
        608 => &["file", "s_id"],                         // file write
        609 => &["file", "s_id"],                         // file read
        610 => &["product", "manufacturer", "serial", "action"], // udev
        611 => &["parent_pid", "pid_tree", "p_cred", "c_cred"],   // privilege_escalation
        612 => &["sa_family", "sip", "sport", "dip", "dport", "flags"], // psad
        613 => &["file_path"],                            // file_creation
        700 => &["name"],                                 // proc file hook
        701 => &["name", "scid"],                         // syscall hook
        702 => &["name"],                                 // hidden module
        703 => &["name", "intno"],                        // interrupt hook
        801 => &["rule", "dns"],                          // exe_warn_dns
        802 => &["rule", "argv", "cwd", "pid_tree", "md5"], // exe_warn_md5
        _ => &[],
    }
}

/// 将一条 \0 分隔的文本记录解析为 `plugins::Record`。
///
/// 假设输出格式为：`data_type\0uid\0exe_path\0...私有字段...\0`
/// （公共头字段顺序见 COMMON_FIELDS，私有字段见 event_fields）。
/// 若实测发现首字段是 timestamp，则把 `split[0]` 当时间戳、`split[1]` 当 data_type。
pub fn parse_record(rec: &[u8]) -> Option<Record> {
    let fields: Vec<&[u8]> = rec.split(|c| *c == 0).filter(|f| !f.is_empty()).collect();
    if fields.is_empty() {
        return None;
    }

    // TODO(linux-verify): 确认首字段是否为 data_type（若带 timestamp 则偏移 +1）
    let data_type = std::str::from_utf8(fields[0]).ok()?.parse::<u32>().ok()?;
    let rest = &fields[1..];

    let mut map: HashMap<String, String> = HashMap::new();
    let mut idx = 0;
    for name in COMMON_FIELDS {
        if idx < rest.len() {
            map.insert((*name).to_string(), String::from_utf8_lossy(rest[idx]).into_owned());
        }
        idx += 1;
    }
    for name in event_fields(data_type) {
        if idx < rest.len() {
            map.insert((*name).to_string(), String::from_utf8_lossy(rest[idx]).into_owned());
        }
        idx += 1;
    }

    let mut pld = Payload::new();
    pld.set_fields(map);
    let mut r = Record::new();
    r.set_data_type(data_type as i32);
    // timestamp 由 agent 侧补充；此处先置 0，待 linux-verify 后确认是否从记录中解析
    r.set_timestamp(0);
    r.set_data(pld);
    Some(r)
}

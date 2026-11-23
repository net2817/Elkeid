//! v1.9 控制层：封装 `ringslot::SmithControl`，负责白名单（放行）/ HIPS 阻断 /
//! 自保护 / 端口扫描（PSAD）规则的统一管理。
//!
//! 取代 v1.7 中直接写 `/dev/hids_driver_allowlist` 的 `control()` 逻辑。

use crate::config::*;
use anyhow::{anyhow, Result};
use log::*;
use ringslot::SmithControl;

pub struct Kmod {
    control: SmithControl,
}

impl Kmod {
    /// 连接到已加载的 elkeid 内核模块的控制接口。
    pub fn new() -> Result<Self> {
        let control = SmithControl::new(RING_KMOD_V1_9, CONTROL_PATH)
            .map_err(|e| anyhow!("SmithControl::new({:x}, {}) failed: {}", RING_KMOD_V1_9, CONTROL_PATH, e))?;
        info!("init elkeid kmod control successfully");
        Ok(Self { control })
    }

    // ---- 白名单（放行） ----

    pub fn add_allow_exe(&self, exe: &str) -> Result<()> {
        self.control
            .ac_add_allow_exe(exe)
            .map_err(|e| anyhow!("ac_add_allow_exe({}) failed: {}", exe, e))
    }

    pub fn add_allow_argv(&self, argv: &str) -> Result<()> {
        self.control
            .ac_add_allow_argv(argv)
            .map_err(|e| anyhow!("ac_add_allow_argv({}) failed: {}", argv, e))
    }

    pub fn del_allow_exe(&self, exe: &str) -> Result<()> {
        self.control
            .ac_del_allow_exe(exe)
            .map_err(|e| anyhow!("ac_del_allow_exe({}) failed: {}", exe, e))
    }

    pub fn del_allow_argv(&self, argv: &str) -> Result<()> {
        self.control
            .ac_del_allow_argv(argv)
            .map_err(|e| anyhow!("ac_del_allow_argv({}) failed: {}", argv, e))
    }

    pub fn clear_allow_all(&self) -> Result<()> {
        self.control.clear_all()
    }

    // ---- HIPS 阻断规则（blocklist） ----
    // 规则内容为 JSON 文件路径，内核按 json 配置下发 exe/cmd/stdin/stdout 多维规则。

    pub fn set_block_exe_argv(&self, json_cfg_path: &str) -> Result<()> {
        self.control
            .ac_set_block_exe_argv(json_cfg_path)
            .map_err(|e| anyhow!("ac_set_block_exe_argv({}) failed: {}", json_cfg_path, e))
    }

    pub fn set_block_md5(&self, json_cfg_path: &str) -> Result<()> {
        self.control
            .ac_set_block_md5(json_cfg_path)
            .map_err(|e| anyhow!("ac_set_block_md5({}) failed: {}", json_cfg_path, e))
    }

    pub fn set_block_dns(&self, json_cfg_path: &str) -> Result<()> {
        self.control
            .ac_set_block_dns(json_cfg_path)
            .map_err(|e| anyhow!("ac_set_block_dns({}) failed: {}", json_cfg_path, e))
    }

    // ---- 自保护 ----

    pub fn enable_self_protection(&self) -> Result<()> {
        self.control.self_protection_enable()
    }

    pub fn disable_self_protection(&self) -> Result<()> {
        self.control.self_protection_disable()
    }

    // ---- 端口扫描（PSAD） ----

    pub fn enable_psad(&self) -> Result<()> {
        self.control.psad_enable()
    }

    pub fn add_psad_ipv4_allowlist(&self, iplist: &Vec<String>) -> Result<()> {
        self.control.psad_add_allowlist_ipv4(iplist)
    }

    pub fn add_psad_ipv6_allowlist(&self, iplist: &Vec<String>) -> Result<()> {
        self.control.psad_add_allowlist_ipv6(iplist)
    }

    // ---- 应用编译期静态白名单 ----

    pub fn apply_static_allowlist(&self) -> Result<()> {
        for exe in EXE_WHITELIST {
            let s = std::str::from_utf8(exe).map_err(|e| anyhow!("invalid EXE_WHITELIST utf8: {}", e))?;
            if !s.is_empty() {
                self.add_allow_exe(s)?;
            }
        }
        for argv in ARGV_WHITELIST {
            let s = std::str::from_utf8(argv).map_err(|e| anyhow!("invalid ARGV_WHITELIST utf8: {}", e))?;
            if !s.is_empty() {
                self.add_allow_argv(s)?;
            }
        }
        Ok(())
    }
}

impl Drop for Kmod {
    fn drop(&mut self) {
        // SmithControl 自身的 Drop 会调用 ac_fini(RING_KMOD)，无需额外卸载。
        info!("kmod control released");
    }
}

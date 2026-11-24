pub mod config;
pub mod kmod;
pub mod event;
// pub mod transformer; // v1.7 文本解析器（\x1e 分隔），已被 v1.9 二进制 sd_event 解析器取代；
//                        // 待实现 src/event.rs，schema（transformer/schema.rs 字段名映射）可复用。
// pub mod utils; // v1.7 模块下载逻辑（ureq/sha2/hex），v1.9 暂无模块自加载（离线 install.sh 直接 insmod），
//                 // 已移除以避免 ureq→url→idna 的 edition-2024 依赖链（CentOS7/Rust1.74 无法解析）。

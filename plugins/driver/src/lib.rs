pub mod config;
pub mod kmod;
pub mod event;
// pub mod transformer; // v1.7 文本解析器（\x1e 分隔），已被 v1.9 二进制 sd_event 解析器取代；
//                        // 待实现 src/event.rs，schema（transformer/schema.rs 字段名映射）可复用。
pub mod utils;

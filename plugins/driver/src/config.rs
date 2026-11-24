use std::collections::HashSet;
use lazy_static::lazy_static;
use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpRange;

// Kernel module release version from driver/LKM/include/kprobe.h. RingSlot ABI is v1.9.
pub const KMOD_VERSION: &str = "3.0.0.7";
pub const KMOD_NAME: &str = "elkeid";

// v1.9 控制接口：sysfs 参数文件（取代 /proc/elkeid-endpoint 与 /dev/hids_driver_allowlist）
pub const CONTROL_PATH: &str = "/sys/module/elkeid/parameters/control_trace";

// v1.7 遗留接口（仅保留作参考，v1.9 不再使用）
pub const PIPE_PATH: &str = "/proc/elkeid-endpoint";

// ringslot 常量（须与 driver/rust/src/bindings.rs 保持一致；该 crate 未 re-export）
pub const RING_KMOD_V1_9: i32 = 0x5254194B; // elkeid
pub const RING_KMOD_V1_8: i32 = 0x5254184B; // smith
pub const RING_KMOD_V1_7: i32 = 0x5254174B; // hids_driver

// 访问控制类型（allowlist 放行 / blocklist 阻断）
pub const AL_TYPE_ARGV: i32 = 0xA1;
pub const AL_TYPE_EXE: i32 = 0xA2;
pub const AL_TYPE_PSAD: i32 = 0xA3;
pub const AL_EBPF_ARGV: i32 = 0xAA;
pub const AL_EBPF_EXE: i32 = 0x0AE; // 0xAE
pub const BL_JSON_DNS: i32 = 0xB0;
pub const BL_JSON_EXE: i32 = 0xB1;
pub const BL_JSON_MD5: i32 = 0xB2;

// 模块参数开关路径
pub const PARAM_PROTECTOR_SWITCH: &str = "/sys/module/elkeid/parameters/protector_switch";
pub const PARAM_PSAD_SWITCH: &str = "/sys/module/elkeid/parameters/psad_switch";
pub const PARAM_PSAD_FLAGS: &str = "/sys/module/elkeid/parameters/psad_flags";

// 内核模块 .ko 下载源（v1.9 模块名为 elkeid）
pub const DOWNLOAD_HOSTS: &'static [&'static str] = &[
    "https://lf3-elkeid.bytetos.com/obj/elkeid-download/ko/",
    "https://lf6-elkeid.bytetos.com/obj/elkeid-download/ko/",
    "https://lf9-elkeid.bytetos.com/obj/elkeid-download/ko/",
    "https://lf26-elkeid.bytetos.com/obj/elkeid-download/ko/",
];

// 编译期静态白名单（放行，前缀匹配；长度 ≤ 128）
pub const EXE_WHITELIST: &[&[u8]] = &[];
pub const ARGV_WHITELIST: &[&[u8]] = &[];
pub const DNS_SUFFIX_WHITELIST: &[&[u8]] = &[];

lazy_static! {
    pub static ref IPV4_FILTER: IpRange<Ipv4Net> = {
        let mut r = IpRange::new();
        r.add("127.0.0.1/8".parse().unwrap());
        r
    };
    pub static ref IPV6_FILTER: IpRange<Ipv6Net> = {
        let mut r = IpRange::new();
        r.add("fe80::/10".parse().unwrap())
            .add("::ffff:127.0.0.1/104".parse().unwrap())
            .add("::1/128".parse().unwrap());
        r
    };
    pub static ref PGID_ARGV_WHITELIST: HashSet<&'static [u8]> = HashSet::new();
    pub static ref PPID_ARGV_WHITELIST: HashSet<&'static [u8]> = HashSet::new();
}

#[allow(unused_macros)]
macro_rules! trace {
    ($fmt:expr) => {{ crate::logging::trace($fmt); }};
    ($fmt:expr, $($args:tt)*) => {{ crate::logging::trace(format_args!($fmt, $($args)*).as_str().unwrap_or_default()); }};
}

#[allow(unused_macros)]
macro_rules! debug {
    ($fmt:expr) => {{ crate::logging::debug($fmt); }};
    ($fmt:expr, $($args:tt)*) => {{ crate::logging::debug(format_args!($fmt, $($args)*).as_str().unwrap_or_default()); }};
}

#[allow(unused_macros)]
macro_rules! info {
    ($fmt:expr) => {{ crate::logging::info($fmt); }};
    ($fmt:expr, $($args:tt)*) => {{ crate::logging::info(format_args!($fmt, $($args)*).as_str().unwrap_or_default()); }};
}

#[allow(unused_macros)]
macro_rules! warn {
    ($fmt:expr) => {{ crate::logging::warn($fmt); }};
    ($fmt:expr, $($args:tt)*) => {{ crate::logging::warn(format_args!($fmt, $($args)*).as_str().unwrap_or_default()); }};
}

#[allow(unused_macros)]
macro_rules! error {
    ($fmt:expr) => {{ crate::logging::error($fmt); }};
    ($fmt:expr, $($args:tt)*) => {{ crate::logging::error(format_args!($fmt, $($args)*).as_str().unwrap_or_default()); }};
}

#[allow(unused)]
pub fn trace(s: &str) {
    log("TRACE", s);
}

#[allow(unused)]
pub fn debug(s: &str) {
    log("DEBUG", s);
}

#[allow(unused)]
pub fn info(s: &str) {
    log("INFO", s);
}

#[allow(unused)]
pub fn warn(s: &str) {
    log("WARN", s);
}

#[allow(unused)]
fn error(s: &str) {
    log("ERROR", s);
}


fn log(_level: &str, _msg: &str) {

    // only works on speculos, logs are lost by default
    #[cfg(feature = "speculos")]
    {
        use nanos_sdk::debug_print;
        debug_print("[");
        debug_print(_level);
        debug_print("]");
        debug_print(_msg);
        debug_print("\n");
    }
}

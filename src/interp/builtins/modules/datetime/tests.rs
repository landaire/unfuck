use super::*;
use crate::interp::vm::ModuleCode;
use crate::interp::vm::ModuleSource;
use crate::interp::vm::VmConfig;

struct NoModules;

impl ModuleSource for NoModules {
    fn find(&self, _name: &str) -> Option<ModuleCode> {
        None
    }
}

fn vm() -> Vm {
    match Vm::new(VmConfig::windows_x64(), Box::new(NoModules)) {
        Ok(vm) => vm,
        Err(_) => panic!("interpreter bootstrap failed"),
    }
}

/// `datetime.<class_name>.fromtimestamp(timestamp)`, as the repr of the
/// result or the exception.
fn fromtimestamp(vm: &Vm, class_name: &str, timestamp: f64) -> String {
    let module = vm.import_module("datetime").expect("datetime imports");
    let class = vm.getattr_str(&module, class_name).expect("class exists");

    match vm.call_method(&class, "fromtimestamp", vec![Value::Float(timestamp)]) {
        Ok(value) => vm.repr_text(&value).expect("repr"),
        Err(Signal::Raise(error)) => vm.describe_exception(&error),
        Err(Signal::Halt(halt)) => format!("halt: {halt}"),
    }
}

/// The CRT `localtime` of CPython 2.7.12 for Windows x64 rejects times
/// before the epoch and after 3000-12-31 23:59:59 whatever the time zone.
#[test]
fn local_timestamps_outside_the_crt_range_raise() {
    let vm = vm();
    let datetime_error = "ValueError: timestamp out of range for platform localtime()/gmtime() function";
    let date_error = "ValueError: timestamp out of range for platform localtime() function";

    for timestamp in [-1.0, -0.5, -1e9, 32_535_244_800.0, 1e12] {
        assert_eq!(fromtimestamp(&vm, "datetime", timestamp), datetime_error, "{timestamp}");
    }
    for timestamp in [-1.0, -1e9, 32_535_244_800.0, 1e12] {
        assert_eq!(fromtimestamp(&vm, "date", timestamp), date_error, "{timestamp}");
    }

    // In range, the local fields depend on the host time zone.
    for timestamp in [0.0, 0.5, 32_535_244_799.5] {
        assert!(fromtimestamp(&vm, "datetime", timestamp).starts_with("<unknown"), "{timestamp}");
    }
    for timestamp in [-0.5, 0.0, 32_535_244_799.0] {
        assert!(fromtimestamp(&vm, "date", timestamp).starts_with("<unknown"), "{timestamp}");
    }
}

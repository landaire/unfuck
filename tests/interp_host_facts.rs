//! Host facts supplied through `VmConfig::host` reach the modules that
//! report them.

use unfuck::interp::HostFacts;
use unfuck::interp::HostTimeZone;
use unfuck::interp::ModuleCode;
use unfuck::interp::ModuleSource;
use unfuck::interp::Vm;
use unfuck::interp::VmConfig;

struct NoModules;

impl ModuleSource for NoModules {
    fn find(&self, _name: &str) -> Option<ModuleCode> {
        None
    }
}

fn attribute_repr(vm: &Vm, module: &str, name: &str) -> String {
    let Ok(module) = vm.import_module(module) else {
        return format!("import of {module} failed");
    };
    let Ok(value) = vm.getattr_str(&module, name) else {
        return format!("{name} is not bound");
    };

    vm.repr_text(&value).unwrap_or_else(|_| "repr failed".to_owned())
}

fn vm(host: HostFacts) -> Vm {
    let mut config = VmConfig::windows_x64();
    config.host = host;

    match Vm::new(config, Box::new(NoModules)) {
        Ok(vm) => vm,
        Err(_) => panic!("interpreter bootstrap failed"),
    }
}

#[test]
fn builtin_module_names_are_sorted_host_names() {
    let host = HostFacts { builtin_module_names: Some(vec!["zlib".to_owned(), "_socket".to_owned(), "Zeta".to_owned(), "sys".to_owned()]), ..HostFacts::default() };

    assert_eq!(attribute_repr(&vm(host), "sys", "builtin_module_names"), "('Zeta', '_socket', 'sys', 'zlib')");
}

#[test]
fn time_zone_comes_from_the_host() {
    let zone = HostTimeZone { timezone: 28800, daylight: 1, tzname: [b"Pacific Standard Time".to_vec(), b"Pacific Daylight Time".to_vec()] };
    let vm = vm(HostFacts { time_zone: Some(zone), ..HostFacts::default() });

    assert_eq!(attribute_repr(&vm, "time", "timezone"), "28800");
    assert_eq!(attribute_repr(&vm, "time", "altzone"), "25200");
    assert_eq!(attribute_repr(&vm, "time", "daylight"), "1");
    assert_eq!(attribute_repr(&vm, "time", "tzname"), "('Pacific Standard Time', 'Pacific Daylight Time')");
}

#[test]
fn time_zone_is_unknown_by_default() {
    let vm = vm(HostFacts::default());

    assert!(attribute_repr(&vm, "time", "timezone").contains("unknown"));
}

#[test]
fn sys_version_comes_from_the_host() {
    let text = "2.7.12 (default, Jun 10 2026, 09:13:26) [MSC v.1934 64 bit (AMD64)]";
    let vm = vm(HostFacts { sys_version: Some(text.to_owned()), ..HostFacts::default() });

    assert_eq!(attribute_repr(&vm, "sys", "version"), format!("'{text}'"));
    assert_eq!(attribute_repr(&vm, "sys", "hexversion"), "34016496");
    assert_eq!(attribute_repr(&vm, "sys", "version_info"), "sys.version_info(major=2, minor=7, micro=12, releaselevel='final', serial=0)");
    assert_eq!(attribute_repr(&vm, "sys", "_mercurial"), "('CPython', '', '')");
}

#[test]
fn sys_version_is_unknown_by_default() {
    let vm = vm(HostFacts::default());

    assert!(attribute_repr(&vm, "sys", "version").contains("unknown"));
}

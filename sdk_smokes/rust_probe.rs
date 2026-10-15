use abstraction_facade_config::ConfigMachine;
use abstraction_facade_native::{self as native, Scope};
use std::{env, time::{Duration, Instant}};

fn main() {
    if env::args_os().len() != 3 {
        eprintln!("usage: rust_probe EXPECTED_SID EXPECTED_PROGRAM");
        std::process::exit(2);
    }
    if env::var_os("ABSTRACTION_RUNTIME_ENDPOINT").is_some() {
        eprintln!("FAIL rust installed SDK smoke: ABSTRACTION_RUNTIME_ENDPOINT must be unset");
        std::process::exit(1);
    }

    let result = (|| -> Result<(), String> {
        let mut args = env::args().skip(1);
        let expected_sid = args.next().ok_or("missing expected SID")?;
        let expected_program = args.next().ok_or("missing expected program")?;
        let selected = abstraction_ipc::select_runtime(Instant::now() + Duration::from_secs(5), None)
            .map_err(|error| format!("installed runtime selection failed: {error}"))?;
        if selected.principal_kind != 1
            || selected.principal != expected_sid
            || selected.program != expected_program
        {
            return Err("installed runtime identity differs from expected Windows SID/program".into());
        }

        let editor = native::discover()
            .resolve_config_editor(vec![], Scope::Local)
            .map_err(|error| format!("default config editor resolution failed: {error:?}"))?;
        match editor.read_user() {
            Ok(snapshot) if !snapshot.revision.is_empty() => {
                println!("PASS Rust installed selection, default discovery and config ReadUser");
                Ok(())
            }
            Ok(_) => Err("ReadUser returned an empty revision".into()),
            Err(error) => Err(format!("ReadUser failed: {error:?}")),
        }
    })();

    if let Err(error) = result {
        eprintln!("FAIL rust installed SDK smoke: {error}");
        std::process::exit(1);
    }
}

pub enum ProgressMode {
    Init,
    InitProxy,
    Update,
    Validation,
    BytecodeCheck,
    GenerateBuildCache,
    ListEvents,
}

pub fn print_progress(s: &str, i: &mut u64, pm: &ProgressMode) {
    use console::style;
    let total = match pm {
        ProgressMode::InitProxy => 14,
        ProgressMode::Init => 12,
        ProgressMode::Update => 4,
        ProgressMode::Validation => 5,
        ProgressMode::BytecodeCheck => 3,
        ProgressMode::GenerateBuildCache => 1,
        ProgressMode::ListEvents => 1,
    };
    println!("{} {}", style(format!("[{i:2}/{total:2}]")).bold().dim(), s);
    *i += 1;
}

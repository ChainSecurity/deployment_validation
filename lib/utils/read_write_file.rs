use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn list_files(outputs_path: &Path, aux_files: &mut Vec<String>) {
    if outputs_path.is_dir() {
        for entry in outputs_path.read_dir().expect("read_dir failed").flatten() {
            list_files(entry.path().as_path(), aux_files);
        }
    } else {
        aux_files.push(outputs_path.to_str().unwrap().to_string());
    }
}

pub fn read_file(json_path: &Path) -> String {
    let mut file = File::open(json_path).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Could not read file");

    data
}

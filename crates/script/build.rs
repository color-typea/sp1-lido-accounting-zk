use std::{path::PathBuf, process::Command};

use sp1_helper::build_program;

fn build_contract_abi(rel_path: &str) {
    let constracts_dir_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel_path);
    let constracts_dir = constracts_dir_path_buf.as_path();
    println!("Building contracts in {:#?}", constracts_dir.as_os_str());

    let mut command = Command::new("forge");
    command.arg("build").current_dir(constracts_dir);
    command.status().expect("Failed to forge build");

    let dirs = vec![
        constracts_dir.join("src"),
        constracts_dir.join("lib"),
        constracts_dir.join("out"), // this is a bit strange, but this line actually make it work
        constracts_dir.join("foundry.toml"),
    ];
    for dir in dirs {
        if dir.exists() {
            println!("cargo::rerun-if-changed={}", dir.canonicalize().unwrap().display());
        }
    }
}

fn build_program_wrapper(rel_path: &str) {
    let abs_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel_path);
    println!("cargo::rerun-if-changed={}", abs_path.canonicalize().unwrap().display());
    // build_program(rel_path);
    let target_name = "sp1-lido-accounting-zk-program";
    let elf_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/elf-compilation/riscv32im-succinct-zkvm-elf/release/")
        .join(target_name);
    println!("cargo:rustc-env=SP1_ELF_{}={}", target_name, elf_path.to_string_lossy());
}

fn main() {
    print!("Running custom build commands");
    build_contract_abi("../../contracts");
    build_contract_abi("../../test_contracts");
    build_program_wrapper("../program");
    println!("Custom build successful");
}

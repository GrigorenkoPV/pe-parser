use pe_parser::{err_to_string, is_pe, read_all};
use std::{env, fs::File, io, process::exit};

enum Mode {
    IsPe { filepath: Option<String> },
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Mode, String> {
    use Mode::*;
    match args.nth(1) {
        Some(mode) => {
            match &*mode {
                "is-pe" => Ok(IsPe {
                    filepath: args.next(),
                }),
                _ => Err("Unknown mode: usage".to_string()), //todo
            }
        }
        None => Err("No mode: usage".to_string()), //todo
    }
}

fn run() -> Result<(), String> {
    match parse_args(env::args())? {
        Mode::IsPe { filepath } => {
            let data = if let Some(filepath) = filepath {
                read_all(File::open(filepath).map_err(err_to_string)?)?
            } else {
                read_all(io::stdin())?
            };
            if is_pe(&data) {
                println!("PE");
                exit(0);
            } else {
                println!("Not PE");
                exit(1);
            }
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        exit(-1);
    }
}

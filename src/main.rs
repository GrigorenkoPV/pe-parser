use pe_parser::{err_to_string, is_pe, read_all};
use std::{env, fs::File, io, process::exit};

const USAGE: &str = "\
Usage:
    pe-parser <command> [infile]

If no infile provided, reads from stdin.

Commands:
    is-pe
        Validate the PE signature starting at [0x3C].
    help, --help, -h
        Display this help message.";

enum Command {
    NoCommand,
    IsPe { filepath: Option<String> },
    Help,
    Unknown(String),
}
use Command::*;

fn parse_args(mut args: impl Iterator<Item = String>) -> Command {
    args.nth(1)
        .map(|mode| match &*mode {
            "is-pe" => IsPe {
                filepath: args.next(),
            },
            "help" | "--help" | "-h" => Help,
            _ => Unknown(mode),
        })
        .unwrap_or(NoCommand)
}

fn run() -> Result<i32, String> {
    match parse_args(env::args()) {
        NoCommand => Err(format!("No command provided.\n{}", USAGE)),
        IsPe { filepath } => {
            let data = if let Some(filepath) = filepath {
                read_all(File::open(filepath).map_err(err_to_string)?)?
            } else {
                read_all(io::stdin())?
            };
            if is_pe(&data) {
                println!("PE");
                Ok(0)
            } else {
                println!("Not PE");
                Ok(1)
            }
        }
        Help => {
            println!("{}", USAGE);
            Ok(0)
        }
        Unknown(command) => Err(format!("Unknown command: \"{}\".\n{}", command, USAGE)),
    }
}

fn main() -> ! {
    match run() {
        Ok(return_code) => exit(return_code),
        Err(e) => {
            eprintln!("{}", e);
            exit(-1);
        }
    }
}

use pe_parser::{err_to_string, import_functions, is_pe, read_all, Res};
use std::{env, fs::File, io, process::exit};

const USAGE: &str = "\
Usage:
    pe-parser <command> [infile]

If no infile provided, reads from stdin.

Commands:
    is-pe
        Validate the PE signature starting at [0x3C].
    import-functions
        Print the list of dll's that the given PE imports
    help, --help, -h
        Display this help message.";

enum Command {
    NoCommand,
    IsPe { filepath: Option<String> },
    ImportFunctions { filepath: Option<String> },
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
            "import-functions" => ImportFunctions {
                filepath: args.next(),
            },
            "help" | "--help" | "-h" => Help,
            _ => Unknown(mode),
        })
        .unwrap_or(NoCommand)
}

fn read_from_file_or_stdin(filepath: Option<String>) -> Res<Vec<u8>> {
    Ok(if let Some(filepath) = filepath {
        read_all(File::open(filepath).map_err(err_to_string)?)?
    } else {
        read_all(io::stdin())?
    })
}

fn run() -> Res<i32> {
    match parse_args(env::args()) {
        NoCommand => Err(format!("No command provided.\n{}", USAGE)),
        IsPe { filepath } => {
            if is_pe(&read_from_file_or_stdin(filepath)?) {
                println!("PE");
                Ok(0)
            } else {
                println!("Not PE");
                Ok(1)
            }
        }
        ImportFunctions { filepath } => {
            for entry in import_functions(&read_from_file_or_stdin(filepath)?)? {
                println!("{}", entry)
            }
            Ok(0)
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

use std::{fs::File, io, path::PathBuf, process::exit};

use anyhow::{Context, Result};
use clap::Parser;

mod cli;

use pe_parser::{export_functions, import_functions, is_pe, read_all};

fn read_from_file_or_stdin(filepath: Option<PathBuf>) -> Result<Vec<u8>> {
    if let Some(filepath) = filepath {
        let file =
            File::open(&filepath).with_context(|| format!("Error opening {:?}", filepath))?;
        read_all(file).with_context(|| format!("Error reading from {:?}", filepath))
    } else {
        read_all(io::stdin()).context("Error reading from stdin")
    }
}

fn run(arguments: cli::Cli) -> Result<i32> {
    use cli::Subcommands::*;
    match arguments.subcommand {
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
            let result = import_functions(&read_from_file_or_stdin(filepath)?)?;
            for (library_name, function_names) in result {
                println!("{}", library_name);
                for function_name in function_names {
                    println!("    {}", function_name);
                }
            }
            Ok(0)
        }
        ExportFunctions { filepath } => {
            let result = export_functions(&read_from_file_or_stdin(filepath)?)?;
            for function_name in result {
                println!("{}", function_name);
            }
            Ok(0)
        }
    }
}

fn main() -> ! {
    match run(cli::Cli::parse()) {
        Ok(return_code) => exit(return_code),
        Err(e) => {
            eprintln!("{:?}", e);
            exit(-1);
        }
    }
}

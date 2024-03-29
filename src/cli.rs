use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about)]
#[command(
    help_expected = true,
    propagate_version = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Subcommand)]
pub enum Subcommands {
    /// Check that the file has PE magic numbers
    #[command(name = "is-pe", author, version)]
    IsPe {
        /// Path to PE file (if none, reads from stdin)
        filepath: Option<PathBuf>,
    },

    /// List out functions imported by a PE
    #[command(name = "import-functions", author, version)]
    ImportFunctions {
        /// Path to PE file (if none, reads from stdin)
        filepath: Option<PathBuf>,
    },

    /// List out functions exported by a PE
    #[command(name = "export-functions", author, version)]
    ExportFunctions {
        /// Path to PE file (if none, reads from stdin)
        filepath: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(author, version, about)]
#[clap(
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
    /// TODO: about
    #[clap(name = "is-pe", author, version)]
    IsPe {
        /// Path to PE file (if none, reads from stdin)
        filepath: Option<PathBuf>,
    },

    /// TODO: about
    #[clap(name = "import-functions", author, version)]
    ImportFunctions {
        /// Path to PE file (if none, reads from stdin)
        filepath: Option<PathBuf>,
    },

    /// TODO: about
    #[clap(name = "export-functions", author, version)]
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
        use clap::IntoApp;
        Cli::command().debug_assert();
    }
}

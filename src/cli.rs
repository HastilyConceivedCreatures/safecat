use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "Safecat")]
#[command(version = "0.0.5")]
#[command(about = include_str!("safecat.txt"), subcommand_required = true, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generates a private key
    Generate,

    /// Shows keys
    ShowKeys {
        #[arg(long, value_parser = ["detailed", "hex"], default_value = "detailed")]
        format: String,
    },

    /// Sign a message using BabyJubJub
    Sign {
        #[arg(long, value_parser = ["poseidon", "sha256"], default_value = "poseidon")]
        hash: String,
        #[arg(long, value_parser = ["detailed", "hex"], default_value = "detailed")]
        format: String,
        message: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        _args: Vec<String>,
    },

    /// Sign BabyJubJub field element
    SignField {
        #[arg(long, value_parser = ["detailed", "hex"], default_value = "detailed")]
        format: String,
        field: String,
    },

    /// Verify a message using BabyJubJub
    Verify {
        #[arg(long, value_parser = ["poseidon", "sha256"], default_value = "poseidon")]
        hash: String,
        message: String,
        signature: String,
        public_key: String,
    },

    /// Show existing certificates
    ShowCerts {
        #[arg(value_parser = ["created", "received"])]
        certificates_folder: String,
    },

    /// Create a certification from an assertation
    Attest {
        #[arg(long, value_parser = ["babyjubjub", "babyjubjub-evmaddres", "babyjubjub-woolball"], default_value = "babyjubjub")]
        certificate_type: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        _args: Vec<String>,
    },
}

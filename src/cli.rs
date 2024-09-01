use crate::{ansi_cat::AnsiCat, io_utils};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "Safecat")]
#[command(version = "0.0.5")]
#[command(about = cat_is_talking_now(), subcommand_required = true, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generates a new private key.
    Generate,

    /// Displays the keys in the specified format.
    ShowKeys {
        /// Format to display the keys ("detailed" or "hex"). Default is "detailed".
        #[arg(long, value_parser = ["detailed", "hex"], default_value = "detailed")]
        format: String,
    },

    /// Signs a message using the EdDSA scheme with the BabyJubJub curve.
    Sign {
        /// Format to display the signature ("detailed" or "hex"). Default is "detailed".
        #[arg(long, value_parser = ["detailed", "hex"], default_value = "detailed")]
        format: String,

        /// The message to sign.
        message: String,

        /// Additional arguments (supports trailing and hyphen-prefixed values).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        _args: Vec<String>,
    },

    /// Signs a BabyJubJub field element with EdDSA scheme.
    SignField {
        /// Format to display the signature ("detailed" or "hex"). Default is "detailed".
        #[arg(long, value_parser = ["detailed", "hex"], default_value = "detailed")]
        format: String,

        /// The field element to sign.
        field: String,
    },

    /// Verifies a message signature using the BabyJubJub signature scheme.
    Verify {
        /// The message to verify.
        message: String,

        /// The signature to verify, in hex format.
        signature: String,

        /// The public key to verify against, in hex format.
        public_key: String,
    },

    /// Creates a certification from an assertion.
    ///
    /// The certificate definition should be a `.toml` file located in the
    /// `data/certificate-formats/` directory.
    Attest {
        /// Specifies the type of certificate. Default is "babyjubjub".
        #[arg(long, default_value = "babyjubjub")]
        certificate_type: String,

        /// Additional arguments (supports trailing and hyphen-prefixed values).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        _args: Vec<String>,
    },

    /// Proves you're a unique human (or alien) to someone.
    Prove {
        /// What to prove ("human" or "alien"). Default is "human".
        #[arg(long, value_parser = ["human", "alien"], default_value = "human")]
        what: String,

        /// To whom to prove your uniqueness.
        #[arg(long, default_value = "")]
        to_whom: String,
    },
}

/// Loads an ANSI cat and makes it say a random sentence from a file.
fn cat_is_talking_now() -> &'static str {
    let cat = AnsiCat::load("src/ansi_cat/ansi_cat.ansi".to_string()).unwrap();
    let sentence = io_utils::read_random_line("src/ansi_cat/help_sentences.txt").unwrap();
    cat.talk(9, 2, sentence)
}

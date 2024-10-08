mod ansi_cat;
mod cast; // module for casting between types
mod cli;
mod commands;
mod consts;
mod crypto_structures;
mod io_utils;
mod serialization;

use clap::Parser; // Command Line Argument Parser
use cli::{Cli, Commands};

// Type alias for a boxed dynamic error trait object, accessible within the crate.
pub(crate) type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Match the subcommand and execute the corresponding logic
    match &cli.command {
        Commands::Generate => {
            commands::generate::generate(consts::DATA_DIR, consts::PRIVATE_KEY_FILENAME)?
        }
        Commands::ShowKeys { format } => {
            commands::show_keys::show_keys(consts::DATA_DIR, consts::PRIVATE_KEY_FILENAME, format)?
        }
        Commands::Sign {
            format,
            message,
            _args,
        } => {
            println!("Signing {}", message);
            commands::sign::sign_and_print_message(message.to_string(), format.to_string())?
        }
        Commands::SignField { format, field } => {
            println!("Signing field element: {}", field);
            commands::sign::sign_and_print_babyjubjub_fq(field.to_string(), format.to_string())?
        }
        Commands::Verify {
            message,
            signature,
            public_key,
        } => {
            println!("Verifying {}", message);
            commands::sign::verify_signature(
                message.to_string(),
                signature.to_string(),
                public_key.to_string(),
            )?
        }
        Commands::Attest { format, _args } => {
            commands::attest::attest(format.to_string())?;
        }
        Commands::Prove {
            cert_format,
            proof_format,
            no_execute,
        } => {
            commands::prove::prove(cert_format, proof_format, *no_execute)?;
        }
    }

    Ok(())
}

mod actions;
mod bn254_scalar_cast;
mod cast; // module for casting between types
mod certificate;
mod cli;
mod consts;
mod io_utils;

use clap::Parser; // Command Line Argument Parser
use cli::{Cli, Commands};

pub(crate) type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Match the subcommand and execute the corresponding logic
    match &cli.command {
        Commands::Generate => actions::generate("priv.key")?,
        Commands::ShowKeys { format } => actions::show_keys(format.to_string())?,
        Commands::Sign {
            hash,
            format,
            message,
            _args,
        } => {
            println!("Signing {}", message);
            actions::sign(message.to_string(), hash.to_string(), format.to_string())
        }
        Commands::SignField { format, field } => {
            println!("Signing field element: {}", field);
            actions::sign_field(field.to_string(), format.to_string())
        }
        Commands::Verify {
            hash,
            message,
            signature,
            public_key,
        } => {
            println!("Verifying {}", message);
            actions::verify_signature(
                message.to_string(),
                signature.to_string(),
                public_key.to_string(),
                hash.to_string(),
            )?
        }
        Commands::ShowCerts {
            certificates_folder,
        } => {
            let certificates_folder_path;
            if certificates_folder == "created" {
                certificates_folder_path = "certs/created";
            } else {
                certificates_folder_path = "certs/received"
            }
            io_utils::show_certs(certificates_folder_path)
                .map_err(|e| format!("Error showing certificates: {}", e))?;
        }
        Commands::Attest {
            certificate_type,
            _args,
        } => {
            actions::attest(certificate_type.to_string());
        }
    }

    Ok(())
}

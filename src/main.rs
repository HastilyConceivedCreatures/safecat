mod actions;
mod bn254_scalar_cast;
mod cast; // module for casting between types
mod cli;
mod consts;
mod io_utils;

use clap::Parser; // Command Line Argument Parser
use cli::{Cli, Commands};

pub(crate) type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Parse command-line arguments using the configured CLI structure
    // let matches = cli;

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
        Commands::Assert { address } => {
            actions::attest(
                address.to_string(),
                2,
                2026572347,
                1048568083,
                "poseidon".to_string(),
                "field".to_string(),
            )?;
        }
    }

    Ok(())
}

// // CLI configuration function
// fn cli() -> Command {
//     let safecat_ascii = include_str!("safecat.txt");

//     // Create the top-level 'safecat' command
//     let mut cmd = Command::new("safecat")
//         .about(safecat_ascii)
//         .subcommand_required(true) // Subcommand is required
//         .arg_required_else_help(true) // At least one argument is required
//         .subcommand(
//             Command::new("generate")
//                 .about("Generates a private key")
//                 .trailing_var_arg(true),
//         )
//         .subcommand(
//             Command::new("show-keys").about("Shows keys").arg(
//                 arg!(--"format" <FORMAT>)
//                     .value_parser(["detailed", "hex"])
//                     .require_equals(false)
//                     .default_missing_value("detailed")
//                     .default_value("detailed"),
//             ),
//         )
//         .subcommand(
//             Command::new("sign")
//                 .about("Sign a message using BabyJubJub")
//                 .arg(
//                     arg!(--"hash" <HASH>)
//                         .value_parser(["poseidon", "sha256"])
//                         .require_equals(false)
//                         .default_missing_value("poseidon")
//                         .default_value("poseidon"),
//                 )
//                 .arg(
//                     arg!(--"format" <FORMAT>)
//                         .value_parser(["detailed", "hex"])
//                         .require_equals(false)
//                         .default_missing_value("detailed")
//                         .default_value("detailed"),
//                 )
//                 .arg_required_else_help(true)
//                 .arg(
//                     arg!(<MESSAGE> "message")
//                         .require_equals(true)
//                         .trailing_var_arg(true),
//                 ),
//         )
//         .subcommand(
//             Command::new("sign-field")
//                 .about("Sign BabyJubJub field element")
//                 .arg(
//                     arg!(--"format" <FORMAT>)
//                         .value_parser(["detailed", "hex"])
//                         .require_equals(false)
//                         .default_missing_value("detailed")
//                         .default_value("detailed"),
//                 )
//                 .arg_required_else_help(true)
//                 .arg(arg!(<FIELD> "field").require_equals(true)),
//         )
//         .subcommand(
//             Command::new("verify")
//                 .about("Verify a message using BabyJubJub")
//                 .arg(
//                     arg!(--"hash" <HASH>)
//                         .value_parser(["poseidon", "sha256"])
//                         .require_equals(false)
//                         .default_missing_value("poseidon")
//                         .default_value("poseidon"),
//                 )
//                 .arg_required_else_help(true)
//                 .arg(arg!(<MESSAGE> "message").require_equals(true))
//                 .arg(arg!(<SIGNATURE> "signature").require_equals(true))
//                 .arg(arg!(<PUBLICKEY> "public key").require_equals(true)),
//         )
//         .subcommand(
//             Command::new("show-certs")
//                 .about("Show existing certificates")
//                 .arg_required_else_help(true)
//                 .arg(
//                     arg!(<CERTIFICATES_FOLDER> "certificates folder")
//                         .value_parser(["created", "received"])
//                         .require_equals(true),
//                 ),
//         );

//     // Separately handle the attest command since it has more options than others
//     let mut attest_cmd = Command::new("attest")
//         .about("Creates a certificate for an assertion")
//         .subcommand_required(true);

//     // Option one: create certificate for a public key
//     let certificate_formats_birth_pubkey =
//         certificate_formats("birth-pubkey", "Birth certificate based on public key");

//     // Option two: create certificate for a blockchain address
//     let certificate_formats_birth_address =
//         certificate_formats("birth-address", "Birth certificate based on address");

//     // Option three: create certificate for public key **and** name
//     let certificate_formats_birth_pubkey_name = certificate_formats_pubkey_name();

//     // Add the two options to the attest command
//     attest_cmd = attest_cmd
//         .subcommand(certificate_formats_birth_pubkey)
//         .subcommand(certificate_formats_birth_address)
//         .subcommand(certificate_formats_birth_pubkey_name);

//     // Add the attest command to the list of commands
//     cmd = cmd.subcommand(attest_cmd);

//     let trail: Vec<_> = cmd.get_many::<String>("cmd").unwrap().collect();

//     cmd
// }

// // Creates and configures a subcommand for the "attest" command.
// // It specified args (ID, BIRTH, EXPIRATION) and output format (json/field).
// fn certificate_formats(cmd_name: &'static str, cmd_description: &'static str) -> Command {
//     let birth_cmd = Command::new(cmd_name)
//         .about(cmd_description)
//         .arg_required_else_help(true)
//         .arg(arg!(<ID> "Identity of the certificate owner, could be a private key, a blockchain address, name, identity number and so on")
//             .require_equals(true))
//         .arg(
//             arg!(<BIRTH> "birth date")
//                 .require_equals(true)
//                 .value_parser(clap::value_parser!(u64)),
//         )
//         .arg(
//             arg!(<EXPIRATION> "expiration date")
//                 .require_equals(true)
//                 .value_parser(clap::value_parser!(u64)),
//         )
//         .arg(
//             arg!(--"format" <FORMAT>)
//                 .value_parser(["json", "field"])
//                 .require_equals(false)
//                 .default_missing_value("json")
//                 .default_value("json"),
//         );

//     birth_cmd
// }

// // Creates and configures a subcommand for the "attest" command.
// // It specified args (ID, BIRTH, EXPIRATION) and output format (json/field).
// fn certificate_formats_pubkey_name() -> Command {
//     let birth_cmd = Command::new("birth-name-pubkey")
//         .about("Birth certificate based on public key and name")
//         .arg_required_else_help(true)
//         .arg(arg!(<PUBKEY> "public key of the person").require_equals(true))
//         .arg(arg!(<NAME> "name of the person").require_equals(true))
//         .arg(
//             arg!(<BIRTH> "birth date")
//                 .require_equals(true)
//                 .value_parser(clap::value_parser!(u64)),
//         )
//         .arg(
//             arg!(<EXPIRATION> "expiration date")
//                 .require_equals(true)
//                 .value_parser(clap::value_parser!(u64)),
//         )
//         .arg(
//             arg!(--"format" <FORMAT>)
//                 .value_parser(["json", "field"])
//                 .require_equals(false)
//                 .default_missing_value("json")
//                 .default_value("json"),
//         );

//     birth_cmd
// }

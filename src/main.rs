mod cast; // module for casting between types
mod consts;
mod io_utils;
mod actions;

use clap::{arg, Command}; // Command Line Argument Parser

pub(crate) type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    // Parse command-line arguments using the configured CLI structure
    let matches = cli().get_matches();

    // Match the subcommand and execute the corresponding logic
    match matches.subcommand() {
        Some(("generate", _)) => actions::generate("priv.key")?,
        Some(("show-keys", sub_matches)) => {
            let format = sub_matches
                .get_one::<String>("format")
                .expect("defaulted in clap");
            actions::show_keys(format.to_string())?
        }
        Some(("sign", sub_matches)) => {
            let msg = sub_matches.get_one::<String>("MESSAGE").expect("required");
            let format = sub_matches
                .get_one::<String>("format")
                .expect("defaulted in clap");
            let hash = sub_matches
                .get_one::<String>("hash")
                .expect("defaulted in clap");
            println!("Signing {}", msg);
            actions::sign(msg.to_string(), hash.to_string(), format.to_string())
        }
        Some(("verify", sub_matches)) => {
            let msg = sub_matches
                .get_one::<String>("MESSAGE")
                .expect("required")
                .to_string();
            let signature = sub_matches
                .get_one::<String>("SIGNATURE")
                .expect("required")
                .to_string();
            let private_key = sub_matches
                .get_one::<String>("PUBLICKEY")
                .expect("required")
                .to_string();
            let hash = sub_matches
                .get_one::<String>("hash")
                .expect("defaulted in clap")
                .to_string();
            println!("Verifying {}", msg);
            actions::verify_signature(msg, signature, private_key, hash)?
        }
        Some(("show-certs", sub_matches)) => {
            let certificates_folder = sub_matches
                .get_one::<String>("CERTIFICATES_FOLDER")
                .expect("required")
                .to_string();

            let certificates_folder_path;
            if certificates_folder == "created" {
                certificates_folder_path = "certs/created";
            } else {
                certificates_folder_path = "certs/received"
            }
            io_utils::show_certs(certificates_folder_path)
                .map_err(|e| format!("Error showing certificates: {}", e))?;
        }
        Some(("attest", sub_matches)) => {
            match sub_matches.subcommand() {
                Some(("birth-pubkey", sub_matches)) => {
                    let id = sub_matches
                        .get_one::<String>("ID")
                        .expect("required")
                        .to_string();
                    let expiration = *sub_matches.get_one("EXPIRATION").expect("required");
                    let birth = *sub_matches.get_one("BIRTH").expect("required");
                    let format = sub_matches
                        .get_one::<String>("format")
                        .expect("defaulted in clap")
                        .to_string();
                    actions::attest(
                        id,
                        1,
                        expiration,
                        birth,
                        "poseidon".to_string(),
                        format,
                    )?;
                }
                Some(("birth-address", sub_matches)) => {
                    let id = sub_matches
                        .get_one::<String>("ID")
                        .expect("required")
                        .to_string();
                    let expiration = *sub_matches.get_one("EXPIRATION").expect("required");
                    let birth = *sub_matches.get_one("BIRTH").expect("required");
                    let format = sub_matches
                        .get_one::<String>("format")
                        .expect("defaulted in clap")
                        .to_string();
                    actions::attest(
                        id,
                        2,
                        expiration,
                        birth,
                        "poseidon".to_string(),
                        format,
                    )?;
                }
                Some((_, _)) => {
                    println!("unknown subcommand of 'attest', For more information, try '--help'.")
                }
                None => todo!(),
            }
        }
        Some((_, _)) => {
            println!("unknown command, For more information, try '--help'.")
        }
        None => todo!(),
    }

    Ok(())
}

// CLI configuration function
fn cli() -> Command {
    let safecat_ascii = include_str!("safecat.txt");

    // Create the top-level 'safecat' command
    let mut cmd = Command::new("safecat")
        .about(safecat_ascii)
        .subcommand_required(true) // Subcommand is required
        .arg_required_else_help(true) // At least one argument is required
        .subcommand(Command::new("generate").about("Generates a private key"))
        .subcommand(
            Command::new("show-keys").about("Shows keys").arg(
                arg!(--"format" <FORMAT>)
                    .value_parser(["detailed", "hex"])
                    .require_equals(false)
                    .default_missing_value("detailed")
                    .default_value("detailed"),
            ),
        )
        .subcommand(
            Command::new("sign")
                .about("Sign a message using BabyJubJub")
                .arg(
                    arg!(--"hash" <HASH>)
                        .value_parser(["poseidon", "sha256"])
                        .require_equals(false)
                        .default_missing_value("poseidon")
                        .default_value("poseidon"),
                )
                .arg(
                    arg!(--"format" <FORMAT>)
                        .value_parser(["detailed", "hex"])
                        .require_equals(false)
                        .default_missing_value("detailed")
                        .default_value("detailed"),
                )
                .arg_required_else_help(true)
                .arg(arg!(<MESSAGE> "message").require_equals(true)),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a message using BabyJubJub")
                .arg(
                    arg!(--"hash" <HASH>)
                        .value_parser(["poseidon", "sha256"])
                        .require_equals(false)
                        .default_missing_value("poseidon")
                        .default_value("poseidon"),
                )
                .arg_required_else_help(true)
                .arg(arg!(<MESSAGE> "message").require_equals(true))
                .arg(arg!(<SIGNATURE> "signature").require_equals(true))
                .arg(arg!(<PUBLICKEY> "public key").require_equals(true)),
        )
        .subcommand(
            Command::new("show-certs")
                .about("Show existing certificates")
                .arg_required_else_help(true)
                .arg(
                    arg!(<CERTIFICATES_FOLDER> "certificates folder")
                        .value_parser(["created", "received"])
                        .require_equals(true),
                ),
        );

    // Separately handle the attest command since it has more options than others
    let mut attest_cmd = Command::new("attest")
        .about("Creates a certificate for an assertion")
        .subcommand_required(true);

    // Option one: create certificate for a public key
    let certificate_formats_birth_pubkey = certificate_formats(
        "birth-pubkey",
        "Birth certificate based on public key",
    );

    // Option two: create certificate for a blockchain address
    let certificate_formats_birth_address = certificate_formats(
        "birth-address",
        "Birth certificate based on address",
    );

    // Add the two options to the attest command
    attest_cmd = attest_cmd
        .subcommand(certificate_formats_birth_pubkey)
        .subcommand(certificate_formats_birth_address);

    // Add the attest command to the list of commands
    cmd = cmd.subcommand(attest_cmd);

    cmd
}

// Creates and configures a subcommand for the "attest" command. 
// It specified args (ID, BIRTH, EXPIRATION) and output format (json/field).
fn certificate_formats(cmd_name: &'static str, cmd_description: &'static str) -> Command {
    let birth_cmd = Command::new(cmd_name)
        .about(cmd_description)
        .arg_required_else_help(true)
        .arg(arg!(<ID> "Identity of the certificate owner, could be a private key, a blockchain address, name, identity number and so on")
            .require_equals(true))
        .arg(
            arg!(<BIRTH> "birth date")
                .require_equals(true)
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            arg!(<EXPIRATION> "expiration date")
                .require_equals(true)
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            arg!(--"format" <FORMAT>)
                .value_parser(["json", "field"])
                .require_equals(false)
                .default_missing_value("json")
                .default_value("json"),
        );

    birth_cmd
}
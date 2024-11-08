use super::babyjubjub;
use super::document::Format;
use crate::crypto_structures::{
    babyjubjub::{fq_to_str_hex, PubKey},
    certificate::Cert,
    document::{self, Document, DocumentField, FieldType, FieldTypeName, FormatField},
    merkle_pederson::MerklePederson,
    signature::SignatureAndSigner,
    society::{MemberSociety, Society},
};
use crate::{consts, Error};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::path::Path;
use std::{
    fs::{self, OpenOptions},
    io::Write,
};

// Represents a path in a Merkle tree
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HashPath {
    pub index: u32,
    pub path: Vec<String>,
}

// Creates an input for the proof program, represented as a Document object
pub fn create_proof_input(
    cert_format: String,
    proof_format: String,
    mut cert: Cert,
    signature_and_signer: SignatureAndSigner,
) -> Result<Document, Error> {
    // Prepare an empty vector of DocumentField to fill with the proof data
    let mut proof_input_parameters: Vec<DocumentField> = Vec::new();

    let cert_hash = babyjubjub::message_to_fq_vec(&cert.cert_type)?;

    // Create a DocumentField for certificate type
    let cert_type_field = DocumentField {
        format_field: FormatField {
            fname: "cert_type".to_string(),
            fdescription: "The type of the certificate".to_string(),
            ftype: FieldTypeName::Text,
        },
        field: FieldType::Hash(cert_hash),
    };

    // Add the certificate to the input
    proof_input_parameters.push(cert_type_field);
    proof_input_parameters.append(&mut cert.to.document_fields);
    proof_input_parameters.append(&mut cert.body.document_fields);

    // Get additional proof parameters from user
    let (society, mut proof_input_from_format) = read_proof_input(cert_format, proof_format)?;

    // Add the input from format to the vector
    proof_input_parameters.append(&mut proof_input_from_format);

    // Add signer
    let signer_cert_field = DocumentField {
        format_field: FormatField {
            fname: "signer".to_string(),
            fdescription: "Singer of the certificate".to_string(),
            ftype: FieldTypeName::BabyjubjubPubkey,
        },
        field: FieldType::BabyjubjubPubkey(signature_and_signer.signer),
    };
    proof_input_parameters.push(signer_cert_field);

    // Find the hash path of the signers of the certificate
    let (signer_society_details, soceity_root) =
        find_hash_path(signature_and_signer.signer, &society)?;

    // Add HashPath to Noir program (see explanation in function header)
    insert_hashpath_code(&signer_society_details)?;

    // Add society root
    let society_root_field = DocumentField {
        format_field: FormatField {
            fname: "society_root".to_string(),
            fdescription: "The root of the society the proof is made for".to_string(),
            ftype: FieldTypeName::Text,
        },
        field: FieldType::Text(soceity_root),
    };
    proof_input_parameters.push(society_root_field);

    // Add signature
    let signature_cert_field = DocumentField {
        format_field: FormatField {
            fname: "signature".to_string(),
            fdescription: "The certificate signature".to_string(),
            ftype: FieldTypeName::Signature,
        },
        field: FieldType::Signature(signature_and_signer.signature),
    };
    proof_input_parameters.push(signature_cert_field);

    // Add hashpath for signer
    let signer_hash_path = HashPath {
        index: signer_society_details.index,
        path: signer_society_details.path,
    };

    let hash_path_cert_field = DocumentField {
        format_field: FormatField {
            fname: "hash_path".to_string(),
            fdescription: "The hash path of the signer".to_string(),
            ftype: FieldTypeName::HashPath,
        },
        field: FieldType::HashPath(signer_hash_path),
    };
    proof_input_parameters.push(hash_path_cert_field);

    Ok(Document {
        document_fields: proof_input_parameters,
    })
}

/// Reads a format from a TOML file into a`Format` object.
pub fn read_document_format_from_toml(file_name: &str) -> Result<document::Format, Error> {
    let mut file = OpenOptions::new().read(true).open(file_name)?;

    let mut toml_string = String::new();
    file.read_to_string(&mut toml_string)?;

    let document_format: Format = toml::from_str(&toml_string)?;
    Ok(document_format)
}

/// Looks for a member Merkle tree hash path inside of society file.
/// Returns a tuple containing a society member's details and the society's root hash.
fn find_hash_path(signer: PubKey, society: &str) -> Result<(MemberSociety, String), Error> {
    // Construct societies file path
    let societies_file_path =
        consts::DATA_DIR.to_string() + "/" + consts::SOCIENTY_FOLDER + "/" + society + ".json";

    // Extract details from Cert
    let signer_id = signer.to_hex_str();

    // Read the JSON data, propagating error if the file cannot be read
    let trust_kernel_json = fs::read_to_string(&societies_file_path)
        .map_err(|_| format!("Unable to read soceity file: {}", societies_file_path))?;

    // Deserialize the JSON data into the MerklePederson struct
    let merkle_tree: MerklePederson =
        serde_json::from_str(&trust_kernel_json).map_err(|_| "JSON was not well-formatted")?;

    // Create a society from the Merkle tree
    let society = Society::from_merkle_pederson(merkle_tree);

    // Find the specified member by comparing lowercase names
    let signer_x = fq_to_str_hex(&signer.x);
    let signer_y = fq_to_str_hex(&signer.y);

    let member = society
        .members
        .iter()
        .find(|m| {
            // Remove "0x" prefix if it exists
            let cleaned_mx = m.x.trim_start_matches("0x");
            let cleaned_my = m.y.trim_start_matches("0x");

            // Compare cleaned_signer_x and cleaned_signer_y with m.x and m.y
            cleaned_mx == signer_x && cleaned_my == signer_y
        })
        .ok_or_else(|| format!("Didn't find member with ID: {}", signer_id))?;

    // Extract society root from the trust kernel
    let society_root = society.root;

    // Return the member (cloned) and the society root
    Ok((member.clone(), society_root))
}

// Read and process the proof input.
// Returns a tuple of a society in which the proof is made,
// and a vector of DocumentField.
fn read_proof_input(
    cert_format: String,
    proof_format: String,
) -> Result<(String, Vec<DocumentField>), Error> {
    // Vector to store processed proof input fields
    let mut proof_input_from_format: Vec<DocumentField> = Vec::new();

    // Default society name if not specified in the input fields
    let mut society: String = consts::DEAFULT_SOCIETY.to_string();

    // Construct path to the certificate formats folder
    let formats_folder_path = format!("{}/{}", consts::DATA_DIR, consts::CERTIFICATE_FORMATS);

    // Construct the path to the proof input format file based on cert_format and proof_format
    let proof_input_path_string = format!(
        "{}/{}/proofs/{}/proof.toml",
        formats_folder_path, cert_format, proof_format
    );

    // Construct the proof input format from the proof TOML file
    let input_format = read_document_format_from_toml(&proof_input_path_string)
        .expect("Couldn't read proof.toml file");

    // Process each field in the proof input format
    for field in input_format.fields {
        let input_field = document::process_document_field(field);

        // If the field name is "society" and of type `Text`, update the society value
        if input_field.format_field.fname == "society" {
            if let FieldType::Text(society_value) = &input_field.field {
                // Update society only if the user entered a non-empty one
                if !society_value.is_empty() {
                    society = society_value.clone();
                }
            }
        } else {
            // Add other processed fields to the proof input
            proof_input_from_format.push(input_field);
        }
    }

    // Return the society name along with the processed proof input fields
    Ok((society, proof_input_from_format))
}

// Insert the HashPath variable into the Noir code.
// This is necessary because Noir lacks support for dynamic arrays,
// and the size of the HashPath array can only be determined after locating
// the signer's details in the specified society file.
fn insert_hashpath_code(signer_society_details: &MemberSociety) -> Result<(), io::Error> {
    let temp_folder = Path::new(consts::TEMP_DIR);
    let main_nr_dst = temp_folder.join("src/main.nr");

    // Read the contents of main.nr
    let mut content = fs::read_to_string(&main_nr_dst)?;

    // Check if the line "HASHPATH_CODE_HERE" exists
    if content.contains("HASHPATH_CODE_HERE") {
        // Determine the size of the path array
        let path_size = signer_society_details.path.len();

        // Define the HashPath struct code with the appropriate size
        let hashpath_code = format!(
            "// Struct representing a hash path in a Merkle tree\n\
             struct HashPath {{\n\
             \tpath: [Field; {}],\n\
             \tindex: Field\n\
             }}",
            path_size
        );

        // Replace "HASHPATH_CODE_HERE" with the actual code
        content = content.replace("HASHPATH_CODE_HERE", &hashpath_code);

        // Write the modified content back to main.nr
        let mut file = fs::File::create(main_nr_dst)?;
        file.write_all(content.as_bytes())?;
    } else {
        println!("No 'HASHPATH_CODE_HERE' placeholder found in main.nr");
    }

    Ok(())
}

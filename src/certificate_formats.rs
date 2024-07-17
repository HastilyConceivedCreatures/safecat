use crate::crypto_structures::certificate::{CertFormat, FieldTypeName, FormatField};

pub fn cert_format_woolball_pubkeybabyjubjub() -> CertFormat {
    let mut format = CertFormat {
        to: vec![],
        body: vec![],
    };

    let woolballname_field = FormatField {
        fname: "WoolballName".to_string(),
        fdescription: "Who is the certificate for (Woolball#): ".to_string(),
        ftype: FieldTypeName::WoolballName,
    };

    let babyjubjubpubkey_field = FormatField {
        fname: "BabyjubjubPubkey".to_string(),
        fdescription: "BabyjubjubPubkey (128 hex): ".to_string(),
        ftype: FieldTypeName::BabyjubjubPubkey,
    };

    let birthday_field: FormatField = FormatField {
        fname: "Birthdate".to_string(),
        fdescription: "Date of birth".to_string(),
        ftype: FieldTypeName::Timestamp,
    };

    format.to.push(woolballname_field);
    format.to.push(babyjubjubpubkey_field);
    format.body.push(birthday_field);

    format
}

pub fn cert_format_pubkeybabyjubjub() -> CertFormat {
    let mut format = CertFormat {
        to: vec![],
        body: vec![],
    };

    let babyjubjubpubkey_field = FormatField {
        fname: "BabyjubjubPubkey".to_string(),
        fdescription: "BabyjubjubPubkey (128 hex): ".to_string(),
        ftype: FieldTypeName::BabyjubjubPubkey,
    };

    let birthday_field: FormatField = FormatField {
        fname: "Birthdate".to_string(),
        fdescription: "Date of birth".to_string(),
        ftype: FieldTypeName::Timestamp,
    };

    let issuance_age_field: FormatField = FormatField {
        fname: "Issuance Age".to_string(),
        fdescription: "Age when the certificate was issued: ".to_string(),
        ftype: FieldTypeName::Age,
    };

    format.to.push(babyjubjubpubkey_field);
    format.body.push(birthday_field);
    format.body.push(issuance_age_field);

    format
}

pub fn cert_format_evm_address() -> CertFormat {
    let mut format = CertFormat {
        to: vec![],
        body: vec![],
    };

    let evm_address_field = FormatField {
        fname: "EVM Address".to_string(),
        fdescription: "EVM address (e.g., 0x1aD2B053b8c6b1592cB645DEfadf105F34d8C6e1)".to_string(),
        ftype: FieldTypeName::EVMAddress,
    };

    let birthday_field: FormatField = FormatField {
        fname: "Birthdate".to_string(),
        fdescription: "Date of birth".to_string(),
        ftype: FieldTypeName::Timestamp,
    };

    format.to.push(evm_address_field);
    format.body.push(birthday_field);

    format
}

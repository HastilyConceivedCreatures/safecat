# Safecat
![safecat logo, generated by stable diffusion and gimp](https://neiman.co.il/images/safecat.png)

A simple CLI tool to generate, sign, and verify digital signatures using EdDSA *Baby Jubjub Elliptic Curve* signatures and a *Poseidon hash function*.

Additionally, Safecat specializes in creating cryptographically signed certificates.

See [the announcement article](http://neimanslab.org/2024-02-19/safecat.html) for more details.

## compile
Install Rust, and run `cargo build`. Last tested with `cargo 1.80.0`.

## usage
1. `safecat generate`. Generates a new EdDSA Baby Jubjub Elliptic Curve private-public key.

    The private key is saved in a file `data/priv.key`, which is not encrypted! Unsafe indeed.

2. `safecat show-keys`. Shows the last generated private-public keys. You can choose which format to show, hex or detailed. Hex is simply a concatenation of the hex values of the public key's `x` and `y` elements. You need "detailed" if you want to verify the signature in Noir (it shows the x and y values of the key), and "hex" if you verify with Safecat.

    Here's how you show the detailed format:
    ```
    safecat show-keys --format detailed
    ```
    and here's how you show the hex format:
    ```
    safecat show-keys --format hex
    ```

3. `safecat sign <message>`. Signs a message using the private key located in data/priv.key. The message is hashed using the Poseidon hash function by default, but you can change it to SHA-256 using the --hash option. You can also choose a format as before (the hex signature is the concatenation of the hex format of the signature's r.x, r.y, s).
    ```
    safecat sign --hash sha256 --format hex "hello world"
    ```

4. `safecat sign-field <field>`. Same as `sign`, but instead of getting a message it accepts an element of the BN254 field. This may be the Poseidon hash of some message, but it can also be something else. Example:
    ```
    safecat sign-field 7185613633770928202545956049438992141449192152982569455300607652365873326347
    ```

5. `safecat verify <message> <signature> <public key>`. Verifies an existing signature of a message. By default, it assumes the message was hashed using Poseidon, but you can change it to SHA-256 using the --hash option like before. The signature and public key must be given in a hex form (see definitions above). 

    Verify commands are a bit long since the signature and public keys are long, so here's an example of how to use them. It doesn't look pretty.

    In later versions, we'll allow reading the parameters from a file or feeding them interactively.

    ```
    safecat verify "hello world" 245a157dc8e23ea8a0ab41b1c2d95ee7d59db5b76cba54b6f10630e5e0aefbdd140996400320386a9a2ec4b06ea7d1c885cd311751445ea171af1ab64dba5ace0420d34429497da49443ae35deb8e3daa745dc0e776df3703640078a67982cad 12055e5d761fd705d1f234770fc55b2cfdfd91e741d8f43b2a88cb5a88f9c1c01061ca2f21151da2903e7ccdf11dbda65c20851dd1df4ac522431041ea1738f9
    ```

5. `safecat attest <certificate_type>`. Creates certificates interactively. The certificate type is a string like "babyjubjub" (which is also the default value). Safecat searches for the toml certificate format specification in the folder data/certificate-formats (So for "babyjubjub" it would be "data/certificate-formats/babyjubjub.toml".

    Example usage:

    ```
    safecat attest --certificate-type babyjubjub
    ```

    Certificates are saved in `certs/created` folder.

    An explanation of certificates .toml format files is given below.

6. `safecat prove <cert_format> <proof_format>`. Creates a zero-knowledge proof using nargo and Barretenberg (by Ztec), based on specified certificate and proof formats. By default, the command assumes the `babyjubjub` certificate format and `personhood` proof format, which are the most common use cases.

Safecat searches for the `.toml` certificate and proof format specifications in the `data/formats` folder. For example, specifying the certificate format as `babyjubjub` and the proof format as `personhood` would look for `data/formats/babyjubjub/format.toml` and `data/formats/babyjubjub/proofs/personhood/proof.toml`, respectively.

Example usage:

```
safecat prove --cert-format babyjubjub --proof-format personhood
```

Additional flags:

    `--no-execute`: Skips execution if set. This flag is optional and can be triggered with `-n` or `--no-execute`. If set then a Noir program for the proof is set but not executed.

Proofs are saved in the `output` folder.


## Directories structure
Safecat has at thsi stage quite a strict data and output directory structure. If you're adding new formats, make sure to place it in the right place or all hell will break loose (i.e., you'll get a run-time error).

All the names can be set in `consts.rs`, we'll write next to each what the variable is.

### Data directory (`DATA_DIR`)
The data safecat use.
- `/formats` (`CERTIFICATE_FORMATS`). Holds the formats of supported certificates. Each folder is a certificate type. Within the folder `format.toml` specifies the certificate format, and there is a subfolder for each possible proof. Each proof folder contains `proof.toml`, which describes the input parameters, and the source of the Noir program for the proof. The toml files are later used to ask for input interactively from the user when creating a certificate of proof.

    We don't specify here in the detail the format of the `.toml` file at this stage, but they qre quite self-explanatory if you want to create new ones.

- 'noir_project_template' (`NOIR_TEMPLATE_FOLDER`). This folder contains a template for a Noir project. When the user proves something the program copies this template and changes it based on the specific proof format for the `format` folder (described above).

- `societies`. This folder includes json files of `societies`. A society is a collection of public keys of entities that are trusted to create certifiates. When you create a proof, you often specify in which "society" the certificates are made. This lets know to whoeever verify the proofs that they come from trusted entities.

- 'test_data'. You can ignore the data for tests for now.

### Output directory (`OUTPUT_DIR`)
This directory contains the output of Safecat. Currently: 
- `priv.key` (`PRIVATE_KEY_FILENAME`): your last generated private key, unencrypted!
- `/noir` folder: holds the latest Noir program created by the `proof` command.

## Limitations
- Poseidon hash is limited to strings of 496 characters. This can be extended to arbitrary length but it's left as a task for later versions.
- The proving system doesn't work.
- ... plenty of other limitations, this is all WIP! I know I've been saying it for half a year already. But well, at least I'm consistent!

# Safecat
A CLI tool to for crypto functions

## compile
`cargo build`

## usage
`safecat generate`: generates a private key and saves it into `priv.key` and `pub.key` files.

`safecat show`: shows the latest generated private and public keys.

`safecat sign <message>`: signs a message, e.g., `safecat sign "this is a message"`.

`safecat verify <message> <signature> <public key>`: verifies a signature of a message.

# Noir Safecat Example: verify humanity based on proof of personhood for a blockchain address
*(Adjusted for Safecat v0.0.4)*

A test integration of Safecat with Noir. It demonstrates how to prove a claim in Noir based on signed certificates created with Safecat.

The claim identifies a person based on their blockchain address. The certificates are create for blockchain address using
the `/safecat attest birth-address` command.

This is a whimsical example that serves as a proof of concept. It was created manually, but our end goal is to automate its creation with Safecat.

The data for this example is all saved in the `data/` folder.


## Example persons
We "created" keys of four persons:

**da Vinci** (private key in `data/keys/davinci.key`):
```
x: 21014832726010724769589766708319316991827096659474412078866184895974855912388
y: 6405279515825326203822750770145743232092764236229921922058389951827061816274
```

**Einstein** (private key in `data/keys/einstein.key`):
```
x: 14074902039331072699881382131648502838777985993210603723729670330905552560892
y: 3956701653239106625633807209791857536511283832857891018818650580010017949918
```

**Newton** (private key in `data/keys/newton.key`):
```
x: 9639479241221416696885834086335477766069548330216025978649155316193630647278
y: 19051381861547306185474270280362597765566899478771361496773368175649436061227
```

**Euclid** (priate key in `data/keys/euclic.key`):
```
x: 3137991897169707002071061914758136666730155095756285875245158253523334739926
y: 19525576774514817123938347101881507395524158867013066055259239948343480995092
```

`**Satoshi** is reporesented as the address ``0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`, which is an address given by Anvil EVM blockchain for testing.


## Example certificates
Safecat certificates are now in the prototype stage. They contain two lines. The first is the certificate itself, and the second is the signature.

The certificate contains four fields. `address` is the blockchain address of the person the certificate is issued to. `expdate` is the expiration date of the certificate, denoted in Unix timestamp. 

`type` is something we put so that later on we can have different types of certificates, each having a different format. Right now we put `type` equal `2` for the certificates in this example, and assume `2` is a certificate someone is human for a blockchain address.

For human certificates, we also add a `bdate`, date of birth of the person (also denoted in Unix timestamp). Later on we can use Noir proofs to distinguish minors from adults.

### Representing certificates as array of Fields
The certificates themselves are given in JSON format. However, since it's difficult to work with strings in Noir, we chose a different representation of the certificates for the proof. 

### Example Data
The example certificates are located in `data/certs/`.

There are two certificates, one from Einstein and one from Euclid. Both of them claim Satoshi is a human born on 1-jan-1990. This is, by the way, not a hint to Satoshi's true identity.

The ceritifacates are created for Satoshi's address.

## Trust kernel
Certificates are worthless unless the person reading them trusts whoever signed them. 

We call a set of trusted entities, or at least trusted to issue certain certificates, a "trust kernel". 

Each entity in the kernel is represented by its private keys. We can make a Merkle tree where the leaves are persons in the trusted set. The roof of this tree represents a trust set.

The trust set of the example is `(da Vinci, Einstein, Newton, Euclid)`. We calculated, using Noir, the Merkle root of `(devinci,newton,Einstein,Euclid)` with Pedersen hash is `0x0b7ce38eae5d7d171103b2879399856eedfacf71a862c7a89ca80a0f03e3be1c`, where the leaves were made left to right.

## Noir program
The Noir program shows that two persons from the trust set verified that Satoshi is a human born on 1-jan-1990.

As public parameters it takes: Satoshi public key and the trust set Merkle tree hash (called "trust set hash").

The private parameters are the certificate, the public key of the two signers, the two signatures of the certificate, and two hash path proofs showing the signers are in the trust set.

If the program passes, Satoshi proves the claim without disclosing the certificates.

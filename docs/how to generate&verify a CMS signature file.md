# Introduction to CMS Signature (Cryptographic Message Syntax)

## WHY CMS Signature Are Needed

As software supply-chain security, firmware integrity, and trusted execution environments become increasingly important, **CMS (Cryptographic Message Syntax)** signatures are widely adopted across modern security architectures.

CMS signatures ensure that data—whether firmware, configuration packages, binaries, or messages—can be safely stored or transmitted through untrusted channels while preserving:

1. **Integrity** — ensuring the data has not been modified
2. **Authenticity** — verifying the identity of the signer

CMS is the basis for PKCS #7 signatures and is directly used in:

* UEFI Secure Boot (for signing PE/COFF executables)
* S/MIME email signatures
* Container and software package signing mechanisms

## What is a CMS Signature
CMS is based on the syntax of [PKCS #7](https://en.wikipedia.org/wiki/PKCS_7 "PKCS 7"), which in turn is based on the [Privacy-Enhanced Mail](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail "Privacy-Enhanced Mail") standard.

The architecture of CMS is built around certificate-based key management, such as the profile defined by the PKIX working group. CMS is used as the key cryptographic component of many other cryptographic standards, such as S/MIME, PKCS #12 and the RFC 3161 digital timestamping protocol.

The CMS file format is as follows:

```
+-------------------------------------------------------------+
|                        ContentInfo                          |
+-------------------------------------------------------------+
| contentType                                  |
| content                                                     |
|   +-----------------------------------------------------+   |
|   |                    SignedData                       |   |
|   +-----------------------------------------------------+   |
|   | version                                             |   |
|   | digestAlgorithms[]                                  |   |
|   |                                                     |   |
|   | encapContentInfo                                    |   |
|   |   +---------------------------------------------+   |   |
|   |   | eContentType                                  |   |
|   |   | eContent (optional)                           |   |
|   |   +---------------------------------------------+   |
|   | certificates[] (optional)                           |
|   | crls[] (optional)                                   |
|   | signerInfos[]                                       |
|   |   +---------------------------------------------+   |
|   |   |                SignerInfo                   |   |
|   |   | version                                     |   |
|   |   | sid (issuer+serial or subjectKeyID)        |   |
|   |   | digestAlgorithm                             |   |
|   |   | signedAttrs (optional)                      |   |
|   |   | signatureAlgorithm                          |   |
|   |   | signature (actual signature value)          |   |
|   |   | unsignedAttrs (optional)                    |   |
|   |   +---------------------------------------------+   |
|   +-----------------------------------------------------+   |
+-------------------------------------------------------------+

```
## How to generate CMS Signature with Signatrust

Signatrust support generate CMS signature within the command as following

```bash
RUST_BACKTRACE=full RUST_LOG=debug ./signatrust-client --config /config/client.toml add --file-type p7s --key-type x509 --key-name my-x509 --detached origin.txt
```

Signatrust will sign the binary stream of data and generate a CMS file that does not include the certificate or the original text

## How to verify CMS Signature

1.Prepare the following file

a)Signing Certificate : sig.crt

b)CA of the signature certificate : ca.crt

c)Signed file : origin.txt

d)signature file ：origin.txt.p7s

2.verify the signature

```bash
openssl cms -verify -binary -inform DER -in origin.txt.p7s  -content origin.txt -signer sig.crt -CAfile ca.crt -purpose any
```

3.display the signature

```bash
openssl cms -inform DER -cmsout -print -noout -in origin.txt.p7s
```

## References
1. https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax

2. https://docs.openssl.org/3.1/man1/openssl-cms

3. https://docs.keyfactor.com/signserver/6.3/code-signing-with-cms-signatures

4. https://www.rfc-editor.org/rfc/rfc5652
# How to sign&verify a generic file(with detached signature)

## Background
We also need to sign the checksum file of the ISO when publishing, for signatrust the checksum case is more simple, since it's treated as a generic file, 
basically the sign system will read the whole file content, sign it with openPGP key and finally generate the detached signature file with `.asc`(stands for ASCII Armor) suffix.

## Sign the generic file with signatrust
Signatrust supports sign a generic file with the following command:
```bash
 RUST_BACKTRACE=full RUST_LOG=debug ./target/debug/signatrust-client --config /path/to/client.toml add  --key-name default-pgp  --file-type generic --key-type pgp .data/somme-file.checksum
```
and the `asc` file will be generated in the same directory with the original file.
```
➜  signatrust: ls -alh
drwxr-xr-x 8 tommylike staff  256 Jun 30 11:36 .
drwxr-xr-x 7 tommylike staff  224 Jun 30 11:09 ..
-rw-r--r-- 1 tommylike staff 106K Jun 30 10:07 somme-file.checksum
-rw-r--r-- 1 tommylike staff  455 Jun 30 11:27 somme-file.checksum.asc
➜  signatrust: cat somme-file.checksum.asc
-----BEGIN PGP SIGNATURE-----

wsBcBAABCAAQBQJknkubCRCC1JrK+HJLdQAASzEIAMqjtGNcpwIODUaTSC9WNCOm
qD+vqcI6PH1OvY9PSzFZKT0ME0C7SRj0J8trGkXWvXYW+CHVPJa2DPpeUvJNyA0o
JXB3wrG/rOkUZWQcKEaWxLpmYGywVMzbGW6vwoHtrGYTF71fQjQSyQLRbI4Rn9Ql
hUKH0RQKSuI5zbFqM7kuN2esBOszb6hUxb1n/JTIagJICzeekt0jqSvV3/828N+Q
o2NDH35orWhuK9x8PO8Ivgb7ZQfA+mMwrYijs0SLEJrUhMkznsZWF8paTmnF583A
J8oOdm+kzAyIfmQi3al5mtlKTY4cdhSdgErsxpLA/Itzbv5CR/d2yRe89tHc8Po=
=OBZj
-----END PGP SIGNATURE-----

```

## Verify the signature of the generic file
In order to verify the signature of the generic file, you will need the pgp tool.
1. Download the pgp tool
```shell
# for ubuntu
sudo apt-get update -y && sudo apt-get install -y pgp
# for mac
brew install gnupg
```
2. Download the public key from signatrust control-server and save it into local file(pgp.public_key as below) in pem format:
```shell
curl -X 'POST' \
  'https://localhost:8080/api/v1/keys/<key-id-or-name>/public_key' \
  -H 'accept: application/json' \
  -H 'Authorization: cBnLPLXl1fA7fKDZnjg9fd9dSWw2RXtUH3MGFUtq' \
  -d ''
```
3. Load the public key into local pgp keyring
```shell
➜  signatrust: gpg --import pgp.public_key
```
4. Edit the public key to make it trusted
```shell
➜  signatrust: gpg --edit-key <key-id>
gpg (GnuPG) 2.4.2; Copyright (C) 2023 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

pub  rsa2048/82D49ACAF8724B75
     created: 2023-06-30  expires: never       usage: SC  
     trust: ultimate      validity: ultimate
[ultimate] (1). default-pgp <infra@openeuler.org>

gpg> trust
pub  rsa2048/82D49ACAF8724B75
     created: 2023-06-30  expires: never       usage: SC  
     trust: ultimate      validity: ultimate
[ultimate] (1). default-pgp <infra@openeuler.org>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y

```
5. Verify the signature
```shell
➜  signatrust: gpg --verify somme-file.checksum.asc somme-file.checksum
gpg: Signature made 五  6/30 11:27:23 2023 CST
gpg:                using RSA key 82D49ACAF8724B75
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: Good signature from "default-pgp <infra@openeuler.org>" [ultimate]

```



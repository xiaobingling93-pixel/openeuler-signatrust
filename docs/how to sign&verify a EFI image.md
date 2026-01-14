# Background
For the background of EFI signature, please refer to [this](how%20to%20sign%20EFI%20file.md) document.
# Prerequisite
- Create an x509 key in data server if you do not have one
    ```bash
    curl -X 'POST' \
    'http://10.0.0.139:8080/api/v1/keys/' \
    -H 'accept: application/json' \
    -H 'Authorization: G2fmAfnLUT4R5TDaQhpCWvGznme0zaA0YQFBKJIc' \
    -H 'Content-Type: application/json' \
    -d '{
    "attributes": {
        "digest_algorithm": "sha2_256",
        "key_length": "4096",
        "key_type": "rsa",
        "common_name": "EFI signer",
        "country_name": "CN",
        "locality": "Chengdu",
        "organization": "openEuler",
        "organizational_unit": "infra",
        "province_name": "Sichuan"
    },
    "description": "a test x509 key pair",
    "expire_at": "2024-05-12 22:10:57+08:00",
    "key_type": "x509",
    "name": "my-x509"
    }'
    ```
- Export the x509 certificate into PEM format
    - get the key id
    ```
    curl -X 'GET' \
        'http://10.0.0.139:8080/api/v1/keys/' \
        -H 'accept: application/json' \
        -H 'Authorization: G2fmAfnLUT4R5TDaQhpCWvGznme0zaA0YQFBKJIc'
    ```
    
    ```
    [
        {
            "id": 5,
            "name": "my-x509",
            "email": "tommylikehu@gmail.com",
            "description": "a test x509 key pair",
            "user": 1,
            "attributes": {
            "common_name": "EFI signer",
            "country_name": "CN",
            "create_at": "2023-05-04 09:24:01.488589752 UTC",
            "digest_algorithm": "sha2_256",
            "expire_at": "2024-05-12 22:10:57+08:00",
            "key_length": "4096",
            "key_type": "rsa",
            "locality": "Chengdu",
            "name": "my-x509",
            "organization": "openEuler",
            "organizational_unit": "infra",
            "province_name": "Sichuan"
            },
            "key_type": "x509",
            "fingerprint": "2A8853F8411F4B243FB424F90B2541D7AE5AF8C9",
            "create_at": "2023-05-04 09:24:01 UTC",
            "expire_at": "2024-05-12 14:10:57 UTC",
            "key_state": "disabled"
        }
    ]
    ```
    - enable the key
    ```
    curl -X 'POST' \
        'http://10.0.0.139:8080/api/v1/keys/5/enable' \
        -H 'accept: */*' \
        -H 'Authorization: G2fmAfnLUT4R5TDaQhpCWvGznme0zaA0YQFBKJIc' \
        -d ''
    ```
    - get key certificate by id
    ```
    curl -X 'POST' \
        'http://10.0.0.139:8080/api/v1/keys/5/certificate' \
        -H 'accept: application/json' \
        -H 'Authorization: G2fmAfnLUT4R5TDaQhpCWvGznme0zaA0YQFBKJIc' \
        -d ''
    ```
    
    ```
       -----BEGIN CERTIFICATE-----
    MIIFTTCCAzWgAwIBAgIBADANBgkqhkiG9w0BAQ4FADBqMRMwEQYDVQQDDApFRkkg
    c2lnbmVyMQ4wDAYDVQQLDAVpbmZyYTESMBAGA1UECgwJb3BlbkV1bGVyMRAwDgYD
    VQQHDAdDaGVuZ2R1MRAwDgYDVQQIDAdTaWNodWFuMQswCQYDVQQGEwJDTjAeFw0y
    MzA1MDQwOTI0MDJaFw0yNDA1MTIwOTI0MDJaMGoxEzARBgNVBAMMCkVGSSBzaWdu
    ZXIxDjAMBgNVBAsMBWluZnJhMRIwEAYDVQQKDAlvcGVuRXVsZXIxEDAOBgNVBAcM
    B0NoZW5nZHUxEDAOBgNVBAgMB1NpY2h1YW4xCzAJBgNVBAYTAkNOMIICIjANBgkq
    hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5xd/p5oqJBpfZlU3WmdKfFS7ZwdUAssX
    yQDxXTUHe4LoZ3imFcpQed41Yu/rBxKQzLtSmHkpZ9Bw6bDplQrvuTYaeLtfiDUA
    a2kZVCBzDnFFx4J6v5jkoC4i1SYeGPtEW4D5m8xn8G5aCslEnpvLYQ1oXi14vORH
    zuC7uMfkDh+/JTOYkRw083lFjZEXEh5Jjf0mZNLN9PhBzOCzDalABGhpcOATtkKx
    EDtXcyVNJEqf8sfpz7FKNpNBNIKb3EZX168OFp+yeK3pd1dhAc+FFkmZmwN+Qb06
    5znGfdltxh9F75yPB1CeJEedirTVj/QvALSSkFlKS9TFgRgh7T2zKlj7Bw+fC9cX
    JCjUevgnl6pFvrEqVTu+topmWcEPKPJiI1xPVtFcRjEEgTnkTRcpfoDxKngh3oj1
    +5szBXwMKnnk1wc7TK8zqTcxEbLeSkiTxU5ptWasnkhqHoJyzO9wjc7qasvSKxUo
    u0+VD0W/EID4KkLgomkwiFUGFeYstpbpiC0FJS3M/JOLIibPRXK54YMxw23bHqDP
    4J02J6NdmrLLiKXaRy2MCcxlovckswqYz/4xjT9ye9dc8DMengLn5+iDpxzCdBjv
    TdGXejY3gTvQ68JKz6TznBcz+ooh6K/bH950Kr3JDwZkCTpuZKQnXSWZhXVN1sHb
    ZJn7IneyPKkCAwEAATANBgkqhkiG9w0BAQ4FAAOCAgEAObCqV91IlCpELDyDdVm1
    yc2xYlwbleeamI4lRQ9dbUxJgmoEvHrigTy6+QddTWTvq1ClB66FFr4CmP4R44ew
    OOnkUhdynZy23+qR0f9RKLpM/bQFzFAJJGkjVaz9OA0nD6lbGHxlljB0palnpeQN
    bXT42I9+pKQ+jmLQeUM5G2OYmEiOeATh5fDG50/Mi71vcjJBpcqoGy0eJQnbpTLr
    H3q3TjffpI4VmB4XZCdv4M8mTeZrT9fz40/tknUpGrD1ZDnOeAEX54KxCDhMpDPd
    JzhZAsd1zT23gEVyiJzXjnJb+ooCjLskFgIDRwim4/P8oMrmYJLC3PTf33AHiIsZ
    xka4Io7xNc58pAZPef1MLMRRxvZL2sHocZ1u3imPW0/9NdICLLCw+kCuXXZyjzsb
    3AhivrkA4pHuEakYcKZ7m4cbEdhn+A8VH+cZ6F8dOt683a3h/1KMUA9RgbmkRfOY
    Bd0ifVYZNlL2P7+aRB5MYYdjvtFTjvuYnaiCsk0rfKeFcLRcdqH/LwsnmYI58ak+
    oBg1q7IwUKiMMQJXv80sYpulMVNf4yogMwxuDb8aKSMoYYHqwpc/APxpxxIYqals
    jm/mYiBzbODW1CkAXzFKlDxwbOHbYE/BjtQka4UKGoJbmhSRae9axKxj1bBj4Vud
    tTN6jZmbEb/Bmclsaooig1g=
    -----END CERTIFICATE-----
    
    ```
    - save it into the `certificate` file.

# Sign a EFI file
```
RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/signatrust-client -c client.toml add --file-type efi-image --key-type x509 --key-name my-x509 --sign-type authenticode  `pwd`/shimx64.efi
```

# Verify the EFI file
## Using sbsigntools
- first we should compile `sbsigntools`
```
sudo dnf in gcc automake autoconf make binutils-devel gnu-efi gnu-efi-devel help2man # buildrequires on openEuler 22.03
git clone https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git
cd sbsigntools
git submodule init && git submodule update
./autogen.sh && ./configure && make
```
- verify the signed EFI image using the certificate we exported
```
$ src/sbverify `pwd`/shimx64.efi --cert certificate
warning: data remaining[827688 vs 953240]: gaps between PE/COFF sections?
Signature verification OK
```

## Using pesign
- Install pesign
```
sudo dnf in -y pesign nss-utils openssl
```
- verify the signed EFI image using pesign
```
openssl x509 -in certificate -inform PEM -out cert.der -outform DER
pesigcheck -i `pwd`/shimx64.efi -c cert.der
pesigcheck: "shimx64.efi" is valid.
```
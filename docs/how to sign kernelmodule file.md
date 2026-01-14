# How to sign a KernelModule (ko) file

## Background

KernelModule file is a file that can be loaded into the kernel at runtime, it's a binary file that contains the code and data that can be loaded into the kernel and run. And for the security concern we need to sign and verify the KernelModule file to make sure the file was not tampered.
There are two files located in the kernel repository that can be used to sign and verify the KernelModule file, they are `scripts/sign-file.c` and `scripts/extract-module-sig.pl`. 
The `sign-file.c` is used to sign the KernelModule file and the `scripts/extract-module-sig.pl` is used to extract the certificate from the signed KernelModule file.

## Signature Layout
The layout of signed KernelModule file is describe as below:

![structure](./images/kernel_module_signature.png)

1. The raw content of kernel module file.
2. The CMS signature, and signature is a DER encoded PKCS#7 structure. The PKCS#7 structure contains the certificate and the signature of the file.
3. The ModuleSignature structure is appended after in the PKCS#7 structure, which contains the information of the signature.
4. The Module Magic string ("~Module signature appended~\n"), and it will be appended after the ModuleSignature structure, which is used to identify the signature.



## Sign the KernelModule file with sign-file.c
For Ubuntu, you can locate the sign-file tool with command:
```bash
tommylike@ubuntu  ~  /usr/src/linux-headers-$(uname -r)/scripts/sign-file
Usage: scripts/sign-file [-dp] <hash algo> <key> <x509> <module> [<dest>]
       scripts/sign-file -s <raw sig> <hash algo> <x509> <module> [<dest>]
```
sign-file support detached(-pd) and attached(-p) signature, considering you have generated the x509 key and cert, the command would as simple as:
```bash
tommylike@ubuntu  ~  /usr/src/linux-headers-$(uname -r)/scripts/sign-file -dp sha256 new.key new.crt simple.ko
```
Command used to check the cms signature in text format:
```bash
tommylike@ubuntu  ~/sign-kernelmodule  openssl pkcs7 -in  simple.ko.p7s -inform DER  -text
-----BEGIN PKCS7-----
MIIBygYJKoZIhvcNAQcCoIIBuzCCAbcCAQExDTALBglghkgBZQMEAgEwCwYJKoZI
hvcNAQcBMYIBlDCCAZACAQEwazBmMQ4wDAYDVQQDDAVpbmZyYTEOMAwGA1UECwwF
SW5mcmExDzANBgNVBAoMBkh1YXdlaTERMA8GA1UEBwwIU2hlblpoZW4xEzARBgNV
BAgMCkd1YW5nIERvbmcxCzAJBgNVBAYTAkNOAgEAMAsGCWCGSAFlAwQCATANBgkq
hkiG9w0BAQEFAASCAQBqyJT0Ibos7e38AM6ni5QYhkgwcMAYJV9MoOTX7MH3onhu
SBw1y1wpO1TIHonhmuRkc9Jqw5lVzaB2kvyHBOfwZBGZJ5BVqSJwq+KEU7e3uIQr
nm4/6mOPY+GS5khaq92b5k7Oq/iDPirD0Wle6dqSu6/0i0oEVUzvdEOwY9J6NK38
7EoP6RvN8YFm2rwxK9meaj8tWLsRdxtdiHscov/ZX/2TWV4VGRBAgzK5IdvfaTU6
yVr45nWbamXzgYXpI1Eb7sr5pZXnkk48SjNt+9uNku5eL0OthPx9n0VTlZ4gc+sD
8SPZGyjWyn+VvQlSrGaT/XD49e2sWqeJ/RvP0bqN
-----END PKCS7-----
```
or in ASN.1 format:
```bash
tommylike@ubuntu  ~/sign-kernelmodule  openssl asn1parse -inform der -in simple.ko.p7s
    0:d=0  hl=4 l= 458 cons: SEQUENCE
    4:d=1  hl=2 l=   9 prim: OBJECT            :pkcs7-signedData
   15:d=1  hl=4 l= 443 cons: cont [ 0 ]
   19:d=2  hl=4 l= 439 cons: SEQUENCE
   23:d=3  hl=2 l=   1 prim: INTEGER           :01
   26:d=3  hl=2 l=  13 cons: SET
   28:d=4  hl=2 l=  11 cons: SEQUENCE
   30:d=5  hl=2 l=   9 prim: OBJECT            :sha256
   41:d=3  hl=2 l=  11 cons: SEQUENCE
   43:d=4  hl=2 l=   9 prim: OBJECT            :pkcs7-data
   54:d=3  hl=4 l= 404 cons: SET
   58:d=4  hl=4 l= 400 cons: SEQUENCE
   62:d=5  hl=2 l=   1 prim: INTEGER           :01
   65:d=5  hl=2 l= 107 cons: SEQUENCE
   67:d=6  hl=2 l= 102 cons: SEQUENCE
   69:d=7  hl=2 l=  14 cons: SET
   71:d=8  hl=2 l=  12 cons: SEQUENCE
   73:d=9  hl=2 l=   3 prim: OBJECT            :commonName
   78:d=9  hl=2 l=   5 prim: UTF8STRING        :infra
   85:d=7  hl=2 l=  14 cons: SET
   87:d=8  hl=2 l=  12 cons: SEQUENCE
   89:d=9  hl=2 l=   3 prim: OBJECT            :organizationalUnitName
   94:d=9  hl=2 l=   5 prim: UTF8STRING        :Infra
  101:d=7  hl=2 l=  15 cons: SET
  103:d=8  hl=2 l=  13 cons: SEQUENCE
  105:d=9  hl=2 l=   3 prim: OBJECT            :organizationName
  110:d=9  hl=2 l=   6 prim: UTF8STRING        :Huawei
  118:d=7  hl=2 l=  17 cons: SET
  120:d=8  hl=2 l=  15 cons: SEQUENCE
  122:d=9  hl=2 l=   3 prim: OBJECT            :localityName
  127:d=9  hl=2 l=   8 prim: UTF8STRING        :ShenZhen
  137:d=7  hl=2 l=  19 cons: SET
  139:d=8  hl=2 l=  17 cons: SEQUENCE
  141:d=9  hl=2 l=   3 prim: OBJECT            :stateOrProvinceName
  146:d=9  hl=2 l=  10 prim: UTF8STRING        :Guang Dong
  158:d=7  hl=2 l=  11 cons: SET
  160:d=8  hl=2 l=   9 cons: SEQUENCE
  162:d=9  hl=2 l=   3 prim: OBJECT            :countryName
  167:d=9  hl=2 l=   2 prim: PRINTABLESTRING   :CN
  171:d=6  hl=2 l=   1 prim: INTEGER           :00
  174:d=5  hl=2 l=  11 cons: SEQUENCE
  176:d=6  hl=2 l=   9 prim: OBJECT            :sha256
  187:d=5  hl=2 l=  13 cons: SEQUENCE
  189:d=6  hl=2 l=   9 prim: OBJECT            :rsaEncryption
  200:d=6  hl=2 l=   0 prim: NULL
  202:d=5  hl=4 l= 256 prim: OCTET STRING      [HEX DUMP]:6AC894F421BA2CEDEDFC00CEA78B941886483070C018255F4CA0E4D7ECC1F7A2786E481C35CB5C293B54C81E89E19AE46473D26AC39955CDA07692FC8704E7F0641199279055A92270ABE28453B7B7B8842B9E6E3FEA638F63E192E6485AABDD9BE64ECEABF8833E2AC3D1695EE9DA92BBAFF48B4A04554CEF7443B063D27A34ADFCEC4A0FE91BCDF18166DABC312BD99E6A3F2D58BB11771B5D887B1CA2FFD95FFD93595E151910408332B921DBDF69353AC95AF8E6759B6A65F38185E923511BEECAF9A595E7924E3C4A336DFBDB8D92EE5E2F43AD84FC7D9F4553959E2073EB03F123D91B28D6CA7F95BD0952AC6693FD70F8F5EDAC5AA789FD1BCFD1BA8D
```

## Sign the KernelModule file with signatrust
Signatrust support sign KernelModule file within the command as following:
```bash
 RUST_BACKTRACE=full RUST_LOG=debug ./target/debug/signatrust-client --config /path/to/client.toml add  --key-name default-x509  --file-type kernel-module --key-type x509 .data/simple.ko
```
Signatrust supports to resign a signed KernelModule file, that's to say instead of append the cert and metadata at the end of file, signatrust will try to parse the kernel module file and replace the signature when resigning.
if you add the `--detached` flag, the signature will be detached from the file as `sign-file` tool, and the signature will be output to the file with the same name as the file to be signed, but with the extension .p7s appended to the file name.
```bash
 RUST_BACKTRACE=full RUST_LOG=debug ./target/debug/signatrust-client --config /path/to/client.toml add  --key-name default-x509  --file-type kernel-module --key-type x509 --detached .data/simple.ko
```

## Verify the Signature of KernelModule file
In order to verify the signature of KernelModule file, you need to extract the signature from the file first, and then verify the signature with the extracted signature and the original file.
1. Download the certificate from signatrust control-server and save it into local file(new.cert as below) in pem format:
```shell
curl -X 'POST' \
  'https://localhost:8080/api/v1/keys/<key-id-or-name>/certificate' \
  -H 'accept: application/json' \
  -H 'Authorization: cBnLPLXl1fA7fKDZnjg9fd9dSWw2RXtUH3MGFUtq' \
  -d ''
```
2. Extract the signature from the KernelModule file or use detached signature(.p7s)
```bash
 tommylike@ubuntu  ~/sign-kernelmodule  perl extract-module-sig.pl -s simple.ko > detached.p7s
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
	LANGUAGE = (unset),
	LC_ALL = (unset),
	LC_TERMINAL = "iTerm2",
	LC_CTYPE = "UTF-8",
	LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to a fallback locale ("en_US.UTF-8").
Read 15805 bytes from module file
Found magic number at 15805
Found PKCS#7/CMS encapsulation
Found 461 bytes of signature [308201c906092a864886f70d010702a0]
```
3. Verify the signature
```bash
openssl smime -verify -binary -inform DER -in detached.p7s  -content simple.ko -certfile new.crt -nointern -noverify
......
......
Verification successful
```
4. Display signature
In order to view the detail of signature, we can convert signature into cms format and view detail with openssl cms sub command.
```shell
 openssl cms -verify -noverify -in detached.p7s -inform DER -cmsout -out detached.cms
 openssl cms -cmsout -print -noout -in detached.cms

CMS_ContentInfo:
  contentType: pkcs7-signedData (1.2.840.113549.1.7.2)
  d.signedData:
    version: 1
    digestAlgorithms:
        algorithm: sha256 (2.16.840.1.101.3.4.2.1)
        parameter: <ABSENT>
    encapContentInfo:
      eContentType: pkcs7-data (1.2.840.113549.1.7.1)
      eContent: <ABSENT>
    certificates:
      <EMPTY>
    crls:
      <EMPTY>
    signerInfos:
        version: 1
        d.issuerAndSerialNumber:
          issuer: CN=Infra, OU=Infra, O=Huawei, L=ShenZhen, ST=GuangDong, C=CN
          serialNumber: 0xB2A68D95D9B92D92E48FDB184FA0BC8B
        digestAlgorithm:
          algorithm: sha256 (2.16.840.1.101.3.4.2.1)
          parameter: <ABSENT>
        signedAttrs:
            object: contentType (1.2.840.113549.1.9.3)
            value.set:
              OBJECT:pkcs7-data (1.2.840.113549.1.7.1)

            object: signingTime (1.2.840.113549.1.9.5)
            value.set:
              UTCTIME:Jul 21 08:49:06 2023 GMT

            object: messageDigest (1.2.840.113549.1.9.4)
            value.set:
              OCTET STRING:
                0000 - ff 87 d2 69 59 94 92 d3-28 a9 53 39 81   ...iY...(.S9.
                000d - 8e b3 95 ff 97 82 59 e4-f2 19 07 52 bc   ......Y....R.
                001a - 32 ad 97 df cd e6                        2.....
        signatureAlgorithm:
          algorithm: rsaEncryption (1.2.840.113549.1.1.1)
          parameter: NULL
        signature:
          0000 - 1d b0 07 d7 23 cd 0e 39-47 7f 64 2a b0 57 7c   ....#..9G.d*.W|
          000f - b8 8a 38 33 4b 36 ea 7a-23 9a ba ac 5a 9f c1   ..83K6.z#...Z..
          001e - 48 4e ca 65 86 3e c2 27-1f 2e bd 02 7b 75 8c   HN.e.>.'....{u.
          002d - fd d1 d0 06 32 65 58 10-bf 8f c4 4c a2 6a 77   ....2eX....L.jw
          003c - 9f 36 df c6 ab 90 02 de-54 b1 96 a9 50 0a b7   .6......T...P..
          004b - f7 2e 5d 72 b1 07 0a 78-ae a3 c3 06 1e a0 9c   ..]r...x.......
          005a - c3 e8 7e 10 5f 97 39 5b-fe 86 9b 58 cf f5 d2   ..~._.9[...X...
          0069 - 3c 61 a0 ca cc 12 48 3c-d4 86 1c 1b fb 3a 47   <a....H<.....:G
          0078 - 2f 31 01 45 a2 ce 32 cc-09 9b 24 18 95 3c ed   /1.E..2...$..<.
          0087 - d1 bf c6 b4 9c 4f 73 dd-10 ab c0 d7 42 ba 13   .....Os.....B..
          0096 - 51 d0 e7 6f 60 84 80 56-ba 33 3f 09 ef 2a 6d   Q..o`..V.3?..*m
          00a5 - c7 84 1c 9e 64 07 bf 9d-ea 1c 9c 59 14 39 77   ....d......Y.9w
          00b4 - 12 92 d4 8d cf 0c 6f c4-bd 9a ca 3e ec 54 1a   ......o....>.T.
          00c3 - ed 5a 87 8c 47 33 53 58-b8 5b 98 ff bb aa 1b   .Z..G3SX.[.....
          00d2 - cf f3 23 cb a4 48 93 4b-87 fe 7d ba da 96 6d   ..#..H.K..}...m
          00e1 - 56 57 6e 7d 25 4c e7 6e-39 27 c3 f3 06 58 72   VWn}%L.n9'...Xr
          00f0 - 2f d8 27 cc ce 78 22 18-df 8a c2 91 29 87 a2   /.'..x".....)..
          00ff - 62                                             b
        unsignedAttrs:
          <EMPTY>
```




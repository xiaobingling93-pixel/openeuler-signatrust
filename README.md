# Signatrust
[![RepoSize](https://img.shields.io/github/repo-size/TommyLike/signatrust)](https://gitee.com/openeuler/signatrust)
[![Clippy check](https://github.com/TommyLike/signatrust/actions/workflows/build.yml/badge.svg)](https://github.com/TommyLike/signatrust/actions/workflows/build.yml)

Signatrust offers a highly secure, async and efficient solution for signing Linux packages and binaries using Rust. Our unified
platform ensures streamlined operations and a high throughput for all signing requests.

# Background

Signing packages and binaries for a Linux distribution is essential in many use cases. Typically, PGP is used for RPM
packages, ISO checksums, AppImages, and repository metadata. X509 certificates, on the other hand, are used to cover the
cases of kernel modules and EFI. While there are several projects and scripts already in use within the community, 
they are often limited to CI/CD environments, and the management and security of private keys are not always covered.

We have observed several projects aiming to address these challenges.
1. [**OBS sign**](https://github.com/openSUSE/obs-sign): Developed by openSUSE, obs-sign is a widely used Linux distro
   packaging system, including [OBS](https://build.opensuse.org/) and [COPR](https://copr.fedorainfracloud.org/). The
   solution provides a comprehensive server-client model for massive signing tasks in a production environment. 
   However, one of the challenges faced by the system is the difficulty in replicating instances to increase throughput.
   Additionally, the system is also plagued by security and management concerns, as PGP is located on the server disk directly.
2. [**sbsigntools**](https://github.com/phrack/sbsigntools) This is a fork version of official sbsigntools which can store
    certificates & key in AWS CloudHSM and targets for UEFI signing.
3. other tools.

# Features

**Signatrust**, stands for `Signature + Trust + Rust` is a rust project that can provide a unified solution for all the challenges:
 
1. **E2E security design**: Our end-to-end security design prioritizes the protection of sensitive data, such as keys and
   certificates, by transparently encrypting them with external KMS providers, like CloudHSM or Huawei KMS, before storing them in the
   database. Additionally, we have eliminated the need to transfer private keys to the client for local sign operations,
   opting instead to deliver content to the sign server and perform signature calculations directly in memory. Furthermore,
   all memory keys are zeroed out when dropped to protect against leaks to swap and core dump. Currently, mutual TLS is required
   for communication between the client and server, with future upgrades planned to integrate with the SPIFF&SPIRE ecosystem.

2. **High throughput**: To ensure high throughput, we have split the control server and data server and made it easy to
   replicate the data server. We have also made several performance enhancements, such as utilizing gRPC stream, client
   round-robin, memory cache, and async tasks to increase single-instance performance.

3. **Complete binaries support**:
   1. RPM/SRPM signature.
   2. Detached PGP signature including ISO checksum and repo metadata.
   3. Kernel module signature.
   4. EFI.
   5. Container Image(todo).
   6. WSL Image(todo).
   7. AppImage(todo).

4. **User-friendly key management**: Signatrust offers a user-friendly, standalone interface for managing sensitive keys,
   which can be seamlessly integrated with external account systems using the OpenID Connect (OIDC) protocol. Administrators
   have the ability to generate, import, export, and delete keys through this intuitive interface.

# System Context
![System Context](./docs/images/System%20Context.png)
# Performance
According to our performance tests, Signatrust outperformed Obs Sign(with pgp agent backend) by a significant margin in a concurrent test environment:

1. **Server**: Single instance with limited resources of 8 CPUs and 8GB RAM.
2. **Clients**: 1/2/4 instances, each with limited resources of 8 CPUs and 10GB RAM.
3. **Task per client**: Signing the entire set of RPM packages in the [openEuler21.09 source](https://archives.openeuler.openatom.cn/openEuler-21.09/source/Packages/), which amounted to 4168 packages and 18GB in total.
4. **Concurrency per client**: 50.
5. **NOTE**: obs sign only support sign a single file, in order to support concurrent operations, we wrap the `obs-sign` command with golang `goroutines` or python `multiprocessing`.

![Performance](./docs/images/sign%20performance.png)

Based on these test results, it appears that Signatrust is a more efficient and effective solution for signing RPM packages, it's also worth noting that the performance issue of obs sign is mainly due to the gpg's agent implementation.

# Backend Security
In order to support different levels of backend security, signatrust supports different kinds of sign backend, `memory` backend is the default one which will provide better performance
while all sensitive data are stored decrypted in memory. the configuration would be like:
```shell
[sign-backend]
type = "memory"
[memory.kms-provider]
type = ""
kms_id = ""
endpoint = ""
project_name = ""
project_id = ""
username = ""
password = ""
domain=""
[memory.encryption-engine]
rotate_in_days = 90
algorithm = "aes256gsm"
```

# Components
This project consists of several binaries:
1. **data-server**: the data server used for handle signing requests and exposes the gRPC for clients.
2. **control-server**: the control server used for handle administration requests and expose http requests for Web UI.
3. **control-admin**: the control-admin is mainly used in develop environment for convenience, i.e. generate administrator and tokens without the integration of external OIDC server.
4. **client**: the client is responsible for handle signing task locally and will exchange signature with data server.
5. **app**: the app used for administrator to manage keys and tokens.

# Documents on sign/verify specific files
1. [RPM/SRPM file](./docs/how%20to%20sign%20rpm&srpm%20file.md)
2. [Kernel module file](./docs/how%20to%20sign%20kernelmodule%20file.md)
3. [EFI file](./docs/how%20to%20sign&verify%20a%20EFI%20image.md)
4. [Generic file](./docs/how%20to%20sign&verify%20a%20generic%20file.md)



# Quick Start Guide
## Local development
There are two ways to setup a local development environment:
- Build and run binary directly:

   Run these commands correspondingly to build service binary:
   ```shell
   # set nightly toolchain
   rustup override set nightly-2023-08-08
   # build binary
   cargo build --bin control-server/data-server/signatrust-client/control-admin   
   # running command
   RUST_BACKTRACE=full RUST_LOG=debug ./target/debug/<binary> --config <config-file-path>
   ```

   Additionally, we have developed a script to set up the MySQL database in a Docker environment. To use the script, you will
   need to install the Docker server, the MySQL binary, and the [Sqlx binary](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md#enable-building-in-offline-mode-with-query).
   Once you have these installed, simply run the command below to initialize the database.
   ```shell
   make db
   ```
  
    Finally, use the command below to generate the default user and token for test environment, including:
    1.  generate default admin and it's token, used for API test
    2.  generate default keys, `1default-x509-ca`, `default-x509-ica`, `default-x509-ee`, `default-pgp-rsa` and `default-pgp-eddsa`
   ```shell
   make init
   ```
    Then we can start the control-server and data-server with default config file in config folder:
    ```shell
    # running command
    RUST_BACKTRACE=full RUST_LOG=debug ./target/debug/control-server --config <path-to-default-sever-config-file>
    # running command
    RUST_BACKTRACE=full RUST_LOG=debug ./target/debug/data-server --config <path-to-default-server-config-file>
    ```
    The control-server will start at `localhost:8080` and the data-server will start at `localhost:8088` and both start without ssl enabled.
    For the last step, use client to sign a generic file
    ```shell
    RUST_BACKTRACE=FULL RUST_LOG=info ./target/debug/signatrust-client --config <path-to-default-client-config-file> add  --key-name default-pgp-rsa --file-type generic  --key-type pgp .data/test --detached
    ```
- Using docker compose:

   Alternately, you can use `docker compose` to setup a develop environment easily:
   ```bash
   docker compose up
   ```
   This will build docker images for `redis`, `mysql`, `control-server` and `data-server` and start them

When using memory backend, to ensure the security of sensitive data, Signatrust requires an external KMS system for encryption and decryption. However,
   to run the system locally for development purpose, you will need to configure a **dummy** KMS provider
   ```shell
   [kms-provider]
   type = "dummy"
   ```

In order to develop without the need of setting up the external OIDC server, simple run the prepared script which will generate the default admin&token and the default keys:
```shell
make init
```
Pay attention to the command output:
```shell
...skipped output
[Result]: Administrator tommylikehu@gmail.com has been successfully created with token XmUICsVV48EjfkWYv3ch1eutRJOQh7mp3bRfmQDL will expire 2023-09-23 11:20:33 UTC
...skipped output
[Result]: Keys 'default-pgp' type pgp has been successfully generated
[Result]: Keys 'default-x509' type x509 has been successfully generated
```
Now you can use this token to debug the control service API or use the pgp keys for signing rpm packages with client.
```shell
curl -k --header "Authorization:XmUICsVV48EjfkWYv3ch1eutRJOQh7mp3bRfmQDL" -v http://localhost:8080/api/v1/keys/\?page_size\=100\&page_number\=1
```
```shell
RUST_BACKTRACE=full RUST_LOG=info ./target/debug/signatrust-client --config <client-config-file-path> add --key-name default-pgp  --file-type rpm --key-type pgp .data/simple.rpm
```
## OpenAPI Documentation
Signatrust supports online openAPI documentation, once control server starts, navigate to `localhost:8080/api/swagger-ui/` and check the document. note you need to add correct `Authorization`
header to try the APIs.

## Local cluster
In order to build and run the project in a local cluster:
1. You may need to install [kind](https://kind.sigs.k8s.io/docs/user/quick-start/) and [kustomize](https://kustomize.io/) first.
2. Use our commands to build and push the images:
```shell
make client-image/make data-server-image/make control-server-image/make control-admin-image
```
3. We have prepared the kustomize yaml files in deploy folder, when your cluster and kube-config gets ready, simply run:
```shell
make deploy-local
```
and you will have these pods running:
```shell
signatrust-client-6cfddccc7-frl5r          ●  1/1          0 Running      0    0       0     n/a       0     n/a 10.10.1.120   10.0.0.56    14m
signatrust-control-admin-665fccc4b-mhknb   ●  1/1          0 Running      0    3     n/a     n/a     n/a     n/a 10.10.1.31    10.0.0.134   10m
signatrust-control-server-967f6d84f-lrbl9  ●  1/1          0 Running      2   13       0     n/a       0     n/a 10.10.0.28    10.0.0.175   17m
signatrust-database-6cfdb54c58-5c2lr       ●  1/1          0 Running      3  491       0     n/a      12     n/a 10.10.0.229   10.0.0.237   6h37m
signatrust-redis-9bcc87b46-88jbp           ●  1/1          0 Running      1   11       0     n/a       0     n/a 10.10.0.29    10.0.0.175   15m
signatrust-server-6995c84749-zj2df         ●  1/1          0 Running      1    1       0     n/a       0     n/a 10.10.0.30    10.0.0.175   4h2m
```
# Contribute

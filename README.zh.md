# Signatrust

[![RepoSize](https://img.shields.io/github/repo-size/TommyLike/signatrust)](https://gitee.com/openeuler/signatrust)

[![Clippy check](https://github.com/TommyLike/signatrust/actions/workflows/build.yml/badge.svg)](https://github.com/TommyLike/signatrust/actions/workflows/build.yml)

Signatrust 提供了一种高度安全、异步且高效的解决方案，用于使用 Rust 对 Linux 包和二进制文件进行签名。我们的统一平台可确保所有签名请求的简化操作和高吞吐量。

# 背景

在许多用例中，对 Linux 发行版的包和二进制文件进行签名至关重要。通常，PGP 用于 RPM 包、ISO 校验和、AppImage  和存储库元数据。另一方面，X509 证书用于涵盖内核模块和 EFI 的情况。虽然社区中已经有多个项目和脚本在使用，但它们通常仅限于 CI/CD  环境，并且并不总是涵盖私钥的管理和安全性。

我们观察到了几个旨在应对这些挑战的项目。

1. OBS  Sign：obs-sign由openSUSE开发，是一种广泛使用的Linux发行版打包系统，包括OBS和COPR。该解决方案为生产环境中的大量签名任务提供了全面的服务器-客户端模型。然而，系统面临的挑战之一是难以复制实例以提高吞吐量。此外，由于PGP直接位于服务器磁盘上，系统还受到安全和管理问题的困扰。
2. sbsigntools 这是官方 sbsigntools 的分支版本，可以将证书和密钥存储在 AWS CloudHSM 和 UEFI 签名的目标中。
3. 其他工具。

# 特征

Signatrust，代表 `Signature + Trust + Rust` ，是一个 Rust 项目，可以为所有挑战提供统一的解决方案：

1. 端到端安全设计：我们的端到端安全设计优先保护密钥和证书等敏感数据，在将其存储到数据库之前，通过外部 KMS 提供商（例如 CloudHSM 或华为  KMS）对其进行透明加密。此外，我们不再需要将私钥传输到客户端进行本地签名操作，而是选择将内容传递到签名服务器并直接在内存中执行签名计算。此外，所有内存密钥在掉落时都会清零，以防止交换和核心转储泄漏。目前，客户端和服务器之间的通信需要相互 TLS，未来计划升级以与 SPIFF&SPIRE 生态系统集成。
2. 高吞吐量：为了保证高吞吐量，我们将控制服务器和数据服务器分开，方便数据服务器的复制。我们还进行了多项性能增强，例如利用 gRPC 流、客户端循环、内存缓存和异步任务来提高单实例性能。
3. 完整的二进制文件支持：
   1. RPM/SRPM 签名。
   2. 分离的 PGP 签名，包括 ISO 校验和和存储库元数据。
   3. 内核模块签名。
   4. EFI。
   5. 容器镜像（待办事项）。
   6. WSL 图像（待办事项）。
   7. 应用程序图像（待办事项）。
4. 用户友好的密钥管理：Signatrust 提供用户友好的独立界面来管理敏感密钥，可以使用 OpenID Connect (OIDC) 协议与外部帐户系统无缝集成。管理员可以通过这个直观的界面生成、导入、导出和删除密钥。

# 系统上下文

![System Context](./docs/images/System%20Context.png)

# 表现

根据我们的性能测试，Signatrust 在并发测试环境中明显优于 Obs Sign（带有 pgp 代理后端）：

1. 服务器：具有有限资源（8 个 CPU 和 8GB RAM）的单实例。
2. 客户端：1/2/4 个实例，每个实例具有 8 个 CPU 和 10GB RAM 的有限资源。
3. 每个客户端的任务：对openEuler21.09源码中的整套RPM包进行签名，总计4168个包，总共18GB。
4. 每个客户端的并发数：50。
5. 注意：obs Sign 仅支持对单个文件进行签名，为了支持并发操作，我们将 `obs-sign` 命令用 golang `goroutines` 或 python `multiprocessing` 包装。

![Performance](./docs/images/sign%20performance.png)

根据这些测试结果，Signatrust 似乎是一种更高效、更有效的 RPM 包签名解决方案，值得注意的是 obs 签名的性能问题主要是由于 gpg 的代理实现造成的。

# 后端安全

为了支持不同级别的后端安全性，signatrust 支持不同类型的签名后端， `memory` 后端是默认后端，它将提供更好的性能，同时所有敏感数据都解密存储在内存中。配置如下：

```
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

# 成分

该项目由几个二进制文件组成：

1. data-server：数据服务器，用于处理签名请求并为客户端公开 gRPC。
2. control-server：控制服务器，用于处理管理请求并公开 Web UI 的 http 请求。
3. control-admin：control-admin主要用于开发环境，方便使用，即生成管理员和令牌，无需集成外部OIDC服务器。
4. 客户端：客户端负责在本地处理签名任务，并与数据服务器交换签名。
5. app：管理员用来管理密钥和令牌的应用程序。

# 签署/验证特定文件的文件

1. RPM/SRPM 文件
2. 内核模块文件
3. EFI文件
4. 通用文件

# 快速入门指南

## 本地开发

设置本地开发环境有两种方法：

- 直接构建并运行二进制文件：

  相应地运行这些命令来构建或运行项目可执行二进制文件：

  ```
  # set nightly toolchain
  rustup override set nightly-2023-08-08
  # build binary
  cargo build --bin control-server/data-server/signatrust-client/control-admin
  # running command
  RUST_BACKTRACE=full RUST_LOG=debug ./target/debug/<binary> --config <config-file-path>
  ```

  此外，我们还开发了一个脚本来在 Docker 环境中设置 MySQL 数据库。要使用该脚本，您需要安装 Docker 服务器、MySQL 二进制文件和 Sqlx 二进制文件。安装完这些后，只需运行以下命令即可初始化数据库。

  ```
  make db
  ```

- 使用 docker 撰写：

  或者，您可以使用 `docker compose` 轻松设置开发环境：

  ```
  docker compose up
  ```

  这将为 `redis` 、 `mysql` 、 `control-server` 和 `data-server` 构建 docker 镜像并启动它们

使用内存后端时，为了保证敏感数据的安全，Signatrust 需要外部 KMS 系统进行加解密。但是，要在本地运行系统以进行开发，您需要配置一个虚拟的 KMS 提供程序

```
[kms-provider]
type = "dummy"
```

为了无需设置外部 OIDC 服务器进行开发，只需运行准备好的脚本即可生成默认的 admin&token 和默认密钥：

```
make init
```

注意命令输出(`created with token`的后面就是curl需要的 Authorization header)：

```
...skipped output
[Result]: Administrator tommylikehu@gmail.com has been successfully created with token XmUICsVV48EjfkWYv3ch1eutRJOQh7mp3bRfmQDL will expire 2023-09-23 11:20:33 UTC
...skipped output
[Result]: Keys 'default-pgp' type pgp has been successfully generated
[Result]: Keys 'default-x509' type x509 has been successfully generated
```

现在您可以使用此令牌来调试控制服务 API 或使用 pgp 密钥与客户端签署 rpm 包。

```
curl -k --header "Authorization:XmUICsVV48EjfkWYv3ch1eutRJOQh7mp3bRfmQDL" -v http://localhost:8080/api/v1/keys/\?page_size\=100\&page_number\=1
```

```
RUST_BACKTRACE=full RUST_LOG=info ./target/debug/signatrust-client --config <client-config-file-path> add --key-name default-pgp  --file-type rpm --key-type pgp .data/simple.rpm
```

## 开放API文档

Signatrust 支持在线 openAPI 文档，控制服务器启动后，导航到 `localhost:8080/api/swagger-ui/` 并检查文档。请注意，您需要添加正确的 `Authorization` 标头才能尝试 API。

## 本地集群

为了在本地集群中构建并运行项目：

1. 您可能需要先安装 kind 和 kustomize。
2. 使用我们的命令来构建和推送图像：

```
make client-image/make data-server-image/make control-server-image/make control-admin-image
```

1. 我们已经在部署文件夹中准备了 kustomize yaml 文件，当您的集群和 kube-config 准备就绪时，只需运行：

```
make deploy-local
```

您将运行这些 pod：

```
signatrust-client-6cfddccc7-frl5r          ●  1/1          0 Running      0    0       0     n/a       0     n/a 10.10.1.120   10.0.0.56    14m
signatrust-control-admin-665fccc4b-mhknb   ●  1/1          0 Running      0    3     n/a     n/a     n/a     n/a 10.10.1.31    10.0.0.134   10m
signatrust-control-server-967f6d84f-lrbl9  ●  1/1          0 Running      2   13       0     n/a       0     n/a 10.10.0.28    10.0.0.175   17m
signatrust-database-6cfdb54c58-5c2lr       ●  1/1          0 Running      3  491       0     n/a      12     n/a 10.10.0.229   10.0.0.237   6h37m
signatrust-redis-9bcc87b46-88jbp           ●  1/1          0 Running      1   11       0     n/a       0     n/a 10.10.0.29    10.0.0.175   15m
signatrust-server-6995c84749-zj2df         ●  1/1          0 Running      1    1       0     n/a       0     n/a 10.10.0.30    10.0.0.175   4h2m
```

# 贡献
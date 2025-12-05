#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

function check-binary {
  echo "checking control-admin binary"
  which ./target/debug/control-admin >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "control-admin binary not found, please use command 'cargo build --bin control-admin' to build it first, exiting."
    exit 1
  else
    echo -n "found control-admin binary, " && docker version
  fi
}

function create_default_admin {
  echo "start to create default admin with tommylikehu@gmail.com"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml create-admin --email tommylikehu@gmail.com
}

function create_default_x509_ca {
  echo "start to create default x509 CA identified with default-x509"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-x509ca --description "used for test purpose only" --key-type x509ca --email tommylikehu@gmail.com --param-key-type rsa --param-key-size 2048 \
  --param-x509-common-name Infra --param-x509-organization Huawei --param-x509-locality ShenZhen --param-x509-province-name GuangDong --param-x509-country-name CN --param-x509-organizational-unit "Infra CA" --digest-algorithm sha2_256 --visibility public
}

function create_default_x509_ica {
  echo "start to create default x509 ICA identified with default-x509"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-x509ica --description "used for test purpose only" --key-type x509ica --email tommylikehu@gmail.com --param-key-type rsa --param-key-size 2048 \
  --param-x509-common-name Infra --param-x509-organization Huawei --param-x509-locality ShenZhen --param-x509-province-name GuangDong --param-x509-country-name CN --param-x509-organizational-unit "Infra ICA" --digest-algorithm sha2_256 --param-x509-parent-name default-x509ca --visibility public
}

function create_default_x509_ee {
  echo "start to create default x509 EE certificate identified with default-x509"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-x509ee --description "used for test purpose only" --key-type x509ee --email tommylikehu@gmail.com --param-key-type rsa --param-key-size 2048 \
  --param-x509-common-name Infra --param-x509-organization Huawei --param-x509-locality ShenZhen --param-x509-province-name GuangDong --param-x509-country-name CN --param-x509-organizational-unit "Infra EE" --digest-algorithm sha2_256 --param-x509-parent-name default-x509ica --visibility public
}

function create_default_x509_ca_sm2 {
  echo "start to create default x509_sm2 CA identified with default-x509ca-sm2"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-x509ca-sm2 --description "used for test purpose only" --key-type x509ca --email tommylikehu@gmail.com --param-key-type sm2 --param-key-size 256 \
  --param-x509-common-name Infra --param-x509-organization Huawei --param-x509-locality ShenZhen --param-x509-province-name GuangDong --param-x509-country-name CN --param-x509-organizational-unit "Infra CA" --digest-algorithm sm3 --visibility public
}

function create_default_x509_ia_sm2 {
  echo "start to create default x509 sm2 ICA identified with default-x509"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-x509ica-sm2 --description "used for test purpose only" --key-type x509ica --email tommylikehu@gmail.com --param-key-type sm2 --param-key-size 256 \
  --param-x509-common-name Infra --param-x509-organization Huawei --param-x509-locality ShenZhen --param-x509-province-name GuangDong --param-x509-country-name CN --param-x509-organizational-unit "Infra ICA" --digest-algorithm sm3 --param-x509-parent-name default-x509ca-sm2 --visibility public
}

function create_default_x509_ee_sm2 {
  echo "start to create default x509 sm2 EE certificate identified with default-x509"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-x509ee-sm2 --description "used for test purpose only" --key-type x509ee --email tommylikehu@gmail.com --param-key-type sm2 --param-key-size 256 \
  --param-x509-common-name Infra --param-x509-organization Huawei --param-x509-locality ShenZhen --param-x509-province-name GuangDong --param-x509-country-name CN --param-x509-organizational-unit "Infra EE" --digest-algorithm sm3 --param-x509-parent-name default-x509ica-sm2 --visibility public
}

function create_default_openpgp_rsa {
  echo "start to create default openpgp keys identified with default-pgp"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-pgp-rsa --description "used for test purpose only" --key-type pgp --email tommylikehu@gmail.com --param-key-type rsa --param-key-size 2048 --param-pgp-email infra@openeuler.org --param-pgp-passphrase husheng1234 --digest-algorithm sha2_256 --visibility public
}

function create_default_openpgp_eddsa {
  echo "start to create default openpgp keys identified with default-pgp"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-pgp-eddsa --description "used for test purpose only" --key-type pgp --email tommylikehu@gmail.com --param-key-type eddsa --param-pgp-email infra@openeuler.org --param-pgp-passphrase husheng1234 --digest-algorithm sha2_256 --visibility public
}

function create_default_private_openpgp_rsa {
  echo "start to create default openpgp keys identified with default-pgp"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-pgp-rsa --description "used for test purpose only" --key-type pgp --email tommylikehu@gmail.com --param-key-type rsa --param-key-size 2048 --param-pgp-email infra@openeuler.org --param-pgp-passphrase husheng1234 --digest-algorithm sha2_256 --visibility private
}




echo "Preparing basic keys for signatrust......"

check-binary

echo "==========================================="

create_default_admin

create_default_x509_ca

create_default_x509_ica

create_default_x509_ee

create_default_x509_ca_sm2

create_default_x509_ia_sm2

create_default_x509_ee_sm2

create_default_openpgp_rsa

create_default_openpgp_eddsa

create_default_private_openpgp_rsa

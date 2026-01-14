GIT_COMMIT=$(shell git rev-parse --verify HEAD)
REGISTRY_NAME = ${REGISTRY_NAME_ENV}

## Prepare the redis database
redis:
	./scripts/initialize-redis.sh

## Prepare mysql database
db: redis
	./scripts/initialize-database.sh


## Prepare basic administrator and keys
init:
	./scripts/initialize-user-and-keys.sh

builder-image:
	docker build -t $(REGISTRY_NAME)/signatrust-builder:$(GIT_COMMIT) -f docker/Dockerfile.openeuler .

build-client-image:
	docker build -t $(REGISTRY_NAME)/signatrust-client:$(GIT_COMMIT) --build-arg BINARY=signatrust-client -f docker/Dockerfile .
push-client-image:
	docker push $(REGISTRY_NAME)/signatrust-client:$(GIT_COMMIT)

client-publish: client-publish-glibc-x86-64 client-publish-glibc-aarch64 client-publish-musl-x86-64 client-publish-musl-aarch64

client-publish-glibc-x86-64:
	docker build -t $(REGISTRY_NAME)/signatrust-client-linux-glibc-x86-64:$(GIT_COMMIT) --build-arg BINARY=signatrust-client --build-arg PLATFORM=x86_64-unknown-linux-gnu -f docker/Dockerfile.client_glibc .
client-publish-glibc-aarch64:
	docker build -t $(REGISTRY_NAME)/signatrust-client-linux-glibc-aarch64:$(GIT_COMMIT) --build-arg BINARY=signatrust-client --build-arg PLATFORM=aarch64-unknown-linux-gnu -f docker/Dockerfile.client_glibc .

client-publish-musl-x86-64:
	docker build -t $(REGISTRY_NAME)/signatrust-client-linux-musl-x86-64:$(GIT_COMMIT) --build-arg BINARY=signatrust-client -f docker/Dockerfile.client_musl_x86_64 .
client-publish-musl-aarch64:
	docker build -t $(REGISTRY_NAME)/signatrust-client-linux-musl-aarch64:$(GIT_COMMIT) --build-arg BINARY=signatrust-client -f docker/Dockerfile.client_musl_aarch64 .

build-data-server-image:
	docker build -t $(REGISTRY_NAME)/signatrust-data-server:$(GIT_COMMIT) --build-arg BINARY=data-server -f docker/Dockerfile.data-server .
push-data-server-image:
	docker push $(REGISTRY_NAME)/signatrust-data-server:$(GIT_COMMIT)

build-control-server-image:
	docker build -t $(REGISTRY_NAME)/signatrust-control-server:$(GIT_COMMIT) --build-arg BINARY=control-server -f docker/Dockerfile.control-server .
push-control-server-image:
	docker push $(REGISTRY_NAME)/signatrust-control-server:$(GIT_COMMIT)

control-admin-image:
	docker build -t $(REGISTRY_NAME)/signatrust-control-admin:$(GIT_COMMIT) --build-arg BINARY=control-admin -f docker/Dockerfile .
push-control-admin-image:
	docker push $(REGISTRY_NAME)/signatrust-control-admin:$(GIT_COMMIT)

app-image:
	docker build -t $(REGISTRY_NAME)/signatrust-app:$(GIT_COMMIT) -f app/Dockerfile ./app
push-app-image:
	docker push $(REGISTRY_NAME)/signatrust-app:$(GIT_COMMIT)

deploy-local:
	kustomize build ./deploy | kubectl apply -f -

remove-images: remove-app-image remove-client-image remove-control-server-image remove-data-server-image remove-control-admin-image

remove-app-image:
	- docker rmi $(REGISTRY_NAME)/signatrust-app:$(GIT_COMMIT)
remove-client-image:
	- docker rmi $(REGISTRY_NAME)/signatrust-client:$(GIT_COMMIT)
remove-control-server-image:
	- docker rmi $(REGISTRY_NAME)/signatrust-control-server:$(GIT_COMMIT)
remove-data-server-image:
	- docker rmi $(REGISTRY_NAME)/signatrust-data-server:$(GIT_COMMIT)
remove-control-admin-image:
	- docker rmi $(REGISTRY_NAME)/signatrust-control-admin:$(GIT_COMMIT)
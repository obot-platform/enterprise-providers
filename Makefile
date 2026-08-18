build:
	./scripts/build.sh

test:
	./scripts/test.sh

vet:
	./scripts/vet.sh

package-providers:
	./scripts/package-providers.sh

docker-build:
	docker build -t obot-platform/enterprise-providers:latest .

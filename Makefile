build:
	./scripts/build.sh

package-providers:
	./scripts/package-providers.sh

docker-build:
	docker build -t obot-platform/enterprise-providers:latest .

build:
	docker build -t ghcr.io/lehigh-university-libraires/antibot:main .

test:
	docker compose -f ci/docker-compose.yaml up --build -d > /dev/null 2>&1
	bash ./ci/test.sh
	docker compose -f ci/docker-compose.yaml down > /dev/null 2>&1

clean:
	docker compose -f ci/docker-compose.yaml down

.PHONY: build test clean

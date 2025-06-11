#!/usr/bin/env bash

set -eou pipefail

echo "Waiting for apache to come online"
while ! curl -s -o /dev/null -f http://localhost:8080/; do sleep 1; done
echo "Waiting for antibot to come online"
while ! curl -s -o /dev/null -f http://localhost:8888/healthcheck; do sleep 1; done

echo "Starting tests"

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/ | grep -q 200 \
  || (echo "Unprotected path should return 200" && exit 1)

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/foo | grep -q 404 \
  || (echo "404 on unprottected should return 404" && exit 1)

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/protected | grep -q 429 \
  || (echo "Protected path should challenge" && exit 1)

curl -s -o /dev/null -w "%{http_code}\n" \
  --data-raw 'cf-turnstile-response=XXXX.DUMMY.TOKEN.XXXX' \
  "http://localhost:8080/protected?challenge=true" | grep -q 200 \
  || (echo "POST to a protected path with challenge key and no body should 404" && exit 1)

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/protected | grep -q 404 \
  || (echo "Protected path should no longer challenge" && exit 1)

echo "Tests passed 🚀"


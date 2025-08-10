#!/bin/bash

podman pod create --name prom-policy -p 8081:8080 -p 8082:8081

podman run -d --replace --pod prom-policy --rm \
	--name cerbos 
	-v cerbosconfig:/config 
	-e GITHUB_USERNAME=$(vault username) \
	-e GITHUB_TOKEN="$(vault token)" \
	ghcr.io/cerbos/cerbos:latest \
		server --config=/config/config.yml

podman run -d --replace --pod prom-policy --rm \
	--name prom-proxy \
 	-e CERBOSAPI=grpc://127.0.0.1:3593 \
 	-e PROMAPI=https://prometheus.apps.example.com \
 	-e MAX_WORKERS=10 \
 	-e DEBUG=0 \
 	localhost/prom-authz:v1.0.4

podman run -d --replace --pod prom-policy --rm \
	--name perses \
	docker.io/persesdev/perses:latest \
		--web.listen-address=:8082

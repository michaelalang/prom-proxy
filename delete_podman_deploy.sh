#!/bin/bash

podman rm -f cerbos prom-proxy perses
podman pod delete prom-policy 

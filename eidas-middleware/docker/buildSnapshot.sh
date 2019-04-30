#!/bin/bash
cp ../target/eidas-middleware.jar .
docker build --no-cache -f Dockerfile-Snapshot .

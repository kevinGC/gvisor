#!/bin/bash

# TODO: Delete

sudo apt update
sudo apt install -y make docker.io
sudo usermod -aG docker $USER
newgrp docker
export GCS_BUCKET="gs://istio-dev2-testbucket/"

#!/bin/bash

# Copyright 2020 Google LLC
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.

set -xeuo pipefail

# TODO: Remove the "runsc" from the filename.

# If GCP_PROJECT isn't set, get the current gcloud project.
declare -r GCP_PROJECT="${GCP_PROJECT:=$(gcloud config get-value project 2>1 | tail -n 1)}"
# Logs will be uploaded to a GCS bucket if provided. GCS bucket should be
# formatted in the style of "gs://bucketname".
# TODO: Remove this default.
declare -r GCS_BUCKET="${GCS_BUCKET:=gs://istio-dev2-testbucket/}"

declare -p DOCKER_RUN_ARGS=(
  "--rm"
  "--volume" "${HOME}/.ssh:/root/.ssh"
)

# Environment variables that must be set for the container entrypoint.
declare -p ENV_VARS=(
  "JOB_NAME=containerd-node-e2e"
  # "GOOGLE_APPLICATION_CREDENTIALS=" # TODO: Override when running in kokoro.
  "BOOTSTRAP_UPLOAD_BUCKET_PATH=${GCS_BUCKET}"
)

for ENV_VAR in "${ENV_VARS[@]}"; do
  DOCKER_RUN_ARGS+=("--env" "$ENV_VAR")
done

# Prefix each environment variable to be passed as docker arguments.

# Entrypoint is:
#   * test-infra/images/bootstrap/entrypoint.sh, which calls
#   * test-infra/images/bootstrap/runner.sh, which calls
#   * test-infra/images/bootstrap/bootstrap.py
# bootstrap.py appears to actually run the jobs on jenkins or maybe it just
# wraps jenkins jobs to be run in prow.

# Arguments passed to the image entrypoint
# https://github.com/kubernetes/test-infra/images/kubekins-e2e, which is based
# on images/bootstrap/images/kubekins-e2e, which is based on images/bootstrap.
# TODO: s/kevinGC/google/, master
declare -p BOOTSTRAP_ARGS=(
  "--repo=k8s.io/kubernetes=master"
  "--repo=github.com/containerd/cri=master"
  "--repo=github.com/kevinGC/gvisor=kubetests"
  "--root=/go/src"
  "--upload=${GCS_BUCKET}"
  "--scenario=kubernetes_e2e"
  "--timeout=90"
)

if ! [[ -n "${GCS_BUCKET}" ]]; then
  BOOTSTRAP_ARGS+=("--upload=${GCS_BUCKET}")
fi

# Arguments passed to the test scenario
# https://github.com/kubernetes/test-infra/blob/master/scenarios/kubernetes_e2e.py.
# TODO: Some of these args don't show up in kuberenetes_e2e.py.
declare -p SCENARIO_ARGS=(
  "--node-args=--image-config-file=/go/src/github.com/kevinGC/gvisor/test/kubernetes/image-config.yaml"
  "--deployment=node"
  "--gcp-project=${GCP_PROJECT}"
  "--gcp-zone=us-central1-f"
  '--node-test-args=--container-runtime=remote --container-runtime-endpoint=unix:///run/containerd/containerd.sock --container-runtime-process-name=/home/containerd/usr/local/bin/containerd --container-runtime-pid-file= --kubelet-flags="--cgroups-per-qos=true --cgroup-root=/ --runtime-cgroups=/system.slice/containerd.service" --extra-log="{\"name\": \"containerd.log\", \"journalctl\": [\"-u\", \"containerd\"]}"'
  "--node-tests=true"
  "--provider=gce"
  '--test_args=--nodes=8 --focus="\[NodeConformance\]|\[NodeFeature:FSGroup\]|\[NodeFeature:\sImageID\]" --skip="\[Flaky\]|\[Serial\]|EmptyDir.*tmpfs|Networking Granular Checks|Summary API|AllowPrivilegeEscalation should allow privilege escalation|privileged|EmptyDir volumes when FSGroup is specified" --flakeAttempts=2'
  "--timeout=65m"
)

# TODO: Remove this, should be up to the driver.
gcloud auth configure-docker --quiet
gcloud compute config-ssh --quiet
sudo gcloud compute config-ssh --quiet

whoami

# TODO: Avoid this hack.
# TODO: Pin to specific version.
# declare -r IMAGE="gcr.io/k8s-testimages/kubekins-e2e:v20200819-491a5ae-master"
declare -r IMAGE="gcr.io/istio-dev2/kubekins-e2e-gvisor:latest"
docker pull "${IMAGE}"

docker run "${DOCKER_RUN_ARGS[@]}" "$IMAGE" "${BOOTSTRAP_ARGS[@]}" -- "${SCENARIO_ARGS[@]}"

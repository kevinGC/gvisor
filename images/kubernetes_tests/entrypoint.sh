#!/usr/bin/env bash

# Copyright something

set -o errexit
set -o nounset
set -o pipefail

# get test-infra for latest bootstrap etc
git clone https://github.com/kubernetes/test-infra

# TODO(krakauer): This hack lets us use the VM's default credentials instead of
# a service account. However, it may be better to call the scenario directly.
sed -i -e 's/# TODO(fejta): allow use of existing gcloud auth/return/' \
  test-infra/jenkins/bootstrap.py

# BOOTSTRAP_UPLOAD_BUCKET_PATH=${BOOTSTRAP_UPLOAD_BUCKET_PATH:-"gs://kubernetes-jenkins/logs"}

# --service-account="${GOOGLE_APPLICATION_CREDENTIALS}" \
# actually start bootstrap and the job, under the runner (which handles dind etc.)
/usr/local/bin/runner.sh \
    ./test-infra/jenkins/bootstrap.py \
        --job="${JOB_NAME}" \
        --upload="${BOOTSTRAP_UPLOAD_BUCKET_PATH}" \
        "$@"

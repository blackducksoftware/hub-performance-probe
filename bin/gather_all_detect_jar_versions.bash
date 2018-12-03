#!/bin/bash

# Utility to gather all the Black Duck hub detect jar files

TARGET_DIR=$1

if [ -z "${TARGET_DIR}" ] || [ ! -d "${TARGET_DIR}" ]; then
	echo "You must supply a target dir to copy the jar files to"
	exit 1
fi

# Add versions here as they are released
# See https://synopsys.atlassian.net/wiki/spaces/INTDOCS/pages/622673/Detect+Properties for list of
# Hub detect versions
DETECT_VERSIONS="3.0.0 3.0.1 3.1.0 3.1.1 3.2.0 3.2.1 3.2.2 3.2.3 4.0.0 4.1.0 4.2.0 4.3.0 4.4.1"

for version in ${DETECT_VERSIONS}
do
	echo "Downloading hub detect $version and copying the jar file to ${TARGET_DIR}"
	export DETECT_LATEST_RELEASE_VERSION=${version}
	bash <(curl -s https://blackducksoftware.github.io/hub-detect/hub-detect.sh) -h > /dev/null 2>&1
	cp /tmp/hub-detect-${version}.jar ${TARGET_DIR}
done
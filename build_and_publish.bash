#!/bin/bash

TAGS=${1:-latest}

IFS=',' read -r -a image_tags <<< "${TAGS}"
for image_tag in "${image_tags[@]}"
do
	BUILD_TAG_OPTS="${BUILD_TAG_OPTS} -t gsnyderbds/hub_performance_probe:${image_tag}"
done

docker build ${BUILD_TAG_OPTS} -f hub_performance_probe.dockerfile .

##################
# Publish the image for each tag supplied
##################
for image_tag in "${image_tags[@]}"
do
	docker push gsnyderbds/hub_performance_probe:${image_tag}
done

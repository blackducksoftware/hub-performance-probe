#!/bin/bash

docker build -t gsnyderbds/hub_performance_probe -f hub_performance_probe.dockerfile .
docker push gsnyderbds/hub_performance_probe
#!/bin/bash

# replicate the showcase app
BASE_TEST_PROJECT=$1

cd test_projects

for i in {1..50}
do
	cp -R $BASE_TEST_PROJECT ${BASE_TEST_PROJECT}$i
done
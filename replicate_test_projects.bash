#!/bin/bash

# replicate the showcase app which is from Apache Struts and 
# Tutorial_files which are the example files used in the Protex tutorial for snippet matching
cd test_projects

for base_project in showcase Tutorial_Files
do
	for i in {1..50}
	do
		cp -R ${base_project} ${base_project}$i
	done
done
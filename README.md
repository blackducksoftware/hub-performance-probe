## Overview
The Hub performance probe provides a benchmarking tool to compare the relative performance of Hub server environments.

It will run hub detect multiple times on the same test project (Struts showcase app), and with increasing concurrency, and accumulate the results into a CSV file. The results can then be compared to the results obtained in other Hub server environments to assess the relative performance of the environment being analyzed. 

## Requirements
The Hub performance probe can either be run directly using python 3.4+ OR can be run via docker using docker CE 17.x or 18.x.

## To build

[![Build Status](https://travis-ci.org/blackducksoftware/hub-performance-probe.svg?branch=master)](https://travis-ci.org/blackducksoftware/hub-performance-probe)
[![Black Duck Security Risk](https://copilot.blackducksoftware.com/github/repos/blackducksoftware/hub-performance-probe/branches/master/badge-risk.svg)](https://copilot.blackducksoftware.com/github/repos/blackducksoftware/hub-performance-probe/branches/master)

```
docker build -f hub_performance_probe.dockerfile -t hub_performance_probe .
```

## To run
### To run directly using python

#### To get help

```
python hub_performance_probe.py -h
```

#### To run using python

1. Install/setup python 3.4+ and pip. 
    * Are you using virtualenv? you should.

1. Clone this repo and cd into it

1. Install the Hub probe python requirements using 

    ```
    pip install -r requirements.txt
    ```

1. Now run the probe, e.g.

	```
	python3 hub_performance_probe.py https://my-hub-dns my-hub-account my-password
	```

    where you should substitute the following,

    * my-hub-dns should be the DNS (or IP address) for your Hub server
    * my-hub-account is an account on the Hub server that has the correct privileges to process a scan

### To run via docker

#### To get help

```
docker run gsnyderbds/hub_performance_probe -h
```

#### To run the container

1. Make a directory for putting the results into, e.g.

    ```
    mkdir /tmp/probe_results
    ```

1. Run the container, mounting /tmp/probe_results to your host's /var/log

    ```
    docker run -d -v /tmp/probe_results:/var/log gsnyderbds/hub_performance_probe https://my-hub-dns
    cd /tmp/probe_results
    tail -f hub_probe.log
    ```
     
    where you should substitute the following,

    * my-hub-dns should be the DNS (or IP address) for your Hub server
    * gsnyderbds/hub_performance_probe should be substituted with your own repo/tag if you decide to build and use your own

3. Check /tmp/probe_results/hub_probe.log for progress and, by default, results are written into .../hub-performance-results.csv

## Release History
* Docker Hub tag: 1.0, Date: Nov 1, 2018
    * supporting different combinations of detect options
    * adding support for snippet matching tests using Protex's tutorial files
    * organizing tests into two major benchmarking areas: component matching (i.e. without snippet matching), and snippet matching
        * this makes it easier to extend, and segment, benchmarking categories
        * can more easily add *binary matching* in future and then choose which type of benchmark you want to run

## Future Work
* Provide a cleanup option that will remove the test projects from the Hub server
* Capture the command used to run the probe along with the version info so the exact tests can be repeated at a later date (e.g. 6 months later or a year later)

If you have feedback regarding the Hub performance probe submit an issue or contact Glenn Snyder gsnyder@synopsys.com


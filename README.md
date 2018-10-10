## Overview ##
The Hub performance probe provides a benchmarking tool to compare the relative performance of Hub server environments.

It will run hub detect multiple times on the same test project (Struts showcase app), and with increasing concurrency, and accumulate the results into a CSV file. The results can then be compared to the results obtained in other Hub server environments to assess the relative performance of the environment being analyzed. 

## Requirements ##
The Hub performance probe can either be run directly using python 3.4+ OR can be run via docker using docker CE 17.x or 18.x.

## To build ##

[![Build Status](https://travis-ci.org/blackducksoftware/hub-performance-probe.svg?branch=master)](https://travis-ci.org/blackducksoftware/hub-performance-probe)

```
docker build -f hub_performance_probe.dockerfile -t hub_performance_probe .
```

## To run ##
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

1. Make a directory that the container can mount to write the results into, e.g.

    ```shell
    mkdir /tmp/log
    ```

2. Now run the container, mounting the directory you created in the first step

    ```
    docker run -d -v /tmp/log:/var/log gsnyderbds/hub_performance_probe https://my-hub-dns --token=$token
    cd /tmp/log
    tail -f hub_probe.log
    ```
     
    Running the container with pasword authentication 

    ```
    docker run -d -v /tmp/log:/var/log gsnyderbds/hub_performance_probe https://my-hub-dns --username=my-hub-account --password=my-password
    cd /tmp/log
    tail -f hub_probe.log
    ```

    where you should substitute the following,

    * my-hub-dns should be the DNS (or IP address) for your Hub server
    * my-hub-account is an account on the Hub server that has the correct privileges to process a scan
    * gsnyderbds/hub_performance_probe should be substituted with your own repo/tag if you decide to build and use your own

3. When the docker container is finished check the directory from the first step for the results

## Future Work ##
* Provide a cleanup option that will remove the test projects from the Hub server
* Capture the command used to run the probe along with the version info so the exact tests can be repeated at a later date (e.g. 6 months later or a year later)
* Add different combinations of detect options, e.g.
  * with and without policy checks
  * with and without risk report generation
  * with and without file system scanning
  * with and without snippet matching


If you have feedback regarding the Hub performance probe submit an issue or contact Glenn Snyder gsnyder@synopsys.com

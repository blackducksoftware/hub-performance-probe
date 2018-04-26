#!/bin/env python

# Runs Hub Detect on a standard set of test projects, gathers and then publishes the metrics
# for comparision purposes
#

import boto3 # for interfacing to AWS
import csv
from datetime import datetime
from hub_detect_wrapper import HubDetectWrapper
import logging
import multiprocessing
import os.path
from pprint import pprint
import threading

# should be a relative path so we can relocate all the outputs whereever we want, see below
TEST_PROJECTS_FOLDER="./test_projects"

# Add another disctionary for each test project that will be part of the test project list
TEST_PROJECTS=[
	{'project_name': 'TEST-PROBE-showcase-%s' % i, 'version': '2.3.30', 'folder' : '%s/showcase%s' % (TEST_PROJECTS_FOLDER, i)} for i in range(1,51)
]

class HubPerformanceProbe:
	'''Starting with one thread test the performance of the hub server by running hub detect on a known project.
	Gradually increase the concurrency up to the limits of the host machine to probe how the hub server performs 
	with increased concurrency.
	'''
	def __init__(
			self, 
			hub_url, 
			hub_user="sysadmin", 
			hub_password="blackduck",
			csv_output_file="out.csv",
			initial_threads=1,
			iterations=4,
			max_threads=-1,
			detect_output_base_dir=None):
		self.hub_url = hub_url
		self.hub_user = hub_user
		self.hub_password = hub_password
		self.detect_options = [
			'--detect.hub.signature.scanner.disabled=true',
			'--detect.policy.check=true',
			'--blackduck.hub.trust.cert=true',
		]
		self.results = []
		self.csv_output_file = csv_output_file
		self.initial_threads = initial_threads
		self.iterations = iterations
		# Max threads is either user specified or a function of the cpu count
		self.max_threads = max_threads if (max_threads > 0) else multiprocessing.cpu_count()
		self.detect_output_base_dir = detect_output_base_dir

	def detect_worker(self, test_project_d, iterations, test_config_d):
		logging.debug("starting %s iterations to analyze project %s with config %s" % (iterations, test_project_d, test_config_d))
		folder = test_project_d['folder']
		project_name = test_project_d['project_name']
		version = test_project_d['version']
		# relocate the output files if a base dir was specified
		if self.detect_output_base_dir:
			output_path = os.path.join(self.detect_output_base_dir, folder)
		else:
			output_path = folder
		options = [
				'--detect.project.name=%s' % project_name,
				'--detect.project.version.name=%s' % version,
				'--detect.source.path=%s' % folder,
				'--detect.output.path=%s_output' % output_path,
			]
		options.extend(self.detect_options)
		for i in range(iterations):
			logging.debug('iteration %s for project %s' % (i + 1, test_project_d))

			# using hard-coded hub detect version for now since the newest version, v3.2.0 breaks some things
			hub_detect_wrapper = HubDetectWrapper(
				self.hub_url, 
				self.hub_user, 
				self.hub_password, 
				additional_detect_options=options,
				detect_path="./hub-detect-3.1.1.jar")
			thread_project_results = hub_detect_wrapper.run()
			thread_project_results.update(test_config_d)
			self.results.append(thread_project_results)
			logging.debug('results for project %s are %s' % (test_project_d, thread_project_results))
		logging.debug("thread exiting after performing %s iterations on project %s" % (iterations, test_project_d))
		
	def _flatten_results(self):
		flattened_results = []
		for result in self.results:
			component_info = result['component_info']
			del result['component_info']
			result.update(component_info)
			flattened_results.append(result)
		return flattened_results

	def _results_as_csv(self):
		flattened_results = self._flatten_results()
		keys = flattened_results[0].keys()
		with open(self.csv_output_file, 'w') as output_file:
			dict_writer = csv.DictWriter(output_file, keys)
			dict_writer.writeheader()
			dict_writer.writerows(flattened_results)

	def run(self):
		threads = []
		analysis_iterations = self.iterations
		num_threads = self.initial_threads
		cpu_count = multiprocessing.cpu_count()
		test_config = {'max_threads': self.max_threads, 'cpu_cout': cpu_count, 'iterations': analysis_iterations}

		start = datetime.now()
		logging.debug("Probing started")
		while num_threads <= self.max_threads:
			test_config['num_threads'] = num_threads
			for i in range(num_threads):
				test_project = TEST_PROJECTS[i]
				new_thread = threading.Thread(target=self.detect_worker, args=(test_project, analysis_iterations, test_config,))
				threads.append(new_thread)
				new_thread.start()
			for t in threads:
				t.join()
			logging.debug(self.results)
			num_threads *= 2

		self._results_as_csv()

		finish = datetime.now()
		logging.debug("Finished probing, elapsed time %s" % (finish - start))

def copy_results_to_s3(results_file, s3bucket):
	s3 = boto3.resource('s3')
	data = open(results_file, 'rb')
	s3.Bucket(s3bucket).put_object(Key=results_file, Body=data)

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument("url")
	parser.add_argument("username", default="sysadmin")
	parser.add_argument("password", default="blackduck")
	parser.add_argument("--csvfile", default="/var/log/hub-performance-results.csv", help="Where to write the results in CSV format (default: out.csv")
	parser.add_argument("--detectoutputbasedir", default="/var/log/hub_probe_outputs", help="Override where detect output files are written. Useful when running the probe inside a docker container and you wnat to write to a host mounted volume")
	parser.add_argument("--description", help="A description that will be included in the test results")
	parser.add_argument("--iterations", type=int, default=4)
	parser.add_argument("--logfile", default="/var/log/hub_probe.log", help="Where to log the hub performance probe output")
	parser.add_argument("--loglevel", choices=["CRITICAL", "DEBUG", "ERROR", "INFO", "WARNING"], default="DEBUG", help="Choose the desired logging level - CRITICAL, DEBUG, ERROR, INFO, or WARNING. (default: DEBUG)")
	parser.add_argument("--s3bucket", default=None, help="If given, the results will be copied to the bucket using the CSV file name - assumes AWS is configured properly to provide write access to the bucket.")
	parser.add_argument("--maxthreads", type=int, default=-1)
	args = parser.parse_args()

	logging_levels = {
		'CRITICAL': logging.CRITICAL,
		'DEBUG': logging.DEBUG,
		'ERROR': logging.ERROR,
		'INFO': logging.INFO,
		'WARNING': logging.WARNING,
	}
	logging.basicConfig(filename=args.logfile, format='%(threadName)s: %(asctime)s: %(levelname)s: %(message)s', level=logging_levels[args.loglevel])

	hpp = HubPerformanceProbe(
		hub_url=args.url, 
		hub_user=args.username, 
		hub_password=args.password, 
		csv_output_file=args.csvfile, 
		iterations=args.iterations,
		max_threads=args.maxthreads,
		detect_output_base_dir=args.detectoutputbasedir)
	hpp.run()

	if args.s3bucket:
		copy_results_to_s3(hpp.csv_output_file, args.s3bucket)













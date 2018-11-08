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

BENCHMARKS = {
	'component_matching': {
		'test_projects' : [
			{ 'project_base_name': 'struts-showcase', 'source_path' : '{}/showcase'.format(TEST_PROJECTS_FOLDER), 'version': '2.3.2'}
		],
		'detect_scanning_options': [
			{'label': 'no-options', 'detect_options': []},
			{'label': 'policy-check', 'detect_options': ['--detect.policy.check.fail.on.severities=ALL',]},
			{'label': 'risk-report', 'detect_options': ['--detect.risk.report.pdf=true',]},
			{'label': 'policy-and-risk', 'detect_options': ['--detect.policy.check.fail.on.severities=ALL', '--detect.risk.report.pdf=true',]},
			{'label': 'no-sig-scanner', 'detect_options': ['--detect.blackduck.signature.scanner.disabled=true',]},	
			{'label': 'policy-check-no-sig-scanner', 'detect_options': ['--detect.blackduck.signature.scanner.disabled=true', '--detect.policy.check.fail.on.severities=ALL',]},
			{'label': 'policy-and-risk-no-sig-scanner', 'detect_options': ['--detect.blackduck.signature.scanner.disabled=true', '--detect.policy.check.fail.on.severities=ALL', '--detect.risk.report.pdf=true',]},
		]
	},
	'snippet_matching': {
		'test_projects' : [
			{ 'project_base_name': 'protex-tutorial-files', 'source_path' : '{}/Tutorial_Files'.format(TEST_PROJECTS_FOLDER), 'version': '1.0'}
		],
		'detect_scanning_options': [
			{'label': 'snippet-mode', 'detect_options': ['--detect.blackduck.signature.scanner.snippet.mode=true']},
		]
	}
}


class HubPerformanceProbe:
	'''Starting with one thread, test the performance of the hub server by running hub detect on a known project.
	Gradually increase the concurrency up to the limits of the client machine to probe how the hub server performs 
	with increased concurrency.
	'''
	def __init__(
			self, 
			blackduck_url, 
			blackduck_username="sysadmin", 
			blackduck_password="blackduck",
			blackduck_api_token="undefined",
			benchmarks = BENCHMARKS.keys(),
			csv_output_file="perf-probe-results.csv",
			initial_threads=1,
			iterations=2,
			max_threads=-1,
			detect_output_base_dir=None,
			detect_version="latest"):
		self.blackduck_url = blackduck_url
		self.blackduck_username = blackduck_username
		self.blackduck_password = blackduck_password
		self.blackduck_api_token = blackduck_api_token
		self.default_detect_options = [
			'--blackduck.trust.cert=true',
		]
		self.overall_results = []
		self.csv_output_file = csv_output_file
		self.initial_threads = initial_threads
		self.iterations = iterations
		# Max threads is either user specified or a function of the cpu count
		self.max_threads = max_threads if (max_threads > 0) else multiprocessing.cpu_count()
		self.detect_output_base_dir = detect_output_base_dir
		self.benchmarks = benchmarks
		self.detect_version = detect_version

	def _assemble_detect_options(self, test_config_d):
		'''Given a test configuration assemble the Hub detection options required to run it
		'''
		source_path = test_config_d['source_path']
		output_dir = test_config_d['output_dir']
		project_name = test_config_d['project_name']
		version = test_config_d['version']
		# relocate the output files if a base dir was specified
		if self.detect_output_base_dir:
			output_path = os.path.join(self.detect_output_base_dir, output_dir)
		else:
			output_path = output_dir

		project_options = [
				'--detect.project.name={}'.format(project_name),
				'--detect.project.version.name={}'.format(version),
				'--detect.source.path={}'.format(source_path),
				'--detect.output.path={}_output'.format(output_path),
			]
		detect_options = project_options
		detect_options.extend(self.default_detect_options)
		detect_options.extend(test_config_d['detect_options'])
		return detect_options

	def detect_worker(self, test_config_d, iterations):
		'''Given a a test config dict and the number of iterations
		run hub detect for the number of iterations using the details in the test config
		and add the results to the overall results
		'''
		logging.debug("starting {} iterations to analyze with config {}".format(iterations, test_config_d))
		options = self._assemble_detect_options(test_config_d)

		for i in range(iterations):
			logging.debug('iteration {} for project {}'.format(i + 1, test_config_d))

			logging.debug("using detect version {}".format(self.detect_version))

			hub_detect_wrapper = HubDetectWrapper(
				self.blackduck_url, 
				self.blackduck_username,
				self.blackduck_password,
				self.blackduck_api_token, 
				detect_version = self.detect_version,
				additional_detect_options=options)

			thread_project_results = hub_detect_wrapper.run()
			logging.debug("Got results back: {}".format(thread_project_results))
			# Failures break CSV output. 
			# I add 1 retry and if unsuccessful - exclude results
			if (thread_project_results['returncode'] > 0):
				logging.warning("Non-zero returncode on hub-detect, trying again...")
				thread_project_results = hub_detect_wrapper.run()
			if (thread_project_results['returncode'] == 0):
				thread_project_results.update(test_config_d)
				self.overall_results.append(thread_project_results)
				logging.debug('results for project {} are {}'.format(test_config_d, thread_project_results))
			else:
				logging.error("Failed to get results for project {}, hub-detect results {}".format(test_config_d, thread_project_results))
		logging.debug("thread exiting after performing {} iterations on project {}".format(iterations, test_config_d['project_name']))
		
	def _save_results_as_csv(self):
		'''Write the Hub detect results out to CSV
		'''
		logging.debug("writing {} results into CSV file {}".format(len(self.overall_results), self.csv_output_file))
		keys = self.overall_results[0].keys()
		logging.debug("Keys for CSV header row are: {}".format(keys))

		with open(self.csv_output_file, 'w') as output_file:
			dict_writer = csv.DictWriter(output_file, keys)
			dict_writer.writeheader()
			dict_writer.writerows(self.overall_results)

	def run(self):
		threads = []
		analysis_iterations = self.iterations
		num_threads = self.initial_threads
		cpu_count = multiprocessing.cpu_count()
		base_test_config = {'max_threads': self.max_threads, 'cpu_count': cpu_count, 'iterations': analysis_iterations}

		start = datetime.now()
		logging.debug("Probing started at {}".format(start))

		for benchmark in self.benchmarks:
			logging.debug("Starting {} benchmark".format(benchmark))

			for test_project in BENCHMARKS[benchmark]['test_projects']:
				logging.debug("Starting project {} in benchmark {}".format(test_project, benchmark))
				# starting with a base test config, merge different combinations of scanning options
				# and run iterations with increasing concurrency
				for detect_scanning_options in BENCHMARKS[benchmark]['detect_scanning_options']:
					# merge the detect scanning options for each benchmark AND the project options
					# with a base configuraion
					test_config_d = base_test_config.copy()
					test_config_d.update(detect_scanning_options)
					test_config_d.update(test_project)

					logging.debug("Running up to {} threads using detect options {} and test config {}".format(
						self.max_threads, detect_scanning_options, test_config_d))
					# Now, for each set of scanning options we ramp up the threads to self.max_threads
					# Each thread adds hub detect results to a list of results
					# At the end, the overall results will be written into a Excel/CSV file
					while num_threads <= self.max_threads:
						test_config_d['num_threads'] = num_threads
						logging.debug("Launching {} threads".format(num_threads))
						for thread_num in range(num_threads):
							# Construct a project name, scan name, and output directory
							#  that will be unique for each thread and project
							project_name = "{}-{}-thread{}".format(
								test_project['project_base_name'],
								detect_scanning_options['label'],
								thread_num)
							scan_location_name = project_name
							test_config_d['project_name'] = project_name
							test_config_d['scan_location_name'] = scan_location_name
							test_config_d['output_dir'] = "{}".format(project_name)

							logging.debug("Launching thread {} with {} analysis_iterations and test_config_d {}".format(
								project_name, analysis_iterations, test_config_d))
							# Passing a copy of the test config dictionary to make things thread safe
							new_thread = threading.Thread(
								name=project_name, 
								target=self.detect_worker, 
								args=(test_config_d.copy(), analysis_iterations, ))
							threads.append(new_thread)
							new_thread.start()
						logging.debug("launched {} threads, waiting for them to finish".format(num_threads))
						for t in threads:
							t.join()
							logging.debug("Joined thread {}".format(t.name))
						logging.debug("Joined all the threads ({})".format(",".join([t.name for t in threads])))
						num_threads *= 2
						threads = []

					num_threads = self.initial_threads

		self._save_results_as_csv()

		finish = datetime.now()
		logging.debug("Finished probing, elapsed time {}".format(finish - start))

def copy_results_to_s3(results_file, s3bucket):
	s3 = boto3.resource('s3')
	data = open(results_file, 'rb')
	s3.Bucket(s3bucket).put_object(Key=results_file, Body=data)

if __name__ == "__main__":
	import os
	
	path=os.environ['PATH']
	path = path + ":/usr/local/bin"
	
	os.environ['PATH'] = path
	
	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument("url")
	parser.add_argument("--username", default="sysadmin")
	parser.add_argument("--password", default="blackduck")
	parser.add_argument("--benchmarks", default="component_matching,snippet_matching", help="A comma-separate list of benchmarks - no spaces")
	parser.add_argument("--token", default="undefined", help="Use authentication token, this will ignore username and password options")
	parser.add_argument("--csvfile", default="/var/log/hub-performance-results.csv", help="Where to write the results in CSV format (default: out.csv")
	parser.add_argument("--detect_version", default="latest")
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
		args.url, 
		blackduck_username=args.username, 
		blackduck_password=args.password, 
		blackduck_api_token=args.token,
		benchmarks=args.benchmarks.split(","),
		csv_output_file=args.csvfile, 
		iterations=args.iterations,
		max_threads=args.maxthreads,
		detect_version = args.detect_version,
		detect_output_base_dir=args.detectoutputbasedir)
	hpp.run()

	if args.s3bucket:
		copy_results_to_s3(hpp.csv_output_file, args.s3bucket)













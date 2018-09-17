#!/bin/env python

# Wraps hub-detect to do the following:
#
#	* launch hub-detect with the policy check and risk report options
#		* which ensures we 'wait' for the scan results before proceeding
#		* which represents one likely way JPMC will want to run the Hub
#	* simulates pushing a message onto the Kafka-based JPMC mesasge bus using AWS SQS
#

from datetime import datetime, timedelta
import logging
import os
from pathlib import Path
import re
import subprocess

class HubDetectWrapper:
	def __init__(self, 
			hub_url, 
			hub_token, 
			target_path="./", 
			queue_name="hub_scan_results", 
			additional_detect_options=[],
			detect_log_path=None,
			detect_path=None):
		self.hub_url=hub_url
		self.hub_token = hub_token
		self.queue_name = queue_name
		self.target_path = target_path
		self.additional_detect_options = additional_detect_options
		self.hub_detect_path = Path(detect_path)
		self._get_detect(self.hub_detect_path)
		self.detect_log_path = None

	def _get_detect(self, path):
		logging.debug("hub detect path given is: %s" % str(path))
		if not path.is_file():
			with open("/tmp/hub-detect.sh", 'w') as f:
				curl_result = subprocess.run(["curl", "-s", "https://blackducksoftware.github.io/hub-detect/hub-detect.sh"], stdout=f)
				chmod_result = subprocess.run(["chmod", "+x", "/tmp/hub-detect.sh"])
				logging.debug("curl and chmod returncodes: %s, %s" % (curl_result.returncode, chmod_result.returncode))

	def _get_results(self, detect_output):
		overall_status = None
		policy_violation = None
		elapsed_time_from_hub_detect = timedelta()
		component_info = {}
		overall_status_search = re.search(r'Overall Status: ([A-Z_]+)', detect_output)
		overall_status = overall_status_search.group(1) if overall_status_search else "Overall status not found"
		policy_violation_search = re.search(r'Policy Status: ([A-Z_]+)', detect_output)
		policy_violation = policy_violation_search.group(1) if policy_violation_search else "Policy check not used"
		run_duration_search = re.search(r'run duration: ([0-9][0-9])h ([0-9][0-9])m ([0-9][0-9])s ([0-9][0-9][0-9])ms', detect_output)
		if run_duration_search:
			hours = int(run_duration_search.group(1))
			minutes = int(run_duration_search.group(2))
			seconds = int(run_duration_search.group(3))
			milliseconds = int(run_duration_search.group(4))
			elapsed_time_from_hub_detect = timedelta(seconds=(3600 * hours + 60 * minutes + seconds), milliseconds=milliseconds)
		component_info_search = re.search(
			r'([0-9]+) components in violation, ([0-9]+) components in violation, but overridden, and ([0-9]+) components not in violation', 
			detect_output)
		if component_info_search:
			component_info['components_in_violation'] = int(component_info_search.group(1))
			component_info['components_in_violation_overridden'] = int(component_info_search.group(2))
			component_info['components_not_in_violation'] = int(component_info_search.group(3))
			component_info['total_components'] = sum(component_info.values())
		component_info_search = re.search(
			r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) INFO .+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) INFO  \[main\] --- uploading', 
			detect_output,re.DOTALL)
		if component_info_search:
			first = datetime.fromisoformat(component_info_search.group(1))
			upload = datetime.fromisoformat(component_info_search.group(2))
			delta = upload - first
			component_info['local_processing'] = delta.total_seconds()
		component_info_search = re.search(
			r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) INFO  \[main\] --- uploading.+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) INFO  \[main\] --- Policy Status', 
			detect_output,re.DOTALL)
		if component_info_search:
			first = datetime.fromisoformat(component_info_search.group(1))
			upload = datetime.fromisoformat(component_info_search.group(2))
			delta = upload - first
			component_info['server_processing'] = delta.total_seconds()
		return {
			'overall_status': overall_status, 
			'policy_violation': policy_violation, 
			'elapsed_time_from_hub_detect': elapsed_time_from_hub_detect.total_seconds(), 
			'component_info': component_info}

	def _redact(self, options):
		redacted_options = []
		for option in options:
			if re.findall(r'--blackduck.hub.api.token=', str(option)):
				redacted_options.append(['--blackduck.hub.api.token=<redacted>'])
			else:
				redacted_options.append(option)
		return redacted_options

	def _output_dir(self, options):
		if self.detect_log_path:
			return self.detect_log_path
		output_dir = os.getcwd()
		for option in options:
			output_path_option_search = re.search(r'--detect.output.path=(.+)', str(option))
			if output_path_option_search:
				output_dir=output_path_option_search.group(1)
		return output_dir

	def _determine_hub_detect_subprocess_options(self):
		''' Parse the hub detect path to determine if it's a jar or shell script and adjust options accordingly
		'''
		file_extension = self.hub_detect_path.name.split(".")[-1]
		acceptable_extensions = ["sh", "jar"]

		assert file_extension in acceptable_extensions, "File extension - %s - not in acceptable list of extensions %s" % (file_extension, acceptable_extensions)

		if file_extension == "jar":
			return ["java", "-jar", self.hub_detect_path]
		else:
			return [self.hub_detect_path]


	def run(self):
		# run hub detect, parse the output results to get the information desired, formulate a message, and send the message
		start = datetime.now()
		options = self._determine_hub_detect_subprocess_options()
		options.extend([
				'--blackduck.hub.url=%s' % self.hub_url,
				'--blackduck.hub.api.token=%s' % self.hub_token,
				])
		options.extend(self.additional_detect_options)
		logging.debug('Running hub detect with options: %s' % self._redact(options))
		# logging.debug('Running hub detect with options: %s' % self._redact(options))
		result = subprocess.run(
			options, 
			stdout=subprocess.PIPE, 
			stderr=subprocess.STDOUT, 
			universal_newlines=True)
		os.makedirs(self._output_dir(options), exist_ok=True)
		with open(self._output_dir(options) + '/detect.log', 'w+') as f:
			f.write(result.stdout)
		logging.debug('Hub detect finished')
		finish = datetime.now()

		run_results = {}
		run_results.update(self._get_results(result.stdout))
		run_results['returncode'] = result.returncode
		run_results['total_elapsed_time'] = (finish - start).total_seconds()
		run_results['start_time'] = start.isoformat()
		run_results['finish_time'] = finish.isoformat()
		run_results['detect_options'] = "|".join([str(i) for i in self._redact(options)])
		return run_results


def parse_options_file(file):
	additional_detect_options = []
	with open(file) as options_file:
		for line in options_file:
			additional_detect_options.extend(line.strip().split())
	return additional_detect_options

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument("url")
	parser.add_argument("token")
	parser.add_argument("--logfile", default="detect_wrapper.log", help="Where to log the hub detect wrapper output")
	parser.add_argument("--loglevel", choices=["CRITICAL", "DEBUG", "ERROR", "INFO", "WARNING"], default="DEBUG", help="Choose the desired logging level - CRITICAL, DEBUG, ERROR, INFO, or WARNING. (default: DEBUG)")
	parser.add_argument("--options_file", help="Additional hub detect options")
	parser.add_argument("--detectlogpath", default=None, help="Override where the detect log will be saved (default is to write the log to 'detect.log' in the output path specified for hub detect or into the current directory if no output path was given to detect)")
	args = parser.parse_args()

	logging_levels = {
		'CRITICAL': logging.CRITICAL,
		'DEBUG': logging.DEBUG,
		'ERROR': logging.ERROR,
		'INFO': logging.INFO,
		'WARNING': logging.WARNING,
	}
	logging.basicConfig(filename=args.logfile, format='%(threadName)s: %(asctime)s: %(levelname)s: %(message)s', level=logging_levels[args.loglevel])

	if args.options_file:
		additional_options = parse_options_file(args.options_file)
	else:
		additional_options = []

	hdw = HubDetectWrapper(
		args.url, 
		args.token, 
		additional_detect_options=additional_options,
		detect_log_path=args.detectlogpath)
	logging.debug(hdw.run())














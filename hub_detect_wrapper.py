#!/bin/env python

from datetime import datetime, timedelta
import logging
import os
from pathlib import Path
import re
import subprocess

# TODO: Refactor this to support choosing a Hub detect version
# TODO: Eliminate the need to include a jar file in the repo?

class HubDetectWrapper:
	def __init__(self, 
			blackduck_url, 
			blackduck_username="sysadmin",
			blackduck_password="blackduck",
			blackduck_token="undefined", 
			target_path="./",
			detect_version="latest",
			additional_detect_options=[],
			detect_log_path=None,
			detect_path=None):
		self.blackduck_url=blackduck_url
		self.blackduck_username=blackduck_username
		self.blackduck_password=blackduck_password
		self.blackduck_token = blackduck_token
		self.target_path = target_path
		self.detect_version = detect_version
		self.detect_log_path = detect_log_path
		self.additional_detect_options = additional_detect_options
		if detect_path:
			self.hub_detect_path = Path(detect_path)
		else:
			self.hub_detect_path = Path(self._get_detect_path())

	def _get_detect_path(self):
		'''Get the detect shell script, if it does not already exist, then return the path to invoke the script'''
		logging.debug("Retrieving the Hub detect shell script")
		detect_shell_script_path="/tmp/hub-detect.sh"
		if not os.path.isfile(detect_shell_script_path):
			with open("/tmp/hub-detect.sh", 'w') as f:
				curl_result = subprocess.run(["curl", "-s", "https://blackducksoftware.github.io/hub-detect/hub-detect.sh"], stdout=f)
				chmod_result = subprocess.run(["chmod", "+x", detect_shell_script_path])
				logging.debug("curl and chmod returncodes: %s, %s" % (curl_result.returncode, chmod_result.returncode))
		return detect_shell_script_path

	def _get_overall_status(self, detect_output):
		overall_status_search = re.search(r'Overall Status: ([A-Z_]+)', detect_output)
		overall_status = overall_status_search.group(1) if overall_status_search else "Overall status not found"
		return {'overall_status': overall_status}

	def _get_policy_violation(self, detect_output):
		policy_violation_search = re.search(r'Policy Status: ([A-Z_]+)', detect_output)
		policy_violation = policy_violation_search.group(1) if policy_violation_search else "Policy check not used"
		return {'policy_violation': policy_violation}

	def _get_elapsed_time_from_detect(self, detect_output):
		'''The elapsed time is the time reported by hub-detect itself
		'''
		# This time should correlate with local processing time, or with (local processing time + server processing time) if using policy check or generating risk report
		run_duration_search = re.search(r'run duration: ([0-9][0-9])h ([0-9][0-9])m ([0-9][0-9])s ([0-9][0-9][0-9])ms', detect_output)
		hours = int(run_duration_search.group(1))
		minutes = int(run_duration_search.group(2))
		seconds = int(run_duration_search.group(3))
		milliseconds = int(run_duration_search.group(4))
		elapsed_time_from_hub_detect = timedelta(seconds=(3600 * hours + 60 * minutes + seconds), milliseconds=milliseconds)
		return {'elapsed_time_from_detect': elapsed_time_from_hub_detect.total_seconds()}

	def _get_component_info(self, detect_output):
		'''The component info is supplied when doing a policy check to determine which components, if any, are
		in violation of policies
		'''
		component_info = {}
		component_info_search = re.search(
			r'([0-9]+) components in violation, ([0-9]+) components in violation, but overridden, and ([0-9]+) components not in violation', 
			detect_output)
		if component_info_search:
			component_info['components_in_violation'] = int(component_info_search.group(1))
			component_info['components_in_violation_overridden'] = int(component_info_search.group(2))
			component_info['components_not_in_violation'] = int(component_info_search.group(3))
			component_info['total_components'] = sum(component_info.values())
		else:
			component_info['components_in_violation'] = 'None found'
			component_info['components_in_violation_overridden'] = 'None found'
			component_info['components_not_in_violation'] = 'None found'
			component_info['total_components'] = 'None found'
		return component_info

	def _scanner_disabled_search(self, detect_output):
		return re.search(
			r'--detect.blackduck.signature.scanner.disabled=true', 
			detect_output, re.DOTALL)

	def _uploading_search(self, detect_output):
		return re.search(
				r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) INFO  \[main\] --- uploading', 
				detect_output, re.DOTALL)

	def _completed_scans_search(self, detect_output):
		return re.search(
				r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) INFO  \[main\] --- Completed the.*[Ss]can.*', 
				detect_output, re.DOTALL)

	def _get_local_processing_time(self, detect_output):
		'''Local processing time is the time from when hub-detect connects to the Hub server until
		it has completed all local work such as signature scanning, or processing package manager files
		'''
		connected_search = re.search(
			r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) INFO  \[main\] --- Successfully connected', 
			detect_output, re.DOTALL)

		signature_scanner_disabled_search = self._scanner_disabled_search(detect_output)
		if signature_scanner_disabled_search:
			end_search = self._uploading_search(detect_output)
		else:
			end_search = self._completed_scans_search(detect_output)

		if connected_search and end_search:
			begin = datetime.fromisoformat(connected_search.group(1))
			end = datetime.fromisoformat(end_search.group(1))
			local_processing_time = (end - begin).total_seconds()
		else:
			local_processing_time = 'Not available'
		return {'local_processing': local_processing_time}

	def _get_server_processing_time(self, detect_output):
		'''Server processing time is the time after local processing has finished until we get the results
		back from the Hub server such as when using the policy check on hub-detect, or generating a PDF risk
		report as part of the scans
		'''
		signature_scanner_disabled_search = self._scanner_disabled_search(detect_output)
		if signature_scanner_disabled_search:
			begin_search = self._uploading_search(detect_output)
		else:
			begin_search = self._completed_scans_search(detect_output)

		bom_updated_search = re.search(
			r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) INFO  \[main\] --- The BOM has been updated', 
			detect_output, re.DOTALL)

		if begin_search and bom_updated_search:
			begin = datetime.fromisoformat(begin_search.group(1))
			end = datetime.fromisoformat(bom_updated_search.group(1))
			server_processing_time = (end - begin).total_seconds()
		else:
			server_processing_time = "Not available"
		return {'server_processing': server_processing_time}

	def _parse_detect_output_to_get_results(self, detect_output, detect_output_path):
		results = {}

		logging.debug("Parsing detect output for detect output file {}".format(str(detect_output_path)))
		try:
			results.update(self._get_overall_status(detect_output))
			results.update(self._get_policy_violation(detect_output))
			results.update(self._get_elapsed_time_from_detect(detect_output))
			results.update(self._get_component_info(detect_output))
			results.update(self._get_local_processing_time(detect_output))
			results.update(self._get_server_processing_time(detect_output))
		except AttributeError:
			logging.exception("AttributeError occured in parsing detect output file {}".format(str(detect_output_path)))
		return results

	def _redact(self, options):
		redacted_options = []
		for option in options:
			if re.findall(r'--blackduck.api.token=', str(option)):
				redacted_options.append(['--blackduck.api.token=<redacted>'])
			elif re.findall(r'--blackduck.password=', str(option)):
				redacted_options.append(['--blackduck.password=<redacted>'])
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

	def _get_shell_script_or_jar_file_options(self):
		''' Parse the hub detect path to determine if it's a jar or shell script and adjust options accordingly
		'''
		file_extension = self.hub_detect_path.name.split(".")[-1]
		acceptable_extensions = ["sh", "jar"]

		assert file_extension in acceptable_extensions, "File extension - %s - not in acceptable list of extensions %s" % (file_extension, acceptable_extensions)

		if file_extension == "jar":
			return ["java", "-jar", self.hub_detect_path]
		else:
			return [self.hub_detect_path]

	def _determine_subprocess_options(self):
		options = self._get_shell_script_or_jar_file_options()
		# options = ["detect"]
		if self.blackduck_token == "undefined" or self.blackduck_token == "":
			options.extend([
				'--blackduck.url=%s' % self.blackduck_url,
				'--blackduck.username=%s' % self.blackduck_username,
				'--blackduck.password=%s' % self.blackduck_password,
				])
		else:
			options.extend([
				'--blackduck.url=%s' % self.blackduck_url,
				'--blackduck.api.token=%s' % self.blackduck_token,
				])
		options.extend(self.additional_detect_options)
		return options


	def _get_detect_log_file_path(self, subprocess_options):
		return self._output_dir(subprocess_options) + '/detect.log'

	def _adjust_detect_options_for_backwards_compatibility(self, options_list, detect_version_str):
		logging.debug("adjusting subprocess options for backwards compatibility, options: {}".format(options_list))
		detect_version = int(detect_version_str.replace(".", ""))
		if detect_version < 420:
			adjusted_options = []
			for o in options_list:
				if isinstance(o, str):
					adjusted_options.append(o.replace("--blackduck.", "--blackduck.hub."))
				else:
					adjusted_options.append(o)
		else:
			adjusted_options = options_list
		return adjusted_options

	def _run_detect(self, subprocess_options):
		# run detect adjusting the environment to include DETECT_LATEST_RELEASE_VERSION if appropriate
		my_env = os.environ.copy()
		if self.detect_version != "latest":
			logging.debug("setting DETECT_LATEST_RELEASE_VERSION to version {} of detect".format(self.detect_version))
			my_env["DETECT_LATEST_RELEASE_VERSION"] = self.detect_version
			subprocess_options = self._adjust_detect_options_for_backwards_compatibility(subprocess_options, self.detect_version)

		result = subprocess.run(
			subprocess_options, 
			env=my_env,
			stdout=subprocess.PIPE, 
			stderr=subprocess.STDOUT, 
			universal_newlines=True)

		os.makedirs(self._output_dir(subprocess_options), exist_ok=True)
		
		with open(self._get_detect_log_file_path(subprocess_options), 'w+') as f:
			f.write(result.stdout)
		logging.debug('Hub detect finished')
		return result

	def run(self):
		# run hub detect, parse the output results to get the information desired
		start = datetime.now()
		subprocess_options = self._determine_subprocess_options()
		logging.debug('Running hub detect with options: %s' % self._redact(subprocess_options))

		result = self._run_detect(subprocess_options)
		finish = datetime.now()

		run_results = {}
		run_results.update(
			self._parse_detect_output_to_get_results(
				result.stdout, self._get_detect_log_file_path(subprocess_options))
			)
		run_results['returncode'] = result.returncode
		run_results['total_elapsed_time'] = (finish - start).total_seconds()
		run_results['start_time'] = start.isoformat()
		run_results['finish_time'] = finish.isoformat()
		run_results['detect_options'] = "|".join([str(i) for i in self._redact(subprocess_options)])
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
	parser.add_argument("--username", default="sysadmin")
	parser.add_argument("--password", default="blackduck")
	parser.add_argument("--token", default="undefined")
	parser.add_argument("--detect-version", default="latest")
	parser.add_argument("--logfile", default="detect_wrapper.log", help="Where to log the hub detect wrapper output")
	parser.add_argument("--loglevel", choices=["CRITICAL", "DEBUG", "ERROR", "INFO", "WARNING"], default="DEBUG", help="Choose the desired logging level - CRITICAL, DEBUG, ERROR, INFO, or WARNING. (default: DEBUG)")
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

	hdw = HubDetectWrapper(
		args.url, 
		args.username,
		args.password,
		args.token, 
		detect_version=args.detect-version,
		detect_log_path=args.detectlogpath)
	logging.debug(hdw.run())














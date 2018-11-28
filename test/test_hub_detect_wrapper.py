#!/usr/bin/env python

import unittest
from hub_detect_wrapper import HubDetectWrapper
import os
from pathlib import Path
import re

class TestHubDetectWrapper(unittest.TestCase):
	def setUp(self):
		self.fake_url="https://non-existent"
		self.expected_shell_script_path = Path("/tmp/hub-detect.sh")
		self.expected_jar_file_path = Path("/tmp/hub-detect-4.2.1.jar")
		self.detect_test_log_files = [
			'detect-without-policy-check.txt', 
			'detect-with-policy-check.txt', 
			'detect-with-policy-check-and-policy-failures.txt',
			'detect-with-risk-report.txt',
			'detect-with-snippet-matching.txt',
			'detect-with-402-error.txt']

	def tearDown(self):
		pass

	def test_init_requires_url(self):
		with self.assertRaises(TypeError):
			wrapper = HubDetectWrapper()

		wrapper = HubDetectWrapper(self.fake_url)

	def test_get_detect_path(self):
		expected_paths = {
			"4.4.1": "hub-detect-4.4.1.jar",
			"4.3.0": "hub-detect-4.3.0.jar",
			"3.1.1": "hub-detect-3.1.1.jar"
		}
		for version, path in expected_paths.items():
			wrapper = HubDetectWrapper(self.fake_url, detect_version=version)
			self.assertEqual(wrapper.detect_version, version)
			self.assertEqual(wrapper.hub_detect_path, path)

	def test_confirm_subprocess_options_when_authenticating_with_username_and_password(self):
		wrapper = HubDetectWrapper(self.fake_url, blackduck_username="the-username", blackduck_password="the-password")

		subprocess_options = wrapper._determine_subprocess_options()
		self.assertTrue("--blackduck.username=the-username" in subprocess_options)		
		self.assertTrue("--blackduck.password=the-password" in subprocess_options)		
		self.assertTrue("--blackduck.api.token" not in subprocess_options)

	def test_confirm_subprocess_options_when_authenticating_with_token(self):
		wrapper = HubDetectWrapper(self.fake_url, blackduck_token="the-token")

		subprocess_options = wrapper._determine_subprocess_options()
		self.assertTrue("--blackduck.username=the-username" not in subprocess_options)		
		self.assertTrue("--blackduck.password=the-password" not in subprocess_options)		
		self.assertTrue("--blackduck.api.token=the-token" in subprocess_options)

	def test_output_dir_returns_detect_log_path_if_one_was_given(self):
		output_dir = "/var/log/output_dir"
		wrapper = HubDetectWrapper(self.fake_url, detect_log_path=output_dir)

		self.assertEqual(wrapper._output_dir([]), output_dir)

	def test_output_dir_returns_output_path_from_detect_options_if_no_log_given(self):
		wrapper = HubDetectWrapper(self.fake_url)

		output_dir = "/var/log/output_dir"
		self.assertEqual(wrapper._output_dir(["--detect.output.path={}".format(output_dir)]), output_dir)	

	def test_redact_will_redact_the_auth_token(self):
		the_token="the-token"
		wrapper = HubDetectWrapper(self.fake_url)
		options=["--blackduck.api.token={}".format(the_token)]
		redacted_options = wrapper._redact(options)

		self.assertTrue(the_token not in redacted_options)

	def test_redact_will_redact_the_password(self):
		the_password="the-password"
		wrapper = HubDetectWrapper(self.fake_url)
		options=["--blackduck.password={}".format(the_password)]
		redacted_options = wrapper._redact(options)

		self.assertTrue(the_password not in redacted_options)

	def test_run_detect_with_no_detect_version_specified(self):
		output_dir="/tmp/output_dir"
		detect_log_path = output_dir + "/detect.log"
		wrapper = HubDetectWrapper(self.fake_url, detect_log_path=output_dir)

		subprocess_options = ["env"] # this is a contrived set of subprocess options
		result = wrapper._run_detect(subprocess_options)

		self.assertEqual(result.returncode, 0)
		# Need to adjust this with any new version that is added to the list
		self.assertEqual(wrapper.detect_version, "4.4.1")
		self.assertEqual(wrapper.hub_detect_path, "hub-detect-4.4.1.jar")
		self.assertTrue(os.path.isfile(detect_log_path))


	def test_run_detect_with_detect_version_specified(self):
		output_dir="/tmp/output_dir"
		detect_log_path = output_dir + "/detect.log"
		detect_version="4.2.0"
		wrapper = HubDetectWrapper(self.fake_url, detect_log_path=output_dir, detect_version=detect_version)

		subprocess_options = ["env"] # this is a contrived set of subprocess options
		result = wrapper._run_detect(subprocess_options)

		self.assertEqual(result.returncode, 0)
		# Need to adjust this with any new version that is added to the list
		self.assertEqual(wrapper.detect_version, "4.2.0")
		self.assertEqual(wrapper.hub_detect_path, "hub-detect-4.2.0.jar")
		self.assertTrue(os.path.isfile(detect_log_path))

	def check_the_parsing(self, test_d, method_to_test):
		wrapper = HubDetectWrapper(self.fake_url)
		for detect_log_file, expected_value in test_d:
			with open(detect_log_file, 'r') as f:
				detect_output = f.read()
				method_to_call = getattr(wrapper, method_to_test)
				result_d = method_to_call(detect_output)
				# print(result_d)
				self.assertEqual(result_d, expected_value)

	def test_get_overall_status(self):
		detect_test_log_files_and_expected_results = [
		 ('detect-without-policy-check.txt', {'overall_status': 'SUCCESS'}), 
		 ('detect-with-policy-check.txt', {'overall_status': 'SUCCESS'}),
		 ('detect-with-policy-check-and-policy-failures.txt', {'overall_status': 'FAILURE_POLICY_VIOLATION'}),
		 ('detect-with-risk-report.txt', {'overall_status': 'SUCCESS'}),
		 ('detect-with-snippet-matching.txt', {'overall_status': 'SUCCESS'}),
		 ('detect-with-402-error.txt', {'overall_status': 'FAILURE_GENERAL_ERROR'}),
		]
		self.check_the_parsing(detect_test_log_files_and_expected_results, '_get_overall_status')

	def test_get_policy_violation(self):
		detect_test_log_files_and_expected_results = [
		 ('detect-without-policy-check.txt', {'policy_violation': 'Policy check not used'}), 
		 ('detect-with-policy-check.txt', {'policy_violation': 'NOT_IN_VIOLATION'}),
		 ('detect-with-policy-check-and-policy-failures.txt', {'policy_violation': 'IN_VIOLATION'}),
		 ('detect-with-risk-report.txt', {'policy_violation': 'Policy check not used'}),
		 ('detect-with-snippet-matching.txt', {'policy_violation': 'Policy check not used'}),
		 ('detect-with-402-error.txt', {'policy_violation': 'Policy check not used'}),
		]
		self.check_the_parsing(detect_test_log_files_and_expected_results, '_get_policy_violation')

	def test_get_elapsed_time_from_detect(self):
		detect_test_log_files_and_expected_results = [
		 ('detect-without-policy-check.txt', {'elapsed_time_from_detect': 44.655}), 
		 ('detect-with-policy-check.txt', {'elapsed_time_from_detect': 58.141}),
		 ('detect-with-policy-check-and-policy-failures.txt', {'elapsed_time_from_detect': 53.786}),
		 ('detect-with-risk-report.txt', {'elapsed_time_from_detect': 60.53}),
		 ('detect-with-snippet-matching.txt', {'elapsed_time_from_detect': 40.332}),
		 ('detect-with-402-error.txt', {'elapsed_time_from_detect': 5.383}),
		]
		self.check_the_parsing(detect_test_log_files_and_expected_results, '_get_elapsed_time_from_detect')

	def test_get_local_processing_time(self):
		detect_test_log_files_and_expected_results = [
		 # 9:57:31 9:57:04 
		 ('detect-without-policy-check.txt', {'local_processing': 43.0}), 
		 ('detect-with-policy-check.txt', {'local_processing': 30.0}),
		 ('detect-430-with-policy-check.txt', {'local_processing': 51.0}),
		 ('detect-with-policy-check-and-policy-failures.txt', {'local_processing': 32.0}),
		 ('detect-with-risk-report.txt', {'local_processing': 32.0}),
		 ('detect-with-snippet-matching.txt', {'local_processing': 38.0}),
		 ('detect-with-402-error.txt', {'local_processing': 'Not available'}),
		 ('detect-with-policy-check-no-signature-scan.txt', {'local_processing': 10.0}),
		]
		self.check_the_parsing(detect_test_log_files_and_expected_results, '_get_local_processing_time')

	def test_get_server_processing_time(self):
		detect_test_log_files_and_expected_results = [
		 ('detect-without-policy-check.txt', {'server_processing': 'Not available'}), 
		 ('detect-with-policy-check.txt', {'server_processing': 26.0}),
		 ('detect-430-with-policy-check.txt', {'server_processing': 107.0}),
		 ('detect-with-policy-check-and-policy-failures.txt', {'server_processing': 20.0}),
		 ('detect-with-risk-report.txt', {'server_processing': 25.0}),
		 ('detect-with-snippet-matching.txt', {'server_processing': 'Not available'}),
		 ('detect-with-402-error.txt', {'server_processing': 'Not available'}),
		 ('detect-with-policy-check-no-signature-scan.txt', {'server_processing': 21.0}),
		]
		self.check_the_parsing(detect_test_log_files_and_expected_results, '_get_server_processing_time')

	def test_local_processing_time_plus_server_processing_time_should_be_very_close_to_elapsed_time_from_hub_detect(self):
		pass

	def test_get_component_info(self):
		detect_test_log_files_and_expected_results = [
		 ('detect-without-policy-check.txt', {'components_in_violation': 'None found', 'components_in_violation_overridden': 'None found', 'components_not_in_violation': 'None found', 'total_components': 'None found'}), 
		 ('detect-with-policy-check.txt', {'components_in_violation': 0, 'components_in_violation_overridden': 0, 'components_not_in_violation': 78, 'total_components': 78}),
		 ('detect-with-policy-check-and-policy-failures.txt', {'components_in_violation': 'None found', 'components_in_violation_overridden': 'None found', 'components_not_in_violation': 'None found', 'total_components': 'None found'}),
		 ('detect-with-risk-report.txt', {'components_in_violation': 'None found', 'components_in_violation_overridden': 'None found', 'components_not_in_violation': 'None found', 'total_components': 'None found'}),
		 ('detect-with-snippet-matching.txt',{'components_in_violation': 'None found', 'components_in_violation_overridden': 'None found', 'components_not_in_violation': 'None found', 'total_components': 'None found'}),
		 ('detect-with-402-error.txt', {'components_in_violation': 'None found', 'components_in_violation_overridden': 'None found', 'components_not_in_violation': 'None found', 'total_components': 'None found'}),
		]
		self.check_the_parsing(detect_test_log_files_and_expected_results, '_get_component_info')

	def test_parse_detect_output_to_get_results_returns_all_keys_all_the_time(self):
		ALL_RESULT_KEYS=[
			'overall_status', 
			'policy_violation', 
			'elapsed_time_from_detect', 
			'components_in_violation', 
			'components_in_violation_overridden', 
			'components_not_in_violation',
			'total_components',
			'local_processing',
			'server_processing',
			]

		for detect_log_file in self.detect_test_log_files:
			with open(detect_log_file, 'r') as f:
				detect_output = f.read()
				wrapper = HubDetectWrapper(self.fake_url)
				results = wrapper._parse_detect_output_to_get_results(detect_output, 'dummy-path')
				# print(results)
				self.assertTrue(all([key in results for key in ALL_RESULT_KEYS]))



	def test_adjust_detect_options_for_backwards_compatibility(self):
		wrapper = HubDetectWrapper(self.fake_url)

		input_options = [
			Path('/tmp/hub-detect.sh'),
			'--blackduck.url={}'.format(self.fake_url), 
			'--blackduck.username=a_user', 
			'--blackduck.password=a_password', 
			'--blackduck.trust.cert=true', 
			'--blackduck.api.timeout', 
			'--detect.api.timeout', 
			'--detect.policy.check.fail.on.severities=ALL'
		]
		expected_options_old_versions = [
			Path('/tmp/hub-detect.sh'),
			'--blackduck.hub.url={}'.format(self.fake_url), 
			'--blackduck.hub.username=a_user', 
			'--blackduck.hub.password=a_password', 
			'--blackduck.hub.trust.cert=true', 
			'--blackduck.hub.api.timeout', 
			'--detect.api.timeout', 
			'--detect.policy.check.fail.on.severities=ALL'
		]
		options_and_versions = {
			'4.4.1' : {'input': input_options, 'expected': input_options},
			'4.2.0' : {'input': input_options, 'expected': input_options},
			'4.1.0' : {'input': input_options, 'expected': expected_options_old_versions},
			'3.0.1' : {'input': input_options, 'expected': expected_options_old_versions},
		}

		for version_str, inputs_and_expected in options_and_versions.items():
			resulting_options = wrapper._adjust_detect_options_for_backwards_compatibility(inputs_and_expected['input'], version_str)
			assert resulting_options == inputs_and_expected['expected']












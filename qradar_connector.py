# File: qradar_connector.py
#
# Copyright (c) 2016-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
import base64
import calendar
import re
import sys
import time
from datetime import datetime, timedelta

import dateutil.parser
import dateutil.tz
import phantom.app as phantom
import pytz
import requests
import simplejson as json
from bs4 import BeautifulSoup
from phantom.app import ActionResult, BaseConnector
from pytz import timezone

import default_timezones
from qradar_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class QradarConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_LIST_OFFENSES = "list_offenses"
    ACTION_ID_LIST_CLOSING_REASONS = "list_closing_reasons"
    ACTION_ID_GET_EVENTS = "get_events"
    ACTION_ID_GET_FLOWS = "get_flows"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_OFFENSE_DETAILS = "offense_details"
    ACTION_ID_CLOSE_OFFENSE = "close_offense"
    ACTION_ID_ADD_TO_REF_SET = "add_to_reference_set"
    ACTION_ID_ADD_NOTE = "add_note"
    ACTION_ID_ASSIGNE_USER = "assign_user"
    ACTION_ID_GET_RULE_INFO = "get_rule_info"
    ACTION_ID_LIST_RULES = "list_rules"

    def __init__(self):

        # Call the BaseConnectors init first
        super(QradarConnector, self).__init__()

        self._ingest_only_open = None
        self._add_to_resolved = None
        self._artifact_max = None
        self._on_poll_action_result = None
        self._event_ingest_end_time = None
        self._offense_ingest_start_time = None
        self._max_events_per_offense = None
        self._is_on_poll = None
        self._state = None
        self._config = None
        self._base_url = None
        self._artifacts_list = None
        self._auth = {}
        self._headers = {}
        self._is_manual_poll = None
        self._events_starttime_list = None
        self._total_events_count = 0
        self._container_id = None
        self._offense_details = None
        self._all_flows_data = None
        self._events_ingest_start_time = None
        self._time_field = None
        self._timezone = None
        self._use_alt_ingest = None
        self._use_alt_ariel_query = None
        self._delete_empty_cef_fields = None
        self._container_only = None
        self._cef_value_map = None
        self._has_offense = None
        self._server = None

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = QRADAR_ERR_CODE_UNAVAILABLE
        error_msg = QRADAR_ERR_MSG_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception:
            self.debug_print("Error occurred while retrieving exception information")

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, QRADAR_VALIDATE_INTEGER.format(param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, QRADAR_VALIDATE_INTEGER.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, QRADAR_VALIDATE_INTEGER_NEGETIVE_ERR.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_PARAM.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: Response data
        :param action_result: Object of ActionResult
        :return: status phantom.APP_ERROR(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)
        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = 'Error while connecting to a server'

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_json_error_message(self, response, action_result):
        """ This function is used to process json error response.

        :param response: Response data
        :param action_result: Object of ActionResult
        :return: status phantom.APP_ERROR(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(error_message)), None)

        error_code = resp_json.get('code', 'Not Found')
        error_message = resp_json.get('message', 'Not Found')
        error_description = resp_json.get('description', 'Not Found')

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Error Code: {1}, Error Message: {2}, Error Description: {3}". \
            format(response.status_code, error_code, error_message, error_description)

        return message

    def _call_api(self, endpoint, method, result, params=None, headers=None, send_progress=False):

        url = "{0}{1}".format(self._base_url, endpoint)

        r = None

        if send_progress:
            self.save_progress(QRADAR_PROG_EXECUTING_ENDPOINT, endpoint=endpoint, method=method)

        # default to success
        result.set_status(phantom.APP_SUCCESS)

        if headers:
            headers.update(self._headers)
        else:
            headers = self._headers

        request_func = getattr(requests, method)

        if not request_func:
            result.set_status(phantom.APP_ERROR, QRADAR_ERR_API_UNSUPPORTED_METHOD, method=method)
            return r

        config = self.get_config()

        if self.get_action_identifier() == 'test_asset_connectivity':
            try:
                sec_token_header = headers.pop('SEC')
            except Exception:
                sec_token_header = None

            # Both the basic auth and token will be present in the headers
            # 1. Testing the basic auth workflow as here
            if 'Authorization' in headers:
                try:
                    r = request_func(
                        url, headers=headers, verify=config[phantom.APP_JSON_VERIFY], params=params
                    )
                    if r.status_code != 200:
                        result.set_status(phantom.APP_ERROR, QRADAR_BASIC_AUTH_ERROR_MESSAGE)
                        return r
                except Exception as e:
                    error_msg = self._get_error_message_from_exception(e)
                    result.set_status(phantom.APP_ERROR, "{0}. {1}".format(QRADAR_ERR_REST_API_CALL_FAILED,
                                                                           QRADAR_BASIC_AUTH_ERROR_MESSAGE), error_msg)
                    return r

            # 2. Testing the auth token workflow
            if sec_token_header:
                r = None
                try:
                    headers.pop('Authorization')
                except Exception:
                    self.debug_print("The 'Authorization' key is not present in headers")

                headers['SEC'] = sec_token_header

                # Testing the auth token workflow
                try:
                    r = request_func(
                        url, headers=headers, verify=config[phantom.APP_JSON_VERIFY], params=params
                    )
                    if r.status_code != 200:
                        result.set_status(phantom.APP_ERROR, QRADAR_AUTH_TOKEN_ERROR_MESSAGE)
                        return r
                except Exception as e:
                    error_msg = self._get_error_message_from_exception(e)
                    result.set_status(phantom.APP_ERROR, "{0}. {1}".format(QRADAR_ERR_REST_API_CALL_FAILED,
                                                                           QRADAR_AUTH_TOKEN_ERROR_MESSAGE), error_msg)
                    return r
        else:
            try:
                r = request_func(
                    url, headers=headers, verify=config[phantom.APP_JSON_VERIFY], params=params
                )
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                result.set_status(phantom.APP_ERROR, '{}. {}'.format(QRADAR_ERR_REST_API_CALL_FAILED, error_msg))

        # Set the status to error
        if phantom.is_success(result.get_status()):
            if r is None:
                result.set_status(phantom.APP_ERROR, QRADAR_ERR_REST_API_CALL_FAILED_RESPONSE_NONE)

        if hasattr(result, 'add_debug_data'):
            # It's ok if r.text is None, dump that
            result.add_debug_data({'r_text': r.text if r else 'r is None'})

        return r

    def _set_auth(self, config):

        # First preference is given to auth_token
        auth_token = phantom.get_str_val(config, QRADAR_JSON_AUTH_TOKEN, None)
        username = phantom.get_str_val(config, phantom.APP_JSON_USERNAME)
        password = phantom.get_str_val(config, phantom.APP_JSON_PASSWORD)

        if not auth_token and (not username or not password):
            self.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_CREDENTIAL_CONFIG)
            return phantom.APP_ERROR

        if auth_token and ((username and not password) or (password and not username)):
            self.set_status(phantom.APP_ERROR, QRADAR_ERR_INCOMPLETE_CREDENTIAL_CONFIG)
            return phantom.APP_ERROR

        # 1. Validation of the auth_token
        if auth_token:
            self._auth['SEC'] = auth_token

        # 2. Validation of the basic auth
        if username and password:
            try:
                user_pass = "{0}:{1}".format(username, password)
                auth_string = "Basic {0}".format(base64.b64encode(user_pass.encode('ascii')).decode('ascii'))

                self._auth['Authorization'] = auth_string
            except Exception:
                error_msg = "Error occurred while generating authorization headers. " \
                            "Please check the credentials in the asset configuration parameters."
                self.set_status(phantom.APP_ERROR, error_msg)
                return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def initialize(self):

        config = self.get_config()

        self._config = self.get_config()
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}
            return self.set_status(phantom.APP_ERROR, QRADAR_STATE_FILE_CORRUPT_ERR)

        self._is_on_poll = False
        self._is_manual_poll = False
        self._events_starttime_list = list()
        self._artifacts_list = list()
        self._total_events_count = 0
        self._container_id = None
        self._offense_details = None
        self._all_flows_data = None
        self._events_ingest_start_time = self._config.get('events_ingest_start_time', 60)
        self._time_field = self._config.get('alt_time_field', "start_time")
        self._timezone = self._config.get('timezone', 'UTC')
        self._use_alt_ingest = self._config.get('alternative_ingest_algorithm', False)
        self._use_alt_ariel_query = self._config.get('alternative_ariel_query', False)
        self._delete_empty_cef_fields = self._config.get("delete_empty_cef_fields", False)
        self._container_only = self._config.get("containers_only", False)
        self._cef_value_map = self._config.get('cef_value_map')
        self._has_offense = self._config.get('has_offense', True)
        self._server = config[phantom.APP_JSON_DEVICE]
        self._max_events_per_offense = self._config.get('max_events_per_offense')
        self._offense_ingest_start_time = self._config.get('offense_ingest_start_time', 0)
        self._event_ingest_end_time = self._config.get('event_ingest_end_time', 0)

        # Validate 'events_ingest_start_time' configuration parameter
        ret_val, self._events_ingest_start_time = self._validate_integer(self, self._events_ingest_start_time,
                                                                         QRADAR_EVENTS_INGEST_START_TIME_KEY)
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Validate 'offense_ingest_start_time', 'event_ingest_end_time' and 'max_events_per_offense' configuration parameters
        ret_val, self._max_events_per_offense = self._validate_integer(self, self._max_events_per_offense, QRADAR_MAX_EVENTS_PER_OFFENSE)
        if phantom.is_fail(ret_val):
            return self.get_status()
        ret_val, self._offense_ingest_start_time = self._validate_integer(self, self._offense_ingest_start_time,
                                                                          QRADAR_OFFENSE_INGEST_START_TIME, True)
        if phantom.is_fail(ret_val):
            return self.get_status()
        ret_val, self._event_ingest_end_time = self._validate_integer(self, self._event_ingest_end_time, QRADAR_EVENT_INGEST_END_TIME, True)
        if phantom.is_fail(ret_val):
            return self.get_status()

        try:
            if self._cef_value_map:
                self._cef_value_map = json.loads(self._cef_value_map, strict=False)
                cef_value_map = self._cef_value_map.copy()
                for key, value in list(cef_value_map.items()):
                    integer_pattern = re.findall(QRADAR_CEF_VALUE_MAP_INT_PATTERN, key, re.IGNORECASE)
                    if integer_pattern:
                        del self._cef_value_map[key]
                        self._cef_value_map[float(integer_pattern[0][0])] = value
            else:
                self._cef_value_map = {}
        except Exception as e:
            cef_map_error_message = "Error cef_value_map is not in the valid expected JSON format"
            self.save_progress(cef_map_error_message)
            error_msg = self._get_error_message_from_exception(e)
            self.set_status(phantom.APP_ERROR, "{}. Error message: {}".format(cef_map_error_message, error_msg))
            return phantom.APP_ERROR

        self._on_poll_action_result = None

        # Base URL
        self._base_url = 'https://{}/api/'.format(self._server)

        self._artifact_max = config.get(QRADAR_JSON_ARTIFACT_MAX_DEF)

        # Validate 'artifact_max' configuration parameter
        ret_val, self._artifact_max = self._validate_integer(self, self._artifact_max, QRADAR_ARTIFACT_MAX_KEY)
        if phantom.is_fail(ret_val):
            return self.get_status()

        self._add_to_resolved = config.get(QRADAR_JSON_ADD_TO_RESOLVED, False)
        self._ingest_only_open = config.get(QRADAR_INGEST_ONLY_OPEN, False)

        # Auth details
        if phantom.is_fail(self._set_auth(config)):
            return self.get_status()

        # default is json, if any action needs to change then let them
        self._headers['Accept'] = QRADAR_JSON_ACCEPT_HDR_JSON

        # Don't specify the version, so the latest API installed on the device will be used.
        # There seems to be _no_ change in the contents or endpoints of the API only the version!!
        self._headers.update(self._auth)

        return phantom.APP_SUCCESS

    def _get_str_from_epoch(self, epoch_milli):
        # Previous line of code was as provided below which was wrong because
        # it generated the datetime based on the local Phantom timezone,
        # but was using the format of Z (which represents UTC) at the end
        # of the datetime string which is incorrect.
        # Hence, fixing it using an already existing method.
        # datetime.fromtimestamp(long(epoch_milli) / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        return self._datetime(epoch_milli).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    def _get_artifact(self, event, container_id):

        cef = phantom.get_cef_data(event, self._cef_event_map)

        if self._cef_value_map:
            for k, v in list(cef.items()):
                if v in self._cef_value_map:
                    cef[k] = self._cef_value_map[v]

        if self._delete_empty_cef_fields:
            cef = {k: v for k, v in list(cef.items()) if v}

        self.debug_print("event: ", event)
        self.debug_print("cef: ", cef)

        get_ph_severity = lambda x: phantom.SEVERITY_LOW if x <= 3 else (
            phantom.SEVERITY_MEDIUM if x <= 7 else phantom.SEVERITY_HIGH)

        artifact = {
            'label': 'event',
            'cef': cef,
            'data': event,
            'source_data_identifier': event['qid'],
            'name': event['qidname_qid'],
            'type': 'network',  # TODO: need to find a better way to map QRadar data to this field
            'severity': phantom.SEVERITY_MEDIUM if ('severity' not in event) else get_ph_severity(event['severity']),
            'container_id': container_id,
            'run_automation': True
        }
        if 'starttime' in event:
            artifact['start_time'] = self._get_str_from_epoch(event['starttime'])
        if 'endtime' in event:
            artifact['end_time'] = self._get_str_from_epoch(event['endtime'])

        return artifact

    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(QRADAR_USING_BASE_URL, base_url=self._base_url)

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._server)

        # Get the databases on the ariel endpoint, this is the fastest way of
        # testing connectivity
        response = self._call_api('ariel/databases', 'get', action_result)

        if phantom.is_fail(action_result.get_status()):
            self.save_progress('Error occurred while connecting QRadar instance with Server Hostname | IP : {0}'.format(self._server))
            self.save_progress(QRADAR_ERR_CONNECTIVITY_TEST)
            self.save_progress("The call_api failed: ", action_result.get_message())
            self.debug_print("The call_api failed: ", action_result.get_status())
            return action_result.get_status()

        if response.status_code != 200:
            if 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)

            if 'json' in response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(response, action_result)
            else:
                status_message = '{0}. {1}. HTTP status_code: {2}, reason: {3}'.format(QRADAR_ERR_CONNECTIVITY_TEST,
                                                                                       QRADAR_MSG_CHECK_CREDENTIALS,
                                                                                       response.status_code, response.reason)
            return action_result.set_status(phantom.APP_ERROR, status_message)

        self.save_progress(QRADAR_SUCC_CONNECTIVITY_TEST)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _utcnow(self):
        return datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())

    def _datetime(self, et):
        return datetime.utcfromtimestamp(float(et) / 1000).replace(tzinfo=dateutil.tz.tzutc())

    def _epochtime(self, dt):
        # datetime_to_epoch
        # time.mktime takes /etc/localtime into account. This is all wrong. ### dateepoch = int(time.mktime(datetuple))
        utcdt = dt.astimezone(dateutil.tz.tzutc())
        return calendar.timegm(utcdt.timetuple())

    def _tzepochtime(self, dt):
        # datetime_to_epoch_based_on_asset_config_timezone_selected
        timez = pytz.timezone(self._timezone)
        tzdt = dt.astimezone(timez)
        return calendar.timegm(tzdt.timetuple())

    def _tzparsedtime(self, datestring):
        # Consider the datetime string provided here as the time based on the
        # timezone provided in the asset configuration parameter
        timez = pytz.timezone(self._timezone)
        tzinfos = default_timezones.timezones()
        dt = dateutil.parser.parse(datestring.upper(), tzinfos=tzinfos)
        dt_tz_asset = timez.localize(dt)
        dt_tz_local = dt_tz_asset.astimezone(dateutil.tz.tzlocal())
        return int(time.mktime(dt_tz_local.timetuple()))

    def _parsedtime(self, datestring):
        default_time = dateutil.parser.parse("00:00Z").replace(tzinfo=dateutil.tz.tzlocal())
        tzinfos = default_timezones.timezones()
        if datestring.lower() == "yesterday":
            delta = timedelta(seconds=(QRADAR_MILLISECONDS_IN_A_DAY / 1000))
            return self._utcnow() - delta
        return dateutil.parser.parse(datestring.upper(), tzinfos=tzinfos, default=default_time)

    def _utcctime(self, et):
        return datetime.utcfromtimestamp(float(et) / 1000).replace(tzinfo=dateutil.tz.tzutc()).strftime("%a %b %d %H:%M:%S %Y %Z %z")

    def _utciso(self, et):
        return datetime.utcfromtimestamp(float(et) / 1000).replace(tzinfo=dateutil.tz.tzutc()).isoformat()

    def _utc_string(self, et):
        return datetime.utcfromtimestamp(float(et) / 1000).replace(tzinfo=dateutil.tz.tzutc()).strftime("%Y-%m-%d %H:%M:%S%z")

    def _createfilter(self, param, action_result):  # noqa: C901

        start_time = None
        end_time = None
        reqfilter = None

        # first determine if there are any offenses requested, if so, no need to limit time range
        offense_ids_list = str(phantom.get_value(param, phantom.APP_JSON_CONTAINER_ID, phantom.get_value(param, QRADAR_JSON_OFFENSE_ID, "")))

        # clean up the string and parse into list, assume whitespace and commas as separators
        if offense_ids_list:
            offense_ids_list = [x.strip() for x in offense_ids_list.split(",")]
            offense_ids_list = list(filter(None, offense_ids_list))

            interim_offense_ids_list = list()
            for x in offense_ids_list:
                try:
                    if len(x.strip()) > 0 and int(x.strip()) >= 0:
                        interim_offense_ids_list.append('{}'.format(int(x.strip())))
                except Exception:
                    self.debug_print("In Alternate Ingestion workflow for fetching offenses, the provided offense: {} is not valid".format(x))

            offense_ids_list = interim_offense_ids_list

        if len(offense_ids_list) > 0:
            reqfilter = "({})".format(" or ".join(["id=" + str(x) for x in offense_ids_list]))
            self.save_progress("Retrieving the following IDs: {}".format(", ".join(offense_ids_list)))
        else:
            # List of precedences for determining start_time
            # 1. if the param has a start time, use what's in the param
            # 2. if the saved state has a last saved ingest time, use that as start time
            # 3. if the configuration set the  alt_initial_ingest_time, decode and set as start_time
            # 4. if nothing configured assume 24 hours ago

            try:
                if self._is_on_poll and not self._is_manual_poll:
                    start_time = self._state.get('last_saved_ingest_time',
                                                 self._config.get('alt_initial_ingest_time', "yesterday"))
                else:
                    start_time = param.get('start_time',
                                           self._config.get('alt_initial_ingest_time', "yesterday"))

                self.save_progress("Initial time for fetching the offenses is : {}".format(start_time))

                # datetime string, decode
                if isinstance(start_time, str):
                    if start_time.isdigit():
                        start_time = int(start_time)

                        if start_time < 0:
                            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME.format(
                                num_type="positive", field_name="Alternative initial ingestion time",
                                field_location="asset configuration parameter")), None, None, None, None
                    else:
                        try:
                            start_time = int(start_time)

                            if start_time < 0:
                                return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME.format(
                                    num_type="positive", field_name="Alternative initial ingestion time",
                                    field_location="asset configuration parameter")), None, None, None, None
                        except Exception:
                            self.debug_print("Checking for negative integer values failed "
                                             "for 'Alternative initial ingestion time' asset configuration parameter")
                            self.save_progress(
                                "The 'initial time' for fetching the offenses is derived from string: {}".format(start_time))
                            start_time = self._epochtime(self._parsedtime(start_time)) * 1000
                else:
                    start_time = int(start_time)

                    if start_time < 0:
                        return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME.format(
                            num_type="positive", field_name="Alternative initial ingestion time",
                            field_location="asset configuration parameter")), None, None, None, None

                # end time is either specified in the param or is now
                end_time = param.get('end_time', self._epochtime(self._utcnow()) * 1000)
                if isinstance(end_time, str):
                    if end_time.isdigit():
                        end_time = int(end_time)

                        if end_time <= 0:
                            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME.format(
                                num_type="non-zero positive", field_name="end_time",
                                field_location="parameter")), None, None, None, None
                    else:
                        try:
                            end_time = int(end_time)

                            if end_time <= 0:
                                return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME.format(
                                    num_type="non-zero positive", field_name="end_time",
                                    field_location="parameter")), None, None, None, None
                        except Exception:
                            self.debug_print("Checking for negative integer values failed for 'end_time' parameter")
                            self.save_progress("The 'end time' for fetching the offenses is derived from string: {}".format(end_time))
                            end_time = self._epochtime(self._parsedtime(end_time)) * 1000
                else:
                    end_time = int(end_time)

                    if end_time <= 0:
                        return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME.format(
                            num_type="non-zero positive", field_name="end_time",
                            field_location="parameter")), None, None, None, None
            except Exception:
                action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_DATETIME_PARSE)
                return phantom.APP_ERROR, None, None, None, None

            try:
                self.save_progress("start_time: {}".format(self._utcctime(start_time)))
                self.save_progress("end_time:   {}".format(self._utcctime(end_time)))
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print('For alternate ingestion workflow of fetching offenses, provided time is invalid. Error: {}'.format(error_msg))

            if end_time < start_time:
                return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME_RANGE), None, None, None, None

            # Backdate the offense ingestion start time by offense_ingest_start_time configuration parameter
            # for alternative ingestion algorithm

            if self._is_on_poll and self._offense_ingest_start_time > 0:
                self.save_progress('Original start_time is: {}'.format(start_time))
                start_time = start_time - self._offense_ingest_start_time * 60 * 1000
                self.save_progress('Back-dating the offense start time by {} minutes'.format(self._offense_ingest_start_time))
                self.save_progress('The modified start_time is: {}'.format(start_time))

            # the time_field configuration parameter determines which time fields are used in the filter,
            # if missing or unknown value, default to start_time
            if self._time_field == "last_updated_time":
                reqfilter = "(last_updated_time >= {} and last_updated_time <= {})".format(start_time, end_time)
            elif self._time_field == "either":
                reqfilter = "((start_time >= {} and start_time <= {}) or (last_updated_time >= {} and last_updated_time <= {}))".format(
                    start_time, end_time, start_time, end_time)
            else:
                self._time_field = 'start_time'
                reqfilter = "(start_time >= {} and start_time <= {})".format(start_time, end_time)

            try:
                self.save_progress("Applying time range between [{} -> {}] inclusive (total minutes {})".format(
                    self._utcctime(start_time),
                    self._utcctime(end_time),
                    (end_time - start_time) / (1000 * 60)))
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print('Provided time is invalid. Error: {}'.format(error_msg))

        # last requirement, are we listing only opened offenses?
        if self._ingest_only_open:
            reqfilter += ' and status=OPEN'

        self.save_progress("For alternate ingestion workflow of fetching offenses, using filter: {}".format(reqfilter))
        return phantom.APP_SUCCESS, start_time, end_time, reqfilter, offense_ids_list

    def _alt_list_offenses(self, param, action_result=None):

        self.save_progress("Utilizing alternative ingestion algorithm")

        reqheaders = dict()
        reqparams = dict()
        offenses = list()

        # create the filter to apply to query
        ret_val, start_time, _, reqfilter, offenses_ids_list = self._createfilter(param, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        reqparams['filter'] = reqfilter

        # prep last saved ingested time to start_time; always start here if not ingested anything
        self._new_last_ingest_time = start_time

        # Initialize count = None to indicate that all the offenses will be fetched
        count = None

        # Update the request parameters based on the sorting order and the time field
        # provided in the asset config for the alternate ariel query
        # Define the ingestion_order
        ingestion_order = self._config.get('alt_ingestion_order')

        if ingestion_order != "latest first" and ingestion_order != "oldest first":
            ingestion_order = "latest first"

        # Define the sorting field on the basis of the 'ingestion_order'
        if ingestion_order == "oldest first":
            self.save_progress("Ingesting the oldest first")
            reqparams['sort'] = "+{}".format(self._time_field)
            if self._time_field == 'either':
                reqparams['sort'] = "+last_updated_time"
        else:
            self.save_progress("Ingesting the latest first")
            reqparams['sort'] = "-{}".format(self._time_field)
            if self._time_field == 'either':
                reqparams['sort'] = "-last_updated_time"

        # Fetch the list of offenses based on the offenses IDs if provided or
        # all the offenses finally limit by the value provided in the count parameter.
        # hence, removing the special handling for the offense_ids_list separately and making the
        # logic uniform for either offense_ids provided or not, in both the cases, the count value will be considered.

        if not self.get_action_identifier() == 'offense_details':
            # Validate 'count' action parameter
            ret_val, count = self._validate_integer(
                action_result,
                param.get(phantom.APP_JSON_CONTAINER_COUNT, param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_OFFENSE_COUNT)),
                QRADAR_COUNT_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        self.save_progress("Retrieving maximum {} offenses".format(count if count or count == 0 else 'all'))

        start_index = 0
        runs = 0

        while True:

            # Removing the error due to the runs concept as now, we are declaring the support
            # for the QRadar instance starting from v7.3.1 and this instance
            # does not seem to have the pagination issues with the API now.
            runs += 1

            # If the action is 'offense_details', fetch all the offenses, and count = None in that case
            if count:
                end_index = min(start_index + QRADAR_QUERY_HIGH_RANGE - 1, count - 1)
            else:
                end_index = start_index + QRADAR_QUERY_HIGH_RANGE - 1

            if start_index > end_index:
                break

            # Start at the end of offenses list and retrieve QRADAR_QUERY_HIGH_RANGE number of offenses
            reqheaders['Range'] = 'items={}-{}'.format(start_index, end_index)
            self.save_progress("Retrieving index: {} -> {}".format(start_index, end_index))

            new_offenses = self._retrieve_offenses(action_result, reqheaders, reqparams)

            if phantom.is_fail(action_result.get_status()):
                self.save_progress("error, exiting")
                return action_result.get_status()

            if len(new_offenses) > 0:
                offenses.extend(new_offenses)
                self._report_back(new_offenses, runs)

            # stop if we exhausted the list of possible offenses
            if len(new_offenses) < QRADAR_QUERY_HIGH_RANGE:
                self.save_progress(QRADAR_PROG_GOT_X_OFFENSES, total_offenses=len(new_offenses))
                break

        self.save_progress("Total offenses discovered: {}".format(len(offenses)))

        if len(offenses) > 0:
            self.save_progress("Ingesting {} offenses".format(len(offenses)))

            # Save the last ingest time for the offense
            if self._is_on_poll and not self._is_manual_poll:
                if ingestion_order == "latest first":
                    if self._time_field == 'either':
                        self._new_last_ingest_time = max(offenses[0]['start_time'], offenses[0]['last_updated_time'])
                    else:
                        self._new_last_ingest_time = offenses[0][self._time_field]
                else:
                    if self._time_field == 'either':
                        self._new_last_ingest_time = max(offenses[-1]['start_time'], offenses[-1]['last_updated_time'])
                    else:
                        self._new_last_ingest_time = offenses[-1][self._time_field]

            # Removing the reverse logic as now the offenses are sorted in the API call itself
            # based on the provision provided in the API for the QRadar instances that we have decided
            # as a minimum QRadar instance version to support v7.3.1

            # add offense to action_result
            for offense in offenses:
                try:
                    self.save_progress("Queuing offense id: {} start_time({}, {}) last_updated_time({}, {})"
                                       .format(offense['id'], offense['start_time'], self._utcctime(offense['start_time']),
                                               offense['last_updated_time'], self._utcctime(offense['last_updated_time'])))
                except Exception as e:
                    error_msg = self._get_error_message_from_exception(e)
                    self.debug_print('Error occurred: {}'.format(error_msg))
                action_result.add_data(offense)

        # add summary for action_result
        action_result.update_summary({QRADAR_JSON_TOTAL_OFFENSES: len(offenses)})

        return action_result.get_status()

    def _retrieve_offenses(self, action_result, reqheaders, reqparams):

        # make rest call
        response = self._call_api('siem/offenses', 'get', action_result, params=reqparams, headers=reqheaders)

        # error with the call_api function, most likely network error
        if phantom.is_fail(action_result.get_status()):
            if response:
                status_code = response.status_code
            else:
                status_code = None
            self.save_progress("For alternate ingestion workflow of fetching offenses, REST call failed: {}\nResponse code: {}"
                               .format(action_result.get_status(), status_code))
            return action_result.get_status()

        # error with the rest call, either authorization or malformed parameters
        if response.status_code != 200:
            if 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)

            if 'json' in response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(response, action_result)
            else:
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_LIST_OFFENSES_API_FAILED,
                                                                                  response.status_code, response.reason)
            self.save_progress("Rest call error: {}\nResponse code: {}".format(
                status_message, response.status_code))
            return action_result.set_status(phantom.APP_ERROR, status_message)

        # decode and save offenses
        try:
            new_offenses = response.json()
        except Exception as e:
            # error with rest call, as it did not return the data as json
            error_msg = self._get_error_message_from_exception(e)
            self.save_progress("Unable to parse response as a valid JSON: {}".format(error_msg))
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        return new_offenses

    def _report_back(self, new_offenses, runs):

        # report back what we downloaded
        offenses_bytime = None
        if self._time_field == "start_time":
            offenses_bytime = sorted(new_offenses, key=lambda x: x['start_time'])
        else:
            offenses_bytime = sorted(new_offenses, key=lambda x: x['last_updated_time'])

        try:
            self.save_progress("Run {}: downloaded ({}) earliest offense [ id ({}) start_time ({}) ] latest offense [ id ({}) start_time ({}) ]"
                               .format(runs, len(new_offenses), offenses_bytime[0]['id'],
                                       self._utcctime(
                                           offenses_bytime[0]['start_time']),
                                       offenses_bytime[-1]['id'],
                                       self._utcctime(offenses_bytime[-1]['start_time'])))
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print('Error occurred: {}'.format(error_msg))

    def _create_offense_artifacts(self, offense, container_id, offense_id):
        """ This function is used to create artifacts in given container using finding data.

        :param offense: Data of single finding
        :param container_id: ID of container in which we have to create the artifacts
        :param offense_id: ID of the offense
        :return: status(success/failure), message
        """

        artifact = {
            'name': 'Offense Artifact',
            'container_id': container_id,
            'source_data_identifier': offense_id,
            'cef': offense,
            'label': 'offense',
            'run_automation': True
        }

        # This method will be called in the loop, add offense artifact only if it is not created earlier.
        # At least one artifact in the list indicates that the offense artifact is already created.
        if not self._artifacts_list:
            self._artifacts_list.append(artifact)

    def _ingest_collected_artifacts(self, offense_id):

        self.save_progress("Started artifacts creation for the collected events and offenses for offense id - {}".format(offense_id))
        for i in range(0, len(self._artifacts_list), QRADAR_DEFAULT_ARTIFACT_CHUNK_SIZE):
            j = i + QRADAR_DEFAULT_ARTIFACT_CHUNK_SIZE
            if j > len(self._artifacts_list):
                j = len(self._artifacts_list)

            self.send_progress("Ingesting {}-{} artifacts, Status: In-progress".format(i + 1, j))

            ret_val, create_artifact_msg, _ = self.save_artifacts(self._artifacts_list[i:j])
            if phantom.is_fail(ret_val):
                self.save_progress('Error occurred while artifact creation for the offense ID: {0}. Error: {1}'.format(
                    offense_id, create_artifact_msg))
                self.send_progress("Ingesting {}-{} artifacts, Status: Failed".format(i + 1, j))
                self.save_progress(" ")
                continue

            self.send_progress("Ingesting {}-{} artifacts, Status: Complete".format(i + 1, j))
            self.save_progress(" ")

        self.save_progress("Artifact ingestion successful for offense id - {}".format(offense_id))

        return phantom.APP_SUCCESS, 'Artifacts created successfully'

    def _on_poll(self, param):  # noqa: C901

        self._is_on_poll = self.get_action_identifier() == "on_poll"
        self._is_manual_poll = self.is_poll_now()

        # if action_result is passed in, use it otherwise generate our own
        if not self._on_poll_action_result:
            self._on_poll_action_result = self.add_action_result(ActionResult(dict(param)))

        action_result = self._on_poll_action_result
        offenses = list()
        artifact_max = self._artifact_max
        add_to_resolved = self._add_to_resolved

        # cef mapping for events
        # 'deviceDirection' = 0 if eventdirection == L2R else 1
        config = self.get_config()
        self._cef_event_map = {
            'signature_id': 'qid',
            'name': 'qidname_qid',
            'severity': 'severity',
            'applicationProtocol': 'Application',
            'destinationMacAddress': 'destinationmac',
            'destinationNtDomain': 'AccountDomain',
            'destinationPort': 'destinationport',
            'destinationAddress': 'destinationaddress',
            'endTime': 'endtime',
            'fileHash': 'File Hash',
            'fileId': 'File ID',
            'filePath': 'File Path',
            'fileName': 'Filename',
            'bytesIn': 'BytesReceived',
            'message': 'Message',
            'bytesOut': 'BytesSent',
            'transportProtocol': 'protocolname_protocolid',
            'sourceMacAddress': 'sourcemac',
            'sourcePort': 'sourceport',
            'sourceAddress': 'sourceaddress',
            'startTime': 'starttime',
            'payload': 'Payload'
        }

        if config.get('cef_event_map', None) is not None:
            try:
                self._cef_event_map.update(json.loads(config.get('cef_event_map')))
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                action_result.set_status(phantom.APP_ERROR, 'Optional CEF event map is not valid JSON: {}'.format(error_msg))
                return action_result.get_status()

        if config.get('event_fields_for_query', None) is not None:
            bad_chars = set("&^%")
            if any((c in bad_chars) for c in config.get('event_fields_for_query')):
                action_result.set_status(phantom.APP_ERROR, 'Please do not use invalid characters in event '
                                                            'field names in event_fields_for_query')
                return action_result.get_status()
            if "'" in config.get('event_fields_for_query'):
                action_result.set_status(phantom.APP_ERROR, 'Please use double quotes instead of single '
                                                            'quotes around event field names in event_fields_for_query')
                return action_result.get_status()

            # Add the additional fields provided by the user in the '' config param to the cef_event_map to ingest them
            event_fields = [event_field.strip() for event_field in config.get('event_fields_for_query').split(',')]
            event_fields = list(filter(None, event_fields))
            event_fields = [field.strip("\"") for field in event_fields]

            for field in event_fields:
                if field not in list(self._cef_event_map.values()):
                    self._cef_event_map[field] = field

        # Call _list_offenses with a local action result,
        # this one need not be added to the connector run
        # result. It will be used to contain the offenses data
        offenses_action_result = ActionResult(dict(param))
        param['artifact_count'] = artifact_max
        curr_msecs = int(time.time()) * 1000
        param[phantom.APP_JSON_END_TIME] = curr_msecs

        try:
            param.pop(phantom.APP_JSON_START_TIME)
        except Exception:
            pass

        if phantom.is_fail(self._list_offenses(param, offenses_action_result)):
            # Copy the status and message into our action result
            self.debug_print('message: {0}'.format(offenses_action_result.get_message()))
            action_result.set_status(offenses_action_result.get_status())
            action_result.append_to_message(offenses_action_result.get_message())
            return action_result.get_status()

        if self.get_action_identifier() == 'offense_details' and offenses_action_result.get_data():
            for offense in offenses_action_result.get_data():
                self._on_poll_action_result.add_data(offense)

        # From here onwards the action is treated as success, if an event query failed
        # it's still a success and the message, summary should specify details about it
        action_result.set_status(phantom.APP_SUCCESS)

        offenses = offenses_action_result.get_data()
        len_offenses = len(offenses)
        action_result.update_summary({QRADAR_JSON_TOTAL_OFFENSES: len_offenses})

        add_offense_id_to_name = self._config.get("add_offense_id_to_name", False)

        for i, offense in enumerate(offenses):

            # Clear the events list per an offense and artifact list
            self._events_starttime_list = []
            self._artifacts_list = []

            self.debug_print('Offense ID:{}'.format(offense['id']), offense)
            self.save_progress('Offense ID:{}'.format(offense['id']))

            get_ph_severity = lambda x: phantom.SEVERITY_LOW if x <= 3 else (
                phantom.SEVERITY_MEDIUM if x <= 7 else phantom.SEVERITY_HIGH)

            # Replace the 'null' string to None if any
            offense = dict([(x[0], None if x[1] == 'null' else x[1]) for x in list(offense.items())])

            # Strip \r, \n and space from the values, QRadar does that for the description field at least
            v_strip = lambda v: v.strip(' \r\n').replace('\u0000', '') if isinstance(v, str) else v
            offense = dict([(k, v_strip(v)) for k, v in list(offense.items())])

            # Don't want dumping non None
            self.debug_print('Offense', phantom.remove_none_values(offense))

            offense_id = offense['id']
            container = {}

            # Validate 'tenant_id' action parameter
            tenant_id = param.get('tenant_id', None)
            if tenant_id:
                ret_val, tenant_id = self._validate_integer(action_result, tenant_id, QRADAR_TENANT_ID_KEY, True)
                if phantom.is_fail(ret_val):
                    return action_result.get_status()
                container['tenant_id'] = tenant_id

            offense_description = offense['description']
            container['name'] = "{} - {}".format(offense['id'], offense_description) if add_offense_id_to_name else offense_description
            container['data'] = offense
            # Two hard coded lines for testing multi-tenancy adds
            # container['asset_id'] = 44
            # container['ingest_app'] = "6cf34589-6947-409f-b776-e8fa62e01509"
            # End of hard coded lines
            container['start_time'] = self._get_str_from_epoch(offense['start_time'])
            container['severity'] = get_ph_severity(offense['severity'])
            container['source_data_identifier'] = offense_id

            self.save_progress("Saving Container # {0}".format(i))
            ret_val, message, container_id = self.save_container(container)
            self.debug_print("Save container returns, ret_val: {0}, message: {1}, id: {2}".format(ret_val, message, container_id))

            self.save_progress("Save container returns, ret_val: {0}, message: {1}, id: {2}".format(ret_val, message, container_id))

            # if there seems an error in saving container, continue from the next offense
            if phantom.is_fail(ret_val):
                error_message = 'Error occurred while container creation for Offense ID: {0}. Error: {1}'.format(offense_id, message)
                self.debug_print(error_message)
                if message and (TENANT_NOT_FOUND_4_8.format(tid=param.get('tenant_id')) in message or TENANT_NOT_FOUND_4_5
                        .format(tid=param.get('tenant_id')) in message):
                    self.save_progress('Aborting the polling process')
                    return action_result.set_status(phantom.APP_ERROR, error_message)
                continue

            if not container_id:
                continue

            if message == 'Duplicate container found':
                self.debug_print("Duplicate container found:", container_id)
                # get status of the duplicate container
                this_container = self.get_container_info(container_id)
                statusOfContainer = this_container[1]['status']  # pylint: disable=E0001,E1126
                self.debug_print("Add_to_resolved: {0}, status: {1}, container_id: {2}"
                                 .format(add_to_resolved, statusOfContainer, container_id))
                if not add_to_resolved and (statusOfContainer == "resolved" or statusOfContainer == "closed"):
                    self.debug_print("Skipping artifact ingest to closed container")
                    continue

            if self._container_only:
                self._create_offense_artifacts(offense, container_id, offense['id'])

                artifacts_creation_status, artifacts_creation_msg = self._ingest_collected_artifacts(offense['id'])
                if phantom.is_fail(artifacts_creation_status):
                    self.debug_print('Logging the artifact creation failure for the current offense and continuing with the next offense')
                    self.debug_print('Error while creating artifacts for the Offense ID: {0} and Container ID {1}. Error: {2}'
                                     .format(offense_id, container_id, artifacts_creation_msg))

                continue

            # If the current container's artifact count exceeds the maximum accumulated artifact count, the phantom won't collect artifacts
            # for a particular container and continue from the next container
            # If _max_events_per_offense is 1 then it will only ingest offense artifact
            if self._max_events_per_offense:
                container_data = self.get_container_info(container_id)[1]
                container_artifact_count = container_data.get('artifact_count')
                self.save_progress("container id({0})'s artifact count : {1}".format(
                    container_id, container_artifact_count))

                if container_artifact_count >= self._max_events_per_offense:
                    self.save_progress("container id({0})'s artifact count({1}) is more than maximum accumulated artifacts count, "
                                       "phantom won't collect artifacts".format(container_id, container_artifact_count))
                    continue

                if self._max_events_per_offense == 1:
                    self._create_offense_artifacts(offense, container_id, offense['id'])

                    artifacts_creation_status, artifacts_creation_msg = self._ingest_collected_artifacts(offense['id'])
                    if phantom.is_fail(artifacts_creation_status):
                        self.debug_print('Logging the artifact creation failure for the current offense and continuing with the next offense')
                        self.debug_print('Error while creating artifacts for the Offense ID: {0} and Container ID {1}. Error: {2}'
                                         .format(offense_id, container_id, artifacts_creation_msg))
                    continue

                if self._max_events_per_offense <= self._artifact_max:
                    param['artifact_count'] = self._max_events_per_offense - 1
                else:
                    param['artifact_count'] = min(int(self._max_events_per_offense) - container_artifact_count, self._artifact_max)

            # set the event params same as that of the input poll params
            # since the time range should be the same
            event_param = dict(param)
            # Add the offense id to the param dict
            event_param['offense_id'] = offense_id
            # We need to fetch even the older events as the events are generated first and then, the offense gets generated.
            # Hence, in PAPP-4584, it was missing events that were generated earlier than the offense start_time and if all the events
            # are older than offense start_time, it starts generating the containers with 0 event artifacts.
            # To solve this, we will fetch everything from the resultant epoch timestamp that gets generated by back-dating the offense's
            # starttime by the number of minutes (default is 60 min)
            # mentioned in the asset configuration parameter 'events_ingest_start_time'
            self.save_progress('Offense start time is: {}'.format(int(offense['start_time'])))
            self.save_progress('Back-dating the event fetching start time relative to offense start time by {} minutes'
                               .format(self._events_ingest_start_time))
            self.save_progress('The modified initial epoch is: {} for fetching the events for the offense ID: {}'.format(
                int(offense['start_time']) - self._events_ingest_start_time * 60 * 1000, offense_id))
            event_param['start_time'] = int(offense['start_time']) - self._events_ingest_start_time * 60 * 1000
            event_param[phantom.APP_JSON_END_TIME] = curr_msecs

            # Keep (updating) | (setting to new values) the global values for the
            # self._total_events_count, self._container_id and the self._offense_details
            self._container_id = container_id
            self._offense_details = offense
            self._total_events_count = 0

            # Validate 'count' action parameter
            ret_val, count = self._validate_integer(action_result, param.get(phantom.APP_JSON_ARTIFACT_COUNT), QRADAR_COUNT_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if count:
                event_param['total_events_count'] = count
            else:
                event_param['total_events_count'] = offense.get('event_count', QRADAR_DEFAULT_EVENT_COUNT)

            # Create a action result specifically for the event
            event_action_result = ActionResult(event_param)
            if phantom.is_fail(self._get_events(event_param, event_action_result)):
                self.debug_print("Failed to get events for the offense ID: {}. Error message: {}"
                                 .format(offense_id, event_action_result.get_message()))
                self.save_progress("Failed to get events for the offense ID: {}. Error message: {}"
                                   .format(offense_id, event_action_result.get_message()))
                action_result.append_to_message(QRADAR_ERR_GET_EVENTS_FAILED.format(offense_id=offense_id))
                continue

            artifacts_creation_status, artifacts_creation_msg = self._ingest_collected_artifacts(offense_id)
            if phantom.is_fail(artifacts_creation_status):
                self.debug_print('Logging the artifact creation failure for the current offense and continuing with the next offense')
                self.debug_print('Error while creating artifacts for the Container ID {0}. Error: {1}'
                                 .format(container_id, artifacts_creation_msg))

        # if we are polling, save the last ingested time
        if self._is_on_poll and not self._is_manual_poll:
            self._state['last_saved_ingest_time'] = self._new_last_ingest_time
            try:
                self.save_progress("Setting last_saved_ingest_time to: {} {}".format(self._state['last_saved_ingest_time'],
                                                                                     self._utcctime(self._state['last_saved_ingest_time'])))
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print('Error occurred: {}'.format(error_msg))
            self.save_state(self._state)

        self.send_progress(" ")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_offenses(self, param, action_result=None):  # noqa: C901

        if not action_result:
            # Create a action result to represent this action
            action_result = self.add_action_result(ActionResult(dict(param)))

        # Validation for the Offense ID|s
        try:
            offense_ids_str = param.get(QRADAR_JSON_OFFENSE_ID, "")
            if isinstance(offense_ids_str, str):
                offense_ids_interim = [x.strip() for x in offense_ids_str.split(",")]
                offense_ids_interim = list(filter(None, offense_ids_interim))
                for x in offense_ids_interim:
                    # Validate 'offense_id' action parameter
                    ret_val, _ = self._validate_integer(action_result, x, QRADAR_OFFENSE_ID_KEY)
                    if phantom.is_fail(ret_val):
                        return action_result.get_status()
            else:
                # Validate 'offense_id' action parameter
                ret_val, _ = self._validate_integer(action_result, offense_ids_str, QRADAR_OFFENSE_ID_KEY)
                if phantom.is_fail(ret_val):
                    return action_result.get_status()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        # 1. Validation of the input parameters
        count = None
        if self.get_action_identifier() == 'list_offenses' or (self._is_on_poll and self._is_manual_poll):
            # Validate 'count' action parameter
            ret_val, count = self._validate_integer(
                action_result,
                param.get(phantom.APP_JSON_CONTAINER_COUNT, param.get(
                    QRADAR_JSON_COUNT, QRADAR_DEFAULT_OFFENSE_COUNT)),
                QRADAR_COUNT_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        try:
            if param.get('start_time') and not str(param.get('start_time')).isdigit():
                return action_result.set_status(phantom.APP_ERROR, QRADAR_START_TIME)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, QRADAR_START_TIME)

        try:
            if (param.get('end_time') and not str(param.get('end_time')).isdigit()) or param.get('end_time') == 0:
                return action_result.set_status(phantom.APP_ERROR, "Please provide valid non-zero epoch "
                                                                   "value (milliseconds) in the 'end_time' parameter")
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Please provide valid non-zero epoch "
                                                               "value (milliseconds) in the 'end_time' parameter")

        # This is alternate offense ingestion | fetching workflow
        if self._use_alt_ingest:
            return self._alt_list_offenses(param, action_result)

        filter_string = ""
        params = dict()
        headers = dict()

        # Validate the start_time and end_time
        ret_val = self._validate_times(param, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # 2. Initialize all time related variables
        curr_epoch_msecs = int(time.time()) * 1000
        start_time_msecs = 0
        end_time_msecs = int(param.get(phantom.APP_JSON_END_TIME, curr_epoch_msecs))

        # Flag for deciding whether to ingest only open offenses or not
        ingest_only_open = self._ingest_only_open

        # 3. Initialize num_days for offense_details and on_poll actions calling list_offenses action
        # a. num_days is used for the offense_details action passing interval_ays in the param
        # via on_poll action by setting ingest_offense flag to TRUE
        # b. num_days is used for the manual polling (poll now)
        # and scheduled polling first run to change the start_time_msecs as
        # already set in the earlier steps

        num_days = param.get(QRADAR_JSON_DEF_NUM_DAYS, self.get_app_config().get(QRADAR_JSON_DEF_NUM_DAYS,
                                                                                 QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME))
        # Validate 'interval_days' action parameter
        ret_val, num_days = self._validate_integer(action_result, num_days, QRADAR_INTERVAL_DAYS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # a. start_time_msecs will get changed based on the value of num_days
        # b. start_time_msecs will again get changed if it is scheduled | interval
        # polling and the first run in it
        try:
            start_time_msecs = int(param.get(phantom.APP_JSON_START_TIME, end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days)))
            if self._is_on_poll and not self._is_manual_poll:
                if self._state.get('last_saved_ingest_time', {}):
                    start_time_msecs = int(self._state['last_saved_ingest_time'])
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while formation "
                                                               "of 'start_time_msecs' for fetching the offenses. Error: {}".format(error_msg))

        if end_time_msecs < start_time_msecs:
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME_RANGE)

        # 4. Assign value of start_time_msecs to the global variable
        # self._new_last_ingest_time which stores where we had stopped
        # while fetching offenses for on_poll action calling list_offenses action
        self._new_last_ingest_time = start_time_msecs

        if self._get_tz_str_from_epoch('start_time_msecs', start_time_msecs, action_result) is None or self._get_tz_str_from_epoch(
                'end_time_msecs', end_time_msecs, action_result) is None:
            self.debug_print("Error occurred in tz_str conversion from epoch for 'start_time_msecs' and 'end_time_msecs'. Error: {}".format(
                action_result.get_message()))
        else:
            self.save_progress('Getting offenses data from {0} to {1}'.format(self._get_tz_str_from_epoch(
                'start_time_msecs', start_time_msecs, action_result),
                self._get_tz_str_from_epoch('end_time_msecs', end_time_msecs, action_result)))

        # Backdate the offense ingestion start time by offense_ingest_start_time configuration parameter
        # for default ingestion algorithm

        if self._is_on_poll and self._offense_ingest_start_time > 0:
            self.save_progress('Original start time is: {}'.format(start_time_msecs))
            start_time_msecs = start_time_msecs - self._offense_ingest_start_time * 60 * 1000
            self.save_progress('Back-dating the offense start time by {} minutes'.format(self._offense_ingest_start_time))
            self.save_progress('The modified start_time is: {}'.format(start_time_msecs))

        # 5. Create the param dictionary for the range
        filter_string += '(({2} >= {0} and {2} <= {1}) or ({3} >= {0} and {3} <= {1}))'.format(
            start_time_msecs, end_time_msecs, 'start_time', 'last_updated_time')

        # get the list of offenses that we are supposed to query for
        offense_ids = str(param.get(phantom.APP_JSON_CONTAINER_ID, param.get(QRADAR_JSON_OFFENSE_ID, None)))

        if offense_ids != 'None':
            offense_ids = [x.strip() for x in offense_ids.split(",")]
            offense_ids = list(filter(None, offense_ids))

            offense_id_list = list()
            for x in offense_ids:
                try:
                    if len(x.strip()) > 0 and int(x.strip()) >= 0:
                        offense_id_list.append('id={}'.format(int(x.strip())))
                except Exception:
                    self.debug_print("The provided offense: {} is not valid".format(x))

            if len(offense_id_list) > 0:
                # If the user is providing the offense IDs to be fetched, irrespective of the
                # start_time and the end_time, we will be fetching those offenses
                filter_string = ' ({0})'.format(' or '.join(offense_id_list))
            else:
                return action_result.set_status(phantom.APP_ERROR, "Please provide valid offense ID|s")

        params['filter'] = filter_string
        params['sort'] = "+last_updated_time"
        self.save_progress('Filter for fetching offenses: {0}'.format(filter_string))

        offenses = list()
        start_index = 0
        total_offenses = 0

        # 5. Pagination logic for fetching the list of offenses
        offenses_status_msg = ''
        while True:

            # Removing the runs concept as now, we are declaring the support
            # for the QRadar instance starting from v7.3.1 and this instance
            # does not seem to have the pagination issues with the API now.

            # If the action is 'offense_details', fetch all the offenses, and count = None in that case
            if count:
                end_index = min(start_index + QRADAR_QUERY_HIGH_RANGE - 1, count - 1)
            else:
                end_index = start_index + QRADAR_QUERY_HIGH_RANGE - 1

            if start_index > end_index:
                break

            headers['Range'] = 'items={0}-{1}'.format(start_index, end_index)
            start_index += QRADAR_QUERY_HIGH_RANGE

            if ingest_only_open:
                offenses_status_msg = 'Fetching all open offenses as the asset configuration parameter for ingest only open is selected. '
                params['filter'] = filter_string + ' and status=OPEN'
                self.save_progress("Updated filter due to 'Ingest only open offenses' being True is:  {0}".format(params['filter']))

            response = self._call_api('siem/offenses', 'get', action_result, params=params, headers=headers)

            if phantom.is_fail(action_result.get_status()):
                self.debug_print("The 'call_api' for fetching offenses failed: ", action_result.get_status())
                return action_result.get_status()

            self.debug_print("Response Code", response.status_code)

            if response.status_code != 200 and 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)

            if not (200 <= response.status_code <= 399):
                # Error condition
                if 'json' in response.headers.get('Content-Type', ''):
                    status_message = self._get_json_error_message(response, action_result)
                else:
                    status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(
                        QRADAR_ERR_LIST_OFFENSES_API_FAILED, response.status_code, response.reason)
                return action_result.set_status(phantom.APP_ERROR, status_message)

            try:
                offenses += response.json()
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print("Unable to parse response of 'call_api' for fetching offenses as a valid JSON", error_msg)
                return action_result.set_status(phantom.APP_ERROR, "Unable to parse response "
                                                                   "of 'call_api' for fetching offenses as a valid JSON")

            total_offenses = len(offenses)

            if len(response.json()) < QRADAR_QUERY_HIGH_RANGE:
                self.save_progress(QRADAR_PROG_GOT_X_OFFENSES, total_offenses=total_offenses)
                break

        # Parse the output, which is an array of offenses
        # Update the summary
        if total_offenses == 0 and offense_ids != 'None':
            return action_result.set_status(phantom.APP_ERROR, "Please provide valid offense ID|s")
        action_result.update_summary({QRADAR_JSON_TOTAL_OFFENSES: len(offenses)})

        for offense in offenses:
            action_result.add_data(offense)

        # 6. Update the last fetched offense time in the global variable
        # self._new_last_ingest_time for the case of only scheduled or interval polling and not manual polling

        # Sort the offenses on the basis of the start_time and last_updated_time both
        # Note the recent start_time and recent last_updated_time
        # Update the _new_last_ingest_time with the maximum of the two as next time we will fetch the offenses
        # whose start_time or last_updated_time is greater than the _new_last_ingest_time
        # This new_last_ingest_time variable will be used only in the On_Poll action to store it in the last_saved_ingest_time of the state file

        if self._is_on_poll and not self._is_manual_poll and offenses:
            offenses.sort(key=lambda x: x['start_time'])
            recent_start_time = offenses[-1]['start_time']
            offenses.sort(key=lambda x: x['last_updated_time'])
            recent_last_updated_time = offenses[-1]['last_updated_time']
            self._new_last_ingest_time = max(recent_start_time, recent_last_updated_time)

        action_result.set_status(phantom.APP_SUCCESS, '{0}Total Offenses: {1}'.format(offenses_status_msg, len(offenses)))
        return action_result.get_status()

    def _handle_list_closing_reasons(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        params = dict()
        if param.get('include_reserved'):
            params['include_reserved'] = True

        if param.get('include_deleted'):
            params['include_deleted'] = True

        if len(params) == 0:
            params = None

        closing_reasons_response = self._call_api('siem/offense_closing_reasons', 'get', action_result, params=params, headers=None)

        if phantom.is_fail(action_result.get_status()):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        if not closing_reasons_response:
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_LIST_OFFENSE_CLOSING_REASONS)

        if closing_reasons_response.status_code != 200:
            if 'html' in closing_reasons_response.headers.get('Content-Type', ''):
                return self._process_html_response(closing_reasons_response, action_result)
            # Error condition
            if 'json' in closing_reasons_response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(closing_reasons_response, action_result)
            else:
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(
                    QRADAR_ERR_LIST_OFFENSE_CLOSING_REASONS,
                    closing_reasons_response.status_code,
                    closing_reasons_response.text if closing_reasons_response.text else "Unknown error occurred."
                )
            return action_result.set_status(phantom.APP_ERROR, status_message)

        try:
            closing_reasons = closing_reasons_response.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print(QRADAR_ERR_INVALID_JSON, error_msg)
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_JSON)

        for closing_reason in closing_reasons:
            action_result.add_data(closing_reason)

        summary = action_result.update_summary({})
        summary['total_offense_closing_reasons'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_rule_info(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        rule_id = param.get('rule_id')
        ret_val, _ = self._validate_integer(action_result, rule_id, QRADAR_RULE_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        get_rule_info_response = self._call_api('analytics/rules/{}'.format(rule_id), 'get', action_result, params=None, headers=None)

        if phantom.is_fail(action_result.get_status()):
            self.debug_print("Call API for 'get_rule_info' failed: ", action_result.get_status())
            return action_result.get_status()

        if not get_rule_info_response:
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_GET_RULE_INFO)

        if get_rule_info_response.status_code != 200:
            if 'html' in get_rule_info_response.headers.get('Content-Type', ''):
                return self._process_html_response(get_rule_info_response, action_result)

            if 'json' in get_rule_info_response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(get_rule_info_response, action_result)
            else:
                rule_info_response_text = get_rule_info_response.text
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(
                    QRADAR_ERR_GET_RULE_INFO,
                    get_rule_info_response.status_code,
                    rule_info_response_text if rule_info_response_text else "Unknown error occurred.")

            return action_result.set_status(phantom.APP_ERROR, status_message)

        try:
            rule_info = get_rule_info_response.json()
            action_result.add_data(rule_info)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print(QRADAR_ERR_INVALID_JSON, error_msg)
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_JSON)

        summary = action_result.update_summary({})
        summary['id'] = rule_info.get('id', None)
        summary['name'] = rule_info.get('name', None)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_rules(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        # 1. Validation of the input parameters
        count = param.get(QRADAR_JSON_COUNT)
        ret_val, count = self._validate_integer(action_result, count, QRADAR_COUNT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        rules = list()
        headers = dict()
        start_index = 0
        total_rules = 0
        while True:

            # If the action is 'offense_details', fetch all the offenses, and count = None in that case
            if count:
                end_index = min(start_index + QRADAR_QUERY_HIGH_RANGE - 1, count - 1)
            else:
                end_index = start_index + QRADAR_QUERY_HIGH_RANGE - 1

            if start_index > end_index:
                break

            headers['Range'] = 'items={0}-{1}'.format(start_index, end_index)
            start_index += QRADAR_QUERY_HIGH_RANGE

            list_rules_response = self._call_api('analytics/rules', 'get', action_result, params=None, headers=headers)

            if phantom.is_fail(action_result.get_status()):
                self.debug_print("call_api for list rules failed: ", action_result.get_status())
                return action_result.get_status()

            if not list_rules_response:
                return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_LIST_RULES)

            if list_rules_response.status_code != 200:
                if 'html' in list_rules_response.headers.get('Content-Type', ''):
                    return self._process_html_response(list_rules_response, action_result)

                if 'json' in list_rules_response.headers.get('Content-Type', ''):
                    status_message = self._get_json_error_message(list_rules_response, action_result)
                else:
                    list_rules_response_text = list_rules_response.text
                    status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(
                        QRADAR_ERR_LIST_RULES,
                        list_rules_response.status_code,
                        list_rules_response_text if list_rules_response_text else "Unknown error occurred.")

                return action_result.set_status(phantom.APP_ERROR, status_message)

            try:
                rules += list_rules_response.json()
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print(QRADAR_ERR_INVALID_JSON, error_msg)
                return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_JSON)

            total_rules = len(rules)

            if len(rules) < QRADAR_QUERY_HIGH_RANGE:
                self.save_progress(QRADAR_PROG_GOT_X_RULES, total_offenses=total_rules)
                break

        for rule in rules:
            action_result.add_data(rule)

        summary = action_result.update_summary({})
        summary['total_rules'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ariel_query(self, ariel_query, action_result, obj_result_key=None, offense_id=None, count=None):  # noqa: C901

        if obj_result_key:
            self.save_progress("Executing ariel query to get {0} {1}", obj_result_key,
                               '' if (not offense_id) else 'for offense: {offense_id}'.format(offense_id=offense_id))
        else:
            self.save_progress("Executing ariel query")

        # First create a search
        params = dict()
        params['query_expression'] = ariel_query

        response = self._call_api(QRADAR_ARIEL_SEARCH_ENDPOINT, 'post', action_result, params=params)

        if response and response.text:
            response_text = response.text
        else:
            response_text = "Unknown response returned."

        if phantom.is_fail(action_result.get_status()):
            self.debug_print("call_api for ariel query failed: ",
                             action_result.get_status())
            return action_result.set_status(phantom.APP_ERROR,
                                            "Error occurred while fetching events for the offense ID: {}. Response code: {}. Response text: {}"
                                            .format(offense_id, None if response is None else response.status_code, response_text))

        self.debug_print("Response Code", response.status_code)
        self.debug_print("Response Text", response_text)

        if response.status_code != 201:
            # Error condition
            action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_ARIEL_QUERY_FAILED)
            try:
                resp_text = response.text
                if response.json().get("description"):
                    resp_text = response.json().get("description", "Please provide valid input")
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide valid input')

            if "InOffense function: Error loading Offense" in resp_text:
                action_result.append_to_message("Queried offense might not contain data on QRadar")
            action_result.append_to_message("\nResponse from QRadar: {0}".format(resp_text))
            return action_result.get_status()

        try:
            response_json = response.json()
        except Exception:
            return action_result.get_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_JSON)

        # Now get the search id
        search_id = response_json.get('search_id')

        if not search_id:
            return action_result.get_status(phantom.APP_ERROR, "Response does not contain the 'search_id' key")

        # Init the response json
        response_json['status'] = 'EXECUTE'
        response_json['progress'] = 0
        got_error = False
        prev_percent = -1

        while not got_error and response_json.get('status') != 'COMPLETED':

            if 'progress' not in response_json:
                return action_result.set_status(phantom.APP_ERROR, "Response JSON does not contain 'progress' key")

            if prev_percent != response_json['progress']:
                # send progress about the query
                self.send_progress(QRADAR_PROG_QUERY_STATUS.format(percent=response_json['progress']))
                prev_percent = response_json['progress']

            time.sleep(6)

            # check the progress again
            response = self._call_api("{0}/{1}".format(QRADAR_ARIEL_SEARCH_ENDPOINT, search_id),
                                      'get', action_result, send_progress=False)

            if phantom.is_fail(action_result.get_status()):
                self.debug_print("call_api failed: ", action_result.get_status())
                self.save_progress(QRADAR_CONNECTION_FAILED)
                return action_result.get_status()

            if response.status_code != 200:
                if 'html' in response.headers.get('Content-Type', ''):
                    return self._process_html_response(response, action_result)
                # Error condition
                if 'json' in response.headers.get('Content-Type', ''):
                    status_message = self._get_json_error_message(response, action_result)
                else:
                    response_text = response.text
                    status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(
                        QRADAR_ERR_ARIEL_QUERY_STATUS_CHECK_FAILED,
                        response.status_code,
                        response_text if response_text else "Unknown error occurred.")
                got_error = True
                return action_result.set_status(phantom.APP_ERROR, status_message)

            # re-setting the failed times
            try:
                response_json = response.json()
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_JSON)

            if 'status' not in response_json:
                return action_result.set_status(phantom.APP_ERROR, "Response JSON does not contain 'status' key")

            status_list = ['COMPLETED', 'EXECUTE', 'SORTING', 'WAIT']

            # What is the status string for error, the sample apps don't have this info
            # neither the documentation
            if response_json.get('status') not in status_list:
                # Error condition
                action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_ARIEL_QUERY_STATUS_CHECK_FAILED)
                # Add the response that we got from the device, it contains additional info
                action_result.append_to_message(json.dumps(response_json))
                # set the error and break
                got_error = True
                return action_result.get_status()

        self.debug_print('response_json', response_json)

        # Looks like the search is complete, now get the results
        # If the action is run_query, then, do not use pagination
        # and simply fetch results else use pagination to fetch the results
        if self.get_action_identifier() == 'run_query':
            ret_val = self._fetch_search_results(action_result, offense_id, search_id, obj_result_key)

            if phantom.is_fail(ret_val):
                return action_result.get_status()
        else:
            self.save_progress('Fetching the events in chunks of {}'.format(QRADAR_QUERY_HIGH_RANGE))
            i = 0
            headers = dict()
            to_stop_fetch = 0
            while True:
                self.save_progress('Current iteration: {}'.format(i + 1))
                # Define the range for fetching the items from the search in the QRadar instance
                start_index = (i * QRADAR_QUERY_HIGH_RANGE)
                end_index = start_index + QRADAR_QUERY_HIGH_RANGE - 1
                headers['Range'] = "items={0}-{1}".format(start_index, end_index)

                ret_val = self._fetch_search_results(action_result, offense_id, search_id, obj_result_key, headers)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                current_events_count = self._total_events_count

                if not self._total_events_count:
                    current_events_count = len(action_result.get_data())

                to_stop_fetch = current_events_count % QRADAR_QUERY_HIGH_RANGE

                if current_events_count == 0 or to_stop_fetch != 0 or (count and current_events_count >= count):
                    break

                i += 1

        return action_result.set_status(phantom.APP_SUCCESS)

    def _fetch_search_results(self, action_result, offense_id, search_id, obj_result_key, headers=None):

        if ((self._is_on_poll or self.get_action_identifier() == 'offense_details') and self._container_id and self._offense_details) or \
                self.get_action_identifier() == 'get_flows':
            local_events_list = list()

        response = self._call_api("{0}/{1}/results".format(QRADAR_ARIEL_SEARCH_ENDPOINT, search_id),
                                  'get', action_result, headers=headers)

        if phantom.is_fail(action_result.get_status()):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        if response.status_code != 200:
            if 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)
            # Error condition
            if 'json' in response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(response, action_result)
            else:
                response_text = response.text
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_ARIEL_QUERY_RESULTS_FAILED, response.status_code,
                                                                                  response_text if response_text else "Unknown error occurred.")
            return action_result.set_status(phantom.APP_ERROR, status_message)

        try:
            # https://www-01.ibm.com/support/docview.wss?uid=swg1IV98260
            # siem bug. no workaround, sort of work with what we got

            r = """
                (?P<error>
                    \\s* { \\s*
                        "http_response": \\s* { \\s*
                            "code": \\s* 500, \\s*
                            "message": \\s* "Unexpected \\s internal \\s server \\s error" \\s*
                        }, \\s*
                        "code": \\s* 13, \\s*
                        "message": \\s* "Invocation \\s was \\s successful, \\s but \\s transformation \\s
                        to \\s content \\s type \\s ..APPLICATION_JSON.. \\s failed", \\s*
                        "description": \\s* "", \\s*
                        "details": \\s* {} \\s*
                    } $
                )"""

            (response_body, subcount) = re.subn(r, "", response.text, flags=re.X)

            if subcount > 0:
                self.save_progress("**** Warning: qradar bug: https://www-01.ibm.com/support/docview.wss?uid=swg1IV98260 *****")
                self.save_progress("Fixing ariel query response and continuing")
                response_body += "]}"

            response_json = json.loads(response_body)

        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print(QRADAR_ERR_INVALID_JSON, error_msg)
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_JSON)

        if obj_result_key:
            # Got the results
            if obj_result_key not in response_json:
                return action_result.set_status(phantom.APP_ERROR, "Response JSON does not contain '{0}' key".format(obj_result_key))

            objs = response_json[obj_result_key]
            # Add then to the action_result
            self.send_progress(QRADAR_MSG_GOT_N_OBJS, num_of_objs=len(objs), obj_type=obj_result_key)

            for obj in objs:
                # Replace the 'null' string to None if any
                obj = dict([(x[0], None if x[1] == 'null' else x[1]) for x in list(obj.items())])
                if self._is_on_poll or self.get_action_identifier() == 'offense_details' or self.get_action_identifier() == 'get_flows':
                    local_events_list.append(obj)
                else:
                    action_result.add_data(obj)

            self.save_progress("Ariel query retrieved {} {} for offense {}".format(len(objs), obj_result_key, offense_id))
            if len(objs) > 0 and 'starttime' in objs[0]:
                try:
                    self.save_progress("Ariel query retrieved {} {} for offense {}; starttime of earliest ({}) latest ({})".format(
                        len(objs), obj_result_key, offense_id, self._utcctime(objs[-1]['starttime']), self._utcctime(objs[0]['starttime'])))
                except Exception as e:
                    error_msg = self._get_error_message_from_exception(e)
                    self.debug_print('Error occurred: {}'.format(error_msg))

        else:
            if self._is_on_poll or self.get_action_identifier() == 'offense_details' or self.get_action_identifier() == 'get_flows':
                if isinstance(response_json, dict):
                    local_events_list.append(response_json)
                else:
                    local_events_list.extend(response_json)
            else:
                action_result.add_data(response_json)

        # Handling for get flows action
        if self.get_action_identifier() == 'get_flows':
            self._all_flows_data += local_events_list
            self._total_events_count += len(local_events_list)
            return action_result.set_status(phantom.APP_SUCCESS)

        # Generate the artifacts in chunk rather than accumulating all the events
        # in a single variable and then, create all artifacts for them at the end
        if (self._is_on_poll or self.get_action_identifier() == 'offense_details') and self._container_id and self._offense_details:
            for event in local_events_list:
                self._events_starttime_list.append({'starttime': event.get('starttime', 0)})

            self._total_events_count += len(local_events_list)

            self._create_events_artifacts(local_events_list, offense_id)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_events_artifacts(self, events, offense_id):

        # To strip \r, \n and space from the values
        v_strip = lambda v: v.strip(' \r\n').replace('\u0000', '') if isinstance(v, str) else v

        self._create_offense_artifacts(self._offense_details, self._container_id, offense_id)

        for event in events:
            # strip \r, \n and space from the values, QRadar does that for the description field at least
            event = dict([(k, v_strip(v)) for k, v in list(event.items())])

            artifact = self._get_artifact(event, self._container_id)

            self._artifacts_list.append(artifact)

    def _validate_times(self, param, action_result):

        if phantom.APP_JSON_START_TIME in param:
            try:
                datetime.utcfromtimestamp(param[phantom.APP_JSON_START_TIME] / 1000).replace(tzinfo=pytz.utc)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Invalid {0}".format(phantom.APP_JSON_START_TIME))

        if phantom.APP_JSON_END_TIME in param:
            try:
                datetime.utcfromtimestamp(param[phantom.APP_JSON_END_TIME] / 1000).replace(tzinfo=pytz.utc)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Invalid {0}".format(phantom.APP_JSON_END_TIME))

        return phantom.APP_SUCCESS

    def _get_tz_str_from_epoch(self, name, epoch_milli, action_result):

        try:
            # Need to convert from UTC to the device's timezone, get the device's tz from config
            config = self.get_config()
            device_tz_sting = phantom.get_req_value(config, QRADAR_JSON_TIMEZONE)

            to_tz = timezone(device_tz_sting)

            utc_dt = datetime.utcfromtimestamp(epoch_milli / 1000).replace(tzinfo=pytz.utc)
            to_dt = to_tz.normalize(utc_dt.astimezone(to_tz))

            to_dt_str = to_dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            action_result.set_status(phantom.APP_ERROR, "Error occurred while converting epoch value of '{0}' to datetime string. Error: {1}".
                                     format(name, error_msg))
            return None

        return to_dt_str

    def _get_events(self, param, action_result=None):  # noqa: C901

        if not action_result:
            # Create a action result to represent this action
            action_result = self.add_action_result(ActionResult(dict(param)))

        # 1. Validation of the input parameters
        # We do not fetch all the events as like we fetch all offenses if the count is not provided by the user

        # The reason for such a logic is that there can be a huge amount of events as compared to less number of offenses
        # Validate 'count' action parameter

        count = param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_EVENT_COUNT)
        ret_val, count = self._validate_integer(action_result, count, QRADAR_COUNT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            if param.get('start_time') and not str(param.get('start_time')).isdigit():
                return action_result.set_status(phantom.APP_ERROR, "Please provide valid epoch value (milliseconds) "
                                                                   "in the 'start_time' parameter")
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Please provide valid non-zero epoch value (milliseconds) "
                                                               "in the 'start_time' parameter")

        try:
            if (param.get('end_time') and not str(param.get('end_time')).isdigit()) or param.get('end_time') == 0:
                return action_result.set_status(phantom.APP_ERROR, "Please provide valid non-zero epoch value (milliseconds) "
                                                                   "in the 'end_time' parameter")
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Please provide valid non-zero epoch "
                                                               "value (milliseconds) in the 'end_time' parameter")

        # Validate 'offense_id' action parameter
        offense_id = param.get('offense_id')
        ret_val, offense_id = self._validate_integer(action_result, offense_id, QRADAR_OFFENSE_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val = self._validate_times(param, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # 2. Create the ariel_query for fetching the events
        config = self.get_config()
        if config.get('event_fields_for_query', None) is not None:
            event_fields = [event_field.strip() for event_field in config.get('event_fields_for_query').split(',')]
            event_fields = list(filter(None, event_fields))
            event_fields_str = ','.join(event_fields)
            ariel_query = QRADAR_AQL_EVENT_SELECT + ', ' + event_fields_str + QRADAR_AQL_EVENT_FROM
        else:
            ariel_query = QRADAR_AQL_EVENT_SELECT + QRADAR_AQL_EVENT_FROM

        # Default the where clause to empty
        where_clause = ''

        # Get the offense ID
        offense_id = phantom.get_str_val(param, QRADAR_JSON_OFFENSE_ID, None)
        if offense_id:
            if len(where_clause):
                where_clause += " and"
            if self._has_offense:
                where_clause += " hasOffense='true' and InOffense({0})".format(offense_id)
            else:
                where_clause += " InOffense({0})".format(offense_id)
            # Update the parameter
            action_result.update_param({QRADAR_JSON_OFFENSE_ID: offense_id})

        # Get the fields where part
        fields_filter = param.get(QRADAR_JSON_FIELDS_FILTER, "")
        if fields_filter:
            if len(where_clause):
                where_clause += " and"
            where_clause += " {0}".format(fields_filter)
            action_result.update_param({QRADAR_JSON_FIELDS_FILTER: fields_filter})

        # 3. Initialize num_days which is used to define | change
        # the start_time_msecs as set in the below steps

        num_days = param.get(QRADAR_JSON_DEF_NUM_DAYS, self.get_app_config().get(QRADAR_JSON_DEF_NUM_DAYS,
                                                                                 QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME))
        # Validate 'interval_days' action parameter
        ret_val, num_days = self._validate_integer(action_result, num_days, QRADAR_INTERVAL_DAYS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # 4. Initialize all time related variables
        # curr_epoch_msecs is current epoch time
        # start_time_msecs is value against the key 'start_time' in param or
        # num_days back then the end_time_msecs or 5 days back then the end_time_msecs
        # end_time_msecs is value against the key 'end_time' in param or curr_epoch_msecs
        curr_epoch_msecs = int(time.time()) * 1000
        end_time_msecs = int(param.get(phantom.APP_JSON_END_TIME, curr_epoch_msecs))
        start_time_msecs = 0

        # 5. Update the start_time_msecs from the state file stored value of last_ingested_events_data
        # in case of only scheduled and interval polling to avoid processing of already ingested events
        # and rather start from the time till what we had already ingested and
        # had stopped ingestion from that point in the last run
        try:
            start_time_msecs = int(param.get(phantom.APP_JSON_START_TIME, end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days)))
            if self._is_on_poll and not self._is_manual_poll:
                if self._state.get('last_ingested_events_data', {}).get(str(param.get('offense_id', ''))):
                    start_time_msecs = int(self._state['last_ingested_events_data'].get(str(param.get('offense_id'))))
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while formation of 'start_time_msecs' for fetching the events. "
                                                               "Error: {}".format(error_msg))

        if end_time_msecs < start_time_msecs:
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME_RANGE)

        # After-date the event ingestion end time by event_ingest_end_time configuration parameter
        # if it exceeds the current time, consider current time as end time

        if self._is_on_poll and self._event_ingest_end_time > 0:
            self.save_progress('Original end_time_msecs is: {0} and start_time_msecs is : {1}'.format(end_time_msecs, start_time_msecs))
            self.save_progress('After-dating the event end time by {} minutes'.format(self._event_ingest_end_time))
            end_time_msecs = start_time_msecs + self._event_ingest_end_time * 60 * 1000
            if end_time_msecs > curr_epoch_msecs:
                self.debug_print("The modified end_time_msecs to fetch events exceeded the current time so the "
                                 "current time is taken as end_time_msecs")
                end_time_msecs = curr_epoch_msecs
            self.save_progress('The modified end_time_msecs is: {}'.format(end_time_msecs))

        # The START clause has to come before the STOP clause, else the query fails
        # The START and STOP clause have to be given, else the results will be for
        # the last 60 seconds or something small like that.
        # We also need to get the events closest to the end time, so add the
        # starttime comparison operators for that
        # The starttime >= and starttime <= clause is required without which the limit clause fails
        if len(where_clause):
            where_clause += " and"

        where_clause += " starttime >= {0} and starttime <= {1}".format(start_time_msecs, end_time_msecs)
        # where_clause += " starttime BETWEEN {0} and {1}".format(start_time_msecs, end_time_msecs)

        # 6. We are removing this because it was causing only 1000 events to be fetched and no more than that.
        # This led into data loss while ingesting a data set which had more than 1000 events in a single offense

        if param.get('total_events_count'):
            where_clause += " order by STARTTIME desc limit {0}".format(int(param.get('total_events_count')))
        else:
            where_clause += " order by STARTTIME desc limit {0}".format(count)

        # From testing queries, it was noticed that the START and STOP are required else the default
        # result returned by the REST API is of 60 seconds or so. Also, the time format needs to be in
        # the device's timezone.
        if self._get_tz_str_from_epoch('start_time_msecs', start_time_msecs, action_result) is None or self._get_tz_str_from_epoch(
                'end_time_msecs', end_time_msecs, action_result) is None:
            return action_result.get_status()

        where_clause += " START '{0}'".format(self._get_tz_str_from_epoch('start_time_msecs', start_time_msecs, action_result))
        where_clause += " STOP '{0}'".format(self._get_tz_str_from_epoch('end_time_msecs', end_time_msecs, action_result))

        # Use the alternate ariel query
        if self._use_alt_ariel_query:
            where_clause = ''
            if fields_filter:
                where_clause += " {0} ".format(fields_filter)
                action_result.update_param({QRADAR_JSON_FIELDS_FILTER: fields_filter})

            if offense_id:
                if len(where_clause):
                    where_clause += " and"
                where_clause += " InOffense({}) ".format(offense_id)

            event_start_time = None
            if self._is_on_poll and not self._is_manual_poll:
                if self._state.get('last_ingested_events_data', {}).get(str(param.get('offense_id', ''))):
                    event_start_time = int(self._state['last_ingested_events_data'].get(str(param.get('offense_id'))))

            if not event_start_time:
                event_days = num_days
            else:
                now = self._utcnow()
                start = self._datetime(event_start_time)
                diff = now - start
                event_days = abs(diff.days) + 1 if diff.seconds != 0 else abs(diff.days)

            if param.get('total_events_count'):
                where_clause += "ORDER BY starttime DESC LIMIT {} LAST {} DAYS".format(int(param.get('total_events_count')), event_days)
            else:
                where_clause += "ORDER BY starttime DESC LIMIT {} LAST {} DAYS".format(count, event_days)

        if self._use_alt_ariel_query and where_clause.startswith("ORDER BY"):
            ariel_query = "{0} {1}".format(ariel_query, where_clause)
        else:
            ariel_query = "{0} where {1}".format(ariel_query, where_clause)

        # Sent the final count which is inserted in the ariel_query to the _handle_ariel_query method
        final_count = QRADAR_QUERY_HIGH_RANGE
        try:
            extracted_limit_list = re.findall(QRADAR_LIMIT_REGEX_MATCH_PATTERN, ariel_query, re.IGNORECASE)

            if extracted_limit_list:
                final_count = int(extracted_limit_list[0])
        except Exception:
            self.debug_print('Error occurred while extracting the LIMIT value from the ariel query string: {}'.format(ariel_query))
            self.debug_print('Fetching {} events by default due to failure in fetching the value of the LIMIT value from the query string'
                             .format(QRADAR_QUERY_HIGH_RANGE))

        self.save_progress('Sending the value {} as count to finally fetch the elements using the ariel query'.format(final_count))
        self.debug_print('Sending the value {} as count to finally fetch the elements using the ariel query'.format(final_count))

        self.debug_print('Ariel query for fetching events: {0}'.format(ariel_query))
        self.save_progress('Ariel query for fetching events: {0}'.format(ariel_query))

        ret_val = self._handle_ariel_query(ariel_query, action_result, 'events', offense_id, count=final_count)

        if phantom.is_fail(ret_val):
            self.debug_print('Fetching events failed with the ariel query: {0} and offense ID: {1}. Error message: {2}'.format(
                ariel_query, offense_id, action_result.get_message()))
            return action_result.get_status()

        # This variable will have value only when the action is
        # other than 'on_poll' and 'offense details'
        # if not self._is_on_poll or not self.get_action_identifier() == 'offense_details':
        if self.get_action_identifier() == 'get_events':
            events_list = action_result.get_data()
        else:
            events_list = self._events_starttime_list

        if self._is_on_poll and not self._is_manual_poll and events_list:
            events_list.sort(key=lambda x: x['starttime'])
            if not self._state.get('last_ingested_events_data'):
                offense_dict = {str(param.get('offense_id')): events_list[-1]['starttime']}
                self._state.update({'last_ingested_events_data': offense_dict})
            else:
                last_ingested_events_data_dict = self._state.get('last_ingested_events_data')
                last_ingested_events_data_dict[str(param.get('offense_id'))] = events_list[-1]['starttime']
                self._state['last_ingested_events_data'] = last_ingested_events_data_dict
        # Set the summary
        action_result.update_summary({QRADAR_JSON_TOTAL_EVENTS: action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_query(self, param):

        # Create a action result
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param[QRADAR_JSON_QUERY]

        # Sent the final count which is inserted in the ariel_query to the _handle_ariel_query method
        final_count = None
        try:
            extracted_limit_list = re.findall(QRADAR_LIMIT_REGEX_MATCH_PATTERN, query, re.IGNORECASE)

            if extracted_limit_list:
                final_count = int(extracted_limit_list[0])
        except Exception:
            self.debug_print('Error occurred while extracting the LIMIT value from the ariel query string: {}'.format(query))
            self.debug_print('Fetching all results by default due to failure in fetching the value of the LIMIT value from the query string')

        self.debug_print('Sending the value {} as count to finally fetch the elements using the ariel query'.format(final_count))

        ret_val = self._handle_ariel_query(query, action_result, count=final_count)

        if phantom.is_fail(ret_val):
            self.debug_print('Execution of the ariel query: {0}. Error message: {1}'.format(
                query, action_result.get_message()))
            return action_result.get_status()

        data = action_result.get_data()

        items = {}

        # get the events, flows dictionaries
        try:
            items = data[0]
        except Exception:
            return action_result.get_status()

        # loop for the event, flows items
        for curr_item, v in list(items.items()):

            if not isinstance(v, list):
                items[curr_item] = [v]

            for i, curr_obj in enumerate(items[curr_item]):
                # Replace the 'null' string to None if any
                curr_obj = dict([(x[0], None if x[1] == 'null' else x[1]) for x in list(curr_obj.items())])
                items[curr_item][i] = curr_obj

        return action_result.set_status(phantom.APP_SUCCESS, QRADAR_SUCC_RUN_QUERY)

    def _get_flows(self, param):  # noqa: C901

        # Create a action result
        action_result = self.add_action_result(ActionResult(dict(param)))

        offense_id = param.get('offense_id')
        # Validate 'offense_id' action parameter
        ret_val, offense_id = self._validate_integer(action_result, offense_id, QRADAR_OFFENSE_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # We do not fetch all the flows as like we fetch all offenses if the count is not provided by the user
        # The reason for such a logic is that there can be a large amount of flows as compared to less number of offenses
        count = param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_FLOW_COUNT)
        # Validate 'count' action parameter
        ret_val, count = self._validate_integer(action_result, count, QRADAR_COUNT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            if param.get('start_time') and not str(param.get('start_time')).isdigit():
                return action_result.set_status(phantom.APP_ERROR, "Please provide valid epoch value (milliseconds) in "
                                                                   "the 'start_time' parameter")
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Please provide valid non-zero epoch value (milliseconds) in "
                                                               "the 'start_time' parameter")

        try:
            if (param.get('end_time') and not str(param.get('end_time')).isdigit()) or param.get('end_time') == 0:
                return action_result.set_status(phantom.APP_ERROR, "Please provide valid non-zero epoch value (milliseconds) in "
                                                                   "the 'end_time' parameter")
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Please provide valid non-zero epoch value (milliseconds) in "
                                                               "the 'end_time' parameter")

        ret_val = self._validate_times(param, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Generate the fix part of the query
        # default the where clause to empty
        where_clause = ''

        # Get the offense id
        if offense_id:
            if len(where_clause):
                where_clause += " and"
            if self._has_offense:
                where_clause += " hasOffense='true' and InOffense({0})".format(offense_id)
            else:
                where_clause += " InOffense({0})".format(offense_id)
            # Update the parameter
            action_result.update_param({QRADAR_JSON_OFFENSE_ID: offense_id})

        ip_to_query = phantom.get_str_val(param, QRADAR_JSON_IP, None)
        if ip_to_query:
            if len(where_clause):
                where_clause += " and"
            where_clause += " (sourceip='{0}' or destinationip='{0}')".format(ip_to_query)
            # Update the parameter
            action_result.update_param({QRADAR_JSON_IP: ip_to_query})

        # Get the fields where part
        fields_filter = param.get(QRADAR_JSON_FIELDS_FILTER, "")
        if fields_filter:
            if len(where_clause):
                where_clause += " and"
            where_clause += " {0}".format(fields_filter)
            action_result.update_param({QRADAR_JSON_FIELDS_FILTER: fields_filter})

        # 3. Initialize num_days which is used to define | change
        # the start_time_msecs as set in the below steps

        # Validate 'interval_days' action parameter
        num_days = param.get(QRADAR_JSON_DEF_NUM_DAYS, self.get_app_config().get(QRADAR_JSON_DEF_NUM_DAYS,
                                                                                 QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME))
        ret_val, num_days = self._validate_integer(action_result, num_days, QRADAR_INTERVAL_DAYS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # 4. Initialize all time related variables
        # curr_epoch_msecs is current epoch time
        # start_time_msecs is value against the key 'start_time' in param or
        # num_days back then the end_time_msecs or 5 days back then the end_time_msecs
        # end_time_msecs is value against the key 'end_time' in param or curr_epoch_msecs
        curr_epoch_msecs = int(time.time()) * 1000
        end_time_msecs = int(param.get(phantom.APP_JSON_END_TIME, curr_epoch_msecs))
        start_time_msecs = 0

        try:
            start_time_msecs = int(param.get(phantom.APP_JSON_START_TIME, end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days)))
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while formation "
                                                               "of 'start_time_msecs' for fetching the flows. Error: {}".format(error_msg))

        if end_time_msecs < start_time_msecs:
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME_RANGE)

        if len(where_clause):
            where_clause += " and"

        # The starttime >= and starttime <= clause is required without which the limit clause fails
        where_clause += " starttime >= {0} and starttime <= {1}".format(start_time_msecs, end_time_msecs)

        where_clause += " ORDER BY starttime DESC LIMIT {0}".format(count)

        # From testing queries, it was noticed that the START and STOP are required else the default
        # result returned by the REST API is of 60 seconds or so. Also, the time format needs to be in
        # the device's timezone.

        if self._get_tz_str_from_epoch('start_time_msecs', start_time_msecs, action_result) is None or self._get_tz_str_from_epoch(
                'end_time_msecs', end_time_msecs, action_result) is None:
            return action_result.get_status()

        where_clause += " START '{0}'".format(self._get_tz_str_from_epoch('start_time_msecs', start_time_msecs, action_result))
        where_clause += " STOP '{0}'".format(self._get_tz_str_from_epoch('end_time_msecs', end_time_msecs, action_result))

        ariel_query = QRADAR_AQL_FLOW_SELECT + QRADAR_AQL_FLOW_FROM

        ariel_query = "{0} where {1}".format(ariel_query, where_clause)

        # Sent the final count which is inserted in the ariel_query to the _handle_ariel_query method
        final_count = None
        try:
            extracted_limit_list = re.findall(QRADAR_LIMIT_REGEX_MATCH_PATTERN, ariel_query, re.IGNORECASE)

            if extracted_limit_list:
                final_count = int(extracted_limit_list[0])
        except Exception:
            self.debug_print('Error occurred while extracting the LIMIT value from the ariel query string: {}'.format(ariel_query))
            self.debug_print('Fetching entire data due to failure in fetching the value of the LIMIT value from the query string')

        self.debug_print('Sending the value {} as count to finally fetch the elements using the ariel query'.format(final_count))

        # Initiating the all items and all items count to zero for every chunk of data
        # for fetching same values for every small chunk of data
        self._total_events_count = 0
        self._all_flows_data = []

        ret_val = self._handle_ariel_query(ariel_query, action_result, 'flows', offense_id, count=final_count)

        if phantom.is_fail(ret_val):
            self.debug_print('Fetching flows failed with the ariel query: {0}. Error message: {1}'.format(
                ariel_query, action_result.get_message()))
            return action_result.get_status()

        if not self._all_flows_data:
            return action_result.set_status(phantom.APP_SUCCESS, "No flows found")

        for data in self._all_flows_data:
            action_result.add_data(data)

        action_result.update_summary({QRADAR_JSON_TOTAL_FLOWS: action_result.get_data_size()})

        return action_result.get_status()

    def _handle_add_note(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        offense_id = param[QRADAR_JSON_OFFENSE_ID]
        note_text = param[QRADER_JSON_NOTE_TEXT]

        # Validate 'offense_id' action parameter
        ret_val, _ = self._validate_integer(action_result, offense_id, QRADAR_OFFENSE_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            'note_text': note_text,
        }

        endpoint = 'siem/offenses/{0}/notes'.format(offense_id)

        response = self._call_api(endpoint, 'post', action_result, params=params)
        if phantom.is_fail(action_result.get_status()):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        if not response:
            # REST Call Failed
            response_text = response.text
            reason = json.loads(response_text if response_text else '{"message": "Unknown error occurred."}')
            if reason.get('message'):
                err_reason = reason.get('message')
            else:
                err_reason = QRADAR_ERR_ADD_NOTE_API_FAILED
            action_result.add_data(reason)
            return action_result.set_status(phantom.APP_ERROR, err_reason)

        # Response JSON just contains note_text and the offense id

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully added note to offense")

    def _handle_assign_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        offense_id = param[QRADAR_JSON_OFFENSE_ID]
        assignee = param[QRADER_JSON_ASSIGNEE]

        # Validate 'offense_id' action parameter
        ret_val, _ = self._validate_integer(action_result, offense_id, QRADAR_OFFENSE_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            'assigned_to': assignee,
        }
        endpoint = 'siem/offenses/{}'.format(offense_id)

        response = self._call_api(endpoint, 'post', action_result, params=params)
        if phantom.is_fail(action_result.get_status()):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        if response.status_code not in [200, 399]:
            response_text = response.text
            reason = json.loads(response_text if response_text else '{"message": "Unknown error occurred."}')
            return action_result.set_status(phantom.APP_ERROR, reason.get('message'))

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully assigned user to offense")

    def _handle_offense_details(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        # Get the list of offense ids
        offense_id = param[QRADAR_JSON_OFFENSE_ID]

        # Validate 'tenant_id' action parameter
        tenant_id = param.get('tenant_id', None)
        ret_val, _ = self._validate_integer(action_result, tenant_id, QRADAR_TENANT_ID_KEY, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Validate 'offense_id' action parameter
        ret_val, _ = self._validate_integer(action_result, offense_id, QRADAR_OFFENSE_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Update the parameter
        action_result.update_param({QRADAR_JSON_OFFENSE_ID: offense_id})

        if param.get("ingest_offense", False):
            self._on_poll_action_result = action_result
            result = self._on_poll(param)

            if phantom.is_fail(action_result.get_status()):
                self.debug_print("call_api failed: ", action_result.get_status())
                return action_result.get_status()

            # return action_result.set_status(phantom.APP_SUCCESS, "Offenses ingested successfully")
            return result

        response = self._call_api('siem/offenses/{0}'.format(offense_id), 'get', action_result)

        if phantom.is_fail(action_result.get_status()):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        self.debug_print("Response Code", response.status_code)

        if response.status_code != 200:
            if 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)
            # Error condition
            if 'json' in response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(response, action_result)
            else:
                response_text = response.text
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_GET_OFFENSE_DETAIL_API_FAILED,
                                                                                  response.status_code,
                                                                                  response_text if response_text else "Unknown error occurred.")
            return action_result.set_status(phantom.APP_ERROR, status_message)

        # Parse the output, which is details of an offense
        try:
            response_json = response.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print(QRADAR_ERR_INVALID_JSON, error_msg)
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_JSON)

        action_result.add_data(response_json)

        time_str = lambda x: datetime.fromtimestamp(int(x) / 1000.0).strftime('%Y-%m-%d %H:%M:%S UTC')

        try:
            # Create a summary
            action_result.update_summary({
                QRADAR_JSON_NAME: response_json['description'].strip('\n'),
                QRADAR_JSON_OFFENSE_SOURCE: response_json['offense_source'],
                QRADAR_JSON_FLOW_COUNT: response_json['flow_count'],
                QRADAR_JSON_STATUS: response_json['status'],
                QRADAR_JSON_STARTTIME: time_str(response_json['start_time']),
                QRADAR_JSON_UPDATETIME: time_str(response_json['last_updated_time'])})
        except Exception:
            # No reason to halt and throw an error since only summary creation has failed.
            self.debug_print("Error occurred while updating action_result summary")

        return phantom.APP_SUCCESS

    def _handle_add_to_reference_set(self, param):

        # Get the list of offense ids
        reference_set_name = param[QRADAR_JSON_REFSET_NAME]
        reference_set_value = param[QRADAR_JSON_REFSET_VALUE]

        # Create a action result
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Update the parameter
        params = dict()

        # value to insert into ref set
        params['value'] = reference_set_value

        response = self._call_api('reference_data/sets/{0}'.format(reference_set_name), 'post', action_result, params=params)

        if phantom.is_fail(action_result.get_status()):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        self.debug_print("Response Code", response.status_code)

        if response.status_code != 200:
            if 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)
            # Error condition
            if 'json' in response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(response, action_result)
            else:
                response_text = response.text
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_GET_OFFENSE_DETAIL_API_FAILED,
                                                                                  response.status_code,
                                                                                  response_text if response_text else "Unknown error occurred.")
            return action_result.set_status(phantom.APP_ERROR, status_message)

        self.debug_print("content-type", response.headers['content-type'])

        # Parse the output, which is details of an offense
        try:
            response_json = response.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print(QRADAR_ERR_INVALID_JSON, error_msg)
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_JSON)

        action_result.add_data(response_json)

        try:
            # Create a summary
            action_result.update_summary({
                'element_type': response_json['element_type'].strip('\n'),
                'name': response_json['name'],
                'number_of_elements': response_json['number_of_elements']})
        except Exception:
            # No reason to halt and throw an error since only summary creation has failed.
            self.debug_print("Error occurred while updating action_result summary")

        return action_result.get_status()

    def _handle_close_offense(self, param):

        # Create a action result
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get the list of offense ids
        offense_id = param[QRADAR_JSON_OFFENSE_ID]
        closing_reason_id = param[QRADAR_JSON_CLOSING_REASON_ID]

        # Validate 'offense_id' action parameter
        ret_val, _ = self._validate_integer(action_result, offense_id, QRADAR_OFFENSE_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Validate 'closing_reason_id' action parameter
        ret_val, _ = self._validate_integer(action_result, closing_reason_id, QRADAR_CLOSING_REASON_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Update the parameter
        action_result.update_param({QRADAR_JSON_OFFENSE_ID: offense_id})
        params = dict()
        params[QRADAR_JSON_CLOSING_REASON_ID] = closing_reason_id

        params['status'] = "CLOSED"

        response = self._call_api('siem/offenses/{0}'.format(offense_id), 'post', action_result, params=params)

        if phantom.is_fail(action_result.get_status()):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        self.debug_print("Response Code", response.status_code)

        if response.status_code != 200:
            if 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)
            # Error condition
            if 'json' in response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(response, action_result)
            else:
                response_text = response.text
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_GET_OFFENSE_DETAIL_API_FAILED,
                                                                                  response.status_code,
                                                                                  response_text if response_text else "Unknown error occurred.")
            return action_result.set_status(phantom.APP_ERROR, status_message)

        self.debug_print("content-type", response.headers['content-type'])

        # Parse the output, which is details of an offense
        try:
            response_json = response.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print(QRADAR_ERR_INVALID_JSON, error_msg)
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_JSON)

        action_result.add_data(response_json)

        time_str = lambda x: datetime.fromtimestamp(int(x) / 1000.0).strftime('%Y-%m-%d %H:%M:%S UTC')

        try:
            # Create a summary
            action_result.update_summary({
                QRADAR_JSON_NAME: response_json['description'].strip('\n'),
                QRADAR_JSON_OFFENSE_SOURCE: response_json['offense_source'],
                QRADAR_JSON_FLOW_COUNT: response_json['flow_count'],
                QRADAR_JSON_STATUS: response_json['status'],
                QRADAR_JSON_STARTTIME: time_str(response_json['start_time']),
                QRADAR_JSON_UPDATETIME: time_str(response_json['last_updated_time'])})
        except Exception:
            # No reason to halt and throw an error since only summary creation has failed.
            self.debug_print("Error occurred while updating action_result summary")

        return action_result.get_status()

    def _alt_manage_ingestion(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        operation = param.get('operation', "get last saved ingestion time data")
        datestring = param.get('datetime')
        offense_id = param.get('offense_id')

        if not operation == "set last saved offense ingest time" and not operation == "set last saved events ingest time" and datestring:
            return action_result.set_status(phantom.APP_ERROR, 'Datestring is required only while setting the last saved ingestion time data')

        # Validation of the datestring in all 4 supported formats
        if (operation == "set last saved offense ingest time" or operation == "set last saved events ingest time") and datestring:
            for fmt in ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d', '%H:%M:%S.%f']:
                try:
                    datetime.strptime(datestring, fmt)
                except Exception:
                    continue

                break
            else:
                return action_result.set_status(phantom.APP_ERROR,
                                                "Invalid datetime format. The supported datestring "
                                                "formats are 'YYYY-MM-DD HH:MM:SS.Z', 'YYYY-MM-DDTHH:MM:SS.Z', 'YYYY-MM-DD', or 'HH:MM:SS.Z'")

        if not operation == "set last saved events ingest time" and offense_id:
            return action_result.set_status(phantom.APP_ERROR, "Offense ID is required only for the "
                                                               "operation 'set last saved events ingest time'")

        if operation == "delete last saved ingestion time data":
            if 'last_saved_ingest_time' in self._state:
                del self._state['last_saved_ingest_time']
            if 'last_ingested_events_data' in self._state:
                del self._state['last_ingested_events_data']
        elif operation == "set last saved offense ingest time":
            if not datestring:
                return action_result.set_status(phantom.APP_ERROR, "The 'datetime' field must be provided for the "
                                                                   "operation 'set last saved offense ingest time'")
            try:
                self._state['last_saved_ingest_time'] = self._tzparsedtime(datestring) * 1000
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Invalid datetime parameter")
        elif operation == "set last saved events ingest time":
            if not offense_id or not datestring:
                return action_result.set_status(phantom.APP_ERROR, "The 'offense_id' and 'datetime' fields must be "
                                                                   "provided for the operation 'set last saved events ingest time'")

            # Validate 'offense_id' action parameter
            ret_val, _ = self._validate_integer(action_result, offense_id, QRADAR_OFFENSE_ID_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                events_data = self._state.get('last_ingested_events_data', {})
                events_data.update({str(offense_id): self._tzparsedtime(datestring) * 1000})
                self._state['last_ingested_events_data'] = events_data
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Invalid datetime parameter")
        else:
            if not operation == "get last saved ingestion time data":
                return action_result.set_status(phantom.APP_ERROR, "Please select a valid operation in the 'operation' action parameter")
        last_saved_offense_ingest_time = self._state.get('last_saved_ingest_time')
        last_ingested_events_ingest_time_as_epoch = self._state.get('last_ingested_events_data', {})
        last_ingested_events_ingest_time_as_datetime = {}

        for key, value in list(last_ingested_events_ingest_time_as_epoch.items()):
            last_ingested_events_ingest_time_as_datetime[str(key)] = self._utcctime(value) if value or value == 0 else None

        last_ingested_events_ingest_time_as_datetime_str = None
        if last_ingested_events_ingest_time_as_datetime:
            last_ingested_events_ingest_time_as_datetime_str = ", ".join(
                ["=".join(['Offense ID_{}'.format(key), val]) for key, val in list(last_ingested_events_ingest_time_as_datetime.items())])

        try:
            action_result.update_summary({
                'last_saved_offense_ingest_time': self._utcctime(
                    last_saved_offense_ingest_time) if last_saved_offense_ingest_time or last_saved_offense_ingest_time == 0 else None,
                'last_ingested_events_ingest_time': last_ingested_events_ingest_time_as_datetime_str
            })
            action_result.add_data({
                'last_saved_offense_ingest_time': self._utcctime(
                    last_saved_offense_ingest_time) if last_saved_offense_ingest_time or last_saved_offense_ingest_time == 0 else None,
                'last_saved_offense_ingest_time_as_epoch': last_saved_offense_ingest_time,
                'last_ingested_events_ingest_time': last_ingested_events_ingest_time_as_datetime_str,
                'last_ingested_events_ingest_time_as_epoch': last_ingested_events_ingest_time_as_epoch
            })
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print('Provided time is invalid. Error: {}'.format(error_msg))
            return action_result.set_status(phantom.APP_ERROR, 'Provided time is invalid. Error: {}'.format(error_msg))

        self.save_state(self._state)
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        result = None
        action = self.get_action_identifier()

        if action == self.ACTION_ID_LIST_OFFENSES:
            result = self._list_offenses(param)
        elif action == self.ACTION_ID_LIST_CLOSING_REASONS:
            result = self._handle_list_closing_reasons(param)
        elif action == self.ACTION_ID_GET_EVENTS:
            result = self._get_events(param)
        elif action == self.ACTION_ID_GET_FLOWS:
            result = self._get_flows(param)
        elif action == self.ACTION_ID_RUN_QUERY:
            result = self._run_query(param)
        elif action == self.ACTION_ID_OFFENSE_DETAILS:
            result = self._handle_offense_details(param)
        elif action == self.ACTION_ID_CLOSE_OFFENSE:
            result = self._handle_close_offense(param)
        elif action == self.ACTION_ID_ADD_TO_REF_SET:
            result = self._handle_add_to_reference_set(param)
        elif action == self.ACTION_ID_ADD_NOTE:
            result = self._handle_add_note(param)
        elif action == phantom.ACTION_ID_INGEST_ON_POLL:
            start_time = time.time()
            result = self._on_poll(param)
            end_time = time.time()
            diff_time = end_time - start_time
            human_time = str(timedelta(seconds=int(diff_time)))
            self.save_progress("Time taken: {0}".format(human_time))
        elif action == "alt_manage_ingestion":
            result = self._alt_manage_ingestion(param)
        elif action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self._test_connectivity(param)
        elif action == self.ACTION_ID_ASSIGNE_USER:
            result = self._handle_assign_user(param)
        elif action == self.ACTION_ID_GET_RULE_INFO:
            result = self._get_rule_info(param)
        elif action == self.ACTION_ID_LIST_RULES:
            result = self._list_rules(param)
        else:
            self.unknown_action()

        return result

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_exception(self, e):
        import traceback
        self.debug_print("Handle exception occurred: {}".format(traceback.format_exc()))
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = BaseConnector._get_phantom_base_url() + "login"
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(
                login_url, verify=verify, data=data, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
            )
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = QradarConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)

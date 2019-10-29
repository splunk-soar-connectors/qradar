# File: qradar_connector.py
# Copyright (c) 2016-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult

# THIS Connector imports
from qradar_consts import *

# Other imports used by this connector
import requests
import base64
import time
import pytz
import re
import calendar
import dateutil.parser
import dateutil.tz
import default_timezones
import simplejson as json
from datetime import datetime
from datetime import timedelta
from pytz import timezone
from bs4 import BeautifulSoup


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

    def __init__(self):

        # Call the BaseConnectors init first
        super(QradarConnector, self).__init__()

        self._base_url = None
        self._auth = {}
        self._headers = {}

    def _create_authorization_header(self, config):

        username = phantom.get_str_val(config, phantom.APP_JSON_USERNAME)
        password = phantom.get_str_val(config, phantom.APP_JSON_PASSWORD)

        if (not username) or (not password):
            return self.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_CREDENTIAL_CONFIG)

        user_pass = username + ":" + password
        auth_string = "Basic {0}".format(base64.b64encode(user_pass.encode('ascii')))

        self._auth['Authorization'] = auth_string

        return phantom.APP_SUCCESS

    @staticmethod
    def _process_html_response(response, action_result):
        """ This function is used to process html response.

        :param response: Response data
        :param action_result: Object of ActionResult
        :return: status phantom.APP_ERROR(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text.encode('utf-8').encode('utf-8')
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = 'Error while connecting to a server'

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    @staticmethod
    def _get_json_error_message(response, action_result):
        """ This function is used to process json error response.

        :param response: Response data
        :param action_result: Object of ActionResult
        :return: status phantom.APP_ERROR(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(str(e))), None)

        error_code = resp_json.get('code')
        error_message = resp_json.get('message').encode('utf-8')
        error_description = resp_json.get('description').encode('utf-8')

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Error Code: {1}, Error Message: {2}, Error Description: {3}".\
            format(response.status_code, error_code, error_message, error_description)

        return message

    def _call_api(self, endpoint, method, result, params=None, headers=None, send_progress=False):

        url = self._base_url + endpoint

        r = None

        if (send_progress):
            self.save_progress(QRADAR_PROG_EXECUTING_ENDPOINT, endpoint=endpoint, method=method)

        # default to success
        result.set_status(phantom.APP_SUCCESS)

        if (headers):
            headers.update(self._headers)
        else:
            headers = self._headers

        request_func = getattr(requests, method)

        if (not request_func):
            result.set_status(phantom.APP_ERROR, QRADAR_ERR_API_UNSUPPORTED_METHOD, method=method)
            return r

        config = self.get_config()

        try:
            r = request_func(url, headers=headers, verify=config[phantom.APP_JSON_VERIFY], params=params)
        except Exception as e:
            result.set_status(phantom.APP_ERROR, QRADAR_ERR_REST_API_CALL_FAILED, e)

        # Set the status to error
        if (phantom.is_success(result.get_status())):
            if (r is None):
                result.set_status(phantom.APP_ERROR, QRADAR_ERR_REST_API_CALL_FAILED_RESPONSE_NONE)

        if (hasattr(result, 'add_debug_data')):
            # It's ok if r.text is None, dump that
            result.add_debug_data({'r_text': r.text if r else 'r is None'})

        return r

    def _set_auth(self, config):

        # First preference is given to auth_token
        auth_token = phantom.get_str_val(config, QRADAR_JSON_AUTH_TOKEN, None)

        if (auth_token):
            self._auth['SEC'] = auth_token

        self._create_authorization_header(config)

        return phantom.APP_SUCCESS

    def initialize(self):

        config = self.get_config()
        self._config = self.get_config()
        self._state = self.load_state()
        self._is_on_poll = False
        self._time_field = None
        self._use_alt_ingest = self._config.get('alternative_ingest_algorithm', False)
        self._use_alt_ariel_query = self._config.get('alternative_ariel_query', False)
        self._delete_empty_cef_fields = self._config.get("delete_empty_cef_fields", False)
        self._container_only = self._config.get("containers_only", False)
        self._cef_value_map = self._config.get('cef_value_map', False)
        self._server = config[phantom.APP_JSON_DEVICE].encode('utf-8')
        if self._cef_value_map and len(self._cef_value_map) > 1:
            try:
                self._cef_value_map = json.loads(self._cef_value_map)
            except Exception:
                self.save_progress("Error cef_value_map is not valid JSON")
        else:
            self._cef_value_map = False

        self._on_poll_action_result = None

        # Base URL
        self._base_url = 'https://' + self._server + '/api/'
        self._artifact_max = config.get(QRADAR_JSON_ARTIFACT_MAX_DEF, 1000)
        self._add_to_resolved = config.get(QRADAR_JSON_ADD_TO_RESOLVED, False)
        self._resolved_disabled = config.get(QRADAR_INGEST_RESOLVED, False)

        # Auth details
        if (phantom.is_fail(self._set_auth(config))):
            return self.get_status()

        # default is json, if any action needs to change then let them
        self._headers['Accept'] = QRADAR_JSON_ACCEPT_HDR_JSON

        # Don't specify the version, so the latest api installed on the device will be usedl.
        # There seems to be _no_ change in the contents or endpoints of the API only the version!!
        self._headers.update(self._auth)

        return phantom.APP_SUCCESS

    def _get_str_from_epoch(self, epoch_milli):
        # 2015-07-21T00:27:59Z
        return datetime.fromtimestamp(long(epoch_milli) / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    def _get_artifact(self, event, container_id):

        cef = phantom.get_cef_data(event, self._cef_event_map)

        if self._cef_value_map:
            for k, v in cef.iteritems():
                if v in self._cef_value_map:
                    cef[k] = self._cef_value_map[v]

        if self._delete_empty_cef_fields:
            cef = { k: v for k, v in cef.iteritems() if v }

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
                'type': 'network',  # TODO: need to find a better way to map qradar data to this field
                'severity': phantom.SEVERITY_MEDIUM if ('severity' not in event) else get_ph_severity(event['severity']),
                'container_id': container_id
                    }
        if 'starttime' in event:
            artifact['start_time'] = self._get_str_from_epoch(event['starttime'])
        if 'endtime' in event:
            artifact['end_time'] = self._get_str_from_epoch(event['endtime'])

        return artifact

    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(QRADAR_USING_BASE_URL, base_url=self._base_url)

        config = self.get_config()

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._server)

        # Get the databases on the ariels endpoint, this is the fastest way of
        # testing connectivity
        response = self._call_api('ariel/databases', 'get', self)

        if (phantom.is_fail(self.get_status())):
            self.save_progress('Error occurred while connecting QRadar instance with Server Hostname | IP : {0}'.format(self._server))
            self.save_progress(QRADAR_ERR_CONNECTIVITY_TEST)
            self.debug_print("call_api failed: ", self.get_status())
            return self.get_status()

        if response.status_code != 200:
            if 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)

            if 'json' in response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(response, action_result)
            else:
                status_message = '{0}. {1}. HTTP status_code: {2}, reason: {3}'.format(QRADAR_ERR_CONNECTIVITY_TEST,
                QRADAR_MSG_CHECK_CREDENTIALS, response.status_code, response.reason)
            return self.set_status(phantom.APP_ERROR, status_message)

        return self.set_status_save_progress(phantom.APP_SUCCESS, QRADAR_SUCC_CONNECTIVITY_TEST)

    def _utcnow(self):
        return datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())

    def _datetime(self, et):
        return datetime.utcfromtimestamp(float(et) / 1000).replace(tzinfo=dateutil.tz.tzutc())

    def _epochtime(self, dt):
        # datetime_to_epoch
        # time.mktime takes /etc/localtime into account. This is all wrong. ### dateepoch = int(time.mktime(datetuple))
        utcdt = dt.astimezone(dateutil.tz.tzutc())
        return calendar.timegm(utcdt.timetuple())

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

    def _createfilter(self, param):

        start_time = None
        end_time = None
        reqfilter = None

        # first determine if there are any offenses requested, if so, no need to limit time range
        offense_ids_list = str(phantom.get_value(param, phantom.APP_JSON_CONTAINER_ID, phantom.get_value(param, QRADAR_JSON_OFFENSE_ID, "")))

        # clean up the string and parse into list, assume whitespace and commas as separators
        offense_ids_list = [ x.strip() for x in offense_ids_list.split(",") ]
        offense_ids_list = list(filter(None, offense_ids_list))

        if len(offense_ids_list) > 0:
            reqfilter = "({})".format(" or ".join([ "id=" + str(x) for x in offense_ids_list]))
            self.save_progress("Retrieving the following ids: {}".format(", ".join(offense_ids_list)))

        else:
            # List of precedences for determining start_time
            # 1. if the param has a start time, use what's in the param
            # 2. if the saved state has a last saved ingest time, use that as start time
            # 3. if the configuration set the  alt_initial_ingest_time, decode and set as start_time
            # 4. if nothing configured assume 24 hours ago

            if self._is_on_poll:
                start_time = self._state.get('last_saved_ingest_time',
                    self._config.get('alt_initial_ingest_time', "yesterday"))
                self.save_progress("last_saved_ingest_time: {}".format(start_time))
            else:
                start_time = param.get('start_time',
                    self._config.get('alt_initial_ingest_time', "yesterday"))
                self.save_progress("param start_time: {}".format(start_time))

            # datetime string, decode
            if isinstance(start_time, basestring):
                if start_time.isdigit():
                    start_time = int(start_time)
                else:
                    self.save_progress("start_time is derived from string: {}".format(start_time))
                    start_time = self._epochtime(self._parsedtime(start_time)) * 1000

            else:
                start_time = int(start_time)

            # end time is either specified in the param or is now

            end_time = param.get('end_time', self._epochtime(self._utcnow()) * 1000)
            if isinstance(end_time, basestring):
                if end_time.isdigit():
                    end_time = int(end_time)
                else:
                    self.save_progress("end_time is derived from string: {}".format(start_time))
                    end_time = self._epochtime(self._parsedtime(end_time)) * 1000
            try:
                self.save_progress("start_time: {}".format(self._utcctime(start_time)))
                self.save_progress("end_time:   {}".format(self._utcctime(end_time)))
            except Exception as e:
                self.debug_print('Provided time is invalid. Error: {}'.format(str(e)))

            # the time_field configuaration parameter determines which time fields are used in the filter,
            #   if missing or unknown value, default to start_time
            self._time_field = self._config.get('alt_time_field', "start_time")

            if self._time_field == "last_updated_time":
                reqfilter = "(last_updated_time > {} and last_updated_time <= {})".format(start_time, end_time)
            elif self._time_field == "either":
                reqfilter = "((start_time > {} and start_time <= {}) or (last_updated_time > {} and last_updated_time <= {}))".format(start_time, end_time, start_time, end_time)
            else:
                self._time_field = 'start_time'
                reqfilter = "(start_time > {} and start_time <= {})".format(start_time, end_time)

            try:
                self.save_progress("Applying time range between [{} -> {}] inclusive (total minutes {})".format(
                    self._utcctime(start_time),
                    self._utcctime(end_time),
                    (end_time - start_time) / (1000 * 60)))
            except Exception as e:
                self.debug_print('Provided time is invalid. Error: {}'.format(str(e)))

        # last requirement, are we listing only opened offenses?
        if not self._config.get('ingest_resolved', False):
            reqfilter + ' and status=OPEN'

        self.save_progress("using filter: {}".format(reqfilter))
        return start_time, end_time, reqfilter, offense_ids_list

    def _alt_list_offenses(self, param, action_result=None):

        self.save_progress("Utilizing alternative ingestion algorithm")

        reqheaders = dict()
        reqparams = dict()
        offenses = list()

        # create the filter to apply to query

        start_time, end_time, reqfilter, offenses_ids_list = self._createfilter(param)
        reqparams['filter'] = reqfilter

        # prep last saved ingested time to start_time; always start here if not ingested anything
        self._new_last_ingest_time = start_time

        # for now retrieve all fields
        # reqparams['fields'] = 'id, start_time'

        # there is a list of offenses ids, retrieve these offenses only
        count = 1
        if len(offenses_ids_list) > 0:
            self.save_progress("Retrieving requested offenses only")
            offenses = self._retrieve_offenses(action_result, reqheaders, reqparams)

            # exit if error
            if (phantom.is_fail(action_result.get_status())):
                return action_result.get_status()
        else:
            count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT, param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_OFFENSE_COUNT)))
            self.save_progress("Retrieving maximum {} number of offenses".format(count))

            max_single_query = QRADAR_QUERY_HIGH_RANGE
            # get offenses, one max_single_query chunk at a time.
            # if retrieved offenses < max_single_query, then we are done

            runs = 0
            while True:

                # check if we can still proceed or error out with too many runs
                runs += 1
                if (runs > QRADAR_MAX_ALLOWED_RUNS_TO_GET_LATEST_OFFENSES):
                    return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_RAN_TOO_MANY_QUERIES_TO_GET_NUMBER_OF_OFFENSES, query_runs=runs)

                # start at the end of offenses list and retrieve max_single_query number of offenses
                current_index = len(offenses)
                reqheaders['Range'] = 'items={}-{}'.format(current_index, current_index + max_single_query - 1)

                self.save_progress("Retrieving index: {} -> {}".format(current_index, current_index + max_single_query - 1))
                new_offenses = self._retrieve_offenses(action_result, reqheaders, reqparams)
                # for testing - new_offenses = [ { 'id': runs, 'start_time': calendar.timegm(time.gmtime()) * 1000, 'last_updated_time': 0 } ]
                # for testing - action_result.set_status(phantom.APP_SUCCESS)

                # exit if error
                if (phantom.is_fail(action_result.get_status())):
                    self.save_progress("error, exiting")
                    return action_result.get_status()

                if len(new_offenses) > 0:
                    offenses.extend(new_offenses)
                    self._report_back(new_offenses, runs)

                # stop if we exhausted the list of possible offenses
                if len(new_offenses) < max_single_query:
                    break

        self.save_progress("Total offenses discovered: {}".format(len(offenses)))

        if len(offenses) > 0:

            if count > len(offenses):
                count = len(offenses)

            # sort the list by timefield
            if self._time_field == "start_time":
                offenses.sort(key=lambda x: x['start_time'])
            else:
                offenses.sort(key=lambda x: x['last_updated_time'])

            self.save_progress("Ingesting {} offenses out of {}".format(count, len(offenses)))

            ingestion_order = self._config.get('alt_ingestion_order')

            # and extract the slice we want
            if count < len(offenses):
                if ingestion_order != "latest first" and ingestion_order != "oldest first":
                    ingestion_order = "latest first"

                if ingestion_order == "oldest first":
                    self.save_progress("Ingesting the oldest first")
                    offenses = offenses[:count]
                else:
                    self.save_progress("Ingesting the latest first")
                    offenses = offenses[-count:]

            # prep last saved ingested time to the offense with the newest last_updated_time
            if self._time_field == "last_updated_time":
                self._new_last_ingest_time = offenses[-1]['last_updated_time']
            else:
                self._new_last_ingest_time = offenses[-1]['start_time']
            # reverse the list of offenses if ingesting latest first
            if ingestion_order == "latest first":
                offenses.reverse()

            # add offense to action_result
            for offense in offenses:
                try:
                    self.save_progress("Queuing offense id: {} start_time({}, {}) last_updated_time({}, {})".format(offense['id'],
                        offense['start_time'], self._utcctime(offense['start_time']),
                                offense['last_updated_time'], self._utcctime(offense['last_updated_time'])))
                except Exception as e:
                    self.debug_print('Error occurred: {}'.format(str(e)))
                action_result.add_data(offense)

        # add summary for action_result
        action_result.update_summary({QRADAR_JSON_TOTAL_OFFENSES: len(offenses)})

        return action_result.get_status()

    def _retrieve_offenses(self, action_result, reqheaders, reqparams):

        # make rest call
        response = self._call_api('siem/offenses', 'get', action_result, params=reqparams, headers=reqheaders)

        # error with the call_api function, most likely network error
        if (phantom.is_fail(action_result.get_status())):
            if response:
                status_code = response.status_code
            else:
                status_code = None
            self.save_progress("Rest call failed: {}\nResponse code: {}".format(action_result.get_status(), status_code))
            return action_result.get_status()

        # error with the rest call, either authorization or malformed parameters
        if response.status_code != 200:
            if 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)

            if 'json' in response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(response, action_result)
            else:
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_LIST_OFFENSES_API_FAILED, response.status_code, response.reason)
            self.save_progress("Rest call error: {}\nResponse code: {}".format(status_message, response.status_code))
            return action_result.set_status(phantom.APP_ERROR, status_message)

        # decode and save offenses
        try:
            new_offenses = response.json()

        except Exception as e:
            # error with rest call, as it did not return the data as json
            self.save_progress("Unable to parse response as a valid JSON: {}".format(e))
            return action_result.set_status(phantom.APP_ERROR, e)

        return new_offenses

    def _report_back(self, new_offenses, runs):

        # report back what we downloaded
        offenses_bytime = None
        if self._time_field == "start_time":
            offenses_bytime = sorted(new_offenses, key=lambda x: x['start_time'])
        else:
            offenses_bytime = sorted(new_offenses, key=lambda x: x['last_updated_time'])

        try:
            self.save_progress("run {}: downloaded ({}) earliest offense [ id ({}) start_time ({}) ] latest offense [ id ({}) start_time ({}) ]"
            .format(runs, len(new_offenses), offenses_bytime[0]['id'], self._utcctime(offenses_bytime[0]['start_time']), offenses_bytime[-1]['id'],
            self._utcctime(offenses_bytime[-1]['start_time'])))
        except Exception as e:
            self.debug_print('Error occurred: {}'.format(str(e)))

    def _create_offense_artifacts(self, offense, container_id):
        """ This function is used to create artifacts in given container using finding data.

        :param finding: Data of single finding
        :param container_id: ID of container in which we have to create the artifacts
        :return: status(success/failure), message
        """

        artifact = {}
        artifact['name'] = 'Artifact'
        artifact['container_id'] = container_id
        artifact['source_data_identifier'] = offense['id']
        artifact['cef'] = offense

        create_artifact_status, create_artifact_msg, _ = self.save_artifacts([artifact])

        if phantom.is_fail(create_artifact_status):
            return phantom.APP_ERROR, create_artifact_msg

        return phantom.APP_SUCCESS, 'Artifacts created successfully'

    def _on_poll(self, param):

        self._is_on_poll = self.get_action_identifier() == "on_poll"

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
        if config.get('cef_event_map', None) is not None:
            try:
                self._cef_event_map = json.loads(config.get('cef_event_map'))
            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, 'Optional CEF event map is not valid JSON: {}'.format(str(e)))
                return action_result.get_status()
        else:
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
                'payload': 'Payload'}

        if config.get('event_fields_for_query', None) is not None:
            bad_chars = set("&^%")
            if any((c in bad_chars) for c in config.get('event_fields_for_query')):
                action_result.set_status(phantom.APP_ERROR, 'Please do not use invalid characters in event field names in event_fields_for_query')
                return action_result.get_status()
            if "'" in config.get('event_fields_for_query'):
                action_result.set_status(phantom.APP_ERROR, 'Please use double quotes instead of single quotes around event field names in event_fields_for_query')
                return action_result.get_status()
        # Call _list_offenses with a local action result,
        # this one need not be added to the connector run
        # result. It will be used to contain the offenses data
        offenses_action_result = ActionResult(dict(param))
        param['artifact_count'] = artifact_max

        if (phantom.is_fail(self._list_offenses(param, offenses_action_result))):
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

        self.debug_print("Number of offenses:", len_offenses)

        add_offense_id_to_name = self._config.get("add_offense_id_to_name", False)

        for i, offense in enumerate(offenses):

            self.debug_print('offense id:{}'.format(offense['id']), offense)

            get_ph_severity = lambda x: phantom.SEVERITY_LOW if x <= 3 else (
                    phantom.SEVERITY_MEDIUM if x <= 7 else phantom.SEVERITY_HIGH)

            # Replace the 'null' string to None if any
            offense = dict([(x[0], None if x[1] == 'null' else x[1]) for x in offense.items()])

            # strip \r, \n and space from the values, qradar does that for the description field atleast
            v_strip = lambda v: v.strip(' \r\n').replace(u'\u0000', '') if type(v) == str or type(v) == unicode else v
            offense = dict([(k, v_strip(v)) for k, v in offense.iteritems()])

            # Don't want dumping non None
            self.debug_print('Offense', phantom.remove_none_values(offense))

            offense_id = offense['id']
            container = {}
            if param.get('tenant_id', None) is not None:
                try:
                    if not str(param.get('tenant_id')).isdigit() or int(param.get('tenant_id')) < 0:
                        return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid integer value in tenant ID')
                except:
                    return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid integer value in tenant ID')

                container['tenant_id'] = param['tenant_id']
            container['name'] = "{} - {}".format(offense['id'], offense['description']) if add_offense_id_to_name else offense['description']
            container['data'] = offense
            # Two hard coded lines for testing multi-tenancy adds
            # container['asset_id'] = 44
            # container['ingest_app'] = "6cf34589-6947-409f-b776-e8fa62e01509"
            # End of hard coded lines
            container['start_time'] = self._get_str_from_epoch(offense['start_time'])
            container['severity'] = get_ph_severity(offense['severity'])
            container['source_data_identifier'] = offense_id

            self.send_progress("Saving Container # {0}".format(i))
            ret_val, message, container_id = self.save_container(container)
            self.debug_print("Save container returns, ret_val: {0}, message: {1}, id: {2}".format(ret_val, message, container_id))

            if (phantom.is_fail(ret_val)):
                error_message = 'Error occurred while container creation for Offense ID: {0}. Error: {1}'.format(offense_id, message)
                self.debug_print(error_message)
                if message and 'Tenant "{0}" was not found or is not enabled'.format(param.get('tenant_id')) in message:
                    self.save_progress('Aborting the polling process')
                    return action_result.set_status(phantom.APP_ERROR, error_message)
                continue

            if (not container_id):
                continue

            if (message == 'Duplicate container found'):
                self.debug_print("Duplicate container found:", container_id)
                # get status of the duplicate container
                this_container = self.get_container_info(container_id)
                statusOfContainer = this_container[1]['status']  # pylint: disable=E0001,E1126
                self.debug_print("Add_to_resolved: {0}, status: {1}, container_id: {2}".format(add_to_resolved, statusOfContainer, container_id))
                if (not add_to_resolved and (statusOfContainer == "resolved" or statusOfContainer == "closed")):
                    self.debug_print("Skipping artifact ingest to closed container")
                    continue

            if self._container_only:
                artifacts_creation_status, artifacts_creation_msg = self._create_offense_artifacts(offense=offense, container_id=container_id)

                if phantom.is_fail(artifacts_creation_status):
                    self.debug_print('Logging the artifact creation failure for the current offense and continuing with the next offense')
                    self.debug_print('Error while creating artifacts for the Offense ID: {0} and Container ID {1}. Error: {2}'
                    .format(offense_id, container_id, artifacts_creation_msg))

                continue

            # set the event params same as that of the input poll params
            # since the time range should be the same
            event_param = dict(param)
            # Add the offense id to the param dict
            event_param['offense_id'] = offense_id
            event_param['offense_start_time'] = offense['start_time']

            # Create a action result specifically for the event
            event_action_result = ActionResult(event_param)
            if (phantom.is_fail(self._get_events(event_param, event_action_result))):
                self.debug_print("Failed to get events for offense", offense_id)
                self.send_progress("Failed to get events for offense")
                action_result.append_to_message(QRADAR_ERR_GET_EVENTS_FAILED.format(offense_id=offense_id))
                continue

            events = event_action_result.get_data()

            self.save_progress("Got {0} events for offense {1}".format(len(events), offense_id))
            count = int(param.get(phantom.APP_JSON_ARTIFACT_COUNT, param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_EVENT_COUNT)))

            if count > QRADAR_QUERY_HIGH_RANGE:
                # Should not set more than the HIGH RANGE, else qradar throws an error
                count = QRADAR_QUERY_HIGH_RANGE
                # put a max count to get after ordering by starttime in descending order

            if len(events) > count:
                self.save_progress("Events count is {}: Truncating table to {} events\n".format(len(events), count))
                events = events[:count]

            offense_artifact = {}
            offense_artifact['container_id'] = container_id
            offense_artifact['name'] = 'Offense Artifact'
            offense_artifact['label'] = 'offense'
            offense_artifact['cef'] = offense

            event_index = 0
            len_events = len(events)
            self.send_progress("Found {} events for offense id {}".format(len_events, offense_id))
            added = 0
            dup = 0
            for j, event in enumerate(events):

                # strip \r, \n and space from the values, qradar does that for the description field atleast
                event = dict([(k, v_strip(v)) for k, v in event.iteritems()])

                artifact = self._get_artifact(event, container_id)

                self.debug_print('Saving artifact(container_id={}, container={}, artifact={}, offense={}, qid={}'.format(container_id, i, j, offense_id, event['qid']), artifact)
                self.send_progress("Saving Container # {0}, Artifact # {1}".format(i, j))

                if ((j + 1) == len_events):
                    artifact['run_automation'] = True

                ret_val, message, artifact_id = self.save_artifact(artifact)

                if (phantom.is_fail(ret_val)):
                    self.debug_print('Logging the artifact creation failure for the current event and continuing with the next event')
                    self.debug_print('Error occurred while artifact creation for the event with QID: {0} for the Offense ID: {1}. Error: {2}'.format(event['qid'], offense_id, message))
                    continue

                if message.startswith("Added"):
                    added += 1
                elif message.startswith("duplicate"):
                    dup += 1

                event_index += 1

            if events:
                self.save_progress("Offense id {} - Container {}: retrieved {} events, added {} artifacts, duplicated {} artifacts".format(
                    offense_id, container_id, len_events, added, dup))

        # if we are polling, save the last ingested time
        if self._is_on_poll:
            self._state['last_saved_ingest_time'] = self._new_last_ingest_time
            try:
                self.save_progress("Setting last_saved_ingest_time to: {} {}".format(self._state['last_saved_ingest_time'],
                    self._utcctime(self._state['last_saved_ingest_time'])))
            except Exception as e:
                self.debug_print('Error occurred: {}'.format(str(e)))
            self.save_state(self._state)

        self.send_progress(" ")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_offenses(self, param, action_result=None):

        if (not action_result):
            # Create a action result to represent this action
            action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT, param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_OFFENSE_COUNT)))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in count parameter')
        # Count zero means get all the possible items
        if (count <= 0):
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in count parameter')

        if (param.get('start_time') and not str(param.get('start_time')).isdigit()) or param.get('start_time') == 0:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide valid start_time parameter')

        if (param.get('end_time') and not str(param.get('end_time')).isdigit()) or param.get('end_time') == 0:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide valid end_time parameter')

        if self._use_alt_ingest:
            return self._alt_list_offenses(param, action_result)

        filter_string = ""
        params = dict()
        headers = dict()

        ret_val = self._validate_times(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Get the param values
        start_time_msecs = param.get(phantom.APP_JSON_START_TIME)
        end_time_msecs = param.get(phantom.APP_JSON_END_TIME)

        # If end_time is not given, then end_time is 'now'
        # If start_time is not given, then start_time is QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME
        # days behind end_time
        #
        resolved_disabled = self._resolved_disabled
        try:
            num_days = int(param.get(QRADAR_JSON_DEF_NUM_DAYS, self.get_app_config().get(QRADAR_JSON_DEF_NUM_DAYS, QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME)))
            if int(num_days <= 0):
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid integer value in interval_days parameter')
        except:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid integer value in interval_days parameter')

        if (self._is_on_poll or param.get('ingest_offense', False)):
            end_time_msecs = int(time.mktime(datetime.utcnow().timetuple())) * 1000
            if self._is_on_poll and self._state.get('last_saved_ingest_time'):
                start_time_msecs = self._state.get('last_saved_ingest_time')
            else:
                start_time_msecs = end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days)
        else:
            curr_epoch_msecs = int(time.mktime(datetime.utcnow().timetuple())) * 1000
            end_time_msecs = curr_epoch_msecs if end_time_msecs is None else int(end_time_msecs)
            start_time_msecs = end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days) if start_time_msecs is None else int(start_time_msecs)

        if (end_time_msecs < start_time_msecs):
            action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME_RANGE)

        self._new_last_ingest_time = start_time_msecs

        self.save_progress('Getting data from {0} to {1}'.format(self._get_tz_str_from_epoch(start_time_msecs), self._get_tz_str_from_epoch(end_time_msecs)))

        # Create the param dictionary for the range
        filter_string += '(({2} >= {0} and {2} <= {1}) or ({3} >= {0} and {3} <= {1}))'.format(
            start_time_msecs, end_time_msecs, 'start_time', 'last_updated_time')

        # get the list of offenses that we are supposed to query for
        container_source_ids = str(param.get(phantom.APP_JSON_CONTAINER_ID,
                param.get(QRADAR_JSON_OFFENSE_ID, None)))

        if (container_source_ids != 'None'):
            # convert it to list

            offense_id_list = list()
            for x in container_source_ids.split(','):
                try:
                    if len(x.strip()) > 0 and int(x.strip()) >= 0:
                        offense_id_list.append('id={}'.format(int(x.strip())))
                except Exception as e:
                    self.debug_print("The provided offense: {} is not valid".format(x))
                    pass

            if (len(offense_id_list) > 0):

                # we have data to work on
                filter_string += ' {0} ({1})'.format(
                        'and' if len(filter_string) > 0 else '',
                        ' or '.join(offense_id_list))
            else:
                return action_result.set_status(phantom.APP_ERROR, "Please provide valid offense ID")

        params['filter'] = filter_string
        params['sort'] = "+last_updated_time"
        self.save_progress('Filter is {0}'.format(filter_string))

        offenses = list()

        runs = 0
        start_index = 0
        total_offenses = 0

        # The following loop queries for offenses in a loop to get details about the most recent 'count' offenses.
        # Steps are as follows:
        # 0.> First query only the starttime and id for all the possible offenses by giving a very high number
        #     of total offenses to query. Let's call this total # of offenses N
        # 1.> Then calculated if the total number of offenses is greater than what we want or less. Let's call the
        #     count of offenses that we want as C
        # 2.> If total is less or equal to than what we want, then get all of them in the second query
        #     if N <= C then range in second query is 0 to N-1
        # 3.> If total is greater that what we want then specify the a range in the second query.
        #     This range would be specify the latest offenses
        #     if N > C then range in second query is N-C till the last index
        offenses_status_msg = ''
        while True:
            if (runs > QRADAR_MAX_ALLOWED_RUNS_TO_GET_LATEST_OFFENSES):
                return action_result.set_status(phantom.APP_ERROR,
                        QRADAR_ERR_RAN_TOO_MANY_QUERIES_TO_GET_NUMBER_OF_OFFENSES, query_runs=runs)

            runs += 1
            end_index = min(start_index + QRADAR_QUERY_HIGH_RANGE - 1, count - 1)

            if start_index > end_index:
                break

            # end_index = min((temp * 1000) + count - 1, end_index + (temp * 1000) - 1)
            headers['Range'] = 'items={0}-{1}'.format(start_index, end_index)
            start_index += QRADAR_QUERY_HIGH_RANGE

            if resolved_disabled:
                offenses_status_msg = 'Fetching all open offenses as the asset configuration parameter for ingest only open is selected. '
                params['filter'] = filter_string + ' and status=OPEN'
                self.save_progress('Filter is {0}'.format(params['filter']))

            response = self._call_api('siem/offenses', 'get', action_result, params=params, headers=headers)

            if (phantom.is_fail(action_result.get_status())):
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
                    status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_LIST_OFFENSES_API_FAILED, response.status_code, response.reason)
                return action_result.set_status(phantom.APP_ERROR, status_message)

            try:
                offenses += response.json()
            except Exception as e:
                self.debug_print("Unable to parse response as a valid JSON", e)
                return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as a valid JSON")

            total_offenses = len(offenses)

            if len(response.json()) < QRADAR_QUERY_HIGH_RANGE:
                self.save_progress(QRADAR_PROG_GOT_X_OFFENSES, total_offenses=total_offenses)
                break

        # Parse the output, which is an array of offenses
        # Update the summary
        action_result.update_summary({QRADAR_JSON_TOTAL_OFFENSES: len(offenses)})

        # Sort the offenses on the basis of the start_time and last_updated_time both
        # Note the recent start_time and recent last_updated_time
        # Update the _new_last_ingest_time with the maximum of the two as next time we will fetch the offenses
        # whose start_time or last_updated_time is greater than the _new_last_ingest_time
        # This _new_last_ingest_time variable will be used only in the On_Poll action to store it in the last_saved_ingest_time of the state file
        if offenses:
            offenses.sort(key=lambda x: x['start_time'])
            recent_start_time = offenses[-1]['start_time']
            offenses.sort(key=lambda x: x['last_updated_time'])
            recent_last_updated_time = offenses[-1]['last_updated_time']
            self._new_last_ingest_time = max(recent_start_time, recent_last_updated_time)

        for offense in offenses:
            action_result.add_data(offense)

        action_result.set_status(phantom.APP_SUCCESS, '{0}Total Offenses: {1}'.format(offenses_status_msg, len(offenses)))
        return action_result.get_status()

    def _list_offense_closing_reasons(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        params = dict()
        if param.get('include_reserved'):
            params['include_reserved'] = True

        if param.get('include_deleted'):
            params['include_deleted'] = True

        if len(params) == 0:
            params = None

        closing_reasons_response = self._call_api('siem/offense_closing_reasons', 'get', action_result, params=params, headers=None)

        if (phantom.is_fail(action_result.get_status())):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        if not closing_reasons_response:
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_LIST_OFFENSE_CLOSING_REASONS)

        if (closing_reasons_response.status_code != 200):
            if 'html' in closing_reasons_response.headers.get('Content-Type', ''):
                return self._process_html_response(closing_reasons_response, action_result)
            # Error condition
            if 'json' in closing_reasons_response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(closing_reasons_response, action_result)
            else:
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_LIST_OFFENSE_CLOSING_REASONS, closing_reasons_response.status_code, closing_reasons_response.text)
            return action_result.set_status(phantom.APP_ERROR, status_message)

        try:
            closing_reasons = closing_reasons_response.json()
        except Exception as e:
            self.debug_print("Unable to parse response as a valid JSON", e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as a valid JSON")

        for closing_reason in closing_reasons:
            action_result.add_data(closing_reason)

        summary = action_result.update_summary({})
        summary['total_offense_closing_reasons'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ariel_query(self, ariel_query, action_result, obj_result_key=None, offense_id=None):

        if (obj_result_key):
            self.save_progress("Executing ariel query to get {0} {1}", obj_result_key,
                    '' if (not offense_id) else 'for offense: {offense_id}'.format(offense_id=offense_id))
        else:
            self.save_progress("Executing ariel query")

        params = dict()

        # First create a search
        params['query_expression'] = ariel_query

        response = self._call_api(QRADAR_ARIEL_SEARCH_ENDPOINT, 'post', action_result, params=params)

        if (phantom.is_fail(action_result.get_status())):
            self.debug_print("call_api for ariel query failed: ", action_result.get_status())
            return action_result.get_status()

        self.debug_print("Response Code", response.status_code)
        self.debug_print("Response Text", response.text)

        if (response.status_code != 201):
            # Error condition
            action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_ARIEL_QUERY_FAILED)
            try:
                resp_text = response.text
            except:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide valid input')

            if ("InOffense function: Error loading Offense" in resp_text):
                action_result.append_to_message("Queried offense might not contain data on QRadar")
            action_result.append_to_message("\nResponse from QRadar: {0}".format(resp_text))
            return action_result.get_status()

        try:
            response_json = response.json()
        except Exception as e:
            return action_result.get_status(phantom.APP_ERROR, "Unable to parse response as a valid JSON")

        # Now get the search id
        search_id = response_json.get('search_id')

        if (not search_id):
            return action_result.get_status(phantom.APP_ERROR, "Response does not contain the 'search_id' key")

        # Init the response json
        response_json['status'] = 'EXECUTE'
        response_json['progress'] = 0
        got_error = False
        prev_percent = -1

        while(not got_error and response_json.get('status') != 'COMPLETED'):

            if ('progress' not in response_json):
                return action_result.set_status(phantom.APP_ERROR, "Response JSON does not contain 'progress' key")

            if (prev_percent != response_json['progress']):
                # send progress about the query
                self.send_progress(QRADAR_PROG_QUERY_STATUS,
                        state=response_json['status'],
                        percent=response_json['progress'])
                prev_percent = response_json['progress']

            time.sleep(6)

            # check the progress again
            response = self._call_api("{0}/{1}".format(QRADAR_ARIEL_SEARCH_ENDPOINT, search_id),
                    'get', action_result, send_progress=False)

            if (phantom.is_fail(action_result.get_status())):
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
                    status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_ARIEL_QUERY_STATUS_CHECK_FAILED, response.status_code, response.text)
                got_error = True
                return action_result.set_status(phantom.APP_ERROR, status_message)

            # re-setting the failed times
            try:
                response_json = response.json()
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Unable to parse reponse as a valid JSON")

            if ('status' not in response_json):
                return action_result.set_status(phantom.APP_ERROR, "Response JSON does not contain 'status' key")

            status_list = ['COMPLETED', 'EXECUTE', 'SORTING', 'WAIT']

            # What is the status string for error, the sample apps don't have this info
            # niether the documentation
            if (response_json.get('status') not in status_list):
                # Error condition
                action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_ARIEL_QUERY_STATUS_CHECK_FAILED)
                # Add the response that we got from the device, it contains additional info
                action_result.append_to_message(json.dumps(response_json))
                # set the error and break
                got_error = True
                return action_result.get_status()

        self.debug_print('response_json', response_json)

        # Looks like the search is complete, now get the results

        response = self._call_api("{0}/{1}/results".format(QRADAR_ARIEL_SEARCH_ENDPOINT, search_id),
                'get', action_result)

        if (phantom.is_fail(action_result.get_status())):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        if response.status_code != 200:
            if 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)
            # Error condition
            if 'json' in response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(response, action_result)
            else:
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_ARIEL_QUERY_RESULTS_FAILED, response.status_code, response.text)
            return action_result.set_status(phantom.APP_ERROR, status_message)

        try:
            # https://www-01.ibm.com/support/docview.wss?uid=swg1IV98260
            # siem bug. no workwaround, sort of work with what we got

            r = """
                (?P<error>
                    \\s* { \\s*
                        "http_response": \\s* { \\s*
                            "code": \\s* 500, \\s*
                            "message": \\s* "Unexpected \\s internal \\s server \\s error" \\s*
                        }, \\s*
                        "code": \\s* 13, \\s*
                        "message": \\s* "Invocation \\s was \\s successful, \\s but \\s transformation \\s to \\s content \\s type \\s ..APPLICATION_JSON.. \\s failed", \\s*
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
            self.debug_print("Unable to parse response as a valid JSON", e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse reponse as a valid JSON")

        if (obj_result_key):
            # Got the results
            if (obj_result_key not in response_json):
                return action_result.set_status(phantom.APP_ERROR, "Response JSON does not contain '{0}' key".format(obj_result_key))

            objs = response_json[obj_result_key]
            # Add then to the action_result
            self.send_progress(QRADAR_MSG_GOT_N_OBJS, num_of_objs=len(objs), obj_type=obj_result_key)

            for obj in objs:
                # Replace the 'null' string to None if any
                obj = dict([(x[0], None if x[1] == 'null' else x[1]) for x in obj.items()])
                action_result.add_data(obj)

            self.save_progress("Ariel query retrieved {} {} for offense {}".format(len(objs), obj_result_key, offense_id))
            if len(objs) > 0 and 'starttime' in objs[0]:
                try:
                    self.save_progress("Ariel query retrieved {} {} for offense {}; starttime of earliest ({}) latest ({})".format(
                        len(objs), obj_result_key, offense_id, self._utcctime(objs[-1]['starttime']), self._utcctime(objs[0]['starttime'])))
                except Exception as e:
                    self.debug_print('Error occurred: {}'.format(str(e)))

        else:
            action_result.add_data(response_json)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_times(self, param, action_result):

        if (phantom.APP_JSON_START_TIME in param):
            try:
                datetime.utcfromtimestamp(param[phantom.APP_JSON_START_TIME] / 1000).replace(tzinfo=pytz.utc)
            except:
                return action_result.set_status(phantom.APP_ERROR, "Invalid {0}".format(phantom.APP_JSON_START_TIME))

        if (phantom.APP_JSON_END_TIME in param):
            try:
                datetime.utcfromtimestamp(param[phantom.APP_JSON_END_TIME] / 1000).replace(tzinfo=pytz.utc)
            except:
                return action_result.set_status(phantom.APP_ERROR, "Invalid {0}".format(phantom.APP_JSON_END_TIME))

        # return utc_dt.strftime('%Y-%m-%d %H:%M:%S')
        return (phantom.APP_SUCCESS)

    def _get_tz_str_from_epoch(self, epoch_milli):

        # Need to convert from UTC to the device's timezone, get the device's tz from config
        config = self.get_config()
        device_tz_sting = phantom.get_req_value(config, QRADAR_JSON_TIMEZONE)

        to_tz = timezone(device_tz_sting)

        utc_dt = datetime.utcfromtimestamp(epoch_milli / 1000).replace(tzinfo=pytz.utc)
        to_dt = to_tz.normalize(utc_dt.astimezone(to_tz))

        # return utc_dt.strftime('%Y-%m-%d %H:%M:%S')
        return to_dt.strftime('%Y-%m-%d %H:%M:%S')

    def _get_events(self, param, action_result=None):

        if (not action_result):
            # Create a action result
            action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            count = int(param.get(phantom.APP_JSON_ARTIFACT_COUNT, param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_EVENT_COUNT)))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in count parameter')

        if (count <= 0):
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in count parameter')

        if (param.get('start_time') and not str(param.get('start_time')).isdigit()) or param.get('start_time') == 0:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide valid start_time parameter')

        if (param.get('end_time') and not str(param.get('end_time')).isdigit()) or param.get('end_time') == 0:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide valid end_time parameter')

        try:
            if param.get('offense_id') and int(param.get('offense_id')) <= 0:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')
        except:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')

        ret_val = self._validate_times(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        config = self.get_config()
        if config.get('event_fields_for_query', None) is not None:
            event_fields = [event_field.strip() for event_field in config.get('event_fields_for_query').split(',')]
            event_fields = list(filter(None, event_fields))
            event_fields_str = ','.join(event_fields)
            ariel_query = 'select qid, QidName(qid), ' + event_fields_str + QRADAR_AQL_EVENT_FROM
        else:
            ariel_query = QRADAR_AQL_EVENT_SELECT + QRADAR_AQL_EVENT_FROM

        # default the where clause to empty
        where_clause = ''

        # Get the offense id
        offense_id = phantom.get_str_val(param, QRADAR_JSON_OFFENSE_ID, None)
        if (offense_id):
            if (len(where_clause)):
                where_clause += " and"
            where_clause += " hasOffense='true' and InOffense({0})".format(offense_id)
            # Update the parameter
            action_result.update_param({QRADAR_JSON_OFFENSE_ID: offense_id})

        # Get the fields where part
        fields_filter = phantom.get_str_val(param, QRADAR_JSON_FIELDS_FILTER, None)
        if (fields_filter):
            if (len(where_clause)):
                where_clause += " and"
            where_clause += " {0}".format(fields_filter)
            action_result.update_param({QRADAR_JSON_FIELDS_FILTER: fields_filter})

        # This is the rule
        # If end_time is not given, then end_time is 'now'
        # If start_time is not given, then start_time is 5 days behind end_time'
        # The START clause has to come before the STOP clause, else the query fails
        # The START and STOP clause have to be given, else the results will be for
        # the last 60 seconds or something small like that.
        # We also need to get the the events closest to the end time, so add the
        # starttime comparison operators for that
        try:
            num_days = int(param.get(QRADAR_JSON_DEF_NUM_DAYS, self.get_app_config().get(QRADAR_JSON_DEF_NUM_DAYS, QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME)))
        except:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid integer value in interval_days parameter')

        if num_days <= 0:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in interval_days parameter')

        curr_epoch_msecs = int(time.time()) * 1000
        start_time_msecs = 0
        end_time_msecs = int(param.get(phantom.APP_JSON_END_TIME, curr_epoch_msecs))

        start_time_msecs = int(param.get(phantom.APP_JSON_START_TIME,
                end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days)))

        if self._is_on_poll:
            if self._state.get('last_ingested_events_data', {}).get(str(param.get('offense_id', ''))):
                start_time_msecs = int(self._state['last_ingested_events_data'].get(str(param['offense_id'])))

        if (end_time_msecs < start_time_msecs):
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME_RANGE)

        if (len(where_clause)):
            where_clause += " and"

        # The starttime >= and starttime <= clause is required without which the limit clause fails
        where_clause += " starttime >= {0} and starttime <= {1}".format(start_time_msecs, end_time_msecs)
        # where_clause += " starttime BETWEEN {0} and {1}".format(start_time_msecs, end_time_msecs)

        if count > QRADAR_QUERY_HIGH_RANGE:
            # Should not set more than the HIGH RANGE, else qradar throws an error
            count = QRADAR_QUERY_HIGH_RANGE
            # put a max count to get after ordering by starttime in descending order

        where_clause += " order by STARTTIME desc limit {0}".format(count)

        # From testing queries, it was noticed that the START and STOP are required else the default
        # result returned by the REST api is of 60 seconds or so. Also the time format needs to be in
        # the device's timezone.
        where_clause += " START '{0}'".format(self._get_tz_str_from_epoch(start_time_msecs))
        where_clause += " STOP '{0}'".format(self._get_tz_str_from_epoch(end_time_msecs))

        # throw it all away, use alternative query
        # btw: LIMIT doesn't seem to work for any values > 150 on this version of qradar (7.2.4)
        if self._use_alt_ariel_query:
            if not param.get(QRADAR_JSON_DEF_NUM_DAYS, False):
                event_start_time = param.get('offense_start_time')
                if self._state.get('last_ingested_events_data', {}).get(str(param.get('offense_id', ''))):
                    event_start_time = int(self._state['last_ingested_events_data'].get(str(param['offense_id'])))

                if not event_start_time:
                    event_days = num_days
                else:
                    now = self._utcnow()
                    start = self._datetime(event_start_time)
                    diff = now - start
                    event_days = abs(diff.days) + 1 if diff.seconds != 0 else abs(diff.days)
            else:
                event_days = num_days
            where_clause = "InOffense({}) ORDER BY starttime DESC LIMIT {} LAST {} DAYS".format(offense_id, count, event_days)

        ariel_query += " where {0}".format(where_clause)

        self._handle_ariel_query(ariel_query, action_result, 'events', offense_id)

        events_list = action_result.get_data()
        if self._is_on_poll and events_list:
            events_list.sort(key=lambda x: x['starttime'])
            if not self._state.get('last_ingested_events_data'):
                offense_dict = {str(param['offense_id']): events_list[-1]['starttime']}
                self._state.update({'last_ingested_events_data': offense_dict})
            else:
                last_ingested_events_data_dict = self._state.get('last_ingested_events_data')
                last_ingested_events_data_dict[str(param['offense_id'])] = events_list[-1]['starttime']
                self._state['last_ingested_events_data'] = last_ingested_events_data_dict
        # Set the summary
        action_result.update_summary({QRADAR_JSON_TOTAL_EVENTS: action_result.get_data_size()})

        return action_result.get_status()

    def _run_query(self, param):

        # Create a action result
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param[QRADAR_JSON_QUERY]

        self._handle_ariel_query(query, action_result)

        data = action_result.get_data()

        items = {}

        # get the events, flows dictionaries
        try:
            items = data[0]
        except:
            return action_result.get_status()

        # loop for the event, flows items
        for curr_item, v in items.iteritems():

            if (type(v) != list):
                items[curr_item] = [v]

            for i, curr_obj in enumerate(items[curr_item]):
                # Replace the 'null' string to None if any
                curr_obj = dict([(x[0], None if x[1] == 'null' else x[1]) for x in curr_obj.items()])
                items[curr_item][i] = curr_obj

        return action_result.set_status(phantom.APP_SUCCESS, QRADAR_SUCC_RUN_QUERY)

    def _get_flows(self, param):

        # Create a action result
        action_result = self.add_action_result(ActionResult(dict(param)))

        offense_id = param.get(QRADAR_JSON_OFFENSE_ID)
        if offense_id:
            try:
                if int(offense_id) <= 0:
                    return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')
            except:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')

        try:
            count = int(param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_FLOW_COUNT))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in count parameter')

        if (count <= 0):
            # set it to the max number we can use in the query, so that we get all of them
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in count parameter')

        if (param.get('start_time') and not str(param.get('start_time')).isdigit()) or param.get('start_time') == 0:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide valid start_time parameter')

        if (param.get('end_time') and not str(param.get('end_time')).isdigit()) or param.get('end_time') == 0:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide valid end_time parameter')

        ret_val = self._validate_times(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # First get all the possible columns for an flow
        response = self._call_api('ariel/databases/flows', 'get', self)

        if (phantom.is_fail(self.get_status())):
            self.debug_print("call_api failed: ", self.get_status())
            return self.get_status()

        # default the self status to failure, so that post processing of action results
        # is carried out properly
        self.set_status(phantom.APP_ERROR)

        self.debug_print("Response Code", response.status_code)

        if response.status_code != 200:
            if 'html' in response.headers.get('Content-Type', ''):
                return self._process_html_response(response, action_result)
            # Error condition
            if 'json' in response.headers.get('Content-Type', ''):
                status_message = self._get_json_error_message(response, action_result)
            else:
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_GET_FLOWS_COLUMNS_API_FAILED, response.status_code, response.text)
            return action_result.set_status(phantom.APP_ERROR, status_message)

        try:
            event_columns_json = response.json()
        except:
            # Many times when QRadar crashes, it gives back the status code as 200, but the reponse
            # in an html saying that an application error occurred. Bail out when this happens
            # The debug_print of response should help in debugging this
            self.debug_print("response", response.text)
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_GOT_INVALID_RESPONSE)

        flow_columns_json = event_columns_json

        flow_columns = ','.join('"{}"'.format(x) for x in [y.get('name') for y in flow_columns_json['columns']])

        self.debug_print("flow_columns", flow_columns)

        ariel_query = QRADAR_AQL_FLOW_SELECT.format(fields=flow_columns) + QRADAR_AQL_FLOW_FROM

        # default the where clause to empty
        where_clause = ''

        # Get the offense id
        if offense_id:
            if len(where_clause):
                where_clause += " and"
            where_clause += " hasoffense='true' and InOffense({0})".format(offense_id)
            # Update the parameter
            action_result.update_param({QRADAR_JSON_OFFENSE_ID: offense_id})

        ip_to_query = phantom.get_str_val(param, QRADAR_JSON_IP, None)
        if (ip_to_query):
            if (len(where_clause)):
                where_clause += " and"
            where_clause += " (sourceip='{0}' or destinationip='{0}')".format(ip_to_query)
            # Update the parameter
            action_result.update_param({QRADAR_JSON_IP: ip_to_query})

        # Get the fields where part
        fields_filter = phantom.get_str_val(param, QRADAR_JSON_FIELDS_FILTER, None)
        if (fields_filter):
            if (len(where_clause)):
                where_clause += " and"
            where_clause += " {0}".format(fields_filter)
            action_result.update_param({QRADAR_JSON_FIELDS_FILTER: fields_filter})

        # This is the rule
        # If end_time is not given, then end_time is 'now'
        # If start_time is not given, then start_time is 5 days behind end_time'
        # The START clause has to come before the STOP clause, else the query fails
        # The START and STOP clause have to be given, else the results will be for
        # the last 60 seconds or something small like that.
        # We also need to get the the flows closest to the end time, so add the
        # starttime comparison operators for that
        num_days = int(param.get(QRADAR_JSON_DEF_NUM_DAYS, self.get_app_config().get(QRADAR_JSON_DEF_NUM_DAYS, QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME)))
        curr_epoch_msecs = int(time.time()) * 1000
        start_time_msecs = 0
        end_time_msecs = int(param.get(phantom.APP_JSON_END_TIME, curr_epoch_msecs))
        start_time_msecs = int(param.get(phantom.APP_JSON_START_TIME,
                end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days)))

        if (end_time_msecs < start_time_msecs):
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME_RANGE)

        if (len(where_clause)):
            where_clause += " and"

        # The starttime >= and starttime <= clause is required without which the limit clause fails
        where_clause += " starttime >= {0} and starttime <= {1}".format(start_time_msecs, end_time_msecs)

        if (count > QRADAR_QUERY_HIGH_RANGE):
            # Should not set more than the HIGH RANGE, else qradar throws an error
            count = QRADAR_QUERY_HIGH_RANGE
            # put a max count to get after ordering by starttime in descending order

        where_clause += " ORDER BY starttime DESC LIMIT {0}".format(count)

        # From testing queries, it was noticed that the START and STOP are required else the default
        # result returned by the REST api is of 60 seconds or so. Also the time format needs to be in
        # the device's timezone.
        where_clause += " START '{0}'".format(self._get_tz_str_from_epoch(start_time_msecs))
        where_clause += " STOP '{0}'".format(self._get_tz_str_from_epoch(end_time_msecs))

        ariel_query += " where {0}".format(where_clause)

        self._handle_ariel_query(ariel_query, action_result, 'flows', offense_id)

        action_result.update_summary({QRADAR_JSON_TOTAL_FLOWS: action_result.get_data_size()})

        return action_result.get_status()

    def _handle_add_note(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        offense_id = param[QRADAR_JSON_OFFENSE_ID]
        note_text = param[QRADER_JSON_NOTE_TEXT]

        try:
            if int(param.get('offense_id')) <= 0:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')
        except:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')

        params = {
            'note_text': note_text,
        }

        endpoint = 'siem/offenses/{0}/notes'.format(offense_id)

        response = self._call_api(endpoint, 'post', action_result, params=params)
        if (phantom.is_fail(action_result.get_status())):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        if not response:
            # REST Call Failed
            reason = json.loads(response.text)
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

        try:
            if int(param.get('offense_id')) <= 0:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')
        except:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')

        params = {
            'assigned_to': assignee,
        }
        endpoint = 'siem/offenses/{}'.format(offense_id)

        response = self._call_api(endpoint, 'post', action_result, params=params)
        if (phantom.is_fail(action_result.get_status())):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        if response.status_code not in [200, 399]:
            reason = json.loads(response.text)
            return action_result.set_status(phantom.APP_ERROR, reason.get('message'))

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully assigned user to offense")

    def _get_offense_details(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        # Get the list of offense ids
        offense_id = param[QRADAR_JSON_OFFENSE_ID]
        try:
            if int(offense_id) <= 0:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')
        except:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')

        # Update the parameter
        action_result.update_param({QRADAR_JSON_OFFENSE_ID: offense_id})

        if param["ingest_offense"]:
            self._on_poll_action_result = action_result
            result = self._on_poll(param)

            if (phantom.is_fail(action_result.get_status())):
                self.debug_print("call_api failed: ", action_result.get_status())
                return action_result.get_status()

            # return action_result.set_status(phantom.APP_SUCCESS, "Offenses ingested successfully")
            return result

        response = self._call_api('siem/offenses/{0}'.format(offense_id), 'get', action_result)

        if (phantom.is_fail(action_result.get_status())):
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
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_GET_OFFENSE_DETAIL_API_FAILED, response.status_code, response.text)
            return action_result.set_status(phantom.APP_ERROR, status_message)

        # Parse the output, which is details of an offense
        try:
            response_json = response.json()
        except Exception as e:
            self.debug_print("Unable to parse response as a valid JSON", e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as a valid JSON")

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
        except:
            # No reason to halt and throw an error since only summary creation has failed.
            pass

        return phantom.APP_SUCCESS

    def _post_add_to_reference_set(self, param):

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

        if (phantom.is_fail(action_result.get_status())):
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
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_GET_OFFENSE_DETAIL_API_FAILED, response.status_code, response.text)
            return action_result.set_status(phantom.APP_ERROR, status_message)

        self.debug_print("content-type", response.headers['content-type'])

        # Parse the output, which is details of an offense
        try:
            response_json = response.json()
        except Exception as e:
            self.debug_print("Unable to parse response as a valid JSON", e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as a valid JSON")

        action_result.add_data(response_json)

        try:
            # Create a summary
            action_result.update_summary({
                'element_type': response_json['element_type'].strip('\n'),
                'name': response_json['name'],
                'number_of_elements': response_json['number_of_elements'] })
        except:
            # No reason to halt and throw an error since only summary creation has failed.
            pass

        return action_result.get_status()

    def _post_close_offense(self, param):

        # Create a action result
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get the list of offense ids
        offense_id = param[QRADAR_JSON_OFFENSE_ID]
        closing_reason_id = param[QRADAR_JSON_CLOSING_REASON_ID]

        try:
            if int(offense_id) <= 0:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')
        except:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in offense_id parameter')

        try:
            if int(closing_reason_id) < 0:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid positive integer value in closing_reason_id parameter')
        except:
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid non-zero positive integer value in closing_reason_id parameter')

        # Update the parameter
        action_result.update_param({QRADAR_JSON_OFFENSE_ID: offense_id})
        params = dict()
        params[QRADAR_JSON_CLOSING_REASON_ID] = closing_reason_id

        params['status'] = "CLOSED"

        response = self._call_api('siem/offenses/{0}'.format(offense_id), 'post', action_result, params=params)

        if (phantom.is_fail(action_result.get_status())):
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
                status_message = '{0}. HTTP status_code: {1}, reason: {2}'.format(QRADAR_ERR_GET_OFFENSE_DETAIL_API_FAILED, response.status_code, response.text)
            return action_result.set_status(phantom.APP_ERROR, status_message)

        self.debug_print("content-type", response.headers['content-type'])

        # Parse the output, which is details of an offense
        try:
            response_json = response.json()
        except Exception as e:
            self.debug_print("Unable to parse response as a valid JSON", e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as a valid JSON")

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
        except:
            # No reason to halt and throw an error since only summary creation has failed.
            pass

        return action_result.get_status()

    def _alt_manage_ingestion(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        operation = param.get('operation', "")
        datestring = param.get('datetime', None)

        if not operation == "set last saved ingest time" and datestring:
            return action_result.set_status(phantom.APP_ERROR, 'Datetime is required only while setting the last saved ingest time')

        if operation == "delete last saved ingest time":
            if 'last_saved_ingest_time' in self._state:
                del self._state['last_saved_ingest_time']
        elif operation == "set last saved ingest time":
            if not datestring:
                return action_result.set_status(phantom.APP_ERROR, "datetime field must be provided if setting last saved ingest time")
            try:
                self._state['last_saved_ingest_time'] = self._epochtime(self._parsedtime(datestring)) * 1000
            except:
                return action_result.set_status(phantom.APP_ERROR, "Invalid datetime parameter")

        last_saved_ingest_time = self._state.get('last_saved_ingest_time', None)
        try:
            action_result.update_summary({
                'last_saved_ingest_time': self._utcctime(last_saved_ingest_time) if last_saved_ingest_time else None,
            })
            action_result.add_data({
                'last_saved_ingest_time': self._utcctime(last_saved_ingest_time) if last_saved_ingest_time else None,
                'last_saved_ingest_time_as_epoch_date': last_saved_ingest_time
            })
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'Provided time is invalid. Error: {}'.format(str(e)))
        self.save_state(self._state)
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        result = None
        action = self.get_action_identifier()

        if (action == self.ACTION_ID_LIST_OFFENSES):
            result = self._list_offenses(param)
        elif (action == self.ACTION_ID_LIST_CLOSING_REASONS):
            result = self._list_offense_closing_reasons(param)
        elif (action == self.ACTION_ID_GET_EVENTS):
            result = self._get_events(param)
        elif (action == self.ACTION_ID_GET_FLOWS):
            result = self._get_flows(param)
        elif (action == self.ACTION_ID_RUN_QUERY):
            result = self._run_query(param)
        elif (action == self.ACTION_ID_OFFENSE_DETAILS):
            result = self._get_offense_details(param)
        elif (action == self.ACTION_ID_CLOSE_OFFENSE):
            result = self._post_close_offense(param)
        elif (action == self.ACTION_ID_ADD_TO_REF_SET):
            result = self._post_add_to_reference_set(param)
        elif (action == self.ACTION_ID_ADD_NOTE):
            result = self._handle_add_note(param)
        elif (action == phantom.ACTION_ID_INGEST_ON_POLL):
            start_time = time.time()
            result = self._on_poll(param)
            end_time = time.time()
            diff_time = end_time - start_time
            human_time = str(timedelta(seconds=int(diff_time)))
            self.save_progress("Time taken: {0}".format(human_time))
        elif (action == "alt_manage_ingestion"):
            result = self._alt_manage_ingestion(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_connectivity(param)
        elif (action == self.ACTION_ID_ASSIGNE_USER):
            result = self._handle_assign_user(param)
        else:
            self.unknown_action()

        return result

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_exception(self, e):
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = QradarConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)

# --
# File: qradar_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult

# THIS Connector imports
from qradar_consts import *

# Other imports used by this connector
import simplejson as json
import requests
import base64
import time
from datetime import datetime
from datetime import timedelta
from pytz import timezone
import pytz


class QradarConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_LIST_OFFENSES = "list_offenses"
    ACTION_ID_GET_EVENTS = "get_events"
    ACTION_ID_GET_FLOWS = "get_flows"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_OFFENSE_DETAILS = "offense_details"

    def __init__(self):

        # Call the BaseConnectors init first
        super(QradarConnector, self).__init__()

        self._base_url = None
        self._auth = {}
        self._headers = {}

        # cef mapping for events
        # 'deviceDirection' = 0 if eventdirection == L2R else 1
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
                'startTime': 'starttime'}

    def _create_authorization_header(self, config):

        username = phantom.get_str_val(config, phantom.APP_JSON_USERNAME)
        password = phantom.get_str_val(config, phantom.APP_JSON_PASSWORD)

        if (not username) or (not password):
            return self.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_CREDENTIAL_CONFIG)

        user_pass = username + ":" + password
        auth_string = "Basic {0}".format(base64.b64encode(user_pass.encode('ascii')))

        self._auth['Authorization'] = auth_string

        return phantom.APP_SUCCESS

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

        # Base URL
        self._base_url = 'https://' + config[phantom.APP_JSON_DEVICE] + '/api/'

        # Auth details
        if (phantom.is_fail(self._set_auth(config))):
            return self.get_status()

        # default is json, if any action needs to change then let them
        self._headers['Accept'] = QRADAR_JSON_ACCEPT_HDR_JSON

        # Don't specify the version, so the latest api installed on the device will be usedl.
        # There seems to be _no_ change in the contents or endpoints of the API only the version!!
        # self._headers['Version'] = '3'
        self._headers.update(self._auth)

        return phantom.APP_SUCCESS

    def _get_str_from_epoch(self, epoch_milli):
        # 2015-07-21T00:27:59Z
        return datetime.fromtimestamp(long(epoch_milli) / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    def _get_artifact(self, event, container_id):

        cef = phantom.get_cef_data(event, self._cef_event_map)

        self.debug_print("event: ", event)
        self.debug_print("cef: ", cef)
        cef['version'] = 0

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
                'container_id': container_id,
                'start_time': '' if ('starttime' not in event) else self._get_str_from_epoch(event['starttime']),
                'end_time': '' if ('endtime' not in event) else self._get_str_from_epoch(event['endtime'])}

        return artifact

    def _test_connectivity(self, param):

        self.save_progress(QRADAR_USING_BASE_URL, base_url=self._base_url)

        config = self.get_config()

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, config[phantom.APP_JSON_DEVICE])

        # Get the databases on the ariels endpoint, this is the fastest way of
        # testing connectivity
        response = self._call_api('ariel/databases', 'get', self)

        if (phantom.is_fail(self.get_status())):
            self.debug_print("call_api failed: ", self.get_status())
            return self.get_status()

        self.debug_print("Response Code", response.status_code)

        if (response.status_code != 200):
            # Error condition
            status_message = '{0}. {1}. HTTP status_code: {2}, reason: {3}'.format(QRADAR_ERR_CONNECTIVITY_TEST,
                QRADAR_MSG_CHECK_CREDENTIALS, response.status_code, response.reason)
            return self.set_status(phantom.APP_ERROR, status_message)

        return self.set_status_save_progress(phantom.APP_SUCCESS, QRADAR_SUCC_CONNECTIVITY_TEST)

    def _on_poll(self, param):

        # Create a action result to represent this action
        action_result = self.add_action_result(ActionResult(dict(param)))
        offenses = list()

        # Call _list_offenses with a local action result,
        # this one need not be added to the connector run
        # result. It will be used to contain the offenses data
        offenses_action_result = ActionResult(dict(param))

        if (phantom.is_fail(self._list_offenses(param, offenses_action_result))):
            # Copy the status and message into our action result
            self.debug_print('message: {0}'.format(offenses_action_result.get_message()))
            action_result.set_status(offenses_action_result.get_status())
            action_result.append_to_message(offenses_action_result.get_message())
            return action_result.get_status()

        # From here onwards the action is treated as success, if an event query failed
        # it's still a success and the message, summary should specify details about it
        action_result.set_status(phantom.APP_SUCCESS)

        offenses = offenses_action_result.get_data()
        len_offenses = len(offenses)
        action_result.update_summary({QRADAR_JSON_TOTAL_OFFENSES: len_offenses})

        self.debug_print("Number of offenses:", len_offenses)

        for i, offense in enumerate(offenses):

            get_ph_severity = lambda x: phantom.SEVERITY_LOW if x <= 3 else (
                    phantom.SEVERITY_MEDIUM if x <= 7 else phantom.SEVERITY_HIGH)

            # Replace the 'null' string to None if any
            offense = dict([(x[0], None if x[1] == 'null' else x[1]) for x in offense.items()])

            # strip \r, \n and space from the values, qradar does that for the description field atleast
            v_strip = lambda v: v.strip(' \r\n') if type(v) == str or type(v) == unicode else v
            offense = dict([(k, v_strip(v)) for k, v in offense.iteritems()])

            # Don't want dumping non None
            self.debug_print('Offense', phantom.remove_none_values(offense))

            offense_id = offense['id']
            container = {}
            container['name'] = offense['description']
            container['data'] = offense
            container['start_time'] = self._get_str_from_epoch(offense['start_time'])
            container['severity'] = get_ph_severity(offense['severity'])
            container['source_data_identifier'] = offense_id

            self.send_progress("Saving Container # {0}".format(i))
            ret_val, message, container_id = self.save_container(container)
            self.debug_print("save_container returns, ret_val: {0}, message: {1}, id: {2}".format(ret_val, message, container_id))

            if (phantom.is_fail(ret_val)):
                continue

            if (not container_id):
                continue

            # set the event params same as that of the input poll params
            # since the time range should be the same
            event_param = dict(param)
            # Add the offense id to the param dict
            event_param['offense_id'] = offense_id

            # Create a action result specifically for the event
            event_action_result = ActionResult(event_param)
            if (phantom.is_fail(self._get_events(event_param, event_action_result))):
                self.debug_print("Failed to get events for offense", offense_id)
                self.send_progress("Failed to get events for offense")
                action_result.append_to_message(QRADAR_ERR_GET_EVENTS_FAILED.format(offense_id=offense_id))
                continue

            events = event_action_result.get_data()
            self.debug_print("Got {0} events for offense {1}".format(len(events), offense_id))

            event_index = 0
            len_events = len(events)
            for j, event in enumerate(events):

                # strip \r, \n and space from the values, qradar does that for the description field atleast
                event = dict([(k, v_strip(v)) for k, v in event.iteritems()])

                # self.debug_print('Event', phantom.remove_none_values(event))

                artifact = self._get_artifact(event, container_id)

                self.debug_print('artifact', artifact)

                self.send_progress("Saving Container # {0}, Artifact # {1}".format(i, j))

                if ((j + 1) == len_events):
                    artifact['run_automation'] = True

                ret_val, message, artifact_id = self.save_artifact(artifact)
                self.debug_print("save_artifact returns, value: {0}, message: {1}, id: {2}".format(ret_val, message, artifact_id))

                event_index += 1

                # self.debug_print("event", event)

        self.send_progress(" ")
        return self.set_status(phantom.APP_SUCCESS)

    def _list_offenses(self, param, action_result=None):

        if (not action_result):
            # Create a action result to represent this action
            action_result = self.add_action_result(ActionResult(dict(param)))

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
        if (self.is_poll_now()):
            end_time_msecs = int(time.mktime(datetime.utcnow().timetuple())) * 1000
            num_days = int(self.get_app_config().get(QRADAR_JSON_DEF_NUM_DAYS, QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME))
            start_time_msecs = end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days)
        else:
            curr_epoch_msecs = int(time.mktime(datetime.utcnow().timetuple())) * 1000
            end_time_msecs = curr_epoch_msecs if end_time_msecs is None else int(end_time_msecs)
            num_days = int(self.get_app_config().get(QRADAR_JSON_DEF_NUM_DAYS, QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME))
            start_time_msecs = end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days) if start_time_msecs is None else int(start_time_msecs)

        if (end_time_msecs < start_time_msecs):
            action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME_RANGE)

        self.save_progress('Getting data from {0} to {1}'.format(self._get_tz_str_from_epoch(start_time_msecs), self._get_tz_str_from_epoch(end_time_msecs)))

        # Create the param dictionary for the range
        filter_string += '(({2} >= {0} and {2} <= {1}) or ({3} >= {0} and {3} <= {1}))'.format(
                start_time_msecs, end_time_msecs, 'start_time', 'last_updated_time')

        # get the list of offenses that we are supposed to query for
        container_source_ids = phantom.get_value(param, phantom.APP_JSON_CONTAINER_ID,
                phantom.get_value(param, QRADAR_JSON_OFFENSE_ID, None))

        if (container_source_ids is not None):
            # convert it to list
            offense_id_list = ['id=' + x.strip() for x in container_source_ids.split(',') if len(x.strip()) > 0]
            if (len(offense_id_list) > 0):

                # we have data to work on
                filter_string += ' {0} ({1})'.format(
                        'and' if len(filter_string) > 0 else '',
                        ' or '.join(offense_id_list))

        params['filter'] = filter_string

        offenses = list()

        runs = 0

        start_index = 0
        total_offenses = 0
        count_to_query = QRADAR_QUERY_HIGH_RANGE
        params['fields'] = '''id, start_time'''

        last_query = False

        count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT, param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_OFFENSE_COUNT)))

        # Count zero means get all the possible items
        if (count == 0):
            # set it to the max number we can use in the query, so that we get all of them
            count = QRADAR_QUERY_HIGH_RANGE

        if (count > QRADAR_QUERY_HIGH_RANGE):
            # Should not set more than the HIGH RANGE, else qradar throws an error
            count = QRADAR_QUERY_HIGH_RANGE

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
        while True:
            if (runs > QRADAR_MAX_ALLOWED_RUNS_TO_GET_LATEST_OFFENSES):
                return action_result.set_status(phantom.APP_ERROR,
                        QRADAR_ERR_RAN_TOO_MANY_QUERIES_TO_GET_NUMBER_OF_OFFENSES, query_runs=runs)

            runs += 1
            # Now the range
            headers['Range'] = 'items={0}-{1}'.format(start_index, start_index + count_to_query - 1)

            self.debug_print("params", params)
            self.debug_print("headers", headers)

            response = self._call_api('siem/offenses', 'get', action_result, params=params, headers=headers)

            if (phantom.is_fail(action_result.get_status())):
                self.debug_print("call_api failed: ", action_result.get_status())
                return action_result.get_status()

            self.debug_print("Response Code", response.status_code)

            if (response.status_code != 200):
                # Error condition
                action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_LIST_OFFENSES_API_FAILED)
                # Add the response that we got from the device, it contains additional info
                action_result.append_to_message(response.text)
                return action_result.get_status()

            try:
                offenses = response.json()
            except Exception as e:
                self.debug_print("Unable to parse response as a valid JSON", e)
                return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as a valid JSON")

            if (last_query):
                break

            number_of_offenses = len(offenses)
            total_offenses += number_of_offenses

            if (number_of_offenses >= count_to_query):
                start_index += count_to_query
                continue

            if (last_query is False):
                # we got the total number of offenses
                self.debug_print("Got {0} total offenses after {1} runs".format(total_offenses, runs), "")
                self.save_progress(QRADAR_PROG_GOT_X_OFFENSES, total_offenses=total_offenses)
                # Now calculate the range that we should be asking for
                start_index = 0 if (total_offenses < count) else (total_offenses - count)
                count_to_query = count
                del params['fields']
                last_query = True

        # Parse the output, which is an array of offenses
        # Update the summary
        action_result.update_summary({QRADAR_JSON_TOTAL_OFFENSES: len(offenses)})
        for offense in offenses:
            action_result.add_data(offense)

        return action_result.get_status()

    def _handle_ariel_query(self, ariel_query, action_result, obj_result_key=None, offense_id=None):

        if (obj_result_key):
            self.save_progress("Executing ariel query to get {0} {1}", obj_result_key,
                    '' if (not offense_id) else 'for offense: {offense_id}'.format(offense_id=offense_id))
        else:
            self.save_progress("Executing ariel query")

        params = dict()

        self.debug_print("Executing ariel query: {0}".format(ariel_query))
        # self.save_progress("Query: {0}".format(ariel_query))

        # First create a search
        params['query_expression'] = ariel_query

        response = self._call_api(QRADAR_ARIEL_SEARCH_ENDPOINT, 'post', action_result, params=params)

        if (phantom.is_fail(action_result.get_status())):
            self.debug_print("call_api for ariel query failed: ", action_result.get_status())
            return action_result.get_status()

        self.debug_print("Response Code", response.status_code)

        if (response.status_code != 201):
            # Error condition
            action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_ARIEL_QUERY_FAILED)
            # Add the response that we got from the device, it contains additional info
            resp_text = response.text
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

        # self.save_progress(QRADAR_PROG_GOT_SEARCH_ID, search_id=search_id)

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

            if (response.status_code != 200):
                # Error condition
                action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_ARIEL_QUERY_STATUS_CHECK_FAILED)
                # Add the response that we got from the device, it contains additional info
                action_result.append_to_message(response.text)
                # set the error and break
                got_error = True
                return action_result.get_status()

            # re-setting the failed times
            try:
                response_json = response.json()
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Unable to parse reponse as a valid JSON")

            if ('status' not in response_json):
                return action_result.set_status(phantom.APP_ERROR, "Response JSON does not contain 'status' key")

            # What is the status string for error, the sample apps don't have this info
            # niether the documentation
            if((response_json.get('status') != 'COMPLETED') and
                    (response_json.get('status') != 'EXECUTE') and
                    (response_json.get('status') != 'SORTING') and
                    (response_json.get('status') != 'WAIT')):
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

        if (response.status_code != 200):
            # Error condition
            action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_ARIEL_QUERY_RESULTS_FAILED)
            # Add the response that we got from the device, it contains additional info
            action_result.append_to_message(response.text)
            return action_result.get_status()

        try:
            response_json = response.json()
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

        self.debug_print("In _get_events")

        if (not action_result):
            # Create a action result
            action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._validate_times(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

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
        # If start_time is not given, then start_time is 10 days behind end_time'
        # The START clause has to come before the STOP clause, else the query fails
        # The START and STOP clause have to be given, else the results will be for
        # the last 60 seconds or something small like that.
        # We also need to get the the events closest to the end time, so add the
        # starttime comparison operators for that
        num_days = int(self.get_app_config().get(QRADAR_JSON_DEF_NUM_DAYS, QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME))
        curr_epoch_msecs = int(time.time()) * 1000
        start_time_msecs = 0
        end_time_msecs = int(param.get(phantom.APP_JSON_END_TIME, curr_epoch_msecs))
        start_time_msecs = int(param.get(phantom.APP_JSON_START_TIME,
                end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days)))

        count = int(param.get(phantom.APP_JSON_ARTIFACT_COUNT, param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_EVENT_COUNT)))

        if (end_time_msecs < start_time_msecs):
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME_RANGE)

        if (len(where_clause)):
            where_clause += " and"

        # The starttime >= and starttime <= clause is required without which the limit clause fails
        where_clause += " starttime >= {0} and starttime <= {1}".format(start_time_msecs, end_time_msecs)
        # where_clause += " starttime BETWEEN {0} and {1}".format(start_time_msecs, end_time_msecs)
        action_result.update_param({phantom.APP_JSON_START_TIME: start_time_msecs,
            phantom.APP_JSON_END_TIME: end_time_msecs})

        if (count == 0):
            # set it to the max number we can use in the query, so that we get all of them
            count = QRADAR_QUERY_HIGH_RANGE

        if (count > QRADAR_QUERY_HIGH_RANGE):
            # Should not set more than the HIGH RANGE, else qradar throws an error
            count = QRADAR_QUERY_HIGH_RANGE
            # put a max count to get after ordering by starttime in descending order

        where_clause += " ORDER BY starttime DESC LIMIT {0}".format(count)

        # From testing queries, it was noticed that the START and STOP are required else the default
        # result returned by the REST api is of 60 seconds or so. Also the time format needs to be in
        # the device's timezone.
        # where_clause += " START '{0}'".format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(start_time_msecs/1000)))
        # where_clause += " STOP '{0}'".format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(end_time_msecs/1000)))
        where_clause += " START '{0}'".format(self._get_tz_str_from_epoch(start_time_msecs))
        where_clause += " STOP '{0}'".format(self._get_tz_str_from_epoch(end_time_msecs))

        self.debug_print('where_clause', where_clause)

        ariel_query += " where {0}".format(where_clause)

        self.debug_print('ariel_query', ariel_query)

        self._handle_ariel_query(ariel_query, action_result, 'events', offense_id)

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

        return action_result.get_status()

    def _get_flows(self, param):

        # Create a action result
        action_result = self.add_action_result(ActionResult(dict(param)))

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

        if (response.status_code != 200):
            # Error condition
            action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_GET_FLOWS_COLUMNS_API_FAILED)
            # Add the response that we got from the device, it contains additional info
            action_result.append_to_message(json.dumps(response.json()))
            return action_result.get_status()

        try:
            event_columns_json = response.json()
        # except JSONDecodeError:
        except:
            # Many times when QRadar crashes, it gives back the status code as 200, but the reponse
            # in an html saying that an application error occurred. Bail out when this happens
            # The debug_print of response should help in debugging this
            self.debug_print("content-type", response.headers['content-type'])
            self.debug_print("response", response.text)
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_GOT_INVALID_RESPONSE)

        flow_columns_json = event_columns_json

        flow_columns = ','.join('"{}"'.format(x) for x in [y.get('name') for y in flow_columns_json['columns']])

        self.debug_print("flow_columns", flow_columns)

        ariel_query = QRADAR_AQL_FLOW_SELECT.format(fields=flow_columns) + QRADAR_AQL_FLOW_FROM

        # default the where clause to empty
        where_clause = ''

        # Get the offense id
        offense_id = phantom.get_str_val(param, QRADAR_JSON_OFFENSE_ID, None)
        if (offense_id):
            if (len(where_clause)):
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
        # If start_time is not given, then start_time is 10 days behind end_time'
        # The START clause has to come before the STOP clause, else the query fails
        # The START and STOP clause have to be given, else the results will be for
        # the last 60 seconds or something small like that.
        # We also need to get the the flows closest to the end time, so add the
        # starttime comparison operators for that
        num_days = int(self.get_app_config().get(QRADAR_JSON_DEF_NUM_DAYS, QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME))
        curr_epoch_msecs = int(time.time()) * 1000
        start_time_msecs = 0
        end_time_msecs = int(param.get(phantom.APP_JSON_END_TIME, curr_epoch_msecs))
        start_time_msecs = int(param.get(phantom.APP_JSON_START_TIME,
                end_time_msecs - (QRADAR_MILLISECONDS_IN_A_DAY * num_days)))
        count = int(param.get(QRADAR_JSON_COUNT, QRADAR_DEFAULT_FLOW_COUNT))

        if (end_time_msecs < start_time_msecs):
            return action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_INVALID_TIME_RANGE)

        if (len(where_clause)):
            where_clause += " and"

        # The starttime >= and starttime <= clause is required without which the limit clause fails
        where_clause += " starttime >= {0} and starttime <= {1}".format(start_time_msecs, end_time_msecs)
        action_result.update_param({phantom.APP_JSON_START_TIME: start_time_msecs,
            phantom.APP_JSON_END_TIME: end_time_msecs})

        if (count == 0):
            # set it to the max number we can use in the query, so that we get all of them
            count = QRADAR_QUERY_HIGH_RANGE

        if (count > QRADAR_QUERY_HIGH_RANGE):
            # Should not set more than the HIGH RANGE, else qradar throws an error
            count = QRADAR_QUERY_HIGH_RANGE
            # put a max count to get after ordering by starttime in descending order

        where_clause += " ORDER BY starttime DESC LIMIT {0}".format(count)

        # From testing queries, it was noticed that the START and STOP are required else the default
        # result returned by the REST api is of 60 seconds or so. Also the time format needs to be in
        # the device's timezone.
        # where_clause += " START '{0}'".format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(start_time_msecs/1000)))
        # where_clause += " STOP '{0}'".format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(end_time_msecs/1000)))
        where_clause += " START '{0}'".format(self._get_tz_str_from_epoch(start_time_msecs))
        where_clause += " STOP '{0}'".format(self._get_tz_str_from_epoch(end_time_msecs))

        self.debug_print('where_clause', where_clause)

        ariel_query += " where {0}".format(where_clause)

        # self.debug_print('ariel_query', ariel_query)

        self._handle_ariel_query(ariel_query, action_result, 'flows', offense_id)

        # Set the summary
        action_result.update_summary({QRADAR_JSON_TOTAL_FLOWS: action_result.get_data_size()})

        return action_result.get_status()

    def _get_offense_details(self, param):

        # Get the list of offense ids
        offense_id = param[QRADAR_JSON_OFFENSE_ID]

        # Create a action result
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Update the parameter
        action_result.update_param({QRADAR_JSON_OFFENSE_ID: offense_id})

        response = self._call_api('siem/offenses/{0}'.format(offense_id), 'get', action_result)

        if (phantom.is_fail(action_result.get_status())):
            self.debug_print("call_api failed: ", action_result.get_status())
            return action_result.get_status()

        self.debug_print("Response Code", response.status_code)

        if (response.status_code != 200):
            # Error condition
            action_result.set_status(phantom.APP_ERROR, QRADAR_ERR_GET_OFFENSE_DETAIL_API_FAILED)
            # Add the response that we got from the device, it contains additional info
            action_result.append_to_message(json.dumps(response.json()))
            return action_result.get_status()

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

        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if (action == self.ACTION_ID_LIST_OFFENSES):
            result = self._list_offenses(param)
        elif (action == self.ACTION_ID_GET_EVENTS):
            result = self._get_events(param)
        elif (action == self.ACTION_ID_GET_FLOWS):
            result = self._get_flows(param)
        elif (action == self.ACTION_ID_RUN_QUERY):
            result = self._run_query(param)
        elif (action == self.ACTION_ID_OFFENSE_DETAILS):
            result = self._get_offense_details(param)
        elif (action == phantom.ACTION_ID_INGEST_ON_POLL):
            start_time = time.time()
            result = self._on_poll(param)
            end_time = time.time()
            diff_time = end_time - start_time
            human_time = str(timedelta(seconds=int(diff_time)))
            self.save_progress("Time taken: {0}".format(human_time))
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_connectivity(param)
        else:
            self.unknown_action()

        return result

    def finalize(self):
        return phantom.APP_SUCCESS

    def handle_exception(self, e):
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    # import simplejson as json

    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = QradarConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (ret_val)

    exit(0)

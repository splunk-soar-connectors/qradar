# --
# File: qradar_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --


QRADAR_JSON_AUTH_TOKEN = "authorization_token"
QRADAR_JSON_ACCEPT_HDR_JSON = "application/json"
QRADAR_JSON_TOTAL_EVENTS = "total_events"
QRADAR_JSON_TOTAL_FLOWS = "total_flows"
QRADAR_JSON_TOTAL_OFFENSES = "total_offenses"
QRADAR_JSON_OFFENSE_ID = "offense_id"
QRADAR_JSON_FIELDS_FILTER = "fields_filter"
QRADAR_JSON_COUNT = "count"
QRADAR_JSON_IP = "ip"
QRADAR_JSON_TIMEZONE = "timezone"
QRADAR_JSON_CLOSING_REASON_ID = "closing_reason_id"
QRADAR_JSON_REFSET_NAME = "reference_set_name"
QRADAR_JSON_REFSET_VALUE = "reference_set_value"
# QRADAR_JSON_INGESTDUPES = "ingestdupes"
QRADAR_JSON_ARTIFACT_MAX_DEF = "artifact_max"
QRADAR_JSON_ADD_TO_RESOLVED = "add_to_resolved"
QRADER_JSON_NOTE_TEXT = "note_text"
QRADER_JSON_ASSIGNEE = "assignee"
QRADAR_INGEST_RESOLVED = "ingest_resolved"

QRADAR_JSON_NAME = "name"
QRADAR_JSON_OFFENSE_SOURCE = "source"
QRADAR_JSON_FLOW_COUNT = "flow_count"
QRADAR_JSON_STATUS = "status"
QRADAR_JSON_STARTTIME = "start_time"
QRADAR_JSON_UPDATETIME = "update_time"
QRADAR_JSON_DEF_NUM_DAYS = "interval_days"
QRADAR_JSON_QUERY = "query"

QRADAR_ERR_INVALID_CREDENTIAL_CONFIG = "Invalid or incomplete credential configuration. Either an auth_key or username & password should be specified."
QRADAR_ERR_REST_API_CALL_FAILED = "Rest API call failed"
QRADAR_ERR_REST_API_CALL_FAILED_RESPONSE_NONE = "Rest API call failed, HTTP response was 'None'"
QRADAR_ERR_API_UNSUPPORTED_METHOD = "API call made with unsupported method {method}"
QRADAR_ERR_GET_OFFENSE_DETAIL_API_FAILED = "API call to get offense details failed"
QRADAR_ERR_ARIEL_QUERY_FAILED = "Rest API ariel query failed"
QRADAR_ERR_ARIEL_QUERY_RESULTS_FAILED = "Failed to get results of the ariel query"
QRADAR_ERR_ARIEL_QUERY_STATUS_CHECK_FAILED = "Failed to get the status of the ariel query"
QRADAR_ERR_LIST_OFFENSES_API_FAILED = "Rest API call to list offenses failed"
QRADAR_ERR_INVALID_TIME_RANGE = "Invalid Time range specified, where the end time is less than start time"
QRADAR_ERR_RAN_TOO_MANY_QUERIES_TO_GET_NUMBER_OF_OFFENSES = "Ran too many queries ({query_runs} to get number of offenses"
QRADAR_ERR_GET_EVENTS_COLUMNS_API_FAILED = "Failed to get columns for events from the device"
QRADAR_ERR_GET_FLOWS_COLUMNS_API_FAILED = "Failed to get columns for flows from the device"
QRADAR_ERR_GET_EVENTS_FAILED = "Failed to get events for offense id {offense_id}"
QRADAR_ERR_GET_ARIEL_DATABASES = "Failed to get the ariel databases"
QRADAR_SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
QRADAR_ERR_CONNECTIVITY_TEST = "Test Connectivity Failed"
QRADAR_ERR_GOT_INVALID_RESPONSE = "Got Invalid response from the device."
QRADAR_CONNECTION_FAILED = "Connection failed"
QRADAR_ERR_ADD_NOTE_API_FAILED = "Failed to added note to offense"
QRADAR_SUCC_RUN_QUERY = "Successfully ran query"

QRADAR_PROG_EXECUTING_ENDPOINT = "Executing {method} on {endpoint}"
QRADAR_PROG_GOT_SEARCH_ID = "Got search id {search_id}"
# QRADAR_PROG_QUERY_STATUS = "Current state of query is {state} with {percent}% complete"
QRADAR_PROG_QUERY_STATUS = "Query {percent}% complete"
QRADAR_PROG_SENDING_QUERY = "Executing ariel query to get {obj_type}"
QRADAR_PROG_GOT_X_OFFENSES = "Got {total_offenses} offenses for the given time range"
QRADAR_PROG_QUERY_DATABASES = "Queried ariel databases for connectivity."
QRADAR_USING_BASE_URL = "Using base url {base_url}"
QRADAR_MSG_CHECK_CREDENTIALS = "Neiter the auth key or the username/password worked. Please check you credentials"
QRADAR_MSG_GOT_N_OBJS = "Got {num_of_objs} {obj_type}"
QRADAR_MSG_QUERYING_FOR_MAX_N_EVENTS = "Querying for max {count} number of events"

# This is what a event query looks like
# The select clause with all the required data
QRADAR_AQL_EVENT_SELECT = 'select qid, severity, Application, destinationmac, AccountDomain, destinationport, destinationip, "Destination Host Name", destinationaddress, endtime, "File Hash", "File ID", "File Path", Filename, BytesReceived, Message, BytesSent, sourceip, "Source Host Name", sourcemac, sourceport, eventcount, sourceaddress, starttime, username, Bytes, EventID, eventdirection, "Installer Filename", ProtocolName(protocolid), QidName(qid), CategoryName(category), logsourceid, relevance, HostName(logsourceid), LogSourceName(logsourceid), LogSourceGroupName(logsourceid), UTF8(payload) as Payload' # noqa
# From clause
QRADAR_AQL_EVENT_FROM = " from events"
QRADAR_AQL_EVENT_WHERE = " where hasoffense='true' "

QRADAR_AQL_FLOW_SELECT = 'select {fields}, ProtocolName(protocolid), ApplicationName(applicationid), QidName(qid), CategoryName(category)'
QRADAR_AQL_FLOW_FROM = " from flows"
QRADAR_AQL_FLOW_WHERE = " where hasoffense='true' "

# Next come the offense id, count and range parts
# and InOffense(1) LIMIT 10 START '2014-12-04 00:00:00' LAST '2014-12-05 00:00:00'

QRADAR_ARIEL_SEARCH_ENDPOINT = "ariel/searches"
QRADAR_MILLISECONDS_IN_A_DAY = 86400000
QRADAR_NUMBER_OF_DAYS_BEFORE_ENDTIME = 5
QRADAR_DEFAULT_EVENT_COUNT = 10
QRADAR_DEFAULT_FLOW_COUNT = 10
QRADAR_DEFAULT_OFFENSE_COUNT = 100
QRADAR_MAX_ALLOWED_RUNS_TO_GET_LATEST_OFFENSES = 50

# This value is set by trial and error by quering qradar
QRADAR_QUERY_HIGH_RANGE = 1000

# Useful baseline number of artifacts to ingest per offense
QRADAR_ARTIFACT_MAX_POLL = 102

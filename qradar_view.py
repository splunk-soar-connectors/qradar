# File: qradar_view.py
#
# Copyright (c) 2016-2024 Splunk Inc.
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
import phantom.app as phantom  # noqa
import phantom.utils as ph_utils

interested_contains = ["ip", "hash", "sha1", "sha256", "md5", "mac address", "url", "email"]


def _get_contains(value):

    contains = []

    if not value:
        return contains

    for contain, validator in list(ph_utils.CONTAINS_VALIDATORS.items()):

        if (not contain) or (not validator):
            continue

        if contain not in interested_contains:
            continue

        # This validation is because the Phantom validators are expecting string or buffer value as input
        if validator(str(value)):
            contains.append(contain)

    return contains


def _process_item(item_name, ctx_result):

    item_data_list = ctx_result['data'][item_name]

    if not item_data_list:
        return

    # get the 1st item on the item list
    headers = list(item_data_list[0].keys())

    output_dict = {}
    output_dict['headers'] = headers
    contains_data_list = []

    for curr_item_data in item_data_list:

        contains_item = {}
        # data_item_contains = {}
        for k, v in list(curr_item_data.items()):
            contains = _get_contains(v)
            contains_item.update({k: contains})
        contains_data_list.append(contains_item)

    output_dict['data'] = list(zip(item_data_list, contains_data_list))
    ctx_result['data'][item_name] = output_dict


def get_ctx_result(result):

    ctx_result = {}
    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    if (summary):
        ctx_result['summary'] = summary

    ctx_result['param'] = param

    if (not data):
        return ctx_result

    ctx_result['data'] = data[0]

    items = ctx_result['data']

    if (not items):
        return ctx_result

    item_keys = list(items.keys())

    # events, flows etc
    for curr_item in item_keys:
        _process_item(curr_item, ctx_result)

    # print (json.dumps(ctx_result, indent=4))
    return ctx_result


def display_query_results(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'display_qr.html'

'''
#######################################################################################################
#######################################################################################################
Copyright 2018 Northeastern University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

#######################################################################################################
#######################################################################################################
'''

from python_lib import *

from google.cloud import bigquery
import json, ast, shutil


def convert_data_to_dict(schema, data):
    data_key_value = {k.name: v for k, v in zip(schema, data)}
    for k in schema:
        if k.fields:
            try:
                casted_value = ast.literal_eval(str(data_key_value[k.name]))
                if isinstance(casted_value, dict):
                    data_key_value[k.name] = casted_value
                else:
                    data_key_value[k.name] = convert_data_to_dict(k.fields, casted_value)
            except:
                data_key_value[k.name] = convert_data_to_dict(k.fields, [None] * len(k.fields))
        elif k.name not in data_key_value.keys():
            data_key_value[k.name] = None
    return data_key_value


def check_schema_field_type(value, field_type, mode):
    try:
        if mode == 'REPEATED':
            return [check_schema_field_type(v, field_type, '') for v in value]
        if field_type == 'INTEGER':
            return int(value)
        if field_type == 'FLOAT':
            return float(value)
        if field_type == 'BOOLEAN':
            return bool(value)
        return value
    except:
        return None


def check_schema(key_val_data, schema):
    for k in schema:
        if k.fields:
            check_schema(key_val_data[k.name], k.fields)
        else:
            try:
                key_val_data[k.name] = check_schema_field_type(key_val_data[k.name], k.field_type, k.mode)
            except:
                key_val_data[k.name] = None


# Wehe results have four datatypes:
ReplayInfo_DATATYPE = 'replayInfo1'
ReplayInfo_SCHEMA = [
    bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
    bigquery.SchemaField("userID", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("clientIP", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("clientIP2", "STRING"),
    bigquery.SchemaField("replayName", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("extraString", "STRING", description="Extra string sent from the client (not used)"),
    bigquery.SchemaField("historyCount", "INTEGER", mode="REQUIRED"),
    bigquery.SchemaField("testID", "STRING", mode="REQUIRED",
                         description="Replay type (0 for original and 1 for bit-inverted replay)"),
    bigquery.SchemaField("exception", "STRING", description="The exception if any during the test"),
    bigquery.SchemaField("testFinished", "BOOLEAN"),
    bigquery.SchemaField("testFinishedWoutError", "BOOLEAN"),
    bigquery.SchemaField("iperfInfo", "STRING"),
    bigquery.SchemaField("testDurationServer", "FLOAT", description="Test length (in seconds) recorded on the server"),
    bigquery.SchemaField("testDurationClient", "FLOAT", description="Test length (in seconds) recorded on the client"),
    bigquery.SchemaField("metadata", "RECORD", fields=[
        bigquery.SchemaField("cellInfo", "STRING"),
        bigquery.SchemaField("model", "STRING"),
        bigquery.SchemaField("manufacturer", "STRING"),
        bigquery.SchemaField("carrierName", "STRING"),
        bigquery.SchemaField("os", "RECORD", fields=[
            bigquery.SchemaField("INCREMENTAL", "STRING"),
            bigquery.SchemaField("RELEASE", "STRING"),
            bigquery.SchemaField("SDK_INT", "INTEGER"),
        ]),
        bigquery.SchemaField("networkType", "STRING"),
        bigquery.SchemaField("locationInfo", "RECORD", fields=[
            bigquery.SchemaField("latitude", "FLOAT"),
            bigquery.SchemaField("longitude", "FLOAT"),
            bigquery.SchemaField("country", "STRING"),
            bigquery.SchemaField("countryCode", "STRING"),
            bigquery.SchemaField("city", "STRING"),
            bigquery.SchemaField("localTime", "TIMESTAMP"),
        ]),
        bigquery.SchemaField("updatedCarrierName", "STRING"),
    ]),
    bigquery.SchemaField("emptyBool", "BOOLEAN", description="A Boolean value no longer used"),
    bigquery.SchemaField("clientVersion", "STRING", description="The version of client app"),
    bigquery.SchemaField("measurementUUID", "STRING", description="Unique measurement identifier")
]

ClientXputs_DATATYPE = 'clientXputs1'
ClientXputs_SCHEMA = [
    bigquery.SchemaField("userID", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("historyCount", "INTEGER", mode="REQUIRED"),
    bigquery.SchemaField("testID", "STRING", mode="REQUIRED",
                         description="Replay type (0 for original and 1 for bit-inverted replay)"),
    bigquery.SchemaField("xputSamples", "FLOAT", mode="REPEATED", description="throughput samples collected at client"),
    bigquery.SchemaField("intervals", "FLOAT", mode="REPEATED",
                         description="time intervals at which the throughput samples are recorded"),
]

Decisions_DATATYPE = 'decisions1'
Decisions_SCHEMA = [
    bigquery.SchemaField("userID", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("historyCount", "INTEGER", mode="REQUIRED"),
    bigquery.SchemaField("testID", "STRING", mode="REQUIRED",
                         description="Replay type (0 for original and 1 for bit-inverted replay)"),
    bigquery.SchemaField("avgXputDiffPct", "FLOAT",
                         description="avgXputDiff / max(control's avgXput, original's avgXput)"),
    bigquery.SchemaField("KSAcceptRatio", "FLOAT", description="KS test acceptance ratio"),
    bigquery.SchemaField("avgXputDiff", "FLOAT", description="control's avgXput - original's avgXput"),
    bigquery.SchemaField("emptyField", "STRING", description="not used anymore"),
    bigquery.SchemaField("originalXputStats", "RECORD", fields=[
        bigquery.SchemaField("max", "FLOAT"),
        bigquery.SchemaField("min", "FLOAT"),
        bigquery.SchemaField("average", "FLOAT"),
        bigquery.SchemaField("median", "FLOAT"),
        bigquery.SchemaField("std", "FLOAT"),
    ]),
    bigquery.SchemaField("controlXputStats", "RECORD", fields=[
        bigquery.SchemaField("max", "FLOAT"),
        bigquery.SchemaField("min", "FLOAT"),
        bigquery.SchemaField("average", "FLOAT"),
        bigquery.SchemaField("median", "FLOAT"),
        bigquery.SchemaField("std", "FLOAT"),
    ]),
    bigquery.SchemaField("minXput", "FLOAT"),
    bigquery.SchemaField("KSAvgDVal", "FLOAT", description="Average D value of the sampled KS test"),
    bigquery.SchemaField("KSAvgPVal", "FLOAT", description="Average P value of the sampled KS test"),
    bigquery.SchemaField("KSDVal", "FLOAT", description="D value of the KS test"),
    bigquery.SchemaField("KSPVal", "FLOAT", description="P value of the KS test"),
]

LocalizeDecisions_DATATYPE = 'localizeDecisions1'
LocalizeDecisions_SCHEMA = [
    bigquery.SchemaField("userID", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("simReplayHistoryCounts", "INTEGER", mode="REPEATED",
                         description="historyCount values of simultaneous replays"),
    bigquery.SchemaField("testID", "STRING", mode="REQUIRED",
                         description="Replay type (0 for original and 1 for bit-inverted replay)"),
    bigquery.SchemaField("localizeTestsList", "STRING", mode="REPEATED",
                         description="list of applied tests to localize traffic differentiation"),
    bigquery.SchemaField("localizeTestsResults", "JSON",
                         description="the output of tests in localizeTestsList"),
]


def get_datatype_results_folder(datatype):
    results_folder = os.path.join(Configs().get('mainPath'), datatype, time.strftime("%Y/%m/%d", time.gmtime()))
    os.makedirs(results_folder, exist_ok=True)
    return results_folder


# Methods that create + save the schema files
def create_replayInfo_schema():
    schemaFile = os.path.join(Configs().get('bqSchemaFolder'), '{}.json'.format(ReplayInfo_DATATYPE))
    with open(schemaFile, 'w') as f:
        f.write(json.dumps([field.to_api_repr() for field in ReplayInfo_SCHEMA]))


def create_clientXputs_schema():
    schemaFile = os.path.join(Configs().get('bqSchemaFolder'), '{}.json'.format(ClientXputs_DATATYPE))
    with open(schemaFile, 'w') as f:
        f.write(json.dumps([field.to_api_repr() for field in ClientXputs_SCHEMA]))


def create_decisions_schema():
    schemaFile = os.path.join(Configs().get('bqSchemaFolder'), '{}.json'.format(Decisions_DATATYPE))
    with open(schemaFile, 'w') as f:
        f.write(json.dumps([field.to_api_repr() for field in Decisions_SCHEMA]))


def create_localizeDecisions_schema():
    schemaFile = os.path.join(Configs().get('bqSchemaFolder'), '{}.json'.format(LocalizeDecisions_DATATYPE))
    with open(schemaFile, 'w') as f:
        f.write(json.dumps([field.to_api_repr() for field in LocalizeDecisions_SCHEMA]))


# Copy files from temporary to permanent directory
# TODO: currenlty we only copy the files (after full transition to jostler change the operation to move)
def move_replayInfo(userID, historyCount, testID):
    tmpReplayInfoFile = '{}/{}/replayInfo/replayInfo_{}_{}_{}.json'.format(
        Configs().get('tmpResultsFolder'), userID, userID, historyCount, testID
    )
    permReplayInfoFile = '{}/replayInfo_{}_{}_{}.json'.format(
        get_datatype_results_folder(ReplayInfo_DATATYPE), userID.replace('@', ''), historyCount, testID
    )

    with open(tmpReplayInfoFile, 'r') as readFile:
        info = json.load(readFile)

    info_key_value = convert_data_to_dict(ReplayInfo_SCHEMA, info)
    check_schema(info_key_value, ReplayInfo_SCHEMA)

    with open(permReplayInfoFile, 'w') as f:
        f.write(json.dumps(info_key_value))


def move_clientXputs(userID, historyCount, testID):
    tmpClientXputsFile = '{}/{}/clientXputs/Xput_{}_{}_{}.json'.format(
        Configs().get('tmpResultsFolder'), userID, userID, historyCount, testID
    )
    permClientXputsFile = '{}/Xput_{}_{}_{}.json'.format(
        get_datatype_results_folder(ClientXputs_DATATYPE), userID.replace('@', ''), historyCount, testID
    )

    with open(tmpClientXputsFile, 'r') as readFile:
        xputs = json.load(readFile)

    xputs_key_value = convert_data_to_dict(ClientXputs_SCHEMA, [userID, historyCount, testID, xputs[0], xputs[1]])
    check_schema(xputs_key_value, ClientXputs_SCHEMA)

    with open(permClientXputsFile, 'w') as f:
        f.write(json.dumps(xputs_key_value))


def move_result_file(userID, historyCount, testID):
    tmpDecisionsFile = '{}/{}/decisions/results_{}_Client_{}_{}.json'.format(
        Configs().get('tmpResultsFolder'), userID, userID, historyCount, testID
    )
    permDecisionsFile = '{}/results_{}_Client_{}_{}.json'.format(
        get_datatype_results_folder(Decisions_DATATYPE), userID.replace('@', ''), historyCount, testID
    )

    with open(tmpDecisionsFile, 'r') as readFile:
        results = json.load(readFile)

    results_key_value = convert_data_to_dict(Decisions_SCHEMA, [userID, historyCount, testID] + results)
    check_schema(results_key_value, Decisions_SCHEMA)

    with open(permDecisionsFile, 'w') as f:
        f.write(json.dumps(results_key_value))


def move_localize_result_file(userID, historyCounts, testID):
    tmpDecisionsFile = '{}/{}/localizeDecisions/localizeResults_{}_{}-{}_{}.json'.format(
        getCurrentResultsFolder(), userID, userID, *historyCounts, testID
    )
    permDecisionsFile = '{}/localizeResults_{}_{}-{}_{}.json'.format(
        get_datatype_results_folder(LocalizeDecisions_DATATYPE), userID.replace('@', ''), *historyCounts, testID
    )
    shutil.copyfile(tmpDecisionsFile, permDecisionsFile)



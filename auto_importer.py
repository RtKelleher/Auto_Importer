#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Requires sentinel-mgmt-sdk-0.9.8
# Sentinel One Auto-Importer to TheHive SIRP via Python 2.x
from __future__ import print_function
from __future__ import unicode_literals
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask, CaseTaskLog, CaseObservable, AlertArtifact, Alert, CustomFieldHelper
from thehive4py.query import Eq
from management.mgmtsdk_v2.mgmt import Management
import requests, logging, json, time, sys, os, pprint

#environmental variables
S1API=('')
S1WEB=('')
api = TheHiveApi('', '')
S1Management = Management(hostname=S1WEB, api_token=S1API)
threats = S1Management.threats.get(resolved=False)
currentNum = threats.pagination['totalItems']
check = True

def main(api):
    i = 0
    while i < (currentNum):
        check = True
        string = searchCaseByDescription(threats.json['data'][i]['id'])
        if string == None and check == True:
            threat = createKeys(threats.json['data'][i], i)
            parsed = createAlertDescription(threat, i)
            case = Case(
                title=threats.json['data'][i]['description'],
                tlp=0,
                pap=0,
                severity=1,
                flag=False,
                tags=['Sentinel One', 
                    threats.json['data'][i]['classification'], 
                    threats.json['data'][i]['agentOsType'],
                    ],
                description = parsed,
                tasks=[CaseTask(
                    title='Communication',
                    description='Auto Imported Sentinel One Alert',
                    owner='sentinelone',
                    group='default',
                    createdAt=time.time())],
                status='Open',
                user='sentinelone',
                createdAt=threats.json['data'][i]['createdDate'])
            response = api.create_case(case)
            postUpdate(searchCaseByDescription(threats.json['data'][i]['id']), i)
            if response.status_code == 201:
                logging.info(json.dumps(response.json(), indent=4, sort_keys=True))
                logging.info('')
                id = response.json()['id']
            else:
                print(check)
                logging.error('ko: {}/{}'.format(response.status_code, response.text))
        i += 1
        

def postUpdate(string, i):
    file_observable = CaseObservable(
        dataType='filename',
        data=[(threats.json['data'][i]['filePath'])],
        tlp=1,
        ioc=False,
        tags=['Auto Imported', 'Filename', 'Suspicious'],
        message='Filepath Observable from Sentinel One Alert'
        )
    response = api.create_case_observable(string, file_observable)
    return response

def searchCaseByDescription(string):
    #search case with a specific string in description
    #returns the ES case ID
    query = dict()
    query['_string'] = 'description:"{}"'.format(string)
    range = 'all'
    sort = []
    response = api.find_cases(query=query, range=range, sort=sort)
    try:
        if response.status_code != 200:
            error = dict()
            error['message'] = 'search case failed'
            error['query'] = query
            error['payload'] = response.json()
            raise ValueError(json.dumps(error, indent=4, sort_keys=True))
        if len(response.json()) == 1:
            #one case matched, set Id
            esCaseId = response.json()[0]['id']
            return esCaseId
        elif len(response.json()) == 0:
            #no cases matched
            return None
        else:
            #unknown case value, likely multiple response
            check = False
            raise ValueError('Unknown case value returned, skipping...')
    except:
        pass
    return string, check


def createKeys(threat, i):
    parsed = {   
            'agentId': threats.json['data'][i]['agentId'],
            'agentIp': threats.json['data'][i]['agentIp'],
            'agentIsActive': threats.json['data'][i]['agentIsActive'],
            'agentNetworkStatus': threats.json['data'][i]['agentNetworkStatus'],   
            'Annotation': threats.json['data'][i]['annotation'],
            'AnnotationURL:': threats.json['data'][i]['annotationUrl'],
            'Benign:': threats.json['data'][i]['markedAsBenign'],
            'CertValid:': threats.json['data'][i]['isCertValid'],
            'Classifier:': threats.json['data'][i]['classifierName'],
            'ComputerName:': threats.json['data'][i]['agentComputerName'],
            'CreatedDate:': threats.json['data'][i]['createdDate'],
            'Decommisioned:': threats.json['data'][i]['agentIsDecommissioned'],
            'Description:': threats.json['data'][i]['description'],
            'Domain:': threats.json['data'][i]['agentDomain'],
            'DotNet:': threats.json['data'][i]['fileIsDotNet'],
            'FileHash:': threats.json['data'][i]['fileContentHash'],
            'FileMaliciousContent:': threats.json['data'][i]['fileMaliciousContent'],
            'FileObjectID:': threats.json['data'][i]['fileObjectId'],
            'FilePath:': threats.json['data'][i]['filePath'],
            'From:': threats.json['data'][i]['fromScan'],
            'FromCloud:': threats.json['data'][i]['fromCloud'],
            'id': threats.json['data'][i]['id'],
            'indicators': threats.json['data'][i]['indicators'],
            'Infected:': threats.json['data'][i]['agentInfected'],
            'MachineType:': threats.json['data'][i]['agentMachineType'],
            'MaliciousGroupL': threats.json['data'][i]['maliciousGroupId'],
            'Mitigated:': threats.json['data'][i]['mitigationStatus'],
            'MitigationMode:': threats.json['data'][i]['mitigationMode'],
            'OS:': threats.json['data'][i]['agentOsType'],
            'Partial:': threats.json['data'][i]['isPartialStory'],
            'Publisher:': threats.json['data'][i]['publisher'],
            'Rank:': threats.json['data'][i]['rank'],
            'S1AgentVersion:': threats.json['data'][i]['threatAgentVersion'],
            'Sha256:': threats.json['data'][i]['fileSha256'],
            'SiteID:': threats.json['data'][i]['siteId'],
            'Source:': threats.json['data'][i]['classificationSource'],
            'ThreatName:': threats.json['data'][i]['threatName'],
            'UserName:': threats.json['data'][i]['username'],
            'Verification:': threats.json['data'][i]['fileVerificationType']
            }
    return parsed


def createAlertDescription(threat, i):
    url = ('https://##Your Base URL###.sentinelone.net/analyze/threats/' + str(threats.json['data'][i]['id']) + '/overview')
    description =('## Summary\n\n' )
    for key,value in threat.iteritems():
        if value is None:
            pass
        elif value is False:
            pass
        else:
            description += (
                '- **' + str(key) + '**  ' + (str(value)) + ' \n')
    description += '```\n\n' + 'Sentinel One Alert Url: ' + url
    return description

main(api)
exit()

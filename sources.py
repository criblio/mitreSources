#  Rev 1 author:  Jim Apger, Cribl (mayhem@cribl.io).  July 2022.  Initial release
#
#  Usage:  python3 sources.py
#
#  Output:
#   T1055.011 , Process
#   T1021.005 , Process
#   T1021.005 , Network Traffic
#   T1021.005 , Logon Session
#   T1113 , Command
#   T1113 , Process
#   T1037 , Windows Registry
#   T1037 , Process
#   T1037 , Active Directory
#   .....
#
#   This script parses the MITRE ATT&CK data dictionary to retrieve the datasources.  
#   Where there are multiple sources sited for a given technique, this script will split
#   the into individual lines.
#
#   How many techniques spanning a few data sources?
#     python3 ./sources.py|grep -E 'Process|File|Command|Registry'|cut -f1 -d","|sort|uniq|wc -l
#  
#   How many techniques have a source mapping?
#     python3 ./sources.py|cut -f1 -d","|sort|uniq|wc -l
#
#   Regarding the above, Process|File|Command|Registry data spans 248 of the 380 total techniques.  That's 65%!
#

import json

f=open("enterprise-attack.json")
jsonData = json.load(f)

#Build a mapping of mitre tactic names to ids
tactics={}
for i in jsonData["objects"]:
    if i['type'] == 'x-mitre-tactic':
        tactics.update({i['x_mitre_shortname']:i['external_references'][0]['external_id']})

finalResults=[]
for i in jsonData["objects"]:
    if i['type'] == 'attack-pattern' and not "revoked" in i:
        tactic_name = []
        tactic_name_id = []
        if 'kill_chain_phases' in i :
            for x in i['kill_chain_phases']:
                tactic_name.append(x['phase_name'])
                tactic_name_id.append(tactics[x['phase_name']])
        result = {}
        dataSources=[]
        result["mitre_technique_id"] = i['external_references'][0]['external_id']
        result["mitre_tactic"] = tactic_name
        result["mitre_tactic_id"] = tactic_name_id
        result["mitre_technique"] = i['name']
        if 'x_mitre_data_sources' in i:
            dataSources = i['x_mitre_data_sources']
        else:
            result["dataSources"] = "None"
        for ds in dataSources:  # Some techniques have a list containing multiple datasources
            result["dataSources"] = ds
            result["dataSourcesShort"] = ds.split(':')[0]
            finalResults.append(result)
            print(result["mitre_technique_id"],",",result["dataSourcesShort"])

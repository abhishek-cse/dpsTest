#!/usr/bin/env python

import  requests
import json
import pytest
import subprocess
import io
import csv
import re
import time
requests.packages.urllib3.disable_warnings()
getIdByName: object=pytest.helpers.getIdByName
getProtIp=pytest.helpers.getProtIp
findAndDelete=pytest.helpers.findAndDelete
findAndDeleteFromDatastore=pytest.helpers.findAndDeleteFromDatastore
analyzeProtect=pytest.helpers.analyzeProtect
null = None


#rest api from parameter file
# def pytest_generate_tests(metafunc):
#     if 'testdata' in metafunc.fixturenames:
#         with open("testdata.yml", 'r') as f:
#             Iterations = yaml.load(f)
#             metafunc.parametrize('testdata', [i for i in Iterations])




restReq=[
    ("post","/dps/v1/management/roles/",'{"name": "role1","description": "","mode": "MANUAL","allowall": False}',),
    ("post","/dps/v1/management/roles/",'{"name": "role2","description": "","mode": "MANUAL","allowall": False}',),
    ("post","/dps/v1/management/sources",'{"name":"FileSource1","description":"hkhjkh","type":"FILE","connection":{"userfile":"exampleusers.txt","groupfile":"examplegroups.txt"}}'),
    ("post",'/dps/v1/management/roles/{0}/members.getIdByName(login,"role1","roles")','[{"name":"exampleuser1","type":"USER","sourceid":getIdByName(login,"FileSource1","sources")}]'),
    ("post",'/dps/v1/management/roles/{0}/members.getIdByName(login,"role2","roles")','[{"name":"exampleuser2","type":"USER","sourceid":getIdByName(login,"FileSource1","sources")}]'),
    ("post","/dps/v1/management/dataelements/",'{"name": "DES","description": "Data Element with Triple DES protection, including IV, CRC and KID","type": "STRUCTURED","algorithm": "QID_3DES_CBC","ivtype": "SYSTEM_APPEND","checksumtype": "CRC32","cipherformat": "INSERT_KEYID_V1"}'),
    ('post', "/dps/v1/management/dataelements/",'{"name":"te_an","description":"DataElementwithalphanumerictokenization","type":"STRUCTURED","algorithm":"QID_TOKEN","tokenelement":{"type":"ALPHANUMERIC","tokenizer":"SLT_1_3","lengthpreserving":True,"fromleft":1,"fromright":3}}'),
    ('post', "/dps/v1/management/dataelements/",'{"name":"TE_CC_S13_L0R0","description":"TE_CC_S13_L0R0","type":"STRUCTURED","algorithm":"QID_TOKEN","tokenelement":{"type":"CREDITCARD","tokenizer":"SLT_1_3","fromleft":0,"fromright":0,"valueidentification":{	"invalidcardtype":False,	"invalidluhndigit":False,	"alphabeticindicator":False,	"alphabeticindicatorposition":1}}}'),
    ('post','/dps/v1/management/masks','{"name":"Mask_L2R2_Hash","description":"","fromleft":2,"fromright":2,"masked":True,"character":"#"}'),
    ('post','/dps/v1/management/policies/', '{"name":"Policy1","description":"","type":"STRUCTURED","permissions":{"access":{"protect":False,"reprotect":False,"unprotect":False},"audit":{"success":{"protect":False,"reprotect":False,"unprotect":False},"failed":{"protect":False,"reprotect":False,"unprotect":False}}}}'),
    ('post','/dps/v1/management/policies/{0}/roles.getIdByName(login,"Policy1","policies")','[{"id":getIdByName(login,"role1","roles")},{"id":getIdByName(login,"role2","roles")}]'),
    ('post','/dps/v1/management/policies/{0}/dataelements.getIdByName(login,"Policy1","policies")','[{"id":getIdByName(login,"DES","dataelements")},{"id":getIdByName(login,"te_an","dataelements")},{"id":getIdByName(login,"TE_CC_S13_L0R0","dataelements")}]'),
    ('post','/dps/v1/management/policies/{0}/roles/permissions.getIdByName(login,"Policy1","policies")','[{"id":getIdByName(login,"role1","roles"),"dataelements":[{"access":{"protect":True,"reprotect":True,"unprotect":True,"delete":True},"audit":{"success":{"protect":True,"reprotect":True,"unprotect":True,"delete":True},"failed":{"protect":True,"reprotect":True,"unprotect":True,"delete":True}},"maskid":0,"id":getIdByName(login,"te_an","dataelements")},{"access":{"protect":True,"reprotect":True,"unprotect":True,"delete":True},"audit":{"success":{"protect":True,"reprotect":True,"unprotect":True,"delete":True},"failed":{"protect":True,"reprotect":True,"unprotect":True,"delete":True}},"maskid":0,"id":getIdByName(login,"DES","dataelements")},{"access":{"protect":True,"reprotect":True,"unprotect":True,"delete":True},"audit":{"success":{"protect":True,"reprotect":True,"unprotect":True,"delete":True},"failed":{"protect":True,"reprotect":True,"unprotect":True,"delete":True}},"maskid":0,"id":getIdByName(login,"TE_CC_S13_L0R0","dataelements")}]}]'),
    ('post','/dps/v1/management/policies/{0}/roles/permissions.getIdByName(login,"Policy1","policies")','[{"id":getIdByName(login,"role2","roles"),"dataelements":[{"access":{"protect":True,"reprotect":True,"unprotect":True,"delete":True},"audit":{"success":{"protect":True,"reprotect":True,"unprotect":True,"delete":True},"failed":{"protect":True,"reprotect":True,"unprotect":True,"delete":True}},"maskid":getIdByName(login,"Mask_L2R2_Hash","masks"),"id":getIdByName(login,"te_an","dataelements")},{"access":{"protect":False,"reprotect":True,"unprotect":False,"delete":True},"audit":{"success":{"protect":True,"reprotect":True,"unprotect":True,"delete":True},"failed":{"protect":True,"reprotect":True,"unprotect":True,"delete":True}},"noaccessoperation":"EXCEPTION","id":getIdByName(login,"DES","dataelements")},{"access":{"protect":False,"reprotect":True,"unprotect":False,"delete":True},"audit":{"success":{"protect":True,"reprotect":True,"unprotect":True,"delete":True},"failed":{"protect":True,"reprotect":True,"unprotect":True,"delete":True}},"noaccessoperation":"NULL","id":getIdByName(login,"TE_CC_S13_L0R0","dataelements")}]}]'),
    ('post','/dps/v1/management/policies/{0}/ready.getIdByName(login,"Policy1","policies")','None'),
    ('post','/dps/v1/management/datastores','{"name": "Datastore1","description": "","default":False}'),
    ('post','/dps/v1/management/datastores/{0}/policies.getIdByName(login,"Datastore1","datastores")','[{"id": getIdByName(login,"Policy1","policies")}]'),
    ('post','/dps/v1/management/datastores/{0}/ranges.getIdByName(login,"Datastore1","datastores")','{"to":getProtIp(login),"from":getProtIp(login)}'),
    ('post','/dps/v1/management/datastores/{0}/deploy.getIdByName(login,"Datastore1","datastores")','None')
 ]

#restReq = [(line.rstrip('\n') ,) for line in open('tests/test_smoke/inputAPI.parm')]

def test_clear_esa(login):
    try:
        findAndDelete(login,'policies')
        findAndDelete(login,'datastores')
        findAndDelete(login,'dataelements')
        findAndDelete(login,'nodes')
        findAndDelete(login,'roles')
        findAndDelete(login, 'sources')


    except:
        assert False




@pytest.mark.parametrize("type,api,payload",restReq)
#@pytest.mark.skipif(test='smoke',reason="skipping for now")
def test_setup_esa(type,api,payload,login):

    if "getIdByName" in api:

        uri,sub=api.split(".",1)
        sub = sub.split("&")
        ids=[]
        for i in sub:
            ids.append(eval(i))
        api=str(uri).format(*ids)
        ifmatch = pytest.helpers.getIfMatch(login, api, ids[0])
        login[1]['If-Match'] = ifmatch

    if type == "post":
        op = login[0].post('https://{0}{1}'.format(login[2],api), verify=False, data=json.dumps(eval(payload)),headers=login[1])
        if op.status_code==400:
            assert True

        else:
            assert op.status_code == 200


def test_wait_for_policy_publish(login):
    count=1
    while True:
        op = login[0].get('https://{0}{1}'.format(login[2], '/dps/v1/management/nodes?fields=datastore.id,datastore.name&extra=datastore'), verify=False,
                       headers=login[1])
        op = json.loads(op.text)
        try:
            #check if policy is seployed successfully
            if 'OK' == [x["status"] for x in op if x['host'] in login[3] ][0]:
                break
            #if node under test is not registered yet
        except IndexError:
            pass
        count=count+1
        if count == 30:
                assert False, "waited for 5 mins for policy to be deployed"
        time.sleep(10)



userDeAccess=[('exampleuser1','DES','[A:URPD--] [S:URPD--] [F:URPD--] [M:<none>          ] [O:CLEAR    ]'),
              ('exampleuser1','te_an','[A:URPD--] [S:URPD--] [F:URPD--] [M:<none>          ] [O:CLEAR    ]'),
              ('exampleuser2','DES','[A:-R-D--] [S:URPD--] [F:URPD--] [M:<none>          ] [O:EXCEPTION]'),
              ('exampleuser2','te_an','[A:URPD--] [S:URPD--] [F:URPD--] [M:M 2 / M 2 / Ch=#] [O:MASK     ]')
              ]



@pytest.mark.parametrize("policyUserName,deName,access" ,userDeAccess)
def test_dpsAdmin(policyUserName,deName,access,dpsadminOutput):
    getPolicyUsers=dpsadminOutput[2]
    getDataElements = csv.DictReader(dpsadminOutput[0], delimiter=';')
    #commented since not used
    #getTokenElements = csv.DictReader(dpsadminOutput[0], delimiter=';')


    #get sr. no of dataelement from getdataelements function
    for row in getDataElements:
        if row['Name']== deName:
            deNo=row['Pos']
    regex = re.compile(policyUserName)
    userindex = [i for i, item in enumerate(getPolicyUsers) if re.search(regex, item)][0]
    assert access in getPolicyUsers[userindex+int(deNo)], "not able match  expected is " + access + " actaul is "+ getPolicyUsers[userindex+int(deNo)]


userProtect=[('exampleuser1','te_an','-prot','Protegrity1234','pass',''),
             ('exampleuser1', 'TE_CC_S13_L0R0', '-prot', '4386280021199090','pass',''),
             ('exampleuser2','DES','-prot','Jayant','pass',''),
             ('exampleuser3', 'DES', '-prot', 'Jayant', 'fail', 'The username could not be found in the policy in shared memory')]

@pytest.mark.parametrize("policyUser,deName,action,input,status,message" ,userProtect)
def test_protect(tools,policyUser,deName,action,input,status,message):
    xcApiTool = tools['xcApiTool']
    shell = tools['shell']
    clearText=input
    #clearText = input.encode('iso-8859-1').hex()
    op = subprocess.Popen(xcApiTool + ' -p 0 -u '+ policyUser +' -d1 '+ deName +' '+ action + ' -in=raw  -out=raw -data ' + clearText,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell, bufsize=1,
                          universal_newlines=True)
    std_out, std_err = op.communicate()
    std_out = std_out.strip()
    std_err = std_err.strip()
    print('std output  :' + std_out )
    print('std err     :' + std_err)
    if status == 'fail':
        assert message in std_err
    if status == 'passed':
        #std_out = std_out.lstrip('0x')
        #cipherText = bytes.fromhex(std_out).decode('iso-8859-1')
        cipherText=std_out
        analyzeProtect(deName,clearText,cipherText)


restReq=[
    ('/dps/v1/management/datastores/{0}/ranges.getIdByName(login,"Datastore1","datastores")')
 ]


@pytest.mark.parametrize("api",restReq)
def test_clear_datastore_ranges(login, api):

    if "getIdByName" in api:
        uri, sub = api.split(".", 1)
        sub = sub.split("&")
        ids = []
        for i in sub:
            ids.append(eval(i))
        api = str(uri).format(*ids)
        ifmatch = pytest.helpers.getIfMatch(login, api, ids[0])
        login[1]['If-Match'] = ifmatch

        findAndDeleteFromDatastore(login, api)


def test_clear_pepserverLog():




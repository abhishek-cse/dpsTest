import pytest
import requests
import json
pytest_plugins = ['helpers_namespace']
global xcApiTool

# example to pass variables on command line
# pytest --esaip=192.168.2.12 --esauser=admin --esapass=admin1234 --protip=192.168.2.11

# run only tests in  test_pim.py
# pytest --esaip=192.168.2.12 --esauser=admin --esapass=admin1234 --protip=192.168.2.1  test_rest/test_pim.py

# see which test function is passed
# pytest -v --esaip=192.168.2.12 --esauser=admin --esapass=admin1234 --protip=192.168.2.1

# execute single test function
# pytest --esaip=192.168.2.12 --esauser=admin --esapass=admin1234 --protip=192.168.2.1  -k 'test_clear_esa'

# run test function test_protect in  test_pim.py
# pytest -s -v --esaip=192.168.2.12 --esauser=admin --esapass=admin1234 --protip=192.168.2.1  test_smoke/test_pim.py -k test_protect

# execute and see standard output
# pytest -s --esaip=192.168.2.12 --esauser=admin --esapass=admin1234 --protip=192.168.2.1

def pytest_addoption(parser):
    parser.addoption("--esaip", action="store")
    parser.addoption("--esauser", action="store",default='admin')
    parser.addoption("--esapass", action="store",default='admin1234')
    parser.addoption("--protip", action="store", default='127.0.0.1')

@pytest.fixture(scope="session",)
def login(request):
    ESA_USERNAME = request.config.getoption('esauser')
    ESA_USER_PASSWORD = request.config.getoption('esapass')
    ESA_IP = request.config.getoption('esaip')
    PROT_IP = request.config.getoption('protip')

    # USERNAME='admin'
    # USER_PASSWORD='admin1234'
    # ESA_IP='192.168.2.12'
    LOGIN_URL = "https://{0}/Management/Login".format(ESA_IP)
    s_request = requests.Session()
    r = s_request.post(LOGIN_URL, data={"loginname": ESA_USERNAME, "password": ESA_USER_PASSWORD},verify=False)
    csrf_token = s_request.cookies.get_dict()['CSRF_TOKEN']
    headers = {'X-CSRF-TOKEN': csrf_token, 'origin': 'https://{0}/'.format(ESA_IP),
               "referer": "https://{0}/".format(ESA_IP), "Content-Type": "application/json",'If-Match':''}
    return [s_request,headers,ESA_IP,PROT_IP,ESA_USERNAME,ESA_USER_PASSWORD]


def find_nth(string, substring, n):
   if (n == 1):
       return string.find(substring)
   else:
       return string.find(substring, find_nth(string, substring, n - 1) + 1)

@pytest.helpers.register
def getProtIp(login):
    return login[3]


@pytest.helpers.register
def getIdByName(login,name,type):
    op = login[0].get('https://{0}/dps/v1/management/{1}/'.format(login[2],type), verify=False, headers=login[1])
    try:
        op = json.loads(op.text)
        return([x["id"] for x in op if x["name"] == name][0])
    except IndexError:
        print(type +" " +name +" not found")

@pytest.helpers.register
def findAndDelete(login,type):
    op = login[0].get('https://{0}/dps/v1/management/{1}/'.format(login[2],type), verify=False, headers=login[1])
    try:
        op = json.loads(op.text)
        for x in op:
            login[0].delete('https://{0}/dps/v1/management/{1}/{2}'.format(login[2], type,x["id"]), verify=False, headers=login[1])
    except IndexError:
        print(type + "not found")


@pytest.helpers.register
def getIfMatch(login,api,id):
    api=api[0:find_nth(api,'/',5)+1]
    op = login[0].get('https://{0}{1}'.format(login[2],api), verify=False, headers=login[1])
    try:
        op = json.loads(op.text)
        return([x["etag"] for x in op if x['id'] == id][0])
        print("etag" + x[etag])
    except IndexError:
        print("ifmatch not found")
        pass


#################################################################Protector related Stuffs##################################################################################################

import subprocess
import os
import csv
@pytest.fixture(scope="session",)
def tools():
    if os.name=='nt':
        basedir='C:\\Program Files\\Protegrity'
        return   {'pepProviderTool':basedir + '\\Defiance DPS QA\\bin\\pepproviderapp.exe',
                  'dpsAdminTool':basedir +'\\Defiance DPS\\bin\\dpsadmin.exe',
                  'xcApiTool': basedir +'\\Defiance DPS QA\\bin\\xcapitestxcpep.exe',
                  'shell':False}

    if os.name =='posix':
        basedir='/opt/protegrity_7.1.0.27'
        return    {'pepProviderTool':basedir+"/defiance_qa/bin/pepproviderapp",
                      'dpsAdminTool' :basedir+"/defiance_dps/bin/dpsadmin",
                      'xcApiTool' :basedir+"/defiance_qa/bin/xcapitestxcpep",
                      'shell':True}


@pytest.fixture(scope="session",)
def dpsadminOutput(tools,login):
    xcApiTool=tools['xcApiTool']
    dpsAdminTool=tools['dpsAdminTool']
    esaAdminUser=login[4]
    esaAdminPass=login[5]
    shell=tools['shell']
    getpolicyusers = subprocess.check_output(dpsAdminTool + ' -u ' + esaAdminUser + ':' + esaAdminPass + ' -s "print(getpolicyusers())" ',
                                 shell=shell, bufsize=1, universal_newlines=True)
    gettokenelements = subprocess.check_output(dpsAdminTool + ' -u ' + esaAdminUser + ':' + esaAdminPass + ' -s "print(gettokenelements())" ',
                                 shell=shell, bufsize=1, universal_newlines=True)
    getdataelements = subprocess.check_output(dpsAdminTool + ' -u ' + esaAdminUser + ':' + esaAdminPass + ' -s "print(getdataelements())" ',
                                 shell=shell, bufsize=1, universal_newlines=True)
    getfpeproperties = subprocess.check_output(dpsAdminTool + ' -u ' + esaAdminUser + ':' + esaAdminPass + ' -s "print(getfpeproperties())" ',
                                shell=shell, bufsize=1, universal_newlines=True)

    getdataelements=getdataelements.splitlines()[2:-1]
    gettokenelements=gettokenelements.splitlines()[8:-1]
    getpolicyusers=getpolicyusers.splitlines()[6:-1]
    #getfpeproperties




    return [getdataelements,gettokenelements,getpolicyusers,getfpeproperties]
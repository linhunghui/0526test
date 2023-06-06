from http.client import REQUEST_URI_TOO_LONG
from urllib.request import Request
import requests,urllib3,datetime,time,re
from urllib.parse import urlparse
import ipaddress
import xmltodict
import json
import configparser
import os


# 建立 configparser 物件
config = configparser.ConfigParser()

# 讀取設定檔
config.read('config.ini',encoding='utf-8-sig')

# 讀取設定檔中的變數
NX_Ip = config.get('info', 'NX_Ip')
username = config.get('info', 'username')
password = config.get('info', 'password')
rolldays= config.getint('info', 'rolldays')
Severity=config.getint('info', 'Severity')
ipsHistoryOutputDir = config.get('info', 'ipsHistoryOutputDir')
TrellixblockIpOutputDir = config.get('info', 'TrellixblockIpOutputDir')
TrellixblockDomainOutputDir = config.get('info', 'TrellixblockDomainOutputDir')
AccesslogOutputDir = config.get('info', 'AccesslogOutputDir')
ErrorlogOutputDir = config.get('info', 'ErrorlogOutputDir')

#導入時間並格式化
datetime_dt=datetime.datetime.today()
datetime_str=datetime_dt.strftime("%Y_%m%d_%H%M") 
#print(datetime_str)

#遇無效證書不提示
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetchFireeyeIPSeventsFor30Day(url):
    #request header設定
    #預設header
    rkwargs = dict(
        headers={'Authorization': 'Basic dGVzdDp0ZXN0','X-FeClient-Token':'BigDataInc','X-FeApi-Token':'ICZ/aXxQlePSINy5KkN/h030XXf7AVBmiZ5LwhPH7F7/AD8='},
        verify=False,
    )
    #取得X-FeApi-Token
    try:
        r = requests.post(login_url,auth=(username,password),**rkwargs)
        token= r.headers['X-FeApi-Token']
        #print(r.headers['X-FeApi-Token'])
        #設定X-FeApi-Token的header
        rkwargsToken=dict(
        headers={'Authorization': 'Basic dGVzdDp0ZXN0','X-FeClient-Token':'BigDataInc','X-FeApi-Token':token},
        verify=False,
        )
    except:
        f=open(f'{ErrorlogOutputDir}err.log',"a")
        f.write(f"{datetime_str} failed to acquire token\n")
        f.close()
  
    

    try:
    #fetch IPS event
        r = requests.get(
        url, **rkwargsToken
    )
        xml_dict = xmltodict.parse(r.text)
        json_response = json.dumps(xml_dict)
        data_dict = json.loads(json_response)
        ips_ip_list=[]
        ips_dateip_list=[]
        #print(data_dict['eventsResponse']['events']['event'][0]['dstIp'])
        if data_dict['eventsResponse'].get('events',None) is None:
            f=open(f'{ErrorlogOutputDir}err.log',"a")
            f.write(f"{datetime_str} Success connect to server,but {url} No ipsevent found.\n")
            f.close()
        else:
            for i in data_dict['eventsResponse']['events']['event']:
                if  i['dstIp'] not in ips_ip_list and int(i['severity']) >= Severity:
                    ips_ip_list.append(i['dstIp'])
                    ips_dateip_list.append({i['occurred']: i['dstIp'],'severity':i['severity']})
        

        #logout
        r=requests.post(logout_url,**rkwargsToken)
        return ips_dateip_list    
    except:
        f=open(f'{ErrorlogOutputDir}err.log',"a")
        f.write(f"{datetime_str} failed to connect to {url}\n")
        f.close()

def SaveIpshistoryData(ips_dateip_list):
    with open(f'{ipsHistoryOutputDir}ipsHistory.txt', 'a') as file:
        for item in ips_dateip_list:
            file.write(str(item) + '\n')
        file.close()

def RemoveDuplicateAndAddToTrellixBlockIp(historyfile):
    data_list = []
    #抓取ipsHistory.txt資料轉換成list
    with open(historyfile, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                data_dict = eval(line)
                data_list.append(data_dict)

    #去除重複性資料
    unique_ips = set()
    unique_data = []

    for item in data_list:
        ip = item.get(list(item.keys())[0])  # 取得字典中的IP地址
        if ip not in unique_ips:
            #去除私有ip
            if not ipaddress.ip_address(ip).is_private:
                #加到unique清單
                unique_ips.add(ip)
                unique_data.append(item)
    #加到trellixblockip.txt
    ipfile=open(f'{TrellixblockIpOutputDir}TrellixblockIp.txt',"a")
    if unique_ips:
        for ip in unique_ips:
            try:
                ipfile.write(ip + "\n")
            except ValueError:
                pass
    else:
        print("No unique IPs to write to file.")
    ipfile.close()
    
def fetchFireeyeIPSevents(ips_url):
#request header設定
    #預設header
    rkwargs = dict(
        headers={'Authorization': 'Basic dGVzdDp0ZXN0','X-FeClient-Token':'BigDataInc','X-FeApi-Token':'ICZ/aXxQlePSINy5KkN/h030XXf7AVBmiZ5LwhPH7F7/AD8='},
        verify=False,
    )
    #取得X-FeApi-Token
    r = requests.post(login_url,auth=('test','1qaz@WSX'),**rkwargs)
    token= r.headers['X-FeApi-Token']
    #print(r.headers['X-FeApi-Token'])
  
    
    #設定X-FeApi-Token的header
    rkwargsToken=dict(
    headers={'Authorization': 'Basic dGVzdDp0ZXN0','X-FeClient-Token':'BigDataInc','X-FeApi-Token':token},
    verify=False,
    )
    try:
    #fetch IPS event
        r = requests.get(
        ips_url, **rkwargsToken
    )
        xml_dict = xmltodict.parse(r.text)
        json_response = json.dumps(xml_dict)
        data_dict = json.loads(json_response)
        ipslist=[]
        #print(data_dict['eventsResponse']['events']['event'][0]['dstIp'])
        if data_dict['eventsResponse'].get('events',None) is None:
            f=open(f'{ErrorlogOutputDir}err.log',"a")
            f.write(f"{datetime_str} Success connect to server,but No ipsevent found.\n")
            f.close()
        else:
            for i in data_dict['eventsResponse']['events']['event']:
                if i['dstIp'] not in ipslist:
                    ipslist.append(i['dstIp'])
        #logout
        r=requests.post(logout_url,**rkwargsToken)
        return ipslist    
    except:
        f=open(f'{ErrorlogOutputDir}err.log',"a")
        f.write(f"{datetime_str} failed to connect to {ips_url}\n")
        f.close()

def saveIpsData(list):
    #開襠案
    ipfile=open(f'{TrellixblockIpOutputDir}TrellixblockIp.txt',"a")
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
    for i in list:
        ipfile.write(i+"\n")
    ipfile.close()


def fetchFireeyeUrllist(url):
    #初始設定
    result = []
    malicious_sw = 0
    callbacks_sw = 0
    #request header設定
    rkwargs = dict(
        stream=False,
        verify=False,
        headers={'user-agent': 'Mozilla/5.0'}
    )
    try:
        #fectch data
        r = requests.get(
            url,
            **rkwargs
        )
        #parse the page
        rx = r.text.split('\n')
        #print(rx)
        for line in rx:
            line = line.strip('\r\n')
            #print(line)
            if "End" in line:
                malicious_sw = 0
                callbacks_sw = 0
            if ( (malicious_sw == 1) ):
                value = line.split("=")
                if value[0].strip() == "url":
                    result.append(value[1])
            if ( (callbacks_sw == 1) ):
                value = line.split("=")
                if value[0].strip() == "url":
                    result.append(value[1])
            if "define condition FireEye_Callbacks" in line:
                callbacks_sw = 1
            if "define condition FireEye_MaliciousURL" in line:
                malicious_sw = 1
        return result
    except:
        f=open(f'{ErrorlogOutputDir}err.log',"a")
        f.write(f"{datetime_str} failed to connect to {url}\n")
        f.close()

def isIP(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False

def saveURLData(list):
    #這個function要在saveIpsData之前因為會清空檔案


    #開襠案
    ipfile=open(f'{TrellixblockIpOutputDir}TrellixblockIp.txt',"a")
    domainfile=open(f'{TrellixblockDomainOutputDir}TrellixblockDomain.txt',"a")
    
    #清理檔案內資料歸零
    ipfile.truncate(0)
    domainfile.truncate(0)
   
    for url in list:
        obj=urlparse(url).netloc
        if(isIP(obj)==True):
            try:
                if not ipaddress.ip_address(obj).is_private:
                    ipfile.write(obj+"\n")
            except ValueError:
                pass
        else:
            domainfile.write(obj+"\n")
    ipfile.close()
    domainfile.close()
            

if __name__ == '__main__':
    urllist=f'https://{NX_Ip}/urllist.txt'
    login_url=f'https://{NX_Ip}/wsapis/v2.0.0/auth/login'
    logout_url=f'https://{NX_Ip}/wsapis/v2.0.0/auth/logout'


    while True:
        datetime_dt=datetime.datetime.today()
        datetime_str=datetime_dt.strftime("%Y_%m%d_%H%M")
        ipstime=datetime_dt.strftime("%Y-%m-%d")
        list_for_url=fetchFireeyeUrllist(urllist)
        
        #清空上次資料
        file=open(f'{ipsHistoryOutputDir}ipsHistory.txt',"a")
        file.truncate(0)


        #Fetch 30 days ips data save to IpsHistory.txt
        current_date = datetime.datetime.now()
        for i in range(rolldays):
            past_date = current_date - datetime.timedelta(days=i)
            past_date_str = past_date.strftime("%Y-%m-%dT%H:%M:00.000-00:00")
            ipsUrl = f"https://{NX_Ip}/wsapis/v2.0.0/events?duration=24_hours&end_time={past_date_str}&event_type=Ips%20Event"
            print(ipsUrl)  # 在这里可以使用URL进行进一步的操作
            try:
                a=fetchFireeyeIPSeventsFor30Day(ipsUrl)
                SaveIpshistoryData(a)
            except:
                f=open(f'{ErrorlogOutputDir}err.log',"a")
                f.write(f"{datetime_str} failed to fetch ips history data\n")
                f.close()

        print(f'Finish fetch {rolldays} days for ips event')
        

        #fetch urllist save data    
        try:
            #這個saveURLData function要在saveIpsData之前因為會清空檔案
            saveURLData(list_for_url)
            print('start urllist process')
            f=open(f'{AccesslogOutputDir}access.log',"a")
            f.write(f"{datetime_str} urllist data saved \n")
            f.close()
        except:
            print('Error occur in urllist process please check err.log file')
            f=open(f'{ErrorlogOutputDir}err.log',"a")
            f.write(f"{datetime_str} failed to save urllist data\n")
            f.close()
        
        #fetch ipsdata save data 
        #檢查ips data saved是否為空
        if os.path.getsize(f'{ipsHistoryOutputDir}ipsHistory.txt') != 0 :
            print('start ips event process')
            RemoveDuplicateAndAddToTrellixBlockIp(f'{ipsHistoryOutputDir}ipsHistory.txt')
            f=open(f'{AccesslogOutputDir}access.log',"a")
            f.write(f"{datetime_str} ips data saved \n")
            f.close()
        else :
            print('Error occur in ips event process please check err.log file')
            f=open(f'{ErrorlogOutputDir}err.log',"a")
            f.write(f"{datetime_str} failed to save ips data because ipsHistory.txt is None\n")
            f.close()
        print('Start sleeping 10 mins')
        time.sleep(600)


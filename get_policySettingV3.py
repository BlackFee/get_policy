import json
import pandas as pd
import requests
from settings import Settings
from settings import Policies
import warnings
warnings.filterwarnings("ignore")
url_pre=Settings().url_pre
headers=Settings().headers
cookies=Settings().cookies
policies_type=Policies().policies_type

import datetime
date=datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
log_file="log_"+date
#日志记录函数
def pLog(txt,*kws):
    with open(log_file,'a+',encoding="utf-8") as f:
        f.write('\n')
        f.write(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')+"：")
        f.write(txt)

#获取custom类型的所有策略名
def get_all_policy_customWeb(policiesName):
    url_policies=url_pre+policiesName
    r=requests.get(url_policies,headers=headers,cookies=cookies,verify=False)
    status=r.status_code
    resp=r.text
    policies=[]
    try:
        t=json.loads(resp)
        policies=t["customWebPolicies"]
    except KeyError as e1:
        pLog("错误提示：%s"%e1)
        pLog(policiesName+"     “%s” 返回的API结果中没有customWebPolicies键值，返回结果为：\n"+resp)
    except BaseException as e2:
        #非200的响应码不会抛错，这种情况requests响应结果为空值,但是json转化空值会抛JSONDecodeError(ValueError)错误。
        pLog("错误提示：%s"%e2)
        # pLog("     “%s” 策略类型API响应码为：'%d'"%(policiesName,status))
        # pLog("     “%s” 策略类型API响应结果为：'%s'"%(policiesName,resp))
        pLog(policiesName+" 策略类型API响应码为：%d"%status)
        pLog(policiesName+" 策略类型API响应结果为："+resp)
    return policies
#获取非custom类型的所有策略名
def get_all_policy_others(policiesName):
    url_policies=url_pre+policiesName
    r=requests.get(url_policies,headers=headers,cookies=cookies,verify=False)
    status=r.status_code
    resp=r.text
    policies=[]     #用于存储某一类型策略下的所有策略
    try:
        t=json.loads(resp)
        if policiesName=="firewallPolicies":
            policies=t["policies"].split(",")
        else:
            policies=t["policies"]
    except KeyError as e1:
        pLog("错误提示：%s"%e1)
        # pLog("     “%s” 返回的API结果中没有policies键值，返回结果为：\n"%(policiesName,resp))
        pLog(policiesName+" 返回的API结果中没有policies键值，返回结果为：\n"+resp)
    except BaseException as e2:
        #非200的响应码不会抛错，这种情况requests响应结果为空值,但是json转化空值会抛JSONDecodeError(ValueError)错误。
        pLog("错误提示：%s"%e2)
        # pLog("     “%s” 策略类型API响应码为：'%d'"%(policiesName,status))
        # pLog("     “%s” 策略类型API响应结果为：'%s'"%(policiesName,resp))
        pLog(policiesName+" 策略类型API响应码为：%d"%status)
        pLog(policiesName+" 策略类型API响应结果为："+resp)
    return policies
#根据不同策略类型，获取所有策略名
def get_all_policy(policiesName):
    #获取某一安全策略类型的所有策略
    custom_list=[ "webApplicationCustomPolicies","webServiceCustomPolicies"]
    if policiesName in custom_list:
        policies=get_all_policy_customWeb(policiesName)
    else:
        policies=get_all_policy_others(policiesName)
    return policies
#获取策略的详细信息
def get_policy_detail(policiesName,policyName):
    #获取某一策略的详细信息，（web界面Security面板最右侧信息）
    url_policy=url_pre+policiesName+"/"+policyName
    r=requests.get(url_policy,headers=headers,cookies=cookies,verify=False)
    data_json=r.text
    policy_deatil=json.loads(data_json)
    return policy_deatil

def get_rules_vMatch(policyName,policy_detail):
    rules_detail={}
    if "enabled" in policy_detail.keys():
        rules_detail["enabled"]=policy_detail["enabled"]
    if "severity" in policy_detail.keys():
        rules_detail["severity"]=policy_detail["severity"]
    if "action" in policy_detail.keys():
        rules_detail["action"]=policy_detail["action"]
    if "followedAction" in policy_detail.keys():
        rules_detail["followedAction"]=policy_detail["followedAction"]
    if rules_detail==[]:
        pLog("     “%s” 策略详细信息为空，请登录确认是否为空"%policyName)
    # data1=df_rules.append(data_rules) #注意append用法将生成一个新的数据变量，并不会改变原来的变量，所以要从新赋值
    data_rules=pd.DataFrame(rules_detail,index=[0])
    data_rules["policy name"]=policyName
    return data_rules
def get_rules_other(policyName,policy_detail):
    rules_detail=policy_detail["rules"]
    if rules_detail==[]:
        pLog("     “%s” 策略详细信息为空，请登录确认是否为空"%policyName)
    # data1=df_rules.append(data_rules) #注意append用法将生成一个新的数据变量，并不会改变原来的变量，所以要从新赋值
    data_rules=pd.DataFrame(rules_detail)
    data_rules["policy name"]=policyName
    return data_rules
#获取策略详细信息中的enable、severity、action、followedAction信息
def get_rules(policiesName,policyName,policy_detail):
    nother_list=["firewallPolicies","webApplicationCustomPolicies","webServiceCustomPolicies","snippetInjectionPolicies"]
    if policiesName in nother_list:
        data_rules=get_rules_vMatch(policyName,policy_detail)
    else:
        data_rules=get_rules_other(policyName,policy_detail)
    return data_rules
#获取策略所应用的站点
def get_applyTo(policiesName,policyName,policy_detail):
    data_apply=pd.DataFrame()
    apply_list=policy_detail["applyTo"]
    for p in apply_list:
        data_apply=data_apply.append(p,ignore_index=True)
    data_apply["policiesName"]=policiesName
    data_apply["policyName"]=policyName
    return data_apply

#爬取单个策略类型的所需策略详细信息
def policy_spider(policiesName,policies):
    data_rules=pd.DataFrame(columns=["name","enabled","severity","action","followedAction","policy name"])
    data_applys=pd.DataFrame(columns=["policiesName","policyName","siteName","serverGroupName","webServiceName","webApplicationName"])
    unknown_policy=[]
    spider_result=[]
    if  policies==[]:
        pLog("“%s” 爬取结果为空,请检查ADC中是否有此类型策略."%policiesName)
    else:
        for policyName in policies:
            if "/" in policyName:
                unknown_policy.append(policyName)
                continue
            policy_detail=get_policy_detail(policiesName,policyName)
            data_rule=get_rules(policiesName,policyName,policy_detail)
            data_apply=get_applyTo(policiesName,policyName,policy_detail)
            data_rules=data_rules.append(data_rule)
            data_applys=data_applys.append(data_apply)

        if unknown_policy !=[]:
            pLog("“%s”类型策略中的策略名存在“/”字符，无法爬取:"%policiesName)
            pLog("     未爬取策略的个数为：%d"%len(unknown_policy))
            pLog("     清单为：%s"%str(unknown_policy))
        spider_result={"data_rules":data_rules,"unknown_policy":unknown_policy,"data_applys":data_applys}
    return spider_result

#爬取所有策略类型的详细信息
def run_spider_policy():
    data_R=pd.DataFrame()
    data_A=pd.DataFrame()
    unknown_policy=[]
    for policiesName in policies_type:
        pLog("开始爬取%s类型的策略："%policiesName)
        print("开始爬取%s类型的策略："%policiesName)
        policies=get_all_policy(policiesName)
        result=policy_spider(policiesName,policies)
        pLog("结束爬取%s类型的策略："%policiesName)
        print("结束爬取%s类型的策略："%policiesName)
        pLog("\n")
        if result==[]:
            continue
        data_rules=result["data_rules"]
        data_applys=result["data_applys"]
        unknown_policy.append(result["unknown_policy"])
        data_R=data_R.append(data_rules)
        data_A=data_A.append(data_applys)
    result={"all_rules":data_R,"all_unknown_policy":unknown_policy,"all_applys":data_A}
    return result



if __name__ == '__main__':
    date_start=datetime.datetime.now()
    data=run_spider_policy()
    rules=data["all_rules"]
    applyTo=data["all_applys"]
    unknownP=data["all_unknown_policy"]
    unknown_name=pd.DataFrame(columns=["policy name"])
    tmp=[]
    for i in unknownP:
        if i==[]:
            continue
        tmp=i+tmp
    unknown_name["policy name"]=tmp
    print("存在未爬取的策略")
    print(unknown_name)

    filename="all_policy"+date+".xlsx"
    writer_rules=pd.ExcelWriter(filename)
    rules.to_excel(writer_rules,"sheet1",index=False)
    applyTo.to_excel(writer_rules,"sheet2",index=False)
    unknown_name.to_excel(writer_rules,"unknownName",index=False)
    writer_rules.save()
    print("爬取结果已存储至%s文件内"%filename)
    date_end=datetime.datetime.now()
    print("本次爬行用时（时-分-秒）：")
    print(date_end-date_start)
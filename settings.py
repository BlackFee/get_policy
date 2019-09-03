

class Settings():
    def __init__(self):
        self.host="127.0.0.1:8083"
        self.url_pre="https://"+self.host+"/SecureSphere/api/v1/conf/policies/security/"
        # self.url_pre="https://"+self.host+"/SecureSphere/api/v1/conf/"    		#11.5无policies/sevurity/后缀
        self.headers={
            'Host': self.host,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        self.cookies={
            "JSESSIONID":"11111111111111111111111111111111111111",
            "SSOSESSIONID":"11111111111111111111111111111111111111"
        }
class Policies():
    def __init__(self):
        self.policies_type=[
            "firewallPolicies",                     #policies string            --->detail
            "httpProtocolSignaturesPolicies",       #policies array[string]     ---->detail.rules [array]
            "streamSignaturesPolicies",             #policies array[string]     ---->detail.rules [array]
            "webApplicationCustomPolicies",         #customWebPolicies  [string]    ---->detail
            "webApplicationSignaturesPolicies",     #policies array[string]     ---->detail.rules [array]
            "webServiceCustomPolicies",             #customWebPolicies  [string]---->detail
            
            "httpProtocolPolicies",                 #policies array[string]     ---->detail.rules [array]
            "http2ProtocolPolicies",                #policies array[string]     ---->detail.rules [array]
            "snippetInjectionPolicies",             #policies array[string]     ---->detail 无servity、action.
            "webCorrelationPolicies",               #policies array[string]     ---->detail.rules [array]
            "webProfilePolicies"                    #policies array[string]     ---->detail.rules [array]
        ]







url={
    "get":"https://... /conf/policies/security/firewallPolicies/{policyName}",
    "get-all":"https://.../conf/policies/security/firewallPolicies",
    "creat-post":"https://... /conf/policies/security/firewallPolicies/{policyName}",
    "update-put":"https://... /conf/policies/security/firewallPolicies/{policyName}",
    "delete":"https://... /conf/policies/security/firewallPolicies/{policyName}",
    "apply-post":"https://.../conf/serverGroups/{siteName}/{serverGroupName}/firewallPolicies/{policyName}"
}


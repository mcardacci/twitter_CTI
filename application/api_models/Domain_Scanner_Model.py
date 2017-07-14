import urllib
import urllib2
import time
import json as simplejson

class Domain_Scanner_Model(object):

    def __init__(self, domain):
        self.domain = domain

    #submits domain to VT to generate a fresh report for DomainReportReader()
    def domain_scanner(self):
        url = 'https://www.virustotal.com/vtapi/v2/url/scan'

        parameters = {
            'url': self.domain,
            'apikey': 'a4b128f4b05396d094ea6e08ddf37b895b05ccbe5d6f24389a197dfdd1f5aaa3'
        }

        #URL encoding and submission
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)

        # print('Domain scanned successfully ')

        #for URL scan report debugging only
        #print(response)  

    def domain_report_dictonary(self):
        #sleep 15 to control requests/min to API. Public APIs only allow for 4/min threshold, you WILL get a warning email to the owner of the account if you exceed this limit. Private API allows for tiered levels of queries/second.
        time.sleep(15)

        #this is the VT url scan api link
        url = 'https://www.virustotal.com/vtapi/v2/url/report'

        #API parameters
        parameters = {'resource': self.domain,
                      'apikey': 'a4b128f4b05396d094ea6e08ddf37b895b05ccbe5d6f24389a197dfdd1f5aaa3'}

        #URL encoding and submission
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()


        #stores json response to variable for calling specific sections in the next block of code
        response_dict = simplejson.loads(json)

        #pull critical snippets from report and convert to strings for output formatting
        permalink = response_dict.get('permalink', {})
        scan_date = response_dict.get('scan_date', {})
        av_hits = str(response_dict.get('positives', {}))
        total = str(response_dict.get('total', {}))
        danger_rating = av_hits + '/' + total

        formatted_domain_report = {
            'permalink': permalink,
            'scan_date' : scan_date,
            'av_hits' : av_hits,
            'total_av_scans' : total,
            'danger_rating' : danger_rating
        } 

        return formatted_domain_report

# --------------TESTING--------------------------------
# D = Domain_Scanner_Model('coderwall.com/p/pstm1w/deploying-a-flask-app-at-heroku') 
# D.domain_scanner()
# D.domain_report_dictonary()
        
'''
 EXAMPLE RESPONSE:
        {  
    u'permalink':    u'https://www.virustotal.com/url/28bd492fffe55c34f11f862589d822224c167bec458607926738f74cb8f58c3d/analysis/1500013912/',
    u'resource':u'coderwall.com',
    u'url':    u'http://coderwall.com/',
    u'response_code':1,
    u'scan_date':    u'2017-07-14 06:31:52    ', u'    scan_id':u'28bd492fffe55c34f11f862589d822224c167bec458607926738f74cb8f58c3d-1500013912',
    u'verbose_msg':u'Scan finished,
    scan information embedded in this object',
    u'filescan_id':None,
    u'positives':1,
    u'total':66,
    u'scans':{  
        u'CLEAN MX':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'VX Vault':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'ZDB Zeus':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Tencent':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Netcraft':{  
            u'detected':False,
            u'result':u'unrated site'
        },
        u'PhishLabs':{  
            u'detected':False,
            u'result':u'unrated site'
        },
        u'Zerofox':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Sangfor':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'K7AntiVirus':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Virusdie External Site Scan':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Quttera':{  
            u'detected':True,
            u'result':u'malicious site'
        },
        u'AegisLab WebGuard':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'MalwareDomainList':{  
            u'detected':False,
            u'result':u'clean site',
            u'detail':            u'http://www.malwaredomainlist.com/mdl.php?search=coderwall.com'
        },
        u'ZeusTracker':{  
            u'detected':False,
            u'result':u'clean site',
            u'detail':            u'https://zeustracker.abuse.ch/monitor.php?host=coderwall.com'
        },
        u'zvelo':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Google Safebrowsing':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'ParetoLogic':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Kaspersky':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'BitDefender':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Dr.Web':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Certly':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'G-Data':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'C-SIRT':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'OpenPhish':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Websense ThreatSeeker':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'MalwarePatrol':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Webutation':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Trustwave':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Web Security Guard':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'desenmascara.me':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'ADMINUSLabs':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Malwarebytes hpHosts':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Opera':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'AlienVault':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Emsisoft':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Malc0de Database':{  
            u'detected':False,
            u'result':u'clean site',
            u'detail':            u'http://malc0de.com/database/index.php?search=coderwall.com'
        },
        u'malwares.com URL checker':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Phishtank':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Malwared':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Avira':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Baidu-International':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'CyberCrime':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Antiy-AVL':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'SCUMWARE.org':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'FraudSense':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Comodo Site Inspector':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Malekal':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'ESET':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Sophos':{  
            u'detected':False,
            u'result':u'unrated site'
        },
        u'Yandex Safebrowsing':{  
            u'detected':False,
            u'result':u'clean site',
            u'detail':            u'http:            //yandex.com/infected?l10n=en&url=http://coderwall.com/'
        },
        u'SecureBrain':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Nucleon':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Malware Domain Blocklist':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Blueliv':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'ZCloudsec':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'AutoShun':{  
            u'detected':False,
            u'result':u'unrated site'
        },
        u'ThreatHive':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'FraudScore':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Rising':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'URLQuery':{  
            u'detected':False,
            u'result':u'unrated site'
        },
        u'StopBadware':{  
            u'detected':False,
            u'result':u'unrated site'
        },
        u'Sucuri SiteCheck':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Fortinet':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'ZeroCERT':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'Spam404':{  
            u'detected':False,
            u'result':u'clean site'
        },
        u'securolytics':{  
            u'detected':False,
            u'result':u'clean site'
        }
    }
}
'''

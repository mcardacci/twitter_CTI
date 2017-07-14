import json, urllib, socket
from urlparse import urlparse

class IP_Scanner_Model(object):

    def __init__(self, domain):
        self.domain = domain

    def ipaddress(self):
    	parsed_uri = urlparse(self.domain)
    	domain = '{uri.netloc}'.format(uri=parsed_uri)
    	ip = socket.gethostbyname(domain)

    	return ip

    def get_vt_scan(self):
    	ip = self.ipaddress()
    	url = 'http://www.virustotal.com/vtapi/v2/ip-address/report'

    	parameters = {
    		'ip' : ip,
    		'apikey' : 'a4b128f4b05396d094ea6e08ddf37b895b05ccbe5d6f24389a197dfdd1f5aaa3'
    	}

    	#URL encoding, IP submission, and json response storage
    	response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
    	response_dict = json.loads(response)

    	downloaded_files = response_dict.get('detected_downloaded_samples', {})
    	country = response_dict.get('country', {})

    	# Only grabs the file hashes of files with 3 or more AV hits
    	dangerous_files = {}
    	for idx, file in enumerate(downloaded_files):
    		if file['positives'] > 2:
    			dangerous_files[idx+1] = {
    				'hash' : file.get('sha256', 'null'),
    				'av_ratio' : str(file.get('positives')) + '/' + str(file.get('total'))
    			}
    	
    	# Takes count of all AV hits makes an all encompasssing av_ratio
    	positive_results = 0
    	total_results = 0
    	for x in response_dict.get('detected_urls', {'positives' : 0, 'total' : 0}):
    		positive_results = positive_results + x.get('positives')
    		total_results = total_results + x.get('total')

    	av_detection_ratio = str(positive_results) + '/' + str(total_results) 

    	formatted_ip_report = {
    		'ip' : ip,
    		'dangerous_files': dangerous_files,
    		'country' : country,
    		'av_detection_ratio' : av_detection_ratio

    	}

    	return formatted_ip_report


# -------------TESTING-------------------------
ip_scanner = IP_Scanner_Model('http://nypost.com/2017/07/14/trump-sues-over-property-taxes-at-his-florida-golf-course/')
# ip_scanner.ipaddress()
ip_scanner.get_vt_scan()

'''
Example response
  file_list = [{u'date': u'2017-04-24 19:51:05', u'positives': 3, u'total': 56, u'sha256': u'b0b63b5d6bb9294c6e75a1dcdb6009c8dec446853597bd0967593e948a0740c5'}, {u'date': u'2016-05-18 16:51:04', u'positives': 1, u'total': 56, u'sha256': u'655f692518e6eebdaa4ee892b83de95434e3dd872f4d75250960c5c74dd4c43d'}, {u'date': u'2016-04-28 15:23:04', u'positives': 1, u'total': 54, u'sha256': u'4121b7b13eded12d65160f9d51d8aec2fb9fb1b20515f5511f5a46acba61a06b'}, {u'date': u'2016-02-01 16:42:05', u'positives': 1, u'total': 54, u'sha256': u'5af506d60609a2e98a50707e32aee78b9b20402e603b3f55d03c3f8bccb63492'}, {u'date': u'2015-02-26 02:51:38', u'positives': 1, u'total': 57, u'sha256': u'2c7edb79ed30d7af669637eaa3e9be91eb555705c72f539b5c5e1f0dc2dd0bbf'}, {u'date': u'2014-07-16 12:58:10', u'positives': 7, u'total': 52, u'sha256': u'63bc287aa7883539b5539e3f5bddf51b91644d3a08bab85668598a50bcce564c'}, {u'date': u'2014-05-08 05:54:02', u'positives': 2, u'total': 48, u'sha256': u'51f0eaee8dc0236f4c4b509dea54bdf773a0ca63650d6f1bd3b5ea0b41363cc8'}]
'''
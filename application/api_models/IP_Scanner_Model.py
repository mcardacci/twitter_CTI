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
# ip_scanner = IP_Scanner_Model('http://nypost.com/2017/07/14/trump-sues-over-property-taxes-at-his-florida-golf-course/')
# ip_scanner.ipaddress()
# ip_scanner.get_vt_scan()

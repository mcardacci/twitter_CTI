import json, urllib

ipaddress = '104.24.127.207'

url = 'http://www.virustotal.com/vtapi/v2/ip-address/report'
parameters = {
        'ip': ipaddress,
        'apikey': 'a4b128f4b05396d094ea6e08ddf37b895b05ccbe5d6f24389a197dfdd1f5aaa3'
        }

#URL encoding, IP submission, and json response storage
response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read() 
response_dict = json.loads(response)

print response_dict

# harvest import info from JSON resopnse
positiveResults = 0
totalResults = 0
try:
    for x in response_dict.get("detected_urls"):
        positiveResults = positiveResults + x.get("positives")
        totalResults = totalResults + x.get("total")
except TypeError: #if no results found program throws a TypeError
    print ("No results")

#convert results to string for output formatting 
positiveResults = str(positiveResults) 
totalResults = str(totalResults)

# print(positiveResults + '/' + totalResults + ' total AV detection ratio')


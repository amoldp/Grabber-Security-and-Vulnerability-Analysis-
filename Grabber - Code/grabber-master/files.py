#!/usr/bin/env python
"""
	File Inclusion Module for Grabber v0.1
	Copyright (C) 2006 - Romain Gaucher - http://rgaucher.info
"""
import sys
from grabber import getContent_POST, getContent_GET
from grabber import getContentDirectURL_GET, getContentDirectURL_POST
from grabber import single_urlencode
from report import appendToReport

severity = ["None", "Low", "Medium", "High"]

def detect_file(output, url_get = "http://localhost/?param=false"):
	listWords = {"root:x:0:0" : 3, "[boot loader]" : 1, "<title>Google</title>" : 3 ,"java.io.FileNotFoundException:" : 1,"fread()" : 1,"include_path" : 1,"Failed opening required" : 1,"file(\"" : 1 ,"file_get_contents(\"" : 1}
	if "404" in output or "403" in output:
		# it probabably report an http error
		return 0
	if "500" in output:
		return 1
	for wrd in listWords:
		if output.count(wrd) > 0:
			return listWords[wrd]
	return 0

def generateOutput(url, gParam, instance,method,type, severityNum = 1):
	astr = "<file>\n\t<severity>%s</severity>\n\t<method>%s</method>\n\t<url>%s</url>\n\t<parameter name='%s'>%s</parameter>\n\t<type name='Files Injection Type'>%s</type>"  % (severity[severityNum],method,url,gParam,str(instance),type)
	if method in ("get","GET"):
		# print the real URL
		p = (url+"?"+gParam+"="+single_urlencode(str(instance)))
		astr += "\n\t<result>%s</result>" % p
	astr += "\n</file>\n"
	return astr

def generateOutputLong(url, urlString ,method,type, severityNum, allParams = {}):
	astr = "<file>\n\t<severity>%s</severity>\n\t<method>%s</method>\n\t<url>%s</url>\n\t<type name='Files Injection Type'>%s</type>"  % (severity[severityNum], method,url,type)
	if method in ("get","GET"):
		# print the real URL
		p = (url+"?"+urlString)
		astr += "\n\t<result>%s</result>" % (p)
	else:
		astr += "\n\t<parameters>"
		for k in allParams:
			astr += "\n\t\t<parameter name='%s'>%s</parameter>" % (k, allParams[k])
		astr += "\n\t</parameters>"
	astr += "\n</file>\n"
	return astr

def generateHTMLOutput(url, urlString, method, type, instance, allParams={}):
	message = "<p class='well'><strong>"+ method +"</strong> <i>"+ url +"</i> <br/>"
	message += "Type: <strong>"+ type +  "</strong> <br/>"
	if method in ("GET", "get"):
		message += "Parameter: <strong>"+ urlString + "</strong><br/>  Value: <strong>"+ instance +  "</strong> <br/></p>"
	
	return message

def permutations(L):
	if len(L) == 1:
		yield [L[0]]
	elif len(L) >= 2:
		(a, b) = (L[0:1], L[1:])
		for p in permutations(b):
			for i in range(len(p)+1):
				yield b[:i] + a + b[i:]

def process(url, database, attack_list, txheaders):
	appendToReport(url, "<div class='panel panel-info'><div class='panel-heading'><h3 class='panel-title'> <a data-toggle='collapse' data-target='#collapseInclude' href='#collapseInclude'>File Injection Attacks </a></h3></div>")
	plop = open('results/files_GrabberAttacks.xml','w')
	plop.write("<filesAttacks>\n")
	appendToReport(url, '<div id="collapseInclude" class="panel-collapse collapse in"><div class="panel-body">');
	for u in database.keys():
		appendToReport(u, "<h4><div class='label label-default'><a target='_balnk' href='"+ u +"'>"+ u +"</a></div></h4>")
		if len(database[u]['GET']):
			print "Method = GET ", u
			for gParam in database[u]['GET']:
				for typeOfInjection in attack_list:
					for instance in attack_list[typeOfInjection]:
						handle = getContent_GET(u,gParam,instance, txheaders)
						if handle != None:
							output = handle.read()
							header = handle.info()
							k = detect_file(output)
							if k > 0:
								# generate the info...
								plop.write(generateOutput(u,gParam,instance,"GET",typeOfInjection, k))
								appendToReport(u, generateHTMLOutput(u, gParam, "GET", typeOfInjection, instance))
			# see the permutations
			if len(database[u]['GET'].keys()) > 1:
				for typeOfInjection in attack_list:
					for instance in attack_list[typeOfInjection]:
						url = ""
						for gParam in database[u]['GET']:
							url += ("%s=%s&" % (gParam, single_urlencode(str(instance))))
						handle = getContentDirectURL_GET(u,url, txheaders)
						if handle != None:
							output = handle.read()
							k = detect_file(output)
							if k > 0:
								# generate the info...
								plop.write(generateOutputLong(u,url,"GET",typeOfInjection,k))
								appendToReport(u, generateHTMLOutput(u, url, "GET", typeOfInjection, instance))
		if len(database[u]['POST']):
			print "Method = POST ", u
			for gParam in database[u]['POST']:
				for typeOfInjection in attack_list:
					for instance in attack_list[typeOfInjection]:
						handle = getContent_POST(u,gParam,instance, txheaders)
						if handle != None:
							output = handle.read()
							header = handle.info()
							k = detect_file(output)
							if k > 0:
								# generate the info...
								plop.write(generateOutput(u,gParam,instance,"POST",typeOfInjection,k))
								appendToReport(u, generateHTMLOutput(u, gParam, "POST", typeOfInjection, instance))
			# see the permutations
			if len(database[u]['POST'].keys()) > 1:
				for typeOfInjection in attack_list:
					for instance in attack_list[typeOfInjection]:
						allParams = {}
						for gParam in database[u]['POST']:
							allParams[gParam] = str(instance)
						handle = getContentDirectURL_POST(u,allParams, txheaders)
						if handle != None:
							output = handle.read()
							k = detect_file(output)
							if k > 0:
								# generate the info...
								plop.write(generateOutputLong(u,url,"POST",typeOfInjection,k,allParams))
								appendToReport(u ,generateHTMLOutput(u, url, "POST", typeOfInjection, instance, allparams))
	plop.write("\n</filesAttacks>")
	appendToReport(url, "</div></div>");
	plop.close()
	return ""

#!/usr/bin/env python
"""
	Cross-Site Scripting Module for Grabber v0.1
	Copyright (C) 2006 - Romain Gaucher - http://rgaucher.info
"""
import sys
from grabber import getContent_POST, getContent_GET
from grabber import getContentDirectURL_GET, getContentDirectURL_POST

from grabber import single_urlencode, partially_in, unescape, escape
from report import appendToReport

def detect_xss(instance, output):
	if unescape(instance) in output:
		return True
	return False

def generateOutput(url, gParam, instance,method,type):
	astr = "<xss>\n\t<method>%s</method>\n\t<url>%s</url>\n\t<parameter name='%s'>%s</parameter>\n\t<type name='XSS Injection Type'>%s</type>"  % (method,url,gParam,str(instance),type)
	if method in ("get","GET"):
		# print the real URL
		p = (url+"?"+gParam+"="+single_urlencode(str(instance)))
		astr += "\n\t<result>%s</result>" % p
	astr += "\n</xss>\n"
	return astr

def generateOutputLong(url, urlString ,method,type, allParams = {}):
	astr = "<xss>\n\t<method>%s</method>\n\t<url>%s</url>\n\t<type name='XSS Injection Type'>%s</type>"  % (method,url,type)
	if method in ("get","GET"):
		# print the real URL
		p = (url+"?"+urlString)
		astr += "\n\t<result>%s</result>" % (p)
	else:
		astr += "\n\t<parameters>"
		for k in allParams:
			astr += "\n\t\t<parameter name='%s'>%s</parameter>" % (k, allParams[k])
		astr += "\n\t</parameters>"
	astr += "\n</xss>\n"
	return astr

def generateHTMLOutput(url, gParam, instance, method, typeofInjection):
	message = "<p class='well'><strong>"+ method +"</strong> "+ url +" <br/>"
	message += "Type: <strong>"+ typeofInjection +  "</strong> <br/>"
	message += "Parameter: <strong>"+ gParam + "</strong><br/>  Value: <strong>"+ escape(instance) +  "</strong> <br/></p>"
	# message += "Parameters"+ gParam +"<br/><br/>";
	return message

def permutations(L):
	if len(L) == 1:
		yield [L[0]]
	elif len(L) >= 2:
		(a, b) = (L[0:1], L[1:])
		for p in permutations(b):
			for i in range(len(p)+1):
				yield b[:i] + a + b[i:]

def process(urlGlobal, database, attack_list ,txheaders):
	appendToReport(urlGlobal, "<div class='panel panel-info'><div class='panel-heading'><h3 class='panel-title'> <a data-toggle='collapse' data-target='#collapseXss' href='#collapseXss'>XSS Attacks </a></h3></div>")
	plop = open('results/xss_GrabberAttacks.xml','w')
	plop.write("<xssAttacks>\n")
	appendToReport(urlGlobal, '<div id="collapseXss" class="panel-collapse collapse in"><div class="panel-body">')

	for u in database.keys():
		appendToReport(u, "<h4><div class='label label-default'><a target='_balnk' href='"+ u +"'>"+ u +"</a></div></h4>")
		if len(database[u]['GET']):
			print "Method = GET ", u
			for gParam in database[u]['GET']:
				for typeOfInjection in attack_list:
					for instance in attack_list[typeOfInjection]:
						if instance != "See Below":
							handle = getContent_GET(u,gParam,instance, txheaders)
							if handle != None:
								output = handle.read()
								header = handle.info()
								if detect_xss(str(instance),output):
									# generate the info...
									plop.write(generateOutput(u,gParam,instance,"GET",typeOfInjection))
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
							if detect_xss(str(instance),output):
								# generate the info...
								plop.write(generateOutputLong(u,url,"GET",typeOfInjection))
		if len(database[u]['POST']):
			print "Method = POST ", u
			for gParam in database[u]['POST']:
				if gParam != "None":
					for typeOfInjection in attack_list:
						for instance in attack_list[typeOfInjection]:
							allParams = {}
							for param in database[u]['POST']:
								if param != gParam:
									allParams[param] = 'abc'
							allParams[gParam] = str(instance)
							if instance != "See Below":
								handle = getContentDirectURL_POST(u,allParams, txheaders)
								if handle != None:
									output = handle.read()
									header = handle.info()
									if detect_xss(str(instance),output):
										# generate the info...
										plop.write(generateOutput(u,gParam,instance,"POST",typeOfInjection))
										appendToReport(u, generateHTMLOutput(u, gParam, instance, "POST", typeOfInjection))
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
							if detect_xss(str(instance), output):
								# generate the info...
								plop.write(generateOutputLong(u,gParam,"POST",typeOfInjection, allParams))
								appendToReport(u, generateHTMLOutput(u, "ALL", instance, "POST", typeOfInjection))
	plop.write("\n</xssAttacks>\n")	
	plop.close()
	appendToReport(urlGlobal, "</div></div>")
	return ""
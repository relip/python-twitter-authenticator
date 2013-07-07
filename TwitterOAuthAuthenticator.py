#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import sys
import time
import random
import urllib
import urllib2
import hmac
import binascii 
import re 
import getpass 

from base64 import b64encode
from hashlib import md5, sha1

from optparse import OptionParser

def escape(s):
	"""Escape a URL including any ~."""
	return urllib.quote(s, safe='~')

class TwitterOAuthAuthenticator:
	def __init__(self, c_k, c_s, id, pw):
		self.ConsumerKey	= c_k
		self.ConsumerSecret	= c_s
		self.ID 		= id
		self.PW			= pw
		self.OAuthVersion	= "1.0"
		self.OAuthSignMethod	= "HMAC-SHA1"
		
	def GenerateOAuthNonce(self):
		random_number = ''.join(str(random.randint(0, 9)) for i in range(40))
		m = md5(str(time.time()) + str(random_number))
		return m.hexdigest()

	def GenerateOAuthSignature(self, url, method, parameters, data, secret, token=""):
		param_keys = parameters.keys()
		param_keys.sort()

		k = secret+"&"
		#print "Key: " + k
		if token: k += token

		v = method+"&" 
		v += escape(url)+"&"

		for i in param_keys:
			v += escape("%s=%s&"%("oauth_"+i, parameters[i]))

		v = v[:-3]
		#print "Value: " + v
		
		if data: v += escape(data)
		
		hashed = hmac.new(k, v, sha1)

		return escape(binascii.b2a_base64(hashed.digest())[:-1])

	def createOAuthHeader(self, header):
		hdr = ""
		for x in header:
			if hdr == "":
				hdr += "OAuth %s=\"%s\""%("oauth_"+x, header[x])
			else: 
				hdr += ", %s=\"%s\""%("oauth_"+x, header[x])

		return hdr

	def sendRequest(self, url, method="GET", header={}, data=None):
		if method == "POST" and data == None:
			Req = urllib2.Request(url, {})

		elif data:
			Req = urllib2.Request(url, data)

		else: Req = urllib2.Request(url)

		for x in header:
			Req.add_header(x, header[x])

		Result = urllib2.urlopen(Req)

		return Result

		
	def GetReqToken(self):
		url = "https://api.twitter.com/oauth/request_token"
		callback = "oob"
		nonce = self.GenerateOAuthNonce()
		timestamp = str(int(time.time()))

		parameters = {
			"callback": escape(callback),
			"consumer_key": self.ConsumerKey,
			"nonce": nonce,
			"signature_method": self.OAuthSignMethod,
			"timestamp": timestamp,
			"version": self.OAuthVersion,
		}

		signature = self.GenerateOAuthSignature(url, "POST", parameters, {}, self.ConsumerSecret)

		parameters.update({'signature': signature})

		Req = self.sendRequest(url, "POST", {"Authorization": self.createOAuthHeader(parameters)})

		try:
			for x in Req.read().split("&"):
				k, v = x.split("=", 1)
				# FIXME
				if k == "oauth_token":	
					if opt.VERBOSE: print("Debug: oauth_token: %s"%(v))
					OAuthToken = v
				elif k == "oauth_token_secret":
					if opt.VERBOSE: print("Debug: oauth_token_secret: %s"%(v))
					OAuthTokenSecret = v
				else: #.. 
					pass

			return OAuthToken, OAuthTokenSecret

		except:
			print Req.msg
			#raise RequestTokenError
			


	def GetAccToken(self, OAuthToken, PIN):
		url = "https://api.twitter.com/oauth/access_token"
		nonce = self.GenerateOAuthNonce()
		timestamp = str(int(time.time()))

		parameters = {
			"consumer_key": self.ConsumerKey,
			"nonce": nonce,
			"signature_method": self.OAuthSignMethod,
			"timestamp": timestamp,
			"token": OAuthToken,
			"version": self.OAuthVersion
		}

		data = "oauth_verifier="+PIN
		
		signature = self.GenerateOAuthSignature(url, "POST", parameters, data, self.ConsumerSecret)
		parameters.update({'signature': signature})
	
		Req = self.sendRequest(url, "POST", {"Authorization": self.createOAuthHeader(parameters)}, data)

		try:
			Res = Req.read()
			t = {}
			map(lambda x: t.update({x.split("=", 1)[0]: x.split("=", 1)[1]}), Res.split("&"))
			return t
		
		except:
			# ? 
			print "Oops"	
		
	def Authorize(self, OAuthToken):
		url = "https://api.twitter.com/oauth/authorize?oauth_token=%s"%(OAuthToken)
		authResult = self.sendRequest(url).read()

		authenticity_token = re.search('name="authenticity_token" type="hidden" value="(\S+)"', authResult, re.M).group(1)
		
		url = "https://api.twitter.com/oauth/authorize?"
		url += "oauth_token=%s&session%%5Busername_or_email%%5D=%s"%(OAuthToken, self.ID)
		url += "&session%%5Bpassword%%5D=%s"%(escape(self.PW))

		try:
			PINResult = self.sendRequest(url, "POST", {}).read()

			PIN = re.search('<code>(\S+)</code>', PINResult, re.M).group(1)

			if opt.SKIP_PIN: 
				return PIN
			else:
				while True:
					p = raw_input('Enter this PIN -> %s: '%(PIN))
					if p == PIN:
						break
				
				return PIN

		except:
			#raise WrongIDorPassword
			print "Wrong username or password"


	def run(self):
		OAuthToken, OAuthTokenSecret = self.GetReqToken()
		PIN = self.Authorize(OAuthToken)
		return self.GetAccToken(OAuthToken, PIN)
		

def optional_arg(arg_default):
	def func(option,opt_str,value,parser):
		if parser.rargs and not parser.rargs[0].startswith('-'):
			val=parser.rargs[0]
			parser.rargs.pop(0)
		else:
			val=arg_default
		setattr(parser.values,option.dest,val)
	return func


if __name__ == "__main__":
	parser = OptionParser("usage: %prog [-v] [--skip-pin] -u [USERNAME] -p [PASSWORD] -k [CONSUMER_KEY] -s [CONSUMER_SECRET]")
	parser.add_option("-v", "--verbose", action="store_true", dest="VERBOSE", help="explain what is being done", default=False)
	parser.add_option("--skip-pin", action="store_true", dest="SKIP_PIN", default=False)
	parser.add_option("-u", "--username", action="callback", dest="USERID", callback=optional_arg(None))
	parser.add_option("-p", "--password", action="callback", dest="PASSWORD", callback=optional_arg(None))
	parser.add_option("-k", "--consumer-key", action="callback", dest="CONSUMERKEY", callback=optional_arg(None))
	parser.add_option("-s", "--consumer-secret", action="callback", dest="CONSUMERSECRET", callback=optional_arg(None))

	(opt, args) = parser.parse_args()

	if not opt.USERID:
		opt.USERID = raw_input('Username or Email: ')

	if not opt.PASSWORD:
		opt.PASSWORD = getpass.getpass()

	if not opt.CONSUMERKEY:
		opt.CONSUMERKEY = raw_input('Consumer key: ')

	if not opt.CONSUMERSECRET:
		opt.CONSUMERSECRET = raw_input('Consumer secret: ')

	TOA = TwitterOAuthAuthenticator(opt.CONSUMERKEY, opt.CONSUMERSECRET, opt.USERID, opt.PASSWORD)

	result = TOA.run()	
	
	print "="*50
	print "oauth_token:", result['oauth_token']
	print "oauth_token_secret:", result['oauth_token_secret']
	print "user_id:",  result["user_id"]
	print "screen_name:", result["screen_name"]

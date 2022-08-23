from burp import IBurpExtender
from burp import IHttpListener
from burp import ISessionHandlingAction
  
import re
import ssl
import urllib2
import base64
import hmac
import hashlib
import json
import sys
import time


print("Loading OAuth Fetcher")
print("https://github.com/intrudir/OAuth-Fetcher")
print("Based on this old tool: https://github.com/t3hbb/OAuthRenew")
print("")
print("Checks for an expired Bearer token and replaces it.")
print("Remember to update any neccessary details in the extension!\n")

# Regex to find the token in the response
AccessTokenRegex = re.compile(r"access_token\"\:\"(.*?)\"")

# Regex to identify if bearer token expired
BearerErrorRegex = re.compile(r"Unauthorized")

###### Change me
CLIENT_ID = ""
CLIENT_SECRET = ""
BASE_URL = "https://some_site.com"
ENDPOINT = 'identity/oauth2/access_token'
REALM = ""
SCOPE = ""
######

AUTH_URL = "{}/{}?realm={}".format(BASE_URL, ENDPOINT, REALM)


def hmac_sha256(key, msg, encode_output=False):
	message = bytes(msg.encode('utf-8'))
	secret = bytes(key.encode('utf-8'))

	signature = hmac.new(secret, message, digestmod=hashlib.sha256).digest()

	return base64.b64encode(signature) if encode_output else signature


def get_client_assertion():
	"""
	Returns a JWT for the given client credentials
	"""

	jwt_header = json.dumps(
		{
			"typ": "JWT",
			"alg": "HS256",
		}
	)

	issue_time = int(time.time())  # Seconds since epoch
	expiry_time = issue_time + 600

	jwt_body = {
		"iss": CLIENT_ID,
		"sub": CLIENT_ID,
		"aud": AUTH_URL,
		"exp": expiry_time,
		"iat": issue_time,
	}

	jwt_header = base64.b64encode(jwt_header)
	jwt_body = json.dumps(jwt_body)
	jwt_body = base64.b64encode(jwt_body)

	jwt_signing_string = jwt_header + '.' + jwt_body
	signature = hmac_sha256(CLIENT_SECRET, jwt_signing_string)
	jwt_signature = base64.b64encode(signature)
	CLIENT_ASSERTION = jwt_signing_string + '.' + jwt_signature

	return CLIENT_ASSERTION


class BurpExtender(IBurpExtender, IHttpListener, ISessionHandlingAction):
	# Variables to hold the tokens found so that it can be inserted in the next request
	discoveredBearerToken = ''

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		callbacks.setExtensionName("OAuth Fetcher")
		callbacks.registerHttpListener(self)
		sys.stdout = callbacks.getStdout()
		sys.stderr = callbacks.getStderr()
		print("Extension loaded successfully.")
		return

  
	def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
		# Operate on your specified Burp tool
		if self._callbacks.getToolName(toolFlag) == "Repeater":
			if messageIsRequest:
				# Check to see if a replacement bearer token exists
				if BurpExtender.discoveredBearerToken:
					self.processRequest(currentMessage)
			else:
				self.processResponse(currentMessage)
			

	def processRequest(self, currentMessage):
		request = currentMessage.getRequest()
		requestInfo = self._helpers.analyzeRequest(request)
		headers = requestInfo.getHeaders()
		requestBody = self._helpers.bytesToString(request[requestInfo.getBodyOffset():])
		
		# headers is an array list
		# Convert to single string to process (sorry!)
		headerStr=""
		for x in range(len(headers)): 
			headerStr = headerStr + headers[x] +"\n"
		reqBody = currentMessage.getRequest()[requestInfo.getBodyOffset():]
		reqBody = self._helpers.bytesToString(request)
		
		updatedheaders = headerStr
		
		# Update Bearer token
		print("Replacing Bearer Token with latest obtained: {}".format(BurpExtender.discoveredBearerToken))
		updatedheaders = re.sub(r"Authorization\: .*", "Authorization: Bearer {0}".format(BurpExtender.discoveredBearerToken), headerStr)
		
		#convert headers back into a list
		headerslist = updatedheaders.splitlines()
		updatedRequest = self._helpers.buildHttpMessage(headerslist, requestBody)
		currentMessage.setRequest(updatedRequest)


	def processResponse(self, currentMessage):
		print("Response received")
		response = currentMessage.getResponse()
		parsedResponse = self._helpers.analyzeResponse(response)
		respBody = self._helpers.bytesToString(response[parsedResponse.getBodyOffset():])
		
		# Search the response for the error message indicating the token has expired
		token_expired = BearerErrorRegex.search(respBody)
		
		if token_expired is None:
			print("Bearer token is valid")
		else:
			print("Bearer token expired - obtaining new one")
			self.BearerRefresh()


	def BearerRefresh(self):
		print("Authing App - {}".format(AUTH_URL))
		req = urllib2.Request(AUTH_URL)
		req.add_header('User-Agent','Mozilla/5.0') # (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0')
		
		CLIENT_ASSERTION = get_client_assertion()
		# data = "grant_type=client_credentials&client_id={}&client_secret={}&scope={}&audience={}".format(CLIENT_ID, CLIENT_SECRET, SCOPE, AUDIENCE)
		data = "grant_type=client_credentials&scope={}&realm={}&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}".format(SCOPE, REALM, CLIENT_ASSERTION)
		req.add_data(data)

		token, wait, retries = "", 20, 0
		while not token:
			try:
				if retries > 3:
					break
				resp = urllib2.urlopen(req) #, context=ssl._create_unverified_context())
				content = resp.read()
				token = AccessTokenRegex.search(content)
			
			except Exception as e:
				print("Error: {}".format(e))
			
			print("Retrying in {} secs...".format(wait))
			time.sleep(wait)
			retries += 1

		# store the new access token
		if token is None:
			print("***Error aquiring token. Check your client credentials.***")
			return
		else:
			print("Token updated!")
			
		BurpExtender.discoveredBearerToken=token.group(1)
		
		

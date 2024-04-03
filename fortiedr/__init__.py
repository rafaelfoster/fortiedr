from fortiedr.fortiedr import *

debug = None
ssl_enabled = True

organization = None

def disable_ssl():
	global ssl_enabled
	ssl_enabled = False
	print("[!] - We strongly advise you to enable SSL validations. Use this at your own risk!")

def enable_debug():
	global debug
	debug = True

def set_organization(orgname):
	global organization
	organization = orgname

def auth( host: str, user: str, passw: str, org: str = None):
	global debug
	global fortiedr_connection
	login = fedrAuth()
	
	if org:
		set_organization(org)

	headers, host = login.get_headers(
		fedr_host=host,
		fedr_user=user,
		fedr_pass=passw,
		fedr_org=org
	)


	if headers is None:
		status = False
		data = host
	else:
		status = True
		data = 'AUTHENTICATION_SUCCEEDED'

	fortiedr_connection = FortiEDR_API_GW()
	authentication = fortiedr_connection.conn(headers, host, debug, ssl_enabled, organization)
	return {
		'status': status,
		'data': data
	}
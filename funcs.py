from hashlib import md5, sha256
from sql import *
from flask import session, request
import re

SALT = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
PEPPER = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

def Hash(val):
	a = md5(val.encode()).hexdigest() + SALT
	return sha256(a.encode()).hexdigest() 

def Hash2(Val):
	a = Val + PEPPER
	return sha256(a.encode()).hexdigest()

def Hash3(Val):
	return md5(Hash(Val).encode()).hexdigest()

def MD5(Val):
	return md5(Val.encode()).hexdigest()

def check_admin_login(username, password):
	res = conn.runQuery("SELECT username FROM admins WHERE username = %s AND password = %s", (username, Hash(password)))
	if len(res) == 1:
		session['login'] = 1
		session['username'] = res[0]['username']
		return True
	return False

def create_token(extra, Val):
	return md5(str(Hash3(str(Val))+extra).encode()).hexdigest()

def check_token(extra, Val, token):
	return create_token(extra, str(Val)) == token

def get_user_name():
	res = conn.runQuery("SELECT username FROM admins WHERE username = %s", (session['username']))
	if len(res) != 1:
		return "-----"
	return res[0]['username']

def check_ip(eveid):
	ips = conn.runQuery("SELECT ips FROM ips_table WHERE active = 1 AND eveid = %s", (eveid))
	user_ip = request.remote_addr.replace('.', '-')
	ips = [X['ips'].replace('.', '-').replace('*', '[0-9]{1,3}') for X in ips]
	for ip in ips:
		l = re.findall(ip, user_ip)
		if len(l) == 1 and l[0] == user_ip:
			return True
	return False

def str_xor(S, S1, S2):
	ret = ""
	for i in range(len(S)):
		oo = ord(S[i]) ^ ord(S1[i%len(S1)]) ^ ord(S2[i%len(S2)])
		ret += chr(oo)
	return ret

def XOR(s1, s2): return ''.join(chr(ord(s1[i])^ord(s2[i%len(s2)])) for i in range(len(s1)))

def CorruptedJARS(teamid, answers, ans, iid):
	Id = teamid[4:]
	x = XOR(answers, teamid)
	opt = XOR(x, Id).upper()
	string = ''
	for i in range(len(ans)):
		if opt[i] == '*':
			string += '-'
		elif opt[i] == ans[i]:
			string += '1'
		else:
			string += '0'
	print("UPDATE event_marks SET answers = '%s', marks = '%s' WHERE id = %s"%(opt, string, iid))
	
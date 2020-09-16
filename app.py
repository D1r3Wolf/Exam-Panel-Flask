import os, re, shutil, time
from flask import *
from flask_bootstrap import Bootstrap
from flask_mynav import *
from forms import *
from sql import *
from funcs import *
import codecs
from datetime import datetime

app = Flask(__name__)
app.debug = 1
app.config['SECRET_KEY'] = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
nav.init_app(app)

@app.before_request
def before_request_hook():
	Parts = request.path.split("/")[1:] ; head = Parts[0]
	if head == 'edmin':
		ips = open("/home/sdcac/admin_ips.txt").read().split()
		print(ips, request.remote_addr)
		if request.remote_addr not in ips:
			return redirect("/")
		if 'login' not in session or session['login'] != 1 or 'username' not in session:
			return redirect(url_for('adminLogin'))

@app.route('/')
def home():
	return render_template('index.html')

@app.route('/edmin')
def adminHome():
	if 'login' not in session or session['login'] != 1:
		return redirect(url_for('home'))
	return redirect(url_for('listEvents_admin'))

@app.route('/utilll/login', methods = ['GET', 'POST'])
def adminLogin():
	lForm = LoginForm()
	if request.method == 'POST' and lForm.validate_on_submit():
		User = lForm.username.data ; Pass = lForm.password.data
		if not check_admin_login(User, Pass):
			flash("Wrong Username or password!", category="danger")
		else:
			session['login'] = 1
			flash("Logged in successfully", category="success")
			return redirect(url_for('listEvents_admin'))
		return redirect(url_for("adminLogin"))
	return render_template("admin_login.html", form=lForm)

@app.route('/edmin/logout')
def logout():
	session.clear()
	return redirect(url_for('adminLogin'))

@app.route('/edmin/event/add', methods = ['GET', 'POST'])
def AddEvent_admin():
	addEvent = AddEventForm()
	if request.method == 'POST' and addEvent.validate_on_submit():
		name = addEvent.eventname.data
		tmp = conn.runQuery("SELECT count(id) X FROM events WHERE event_name = %s", (name))
		if len(tmp) != 1 or tmp[0]['X'] != 0:
			flash('Another event with same name already exists!', category = 'danger')
			return render_template('add_event.html', form = addEvent)
		route = addEvent.eventroute.data
		tmp = conn.runQuery("SELECT count(id) X FROM events WHERE event_route = %s", (route))
		if len(tmp) != 1 or tmp[0]['X'] != 0:
			flash('Another event with same route already exists!', category = 'danger')
			return render_template('add_event.html', form = addEvent)
		conn.runQuery("INSERT INTO events(event_name, event_route, allow_access) VALUES(%s, %s, 0)", (name, route))
		flash('Event added successfully', category = 'success')
		return redirect(url_for('listEvents_admin'))
	return render_template('add_event.html', form = addEvent)

@app.route('/edmin/event/<num>/visible/enable', methods = ['POST'])
def MakeXamOpen(num):
	Token = request.form.get('token')
	if num == None or Token == None or not check_token("active_xam_56464", num, Token):
		return abort(404)
	x = conn.runQuery("UPDATE events SET allow_access = 1 WHERE id = %s", (num))
	return "OK"

@app.route('/edmin/event/<num>/visible/disable', methods = ['POST'])
def MakeXamClose(num):
	Token = request.form.get('token')
	if num == None or Token == None or not check_token("remove_xam_64736", num, Token):
		return abort(404)
	x = conn.runQuery("UPDATE events SET allow_access = 0 WHERE id = %s", (num))
	return "OK"

@app.route('/edmin/event/list')
def listEvents_admin():
	res = conn.runQuery("SELECT id 'ID', event_name 'Event Name', event_route 'Event Route', allow_access 'Allow Access' FROM events")
	listEmpty = not bool(res)
	dataHead = list(res[0]) if not listEmpty else []
	dataHead += ['View Event', 'Upload Files', 'Passwords', 'TST Setup', 'Allowed IPs', 'Team View', 'Results']
	content = [[D[x] for x in D] for i, D in enumerate(res)]
	visible_tokens = []
	for D in res: 
		if D['Allow Access'] == 0: x = create_token('active_xam_56464', D['ID'])
		elif D['Allow Access'] == 1: x = create_token('remove_xam_64736', D['ID'])
		else: x = ''
		visible_tokens.append(x)
	view_tokens = [D['Event Route'] for D in res]
	upload_files_tokens = [create_token('upload_files_tokens', D['ID']) for D in res]
	passwd_tokens = [create_token('passwd_tokens', D['ID']) for D in res]
	allowed_ip_tokens = [create_token('allowed_ip_tokens', D['ID']) for D in res]
	tst_setup_tokens = [create_token('tst_setup_tokens_1244', D['ID']) for D in res]
	team_tokens = [create_token('allowed_team_tokens', D['ID']) for D in res]
	return render_template('list_xam_events.html', listEmpty = listEmpty, dataHead = dataHead, content_tokens = zip(content, visible_tokens, view_tokens, upload_files_tokens, passwd_tokens, tst_setup_tokens, allowed_ip_tokens, team_tokens))

@app.route('/edmin/event/<eveid>/results')
def results_admin(eveid):
	res = conn.runQuery("SELECT em.id 'ID', em.team_id 'Team ID', em.answers 'Answers', em.ip 'Submission IP', em.time 'Submission time', em.marks 'Marks' FROM event_marks em WHERE em.answers != '' AND em.eveid = %s", (eveid))
	event_name = conn.runQuery("SELECT event_name FROM events WHERE id = %s", (eveid))[0]['event_name']
	listEmpty = not bool(res)
	if listEmpty:
		flash('No TST uploads & results yet!', category = 'danger')
		return redirect(url_for('listEvents_admin'))
	dataHead = list(res[0])[:-1] if not listEmpty else []
	dataHead.insert(2, 'Unattempted') 
	dataHead.insert(2, 'Wrong')
	dataHead.insert(2, 'Correct')
	dataHead += ['Q%s'%(i+1) for i in range(len(res[0]['Marks']))]
	content = [[D[x] for x in D] for D in res]
	content = []
	for D in res:
		ll = []
		for x in D:
			if x == 'Marks':
				continue
			elif x == 'Submission time':
				ll.append(datetime.fromtimestamp(D[x]).strftime("%c"))
			else:
				ll.append(D[x])
		ll.insert(2, D['Marks'].count('-'))
		ll.insert(2, D['Marks'].count('0'))
		ll.insert(2, D['Marks'].count('1'))
		for x in D['Marks']:
			ll.append(x)
		content.append(ll)
	return render_template('result.html', listEmpty = listEmpty, dataHead = dataHead, content_tokens = content, event_name = event_name)

@app.route('/edmin/event/<eveid>/tst_setup', methods = ['GET', 'POST'])
def TSTSetup_admin(eveid):
	form = TSTSetupForm()
	res = conn.runQuery("SELECT id, sub_name, jar_pass, hash, active, answers FROM tst_setup WHERE eveid = %s", (eveid))
	jars = [[x['id'], x['sub_name'], x['answers'], x['jar_pass'], x['active']] for x in res]
	for x in range(len(jars)):
		bb = jars[x][-1]
		if bb == 1: jars[x].append(create_token('hide_jar_upload_token_1234', jars[x][0]))
		else: jars[x].append(create_token('show_jar_upload_token_1234', jars[x][0]))
	if request.method == 'POST' and form.validate_on_submit():
		sub_name = form.subname.data
		answers = form.answers.data
		passwd = form.passwd.data
		hashh = Hash(str(time.time()))
		conn.runQuery("INSERT INTO tst_setup(eveid, jar_pass, hash, sub_name, active, answers) VALUES(%s, %s, %s, %s, 0, %s)", (eveid, passwd, hashh, sub_name, answers))
		flash('TST Form created successfully!', category = 'success')
		return redirect(url_for('TSTSetup_admin', eveid = eveid))
	return render_template('TST_setup.html', form = form, content = jars, eventid = eveid)

@app.route('/edmin/event/edit/tst_setup/<Id>/activate', methods = ['POST'])
def MakeTSTFormsVisible(Id):
	Token = request.form.get('token')
	if Token is None or not check_token('show_jar_upload_token_1234', Id, Token):
		return abort(404)
	conn.runQuery("UPDATE tst_setup SET active = 1 WHERE id = %s", (Id))
	return "OK"

@app.route('/edmin/event/edit/tst_setup/<Id>/deactivate', methods = ['POST'])
def MakeTSTFormsInvisible(Id):
	Token = request.form.get('token')
	if Token is None or not check_token('hide_jar_upload_token_1234', Id, Token):
		return abort(404)
	conn.runQuery("UPDATE tst_setup SET active = 0 WHERE id = %s", (Id))
	return "OK"

@app.route('/edmin/event/<eveid>/edit/up_files', methods = ['GET', 'POST'])
def UploadFiles_admin(eveid):
	token = request.args.get('token')
	if not eveid or not token or not check_token('upload_files_tokens', eveid, token):
		return abort(404)
	form = SetUploadFilesForms()
	res = conn.runQuery("SELECT id, file_name, active FROM up_files_table WHERE eveid = %s", (eveid))
	file_name = [[x['id'], x['file_name'], x['active']] for x in res]
	for x in range(len(file_name)):
		bb = file_name[x][2]
		if bb == 1: file_name[x].append(create_token('hide_up_files_token_1234', file_name[x][0]))
		else: file_name[x].append(create_token('show_up_files_token_1234', file_name[x][0]))
	if request.method == 'POST' and form.validate_on_submit():
		file_name = secure_filename(form.file_name.data)
		file_path = Hash(file_name + str(time.time()))
		if not os.path.exists('serving_files/'):
			os.mkdir('serving_files/')
		form.file.data.save('serving_files/' + file_path)
		conn.runQuery("INSERT INTO up_files_table(eveid, file_name, file_path, active) VALUES(%s, %s, %s, 0)", (eveid, file_name, file_path))
		flash('File added successfully', category = 'success')
		return redirect(url_for('UploadFiles_admin', eveid = eveid, token = token))
	return render_template('uploaded_files.html', form = form, content = file_name, eventid = eveid)

@app.route('/edmin/event/edit/up_files/<file_name>/activate', methods = ['POST'])
def MakeUpFilesVisible(file_name):
	Token = request.form.get('token')
	if Token is None or not check_token('show_up_files_token_1234', file_name, Token):
		return abort(404)
	conn.runQuery("UPDATE up_files_table SET active = 1 WHERE id = %s", (file_name))
	return "OK"

@app.route('/edmin/event/edit/up_files/<file_name>/deactivate', methods = ['POST'])
def MakeUpFilesInvisible(file_name):
	Token = request.form.get('token')
	if Token is None or not check_token('hide_up_files_token_1234', file_name, Token):
		return abort(404)
	conn.runQuery("UPDATE up_files_table SET active = 0 WHERE id = %s", (file_name))
	return "OK"

@app.route('/edmin/event/<eveid>/edit/passwd', methods = ['GET', 'POST'])
def Password_admin(eveid):
	token = request.args.get('token')
	if not eveid or not token or not check_token('passwd_tokens', eveid, token):
		return abort(404)
	form = SetPasswdsNames()
	res = conn.runQuery("SELECT id, title,passwd, active FROM passwd_table WHERE eveid = %s", (eveid))
	passwd = [[x['id'], x['title'], x['passwd'], x['active']] for x in res]
	for x in range(len(passwd)):
		bb = passwd[x][-1]
		if bb == 1: passwd[x].append(create_token('hide_passwd_token_1234', passwd[x][0] ))
		else: passwd[x].append(create_token('show_passwd_token_1234', passwd[x][0] ))
	if request.method == 'POST' and form.validate_on_submit():
		passwd = form.passwd.data
		title = form.title.data
		conn.runQuery("INSERT INTO passwd_table(eveid, title, passwd, active) VALUES(%s, %s, %s, 0)", (eveid, title, passwd))
		flash('Password added successfully', category = 'success')
		return redirect(url_for('Password_admin', eveid = eveid, token = token))
	return render_template('passwds.html', form = form, content = passwd, eventid = eveid)

@app.route('/edmin/event/edit/passwd/<password>/activate', methods = ['POST'])
def MakePasswdVisible(password):
	Token = request.form.get('token')
	if Token is None or not check_token('show_passwd_token_1234', password, Token):
		return abort(404)
	conn.runQuery("UPDATE passwd_table SET active = 1 WHERE id = %s", (password))
	return "OK"

@app.route('/edmin/event/edit/passwd/<password>/deactivate', methods = ['POST'])
def MakePasswdInvisible(password):
	Token = request.form.get('token')
	if Token is None or not check_token('hide_passwd_token_1234', password, Token):
		return abort(404)
	conn.runQuery("UPDATE passwd_table SET active = 0 WHERE id = %s", (password))
	return "OK"

@app.route('/edmin/event/<eveid>/edit/ips', methods = ['GET', 'POST'])
def SetAllowedIPs_admin(eveid):
	token = request.args.get('token')
	if not eveid or not token or not check_token('allowed_ip_tokens', eveid, token):
		return abort(404)
	form = SetIPsForm()
	res = conn.runQuery("SELECT id, ips, active FROM ips_table WHERE eveid = %s", (eveid))
	ips = [[x['id'], x['ips'], x['active']] for x in res]
	for x in range(len(ips)):
		bb = ips[x][2]
		if bb == 1: ips[x].append(create_token('hide_ip_token_1234', ips[x][0]))
		else: ips[x].append(create_token('show_ip_token_1234', ips[x][0]))
	if request.method == 'POST' and form.validate_on_submit():
		ips = form.ips.data
		conn.runQuery("INSERT INTO ips_table(eveid, ips, active) VALUES(%s, %s, 0)", (eveid, ips))
		flash('IP added successfully', category = 'success')
		return redirect(url_for('SetAllowedIPs_admin', eveid = eveid, token = token))
	return render_template('setIPs.html', form = form, content = ips, eventid = eveid)

@app.route('/edmin/event/edit/ips/<ipid>/activate', methods = ['POST'])
def MakeIPVisible(ipid):
	Token = request.form.get('token')
	if Token is None or not check_token('show_ip_token_1234', ipid, Token):
		return abort(404)
	conn.runQuery("UPDATE ips_table SET active = 1 WHERE id = %s", (ipid))
	return "OK"

@app.route('/edmin/event/edit/ips/<ipid>/deactivate', methods = ['POST'])
def MakeIPInvisible(ipid):
	Token = request.form.get('token')
	if Token is None or not check_token('hide_ip_token_1234', ipid, Token):
		return abort(404)
	conn.runQuery("UPDATE ips_table SET active = 0 WHERE id = %s", (ipid))
	return "OK"

@app.route('/edmin/event/<eveid>/edit/teams', methods = ['GET', 'POST'])
def SetRegTeams_admin(eveid):
	token = request.args.get('token')
	if not eveid or not token or not check_token('allowed_team_tokens', eveid, token):
		return abort(404)
	form = SetTeamsForm()
	res = conn.runQuery("SELECT * FROM event_marks WHERE eveid=%s", (eveid))
	ips = []
	for row in res:
		temp = [row['id'], row['team_id'], row['answers'], row['marks'], ]
		if row['ip'] == None: temp.append('====')
		else : temp.append(row['ip'])
		if row['time'] == None: temp.append('####')
		else: temp.append(datetime.fromtimestamp(row['time']).strftime("%c")) 
		ips.append(temp)
	if request.method == 'POST' and form.validate_on_submit():
		data = form.teams.data.split(',') ; err = 0 ; suc = 0 ; past = 0
		for team in data:
			res = conn.runQuery("SELECT * FROM event_marks WHERE eveid = %s AND team_id = %s", (eveid, team))
			if len(re.findall(r'^Team_[0-9]{6}$',team)) != 1:
				err += 1
			elif len(res) != 0:
				past += 1
			else:
				conn.runQuery("INSERT INTO event_marks(eveid, team_id) VALUES (%s, %s)", (eveid, team))
				suc += 1
		flash('Teams added -- [*] Wrong - (%s) | [-] Already - (%s) | [+] Done - (%s)'%(err, past, suc), category = 'success')
		return redirect(url_for('SetRegTeams_admin', eveid = eveid, token = token))
	return render_template('setTeams.html', form = form, content = ips, eventid = eveid)

@app.route('/event/<event_route>')
def Event_page(event_route):
	res = conn.runQuery("SELECT * FROM events WHERE event_route = %s", (event_route))
	if len(res) != 1: return abort(404)
	if res[0]['allow_access'] != 1: return abort(403)
	if not check_ip(res[0]['id']): abort(401)

	event_name = res[0]['event_name']
	Id = res[0]['id']
	form = TSTUploadForm()
	passwd_dat = conn.runQuery("SELECT title, passwd FROM passwd_table WHERE active = 1 AND eveid = %s", (Id))
	files_dat = conn.runQuery("SELECT file_name, file_path FROM up_files_table WHERE active = 1 AND eveid = %s", (Id))
	upload_dat = conn.runQuery("SELECT hash FROM tst_setup WHERE active = 1 AND eveid = %s", (Id))
	if len(upload_dat) == 1:
		hh = upload_dat[0]['hash']
	elif len(upload_dat) == 0:
		hh = ''
	else:
		upload_dat = [] ; hh = ''
		flash('Error with TST upload forms, contact the organisers!', category = 'danger')
	return render_template('event_view.html', title = event_name, passwds = passwd_dat, files = files_dat, form = form, upload_hash = hh, event_route = event_route, tst_sss = len(upload_dat), pwd_sss = len(passwd_dat) != 0)

@app.route('/download/<path>')
def DownloadShit(path):
	res = conn.runQuery("SELECT * FROM up_files_table WHERE file_path = %s", (path))
	if len(res) != 1: abort(404)
	if res[0]['active'] != 1: abort(403)
	if not check_ip(res[0]['eveid']): abort(401)
	file_name = res[0]['file_name']
	f = open('serving_files/' + path, 'rb')
	return send_file(f, as_attachment = True, attachment_filename = file_name, cache_timeout=0)

@app.route('/tst/<path>', methods = ['POST'])
def ServeTSTFile(path):
	res = conn.runQuery("SELECT * FROM tst_setup WHERE hash=%s", (path))
	if len(res) != 1: abort(404)
	if res[0]['active'] != 1: abort(403)
	if not check_ip(res[0]['eveid']): abort(401)

	ans = res[0]['answers'] ; pwd = res[0]['jar_pass'] ; eveid = res[0]['eveid'] ; subj = res[0]['sub_name']
	event_det = conn.runQuery("SELECT event_route FROM events WHERE id = %s", (eveid))[0]
	eve_route = event_det['event_route']

	if 'tst_file' not in request.files: # File check
		flash("File is not uploaded !...", category = 'danger')
		return redirect(url_for('Event_page', event_route = eve_route))
	file = request.files['tst_file'] ; parts = file.filename.split('.tst')
	if len(parts) != 2 or parts[1] != '' or len(parts[0].split('-')) != 2:
		flash("Invalid File Name !...", category = 'danger')
		return redirect(url_for('Event_page', event_route = eve_route))
	teamid , subject = parts[0].split('-')
	if len(re.findall(r'^Team_[0-9]{6}$',teamid)) != 1:
		flash('Invalid Teckzite Team id')
	if subject != subj:
		flash("Invalid File name !...", category = 'danger')
		return redirect(url_for('Event_page', event_route = eve_route))

	res = conn.runQuery("SELECT * FROM event_marks WHERE eveid = %s AND team_id = %s", (eveid, teamid))
	if len(res) != 1:
		flash("Team not registered for the event !...", category = 'danger')
		return redirect(url_for('Event_page', event_route = eve_route))
	if res[0]['answers'] != '':
		flash("Exam upload already completed !...", category = 'danger')
		return redirect(url_for('Event_page', event_route = eve_route))

	content = file.read()
	string = ''
	try:
		opt = codecs.decode(content, 'hex').decode()
		opt = str_xor(opt, teamid.upper(), pwd)

		for i in range(len(ans)): # Evaluting Answers
			if opt[i] == '*':
				string += '-'
			elif opt[i] == ans[i]:
				string += '1'
			else:
				string += '0'
		ip_addr = request.remote_addr
		tt = int(time.time())

		conn.runQuery("UPDATE event_marks SET answers=%s, marks=%s, ip=%s, `time`=%s WHERE id=%s", (opt, string, ip_addr, tt, res[0]['id']))
		flash("Exam completed successfully !...", category = 'success')
		return redirect(url_for('Event_page', event_route = eve_route))
	except:
		flash("Error", category="danger")
		return redirect(url_for('Event_page', event_route = eve_route))

@app.route('/self-check/<path>', methods=['POST'])
def Self_Check(path):
	res = conn.runQuery("SELECT * FROM tst_setup WHERE hash=%s", (path))
	if len(res) != 1:
		abort(404)
	if request.form.get('teamid') == None :
		abort(403)
	teamid = request.form.get('teamid')
	eveid = res[0]['eveid']
	res = conn.runQuery("SELECT * FROM event_marks WHERE eveid = %s AND team_id = %s", (eveid, teamid))
	if len(res) != 1:
		return "Team not registered for this event"
	if res[0]['answers'] == '':
		return "Not yet uploaded"
	return "Completed successfully !..."


if __name__ == '__main__':
	app.run('0.0.0.0', 80)

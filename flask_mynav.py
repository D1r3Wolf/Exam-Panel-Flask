from flask import url_for, session
from flask_nav import Nav
from sql import *
from funcs import *

class MyNav:
	def __init__(self, mainname, ll, rl):
		self.MainName = mainname
		self.components = {"left" : ll , "right" : rl}

class SubGroup:
	def __init__(self, mainname, *args):
		self.MainName = mainname
		self.items = args

	def render(self):
		return '''
		<li>
			<a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">{} <span class="caret"></span></a>
			<ul class="dropdown-menu">
		'''.format(self.MainName) + '\n'.join([
				x.render() for x in self.items
			]) + '''
			</ul>
		</li>
		'''

class View:
	def __init__(self, mainname, fnName = 'home'):
		self.MainName = mainname
		self.fnName = fnName
	def render(self):
		return '<li><a href="{}">{}</a></li>'.format(url_for(self.fnName), self.MainName)

class Link:
	def __init__(self, mainname, path = '#'):
		self.MainName = mainname
		self.path = path
	def render(self):
		return '<li><a href="{}">{}</a></li>'.format(self.path, self.MainName)

class Separator:
	def render(self):
		return '<li role="separator" class="divider"></li>'		

class Label:
	def __init__(self, mainname):
		self.MainName = mainname
	def render(self):
		return '<li class="dropdown-header">{}</li>'.format(self.MainName)

nav = Nav()
@nav.navigation()
def mynavbar():
	if 'login' not in session or session['login'] != 1:
		return MyNav('Anonymous', [ 
			], [
				View('Log in', 'adminLogin')
			])
	if session['login'] == 1:
		return MyNav(
			'Admin [ %s ]'%session['username'], [
				View('View All Events', 'listEvents_admin') ,
				View('Add Event', 'AddEvent_admin') ,
			], [
				SubGroup(
					session['username'], 
					Label(get_user_name()),
					Separator(), 
					View('Logout', 'logout') 
				)
		])
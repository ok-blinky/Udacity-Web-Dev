import os
import webapp2, jinja2, re, hmac, hashlib, random, urllib2, json, logging
import time
from xml.dom import minidom
from string import letters

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'html')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

secret = 'sl;dkfjdsaFSTJ@#$23421,;['
#secret should not be stored in the same file like this

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def hash_str(s):
	return hmac.new(secret,s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Handler(webapp2.RequestHandler):

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render(self, template, **kw):
		self.write(render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login_success(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))
#initialize is a built-in function of the Google Webapp framework
#similar to __init__, it runs this first thing when you visit a page
#so, it runs this to check if you're user_id cookie matches the cookie
#associated with that user_id in the db on every page you visit

def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)
#users_key is there in case we want to implement user groups later

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()
	join_date = db.DateTimeProperty(auto_now_add = True)

	@classmethod
#@classmethod is known as a decorator, basically lets you call this method
#on this object instead of an instance of the object
#instead of using "self" we're using "cls" to refer to the User class
#rather than the User object
	def by_id(cls, uid):
		return cls.get_by_id(uid, parent = users_key())
#the get_by_id function will load a user out of the database

	@classmethod
	def by_name(cls, name):
		u = cls.all().filter('name =', name).get()
		return u
#this lets your call by_name to retrieve a username from the database
#rather than using GqlQuery("select * from User where name=:1" "name").get()

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return cls(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)
#this creates the user object, but does not store it into the db

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

class DBHandler(Handler):

	def get(self):
		Users = db.GqlQuery("select * from User order by join_date desc")
		self.render("db_visual.html", User=Users)

class LoginHandler(Handler):
	
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
#returns the user if it's a valid name/pw combo, and None otherwise
		if u:
			self.login_success(u)
			self.redirect('/welcome')
		else:
			login_error = "Invalid login!"
			self.render('login.html', login_error = login_error)

class LogoutHandler(Handler):

	def get(self):
		self.logout()
		self.redirect('/blag/signup')

class SignupHandler(Handler):

	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
					  email = self.email)

		if not valid_username(self.username):
			params['user_error'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['pass_error'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['verify_error'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['email_error'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render("signup.html", **params)
		else:
			self.done()
#the done method does nothing within this class, but other classes
#will inherit from this class and overwrite the method
#makes it so we don't have to repeat code for validating login info

	def done(self, *a, **kw):
		raise NotImplementedError

class RegisterHandler(SignupHandler):
	def done(self):
		#make sure the user doesn't exist already
		u = User.by_name(self.username)
		if u:
			msg = 'That user exists already.'
			self.render('signup.html', user_error = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login_success(u)
			self.redirect('/welcome')

class WelcomeHandler(Handler):

	def get(self):
		if self.user:
			self.render('welcome.html', username = self.user.name)
		else:
			self.redirect('/blag/signup')


GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
#this is gmaps api for drawing a static google map
def gmaps_img(points):
	pins = '&'.join('markers=%s,%s' % (p.lat, p.lon) for p in points)
	return GMAPS_URL + pins
#this adds the query parameters for the pins on the map from the coords
#we retrieved using the hostip api below that were added to our Art db

IP_URL = "http://api.hostip.info/?ip="
#this is the api from www.hostip.info for getting coordinates from an IP
def get_coords(ip):
	url = IP_URL + ip
	content = None
	try:
		content = urllib2.urlopen(url).read()
	except URLError:
		return
#urllib will return the above error if the service is down or it cant
#get coords for some reason, so this will catch that
	if content:
		d = minidom.parseString(content)
		coords = d.getElementsByTagName("gml:coordinates")
		if coords and coords[0].childNodes[0].nodeValue:
			lon, lat = coords[0].childNodes[0].nodeValue.split(',')
			return db.GeoPt(lat, lon)
#db.GeoPt(lat,lon) is part of google app engine
#it's the datatype for storing a lattitude and longitude

class Art(db.Model):
	title = db.StringProperty(required = True)
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	coords = db.GeoPtProperty()
	#google specific datatype for storing lat/long

def top_arts(update = False):
	#added update param so we can prevent cache stampede
	#now only a user who posts to the db will trigger a cache update
	key = 'top_art'
	#this is how we'll reference the result of our query in the cache
	arts = memcache.get(key)
	if arts is None or update:
		logging.error("DB QUERY")
	#this prints "DB QUERY" to the console as an error when we run this
	#only doing this to illustrate how caching this result makes it
	#not run this function until the cache is cleared
		arts = db.GqlQuery("SELECT * FROM Art "
							"ORDER BY created DESC LIMIT 10")
	#above query is run every time we iterate over the cursor
	#to prevent running multiple queries we turn it into a list:
		arts = list(arts)
		memcache.set(key, arts)
	return arts

class AsciiPage(Handler):
	def render_ascii_front(self, title="", art="", created="",
							ascii_error=""):
		arts = top_arts()

		#find which arts have coords
		points = filter(None, (a.coords for a in arts))
		#if any arts have coords, make an image url
		img_url = None
		if points:
			img_url = gmaps_img(points)
		#display the image url

		self.render("ascii_front.html", title=title, art=art, 
					created=created, ascii_error=ascii_error, 
					arts=arts, img_url=img_url)

	def get(self):
#		self.write(repr(get_coords(self.request.remote_addr)))
#above is a hacky way to display what our get_coords is returning
#repr adds quotes to python objects so they won't be treated as html
#self.request.remote_addr is AppEngine's way of obtaining user's IPs
		self.render_ascii_front()

	def post(self):
		title = self.request.get("title")
		art = self.request.get("art")

		if title and art:
			a = Art(title=title, art=art)
			coords = get_coords(self.request.remote_addr)
			#lookup user's IP and get coordinates
			if coords:
				a.coords = coords
			#if we have coords, add them to the art
			a.put()
#			ART_CACHE.clear()
#clearing the cache works but can result in cache stampede
#instead we will update the cache with new data as we receive it
			top_arts(True)
	#now our top_arts function will rerun the query and update the cache
			self.redirect("/ascii")
		else:
			ascii_error = "I only asked for two things, c'mon!"
			self.render_ascii_front(title, art, ascii_error=ascii_error)

class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("blag_post.html", p = self)
#render function here is used to preserve new lines in blog posts

def top_posts(update = False):
	key = 'top_post'
	try:
		posts = memcache.get(key)[1]
	except:
		posts = None
	#pulls just the posts from the tuple of (query_time, posts)
	if posts is None or update:
		logging.error("DB QUERY")
		posts = db.GqlQuery("SELECT * FROM Post "
							"ORDER BY created DESC LIMIT 10")
		posts = list(posts)
		memcache.set(key, (time.time(), posts))
		#sets the key's value to be a tuple of (query_time, posts)
	return posts

class BlagPage(Handler):
	def render_blag_front(self, subject="", content="", created=""):
		entries = top_posts()
		query_time = time.time() - memcache.get("top_post")[0]
		QUERIED = "Queried %f seconds ago" % query_time
		self.render("blag_front.html", subject=subject, content=content,
					created=created, entries=entries, QUERIED=QUERIED)

	def get(self):
		self.render_blag_front()

def blag_permalinks(key, update = False):
	try:
		permalink = memcache.get(key)[1]
	except TypeError:
		permalink = None
	if permalink is None or update:
		logging.error("DB QUERY")
		permalink = db.get(db.Key.from_path('Post', int(key)))
		memcache.set(key, (time.time(), permalink))
	return permalink

class BlagPost(Handler):
	def render_blag_post(self, subject="", content="", created="",
						  blag_error=""):
		self.render("blag_post.html", subject=subject, content=content, 
					created=created, blag_error=blag_error)

	def get(self):
		self.render_blag_post()

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			e = Post(subject=subject, content=content)
			e_key = e.put() # Key('Entry', id)
			e.put()
			top_posts(True)

			self.redirect("/blag/%d" % e_key.id())
		else:
			blag_error = "I only asked for two things, c'mon!"
			self.render_blag_post(subject, content, blag_error=blag_error)

class JsonHandler(BlagPage):
	def get(self):
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'

		l = []
		posts = top_posts()
		#viewing the json page no longer performs a db read

		for p in posts:
			j = {}
			j["content"]=p.content
			j["subject"]=p.subject
			j["created"]=p.created.strftime('%c')
			l.append(j)

		self.write(json.dumps(l))

class BlagPostPermalink(BlagPage):
	def get(self, post_id):
#		self.write(repr(post_id))
		s = blag_permalinks(key=post_id)
		query_time = time.time() - memcache.get(post_id)[0]
		QUERIED = "Queried %f seconds ago" % query_time
		self.render("blag_front.html", entries=[s], QUERIED=QUERIED)

class JsonPermalink(BlagPostPermalink):
	def get(self, post_id):
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		s = Post.get_by_id(int(post_id))
		j = {"content":s.content, "subject":s.subject,
			 "created":s.created.strftime('%c')}

		self.write(json.dumps(j))

class FlushCache(Handler):
	def get(self):
		memcache.flush_all()
		self.redirect("/blag")

app = webapp2.WSGIApplication([("/blag/signup/?", RegisterHandler),
							   ("/welcome/?", WelcomeHandler),
							   ("/login/?", LoginHandler),
							   ("/logout/?", LogoutHandler),
							   ('/ascii/?', AsciiPage),
							   ('/blag/?', BlagPage),
							   ('/blag/newpost/?', BlagPost),
							   ('/blag/(\d+)', BlagPostPermalink),
							   ('/database/?', DBHandler),
							   ('/blag/?(?:\.json)?', JsonHandler),
							   ('/blag/(\d+)/?(?:\.json)?', JsonPermalink),
							   ('/blag/flush/?', FlushCache)],
								debug=True)
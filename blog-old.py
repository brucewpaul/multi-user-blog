import os
import webapp2
import jinja2
import random
import string
import hashlib
import hmac
import re
import logging

SECRET = 'imsosecret'

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class Handler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

class Entry(db.Model):
  subject = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
  username = db.StringProperty(required = True)
  password = db.StringProperty(required = True)
  salt = db.StringProperty(required = True)
  email = db.StringProperty(required = False)

class MainPage(Handler):
  def render_front(self):
    entries = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC LIMIT 10")
    self.render('front.html', entries=entries)

  def get(self):
    self.render_front()

class PostPage(Handler):
  def get(self, entry_id, error=''):
    single_entry = Entry.get_by_id(int(entry_id))
    self.render('post.html', error=error, entry=single_entry)

class NewPostPage(Handler):
  def render_new_post(self, subject='', content='', error=''):
    self.render('newpost.html', subject=subject, content=content, error=error)

  def get(self):
    self.render_new_post()

  def post(self):
    subject = self.request.get('subject')
    content = self.request.get('content')

    if subject and content:
      e = Entry(subject = subject, content = content)
      e.put()
      entry_id = e.key().id()
      self.redirect("/post/%d" % entry_id)
    else:
      error = 'we need a subject and content'
      self.render_new_post(subject,content,error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PW_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
  return USER_RE.match(username)

def valid_password(password):
    return PW_RE.match(password)

def valid_verify(password, verify):
    return password == verify

def valid_email(email):
    return email == '' or EMAIL_RE.match(email)

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)

def hash_str(s):
  return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
  return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
  val = h.split('|')[0]
  if h == make_secure_val(val):
    return val

class SignUpPage(Handler):
  def get(self):
    user_id_cookie_str = self.request.cookies.get('user_id')
    if user_id_cookie_str:
        cookie_val = check_secure_val(user_id_cookie_str)
        if cookie_val:
          self.redirect("/welcome")
    else:
      self.render("signup.html")

  def post(self):
    have_error = False
    username   = self.request.get('username')
    password   = self.request.get('password')
    verify     = self.request.get('verify')
    email      = self.request.get('email')

    params = dict(username = username,
                     email = email)

    query = db.GqlQuery(' select *  from User where username = :1 ', username)
    usernames = query.count(limit=2)

    if usernames:
        params['username_error'] = "That username is taken."
        have_error               = True

    if not valid_username(username):
        params['username_error'] = "That's not a valid username."
        have_error               = True

    if not valid_password(password):
        params['password_error'] = "That wasn't a valid password."
        have_error               = True
    elif password != verify:
        params['verify_error']   = "Your passwords didn't match."
        have_error               = True

    if not valid_email(email):
        params['email_error']    = "That's not a valid email."
        have_error               = True

    if have_error:
        self.render('signup.html', **params)

    else:

      pw_hash_salt  = make_pw_hash(username, password)
      password_hash = pw_hash_salt.split('|')[0]
      salt          = pw_hash_salt.split('|')[1]
      a = User(username = username, password = password_hash, salt = salt, email = email)
      a_key = a.put()

      new_cookie_val   = make_secure_val(str(a_key.id()))

      self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_cookie_val)
      self.redirect("/welcome")

class LoginPage(Handler):
  def get(self):
    user_id_cookie_str = self.request.cookies.get('user_id')
    if user_id_cookie_str:
        cookie_val = check_secure_val(user_id_cookie_str)
        if cookie_val:
          self.redirect("/welcome")
        else:
          self.render("login.html")
    else:
      self.render("login.html")

  def post(self):
    username   = self.request.get('username')
    password   = self.request.get('password')

    error = 'Invalid Login'

    user = User.gql("where username = :1", username).get()
    user_id = user.key().id_or_name()

    if user != None and password:
      h = make_pw_hash(username,password)
      if valid_pw(username, password, h):
        new_cookie_val = make_secure_val(str(user_id))

        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_cookie_val)
        self.redirect("/welcome")
      else:
        self.render("login.html",error=error)
    else:
      self.render("login.html",error=error)

class LogoutPage(Handler):
  def get(self):
    new_cookie_val = ''
    self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_cookie_val)
    self.redirect("/signup")

class WelcomePage(Handler):
  def get(self):

    user_id_cookie_str = self.request.cookies.get('user_id')
    if user_id_cookie_str:
        cookie_val = check_secure_val(user_id_cookie_str)
        if cookie_val:
          user_id   = str(cookie_val)
          user = User.get_by_id(int(user_id.split('|')[0]))
          username = user.username
          self.render('welcome.html', username = username)
    else:
      self.redirect("/signup")


app = webapp2.WSGIApplication([
  ('/',MainPage),
  ('/post/([\w]+)',PostPage),
  ('/newpost', NewPostPage),
  ('/signup', SignUpPage),
  ('/login', LoginPage),
  ('/logout', LogoutPage),
  ('/welcome', WelcomePage)
  ],
  debug=True)
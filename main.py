import jinja2
import webapp2
import hashlib
import hmac
import os
import time
import random
from google.appengine.ext import db
from string import *
import re
import json

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
username = ""

# this class checks the cookie


class check(webapp2.RequestHandler):
    def check_cookie(self):
        user = self.request.cookies.get("userID")
        if user:
            user = user.split("|")
            if user[1] != hmac.new("secret", user[0]).hexdigest():
                self.response.delete_cookie('userID')
                return False
            else:
                return True
        else:
            return False

# models
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=False)


class Comments_Table(db.Model):
    post_key = db.StringProperty(required=True)
    user = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)


class Like(db.Model):
    postkey = db.StringProperty(required=True)
    post_lovers = db.StringProperty(required=True)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    username = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return ""

    def rendercomment(self, t,userid):
        # post_key=str(self.key().id())
        post_key = str(t)
        comments = db.GqlQuery("SELECT * FROM Comments_Table "
                               "where post_key=:1", post_key)
        key = db.Key.from_path('Post', int(t))
        post = db.get(key)
        return render_str("comments.html", comments=comments, k=t,p=post,userid=userid)


class Welcome(webapp2.RequestHandler):
    def get(self):
        t = jinja_env.get_template("welcome.html")
        # j = self.request.get("form1")
        self.response.out.write(t.render())

    def post(self):
        username1 = self.request.get("username")
        password = self.request.get("password")
        a = Signup()
        q = User.all().filter("name =", username1).get()
        print(q)
        pwhash = ""
        salt = ""
        if q:
            salt = q.pw_hash.split(',')[0]
            pwhash = q.pw_hash
            # to compare hash value in db with password given
            if pwhash == a.make_pw_hash(str(username1),
                                        str(password), str(salt)):
                username1 = str(username1)
                userid = hmac.new("secret", username1).hexdigest()
                self.response.headers.add_header('Set-Cookie',
                                                 'userID=%s|%s; Path=/'
                                                 % (username1, userid))
                return self.redirect('/blog')
            else:
                # password is invalid
                t = jinja_env.get_template("welcome.html")
                self.response.out.write(t.render
                                        (login_error="invalid  password"))
        else:
            t = jinja_env.get_template("welcome.html")
            self.response.out.write(t.render(login_error="invalid  username"))


class Signup(webapp2.RequestHandler):
    def valid_username(self, username):
        # to check if username exist or not
        u = User.all().filter('name =', username).get()
        if u:
            return 1
        else:
            return 0

    def make_salt(self, length=5):
        return ''.join(random.choice(letters) for x in xrange(length))

    def make_pw_hash(self, name, pw, salt=None):
        if salt is None:
            salt = self.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, h)

    def get(self):
        t = jinja_env.get_template("form.html")
        # j = self.request.get("form1")
        self.response.out.write(t.render())

    def post(self):
        global username
        username = self.request.get("username")
        pass1 = self.request.get("pass1")
        pass2 = self.request.get("pass2")
        email = self.request.get("email")
        name_error = pass1_error = pass2_error = email_error = ""
        username = str(username)
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PASS_RE = re.compile(r"^.{3,20}$")
        EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
        u = self.valid_username(username)
        if username.strip() == "" or not USER_RE.match(username) or u == 1:
            if u == 1:
                name_error = "username already exists"
            else:
                name_error = "enter valid username please"
        if pass1.strip() == "" or not PASS_RE.match(pass1):
            pass1_error = "enter valid password i.e b/w 3 and 20 characters"
        if pass2.strip() == "":
            pass2_error = "confirm password please"
        if pass1 != pass2:
            pass1_error = "password is not valid"
        if email.strip() != "" and not EMAIL_RE.match(email):
            email_error = "enter valid email"
        if name_error == pass1_error == pass2_error == email_error == "":
            userid = hmac.new("secret", username).hexdigest()
            # pw_hash=hmac.new("secret", pass1).hexdigest()
            pw_hash = self.make_pw_hash(username, pass1)
            self.response.headers.add_header('Set-Cookie',
                                             'userID=%s|%s; Path=/'
                                             % (username, userid))

            # self.response.out.write("welocme")
            a = User(name=username, pw_hash=pw_hash, email=email)
            a.put()
            return self.redirect('/blog')
        else:
            t = jinja_env.get_template("form.html")
            # j = self.request.get("form1")
            self.response.out.write(t.render(name_error=name_error,
                                             pass1_error=pass1_error,
                                             pass2_error=pass2_error,
                                             email_error=email_error))


class Login(webapp2.RequestHandler):
    def get(self):
        t = jinja_env.get_template("login.html")
        # j = self.request.get("form1")
        self.response.out.write(t.render())

    def post(self):
        username1 = self.request.get("username")
        password = self.request.get("password")
        a = Signup()
        # to check if username exist
        q = User.all().filter("name =", username1).get()
        pwhash = ""
        salt = ""
        if q:
            salt = q.pw_hash.split(',')[0]
            pwhash = q.pw_hash
            # check the password by hashing it and comparing hashed values
            if pwhash == a.make_pw_hash(str(username1),
                                        str(password), str(salt)):
                username1 = str(username1)
                userid = hmac.new("secret", username1).hexdigest()
                self.response.headers.add_header('Set-Cookie',
                                                 'userID=%s|%s; Path=/'
                                                 % (username1, userid))
                return self.redirect('/blog')
            else:

                t = jinja_env.get_template("login.html")
                self.response.out.write(t.render
                                        (login_error="invalid  password"))
        else:
            t = jinja_env.get_template("login.html")
            self.response.out.write(t.render(login_error="invalid  username"))


class BlogFront(check):
    def get(self):
        posts = Post.all().order('-created')
        t = jinja_env.get_template("blog.html")
        userid = self.request.cookies.get("userID")
        if self.check_cookie() :
            userid = userid.split('|')[0]
            userid = str(userid)
        else:
            userid = "Non"
        results = db.GqlQuery("SELECT * FROM Like")
        results = results.count()
        self.response.out.write(t.render(posts=posts,
                                         userid=userid,
                                         numlikes=results,
                                         obj=self))

    def post(self):
        form_name = self.request.get("formname")
        # to check which form is submitted
        user = self.request.cookies.get("userID")

        # check_cookie checks validation of
        if self.check_cookie() :
            return self.redirect("/blog")

        if form_name == "submit_comment":
            post_key = self.request.get("post_key")
            comment = self.request.get("comment")
            post_key_int = int(post_key)
            keys = db.Key.from_path('Post',post_key_int)
            post = db.get(keys)
            if post is None or comment.strip() == "":
                return self.redirect("/blog")
            post_key = str(post_key)

            user = user.split("|")[0]
            c = Comments_Table(post_key=post_key, user=user, comment=comment)
            c.put()
        elif form_name == "delete_comment":
            user = user.split("|")[0]
            comment_key = self.request.get("comment_key")
            comment_key = int(comment_key)
            keys = db.Key.from_path('Comments_Table', comment_key)
            comment = db.get(keys)
            if comment is None:
                return self.redirect("/blog")
            # to check if that comment is submitted by the user
            if comment.user == user:
                comment.delete()
        else:
            comment_key = self.request.get("comment_key")
            comment_key = int(comment_key)
            keys = db.Key.from_path('Comments_Table', comment_key)
            prev_comment = db.get(keys)
            # to check if user owns comment or not
            if self.user_owns_comment(prev_comment) and prev_comment is not None:
                final_comment = self.request.get("comment")
                final_comment = str(final_comment)
                # change the comment and store it
                prev_comment.comment = final_comment
                prev_comment.put()
        posts = Post.all().order('-created')
        return self.redirect('/blog')

    def user_owns_comment(self, prev_comment):
        user = self.request.cookies.get("userID")
        user = user.split("|")[0]
        # check_cookie check user authorization
        if self.check_cookie() and prev_comment.user == user:
            return True

    def getvalues(self):
        post_keys = self.request.get("post_key2")

    def likes(self, key):
        user = self.request.cookies.get("userID")
        if user:
            user = user.split("|")[0]
        key = str(key)
        results = db.GqlQuery("SELECT * FROM Like where postkey=:1", key)
        results = results.count()
        results = str(results)
        return results
        # it returns number of likes in a given post

    def like_or_not(self, key):
        user = self.request.cookies.get("userID")
        key = str(key)
        if user:
            user = user.split("|")[0]
            user = str(user)
        # to obtain all posts that are liked by the user
        likedpost = Like.all().filter('postkey =', key).filter('post_lovers =',
                                                               user).get()

        if likedpost:
            return "glyphicon glyphicon-thumbs-up"
        # it returns thumbs up icon if given post is liked by user

    def like_html(self, key):
        user = self.request.cookies.get("userID")
        if self.check_cookie():
            user = user.split("|")[0]
            user = str(user)
        key = str(key)
        results = Like.all().filter('postkey =', key).filter('post_lovers =',
                                                               user).get()
        if results:
            return "unlike"
        else:
            return "like"


class NewPost(check):
    def get(self):

        if self.check_cookie():
            t = jinja_env.get_template("newpost.html")
            self.response.out.write(t.render())
        else:
            return self.redirect("/login")

    def post(self):
        user = self.request.cookies.get("userID")
        if self.check_cookie() is False:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            user = user.split("|")[0]
            p = Post(subject=subject, content=content, username=user)
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            t = jinja_env.get_template("newpost.html")
            self.response.out.write(t.render(subject=subject,
                                             content=content,
                                             error=error))


class PostPage(check):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        userid = self.request.cookies.get("userID")
        if self.check_cookie():
            userid = userid.split("|")[0]
            userid = str(userid)
        else:
            userid = "Non"
        if not post:
            self.error(404)
            return

        t = jinja_env.get_template("permalink.html")
        self.response.out.write(t.render(post=post, userid=userid))


class Logout(webapp2.RequestHandler):
    def get(self):
        self.response.delete_cookie('userID')
        return self.redirect('/')


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class LikeBlog(check):
    def get(self):
        key = self.request.get("postkey")
        userid = self.request.cookies.get("userID")
        key = db.Key.from_path('Post', int(key))
        post = db.get(key)
        if post is None:
            return self.redirect("/blog")
        # to like it should not user's ownpost
        if self.check_cookie() and userid != post.username :
            userid = str(userid)
            userid = userid.split("|")[0]
            key = str(key)
            print(key)
            likepost = Like.all().filter('postkey =', key)
            likepost = likepost.filter('post_lovers =', userid).get()

            if likepost:
                # if post is liked then unlike it by deleting liked post from database
                likepost.delete()
            else:
                # if post is not liked then like it and store it in a database
                a = Like(postkey=key, post_lovers=userid)
                a.put()
            time.sleep(1)
            results = db.GqlQuery("SELECT * FROM Like where postkey=:1", key)
            results = results.count()
            results = str(results)

            self.render_json({
                'numlikes': results,

            })

    def render_json(self, data):
        self.response.headers['Content-Type'] = 'application/json'
        self.response.out.write(json.dumps(data))


class EditPost(check):
    def get(self, post_key):
        userid = self.request.cookies.get("userID")
        key = db.Key.from_path('Post', int(post_key))
        post = db.get(key)
        # check if post exist or not
        if not post or self.check_cookie() is False :
            return self.redirect("/")

        # check if userid is there and if its user ownpost or not
        if self.user_owns_post(post, userid):
            t = jinja_env.get_template("editpost.html")
            userid = str(userid)
            userid = userid.split("|")[0]
            self.response.out.write(t.render(post=post, userid=userid))

        else:
            return self.redirect("/")

    def user_owns_post(self, post, userid):
        userid = str(userid)
        userid = userid.split("|")[0]
        # check_cookie decrupt and check the hash value
        if self.check_cookie() and post.username == userid:
            return True
        else:
            return False

    def post(self, post_key):
        # key=self.request.get("post_key")
        key = db.Key.from_path('Post', int(post_key))
        post = db.get(key)
        userid = self.request.cookies.get("userID")
        if not post or self.check_cookie() is False:
            return self.redirect("/")
        userid = str(userid)
        userid = userid.split("|")[0]
        form = self.request.get("hiddeninput")
        if userid == post.username:
            # to check if its user own post or not
            form = self.request.get("hiddeninput")
            form = str(form)
            if form == "editpost":
                subject = self.request.get("subject")
                content = self.request.get("content")
                post.subject = str(subject)
                post.content = str(content)
                post.put()
            else:
                # delete post if clicked on Delete Button
                post.delete()
                return self.redirect("/blog")

        else:
            return self.redirect("/")


app = webapp2.WSGIApplication([('/', Welcome),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/blog/newpost', NewPost),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/logout', Logout),
                               ('/like', LikeBlog),
                               ('/editpost/([0-9]+)', EditPost)
                               ], debug=True)

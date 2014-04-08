mruf
====

An online ordering system for small farms based on [Flask][] and such. Live at [order.citygrownseattle.com](http://order.citygrownseattle.com).

[Flask]: http://flask.pocoo.org/


Getting Started
---------------

Here's how you might set this thing up:

1. Make sure you have [Python 2.7][py27] and [pip][].

2. Install the dependencies by going into this directory and typing `pip
   install -r requirements.txt`.

3. Create a configuration file called `mruf.site.cfg`. This includes secret
   tokens and API keys, so keep the file safe. There's an example configuration
   file below.

4. Start up the local server by typing `python mruf.py`. Then you can head to
   [127.0.0.1:5000][local-url] to view the site.

5. The initial user has the email address `user@example.com` and the password
   `moonrabbit`. Log in to change these and make more users.

6. When you're ready to deploy, the Flask documentation has [great
   advice][flask-deploy] about the available options. There's also a
   [Dockerfile][] available in case [Docker][] is an option on your server.
   That build exposes the server on port 8118; you'll need to route that port
   and provide some way to access your database.

[Docker]: http://www.docker.io/
[Dockerfile]: https://www.docker.io/learn/dockerfile/
[flask-deploy]: http://flask.pocoo.org/docs/deploying/
[pip]: http://www.pip-installer.org/en/latest/installing.html#install-pip
[py27]: https://www.python.org/download/releases/2.7.6/
[local-url]: http://127.0.0.1:5000/


mruf.site.cfg
-------------

Here's what should go in the
configuration file:

    # These should be two randomly generated strings of bytes. One is
    # used for password hashing (which uses pbkdf2) and the other is for
    # sessions.
    SALT = b'random bytes'
    SECRET_KEY = b'more random bytes'

    # This can by any database supported by SQLAlchemy. I've tested with
    # SQLite and PostgreSQL.
    SQLALCHEMY_DATABASE_URI = 'sqlite:///mydatabase.db'

    # The app sends email using Mailgun. Set up a free account there and
    # record your credentials here.
    MAILGUN_API_KEY = 'secret'
    MAILGUN_DOMAIN = 'subdomain.mailgun.org'

    # A Flickr API account lets the tool automatically look up thumbnails
    # for store images.
    FLICKR_API_KEY = 'secret'

You can also set `DEBUG = True` if you run into trouble. This enables
browser-legible tracebacks when exceptions arise.

The site configuration can also override any of the default options enumerated
in `mruf.base.cfg`.

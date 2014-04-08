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


Architecture
------------

### State Object

Most of the site's configuration is stored in a single-row database table
called `state`. This makes it easy for farmers to change configuration using
the "administration" page on the site.

Settings are accessed by reading `g.state[key]`. Let's break this down:

* `g` is Flask's [global context][]. It's populated by our `_load_globals`
  function before handling each request.
* `g.state` represents the only row in the `state` table. It's an
  [SQLAlchemy][] model object.
* Item access (`g.state[foo]`) accesses a JSON-serialized dictionary in the
  row. If the key is missing from the dictionary, it falls back to defaults
  provided as `DEFAULT_SETTINGS` in `mruf.base.cfg`.

[SQLAlchemy]: http://www.sqlalchemy.org/
[global context]: http://flask.pocoo.org/docs/api/#application-globals

### The Next Harvest

Different products are available at different times. To account for this, the
farmer sets a *next harvest time* indicating the window during which customers
can order a particular set of products. This timestamp is stored in the global
`g.next_harvest`.

Every order, when placed, records the next-harvest timestamp at the time it was
placed. This helps group together all orders placed during a given window.
Crucially, this lets farmers view all the products that were ordered during a
given cycle. A group of orders with the same next-harvest timestamp are called
a *harvest*.

The `all_harvest` function recovers all the unique timestamps for which orders
were placed. These can then be used to fetch the group of orders associated
with each timestamp. Most usefully, you can get the latest harvest by looking
up the last timestamp returned by this function (as `latest_harvest` does).

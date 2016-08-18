from flask import Flask
from flask import request, session, redirect, url_for, render_template, g
from flask import abort, flash
from flask.ext.sqlalchemy import SQLAlchemy
import pbkdf2
from decimal import Decimal
import sqlalchemy
import string
import random
import datetime
import parsedatetime
import time
from werkzeug import url_decode
import requests
from urlparse import urlparse, urljoin
import urllib
import re
import pytz
import json
from collections import OrderedDict


# The Flask application and its configuration.

app = Flask(__name__)
app.config.from_pyfile('mruf.base.cfg')
app.config.from_pyfile('mruf.site.cfg', silent=True)
app.config.from_envvar('MRUF_CFG', silent=True)
db = SQLAlchemy(app)


# Useful Flask snippets.

# http://flask.pocoo.org/snippets/38/
class MethodRewriteMiddleware(object):
    """Middleware emulating non-GET/POST HTTP request methods from
    browsers that don't support them for Ajax calls. The frontend sets a
    special key in a POST request indicating which method it wants to
    use. We use this for DELETE requests.
    """
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        if 'METHOD_OVERRIDE' in environ.get('QUERY_STRING', ''):
            args = url_decode(environ['QUERY_STRING'])
            method = args.get('__METHOD_OVERRIDE__')
            if method:
                method = method.encode('ascii', 'replace')
                environ['REQUEST_METHOD'] = method
        return self.app(environ, start_response)
app.wsgi_app = MethodRewriteMiddleware(app.wsgi_app)


# http://flask.pocoo.org/snippets/62/
def is_safe_url(target):
    """Ensure that a URL is safe for redirection.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


# Utilities.

def _hash_pass(password):
    if isinstance(password, unicode):
        password = password.encode('utf8')
    return pbkdf2.pbkdf2_hex(password, app.config['SALT'])


def _parse_price(s):
    if s.startswith('$'):
        s = s[1:]
    elif s.startswith('-$'):
        s = '-' + s[2:]
    return Decimal(s).quantize(Decimal('1.00'))


_calendar = parsedatetime.Calendar()


def _parse_dt(s):
    """Parse a (potentially human-written) string indicating a date and
    time to a Python `datetime` object.
    """
    ts, _ = _calendar.parse(s)
    zone = pytz.timezone(g.state['timezone'])
    naivedt = datetime.datetime.fromtimestamp(time.mktime(ts))
    localdt = zone.localize(naivedt)
    return _normdt(localdt)


def _now():
    """Get a `datetime` object reflecting the current time.
    """
    return datetime.datetime.utcnow()


def _normdt(dt):
    """Normalize a `datetime` object's timezone. This lets us force all
    timestamps used internally to UTC, avoiding lots of weird timezone
    issues.
    """
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(pytz.utc).replace(tzinfo=None)


def _random_string(length=20, chars=(string.ascii_letters + string.digits)):
    return ''.join(random.choice(chars) for i in range(length))


def _next_url():
    if 'next' in request.values:
        dest = request.values['next']
        if is_safe_url(dest):
            return dest
    return url_for('main')


# Email.

def mailgun_request(apikey, path, data, base='https://api.mailgun.net/v2'):
    req = requests.post(
        '{}/{}'.format(base, path),
        data=data,
        auth=requests.auth.HTTPBasicAuth('api', apikey)
    )
    return req.json()


def mailgun_send(apikey, domain, from_addr, to_addrs, subject, body,
                 cc_addrs=(), bcc_addrs=()):
    data = {
        'from': from_addr,
        'to': ','.join(to_addrs),
        'subject': subject,
        'text': body,
    }
    if cc_addrs:
        data['cc'] = ','.join(cc_addrs)
    if bcc_addrs:
        data['bcc'] = ','.join(bcc_addrs)
    return mailgun_request(apikey, '{}/messages'.format(domain), data)


def send_email(to_addrs, subject, body, cc_addrs=(), bcc_addrs=()):
    """Send an email.
    """
    return mailgun_send(
        app.config['MAILGUN_API_KEY'],
        app.config['MAILGUN_DOMAIN'],
        g.state['mail_from'],
        to_addrs, subject, body, cc_addrs, bcc_addrs,
    )


def send_receipt(order):
    """Send an order receipt email using templates from the database.
    """
    farmer_addrs = [u.email for u in User.query.filter_by(admin=True)]
    send_email(
        [order.customer.email],
        g.state['receipt_subject'],
        g.state['receipt_body'].format(
            name=order.customer.name,
            receipt_url=url_for('receipt', order_id=order.id, _external=True),
            farm=g.state['farm'],
        ),
        bcc_addrs=farmer_addrs,
    )


# Photos.

def flickr_image_url(apikey, photoid, label,
                     base='https://api.flickr.com/services/rest/'):
    req = requests.get(base, params={
        'method': 'flickr.photos.getSizes',
        'api_key': apikey,
        'photo_id': str(photoid),
        'format': 'json',
        'nojsoncallback': '1',
    })
    sizes = req.json()['sizes']['size']
    for size in sizes:
        if size['label'] == label:
            return size['source']


def thumbnail_url(url):
    match = re.search(r'flickr\.com/photos/[^/\?]+/(\d+)', url, re.I)
    if match:
        return flickr_image_url(
            app.config['FLICKR_API_KEY'],
            match.group(1),
            'Square'
        )


# SQLAchemy types.

class IntegerDecimal(sqlalchemy.types.TypeDecorator):
    impl = sqlalchemy.types.Integer
    _unitsize = 100

    def process_bind_param(self, value, dialect):
        value = Decimal(value)
        return int(value * self._unitsize)

    def process_result_value(self, value, dialect):
        return Decimal(value) / self._unitsize


class JSONEncodedDict(sqlalchemy.types.TypeDecorator):
    """Represents an immutable structure as a json-encoded string.
    """
    impl = sqlalchemy.types.Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


# Models.

class SettingsMixin(object):
    """A mixin class for SQLAlchemy Model classes that provides a
    JSON-encoded dictionary of free-form *settings*. These values are
    accessed by subscripting the model object.
    """
    settings = db.Column(JSONEncodedDict())
    settings_default = {}

    def __init__(self):
        self.settings = dict(self.settings_default)

    def __getitem__(self, key):
        if self.settings is not None and key in self.settings:
            return self.settings[key]
        else:
            return self.settings_default.get(key)

    def __setitem__(self, key, value):
        self.update({key: value})

    def update(self, mapping):
        if self.settings is None:
            new_settings = {}
        else:
            new_settings = dict(self.settings)
        new_settings.update(mapping)
        self.settings = new_settings


class AutoincrementMixin(object):
    """A mixin for SQLAlchemy models that makes SQLite id columns
    auto-increment (i.e., avoid resuing unique ids).
    """
    __table_args__ = {'sqlite_autoincrement': True}


class User(db.Model, SettingsMixin, AutoincrementMixin):
    """A User can either be a customer or a farmer (farmers have
    administrative access).
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Unicode(256), unique=True)
    name = db.Column(db.Unicode(512))
    password = db.Column(db.String(256))
    admin = db.Column(db.Boolean)
    delivery_notes = db.Column(db.UnicodeText)
    settings_default = {
        'fruit': False,
    }

    def __init__(self, email, name, password, admin):
        SettingsMixin.__init__(self)
        self.email = email
        self.name = name
        self.password = _hash_pass(password)
        self.admin = admin

    def __repr__(self):
        return '<User {0}>'.format(self.email)

    @property
    def account_history(self):
        """Get a chronologically ordered sequence of Order and
        CreditDebit objects for this user.
        """
        out = list(self.transactions) + list(self.orders)
        out.sort(key=lambda o: o.date if isinstance(o, CreditDebit)
                 else o.placed)
        return out

    @property
    def balance(self):
        bal = Decimal('0.00')
        for txn in self.transactions:
            bal += txn.amount
        for order in self.orders:
            bal -= order.total
        return bal


class Order(db.Model, AutoincrementMixin):
    """An `Order` is a collection of `OrderItem` instances along with a
    timestamps and a reference to the user who placed the order.
    """
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    customer = db.relationship('User',
                               backref=db.backref('orders', lazy='dynamic'))
    placed = db.Column(db.DateTime)
    harvested = db.Column(db.DateTime)

    def __init__(self, customer):
        self.customer = customer
        self.placed = _now()
        self.harvested = g.state.next_harvest

    def __repr__(self):
        return '<Order {0} for {1}>'.format(self.id, self.customer.email)

    @property
    def total(self):
        """The total cost of this order.
        """
        total = Decimal('0.00')
        for item in self.items:
            total += item.cost
        return total

    @property
    def items_by_product(self):
        """A dictionary mapping `Product` instances to `OrderItem`
        instances for that product.
        """
        out = {}
        for item in self.items:
            out[item.product] = item
        return out


class OrderItem(db.Model, AutoincrementMixin):
    """A single "row" of an `Order`, representing a customer's request
    for one particular product.

    Includes the quantity as well as the price at the time the order was
    placed. Caching the price in this way lets the price change later without
    affecting the total for orders placed in the past.
    """
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    order = db.relationship('Order', backref='items')
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    product = db.relationship('Product',
                              backref=db.backref('ordered', lazy='dynamic'))
    count = db.Column(db.Integer)
    price = db.Column(IntegerDecimal)

    def __init__(self, order, product, count):
        self.order = order
        self.product = product
        self.count = count
        self.price = product.price

    @property
    def cost(self):
        return self.count * self.price


class Product(db.Model, AutoincrementMixin):
    """An item for sale in the store.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(256))
    price = db.Column(IntegerDecimal)
    available = db.Column(db.Boolean)
    link = db.Column(db.UnicodeText())
    photo = db.Column(db.UnicodeText())

    def __init__(self, name, price, link):
        self.name = name
        self.price = price
        self.link = link
        self.infer_photo()
        self.order_by = None

    def __repr__(self):
        return '<Product {0}>'.format(self.name)

    def infer_photo(self):
        """Using this product's link, try to guess a photo URL and set
        it.
        """
        if self.link:
            self.photo = thumbnail_url(self.link)


class State(db.Model, SettingsMixin, AutoincrementMixin):
    """A singleton model reflecting the site's settings.

    Most settings are packed in a JSON-encoded dictionary. These values
    are read and written via item access (`state[key]`). The site's next
    harvest date is the exception.
    """
    id = db.Column(db.Integer, primary_key=True)
    next_harvest = db.Column(db.DateTime())
    settings_default = app.config['DEFAULT_SETTINGS']

    def __init__(self):
        SettingsMixin.__init__(self)
        self.next_harvest = _now()

    # `settings` is a JSON-encoded immutable dict. This could be made
    # lazy using SQLAlchemy's mutation tracking; for the moment, it is
    # eager and therefore probably inefficient.

    @property
    def open(self):
        if self.next_harvest is None:
            return False
        return _normdt(self.next_harvest) > _now()

    @property
    def location_map(self):
        """An OrderedDict that maps short location names to long names.
        """
        out = OrderedDict()
        for line in self['locations'].strip().split('\n'):
            line = line.strip()
            short = re.sub(r'\([^\)]*\)', '', line).strip()
            out[short] = line
        return out


class CreditDebit(db.Model, AutoincrementMixin):
    """An addition or subtraction a customer's account.

    A credit/debit is *not* tied to an order---those are charged
    separately. These are used when a customer makes a deposit into
    their account, for example, and are created explicitly by farmers.
    """
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    customer = db.relationship(
        'User',
        backref=db.backref('transactions', lazy='dynamic'),
    )
    amount = db.Column(IntegerDecimal)
    date = db.Column(db.DateTime)
    description = db.Column(db.UnicodeText())

    def __init__(self, customer, amount, description):
        self.customer = customer
        self.amount = amount
        self.date = _now()
        self.description = description


# Hooks.

@app.before_first_request
def db_setup():
    """Ensure that schema and initial data is present: create tables,
    add an initial user, and create the state object.
    """
    db.create_all()
    if not State.query.first():
        db.session.add(State())
    if not User.query.first():
        # Create an administrator (farmer) who can create other initial
        # accounts.
        db.session.add(User(
            app.config['INITIAL_USER_EMAIL'],
            app.config['INITIAL_USER_NAME'],
            app.config['INITIAL_USER_PASSWORD'],
            True,
        ))
    db.session.commit()


@app.before_request
def _load_globals():
    """Get the session's user and the global state object for the
    request.
    """
    if 'userid' in session:
        g.user = User.query.filter_by(id=session['userid']).first()
        if g.user is not None:
            g.admin = g.user.admin
    else:
        g.user = None
        g.admin = False

    g.state = State.query.first()


# Jinja2 template elements.

@app.template_filter('price')
def _price_filter(value):
    """A template filter for formatting prices in dollars and cents.
    """
    negative = value < 0
    if negative:
        value = 0 - value
    value = Decimal(value).quantize(Decimal('1.00'))
    out = u'${0}'.format(value)
    if negative:
        out = u'-' + out
    return out


@app.template_filter('pennies')
def _pennies_filter(value):
    """A template filter that formats a price as an integer number of
    pennies. This is useful for plumbing when communicating prices to
    the JavaScript frontend without resorting to floating-point.
    """
    return unicode(int(value * 100))


@app.template_filter('dt')
def _datetime_filter(value, withtime=False):
    """Format a `datetime` object as a human-readable string. `withtime`
    indicates whether this should be just a day or a day with a time.
    """
    if value is None:
        return ''

    if not value.tzinfo:
        value = pytz.utc.localize(value)
    value = value.astimezone(pytz.timezone(g.state['timezone']))

    fmt = '%B %-e, %Y'
    if withtime:
        fmt += ', %-l:%M %p'
    return value.strftime(fmt)


# Data access helper.

def all_harvests():
    """Get a list of harvest dates for which orders have been placed.
    """
    res = db.session.query(sqlalchemy.distinct(Order.harvested)) \
                    .filter(Order.harvested is not None) \
                    .order_by(Order.harvested) \
                    .all()
    return [r[0] for r in res]


# Authentication decorators.

def administrative(func):
    """Decorator for pages accessible only to administrators."""
    def wrapped(*args, **kwargs):
        if not g.admin:
            abort(403)
        return func(*args, **kwargs)
    wrapped.__name__ = func.__name__
    return wrapped


def authenticated(func):
    """Decorator for pages accessible only when logged in."""
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect('{}?{}'.format(
                url_for('main'),
                urllib.urlencode({'next': request.url}),
            ))
        return func(*args, **kwargs)
    wrapped.__name__ = func.__name__
    return wrapped


# The routes themselves.

@app.route("/")
def main():
    """The home page. Either show the login form or redirect to a
    relevant front page for the logged-in user.
    """
    if g.user:
        if g.user.admin:
            return redirect(url_for('availability'))
        else:
            return redirect(url_for('order'))
    else:
        return render_template('login.html', next=_next_url())


@app.route("/login", methods=['POST'])
def login():
    """Handle a login form request. Show the login page on failure or
    redirect to an appropriate destination on success.
    """
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter(
        db.func.lower(User.email) == email.strip().lower()
    ).first()
    if user is not None and user.password == _hash_pass(password):
        # Successful login.
        session['userid'] = user.id
        session.permanent = True
        return redirect(_next_url())
    else:
        # Login failed.
        flash('Please try again.', 'error')
        return render_template('login.html')


@app.route("/logout")
def logout():
    """Handle a logout request and redirect home.
    """
    if 'userid' in session:
        del session['userid']
        session.permanent = False
    return redirect(url_for('main'))


@app.route("/register", methods=['POST'])
def register():
    """Handle an account registration request.

    At the moment, this just sends an email to the farmers asking them
    to set up an account.
    """
    name = request.form['name']
    email = request.form['email']

    # Send email to farmers.
    subs = {
        'name': name,
        'email': email,
        'farm': g.state['farm'],
        'url': url_for('customers', _external=True),
    }
    send_email(
        [u.email for u in User.query.filter_by(admin=True)],
        g.state['register_subject'].format(**subs),
        g.state['register_body'].format(**subs),
    )

    flash(g.state['register_success'], 'success')
    return render_template('login.html')


@app.route("/products", methods=['GET', 'POST'])
def products():
    """Show or add to the list of available products.
    """
    if g.admin:
        if request.method == 'POST':
            product = Product(
                request.form['name'],
                _parse_price(request.form['price']),
                request.form['link'],
            )
            db.session.add(product)
            db.session.commit()
        return render_template('products.html', products=Product.query.all())

    else:
        return render_template(
            'product_preview.html',
            products=Product.query.filter_by(available=True).all(),
        )


@app.route("/products/<int:product_id>", methods=['POST', 'DELETE'])
@administrative
def product(product_id):
    """Update or delete an existing product.
    """
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        product.name = request.form['name']
        product.price = _parse_price(request.form['price'])
        product.link = request.form['link']
        product.infer_photo()
        db.session.commit()
    elif request.method == 'DELETE':
        db.session.delete(product)
        db.session.commit()

    return redirect(url_for('products'))


@administrative
def _show_harvest(dt):
    """Helper: render a page depicting the products harvested at a
    particular timestamp.
    """
    orders = Order.query.filter_by(harvested=dt).all()
    order_ids = [o.id for o in orders]
    # There is almost certainly a real query for this.
    product_info = []
    for product in Product.query:
        items = product.ordered.filter(OrderItem.order_id.in_(order_ids)).all()
        if items:
            total = sum(item.count for item in items)
            product_info.append((product, items, total))

    return render_template('harvest.html',
                           orders=orders,
                           product_info=product_info,
                           harvestdt=dt)


@app.route("/harvests/latest")
def latest_harvest():
    """Show the products harvested most recently.
    """
    harvests = all_harvests()
    if not harvests:
        abort(404)
    return _show_harvest(harvests[-1])


@app.route("/harvests/<int:year>-<int:month>-<int:day>")
def harvest(year, month, day):
    """Show the products harvested on a particular day.
    """
    target = datetime.date(year, month, day)
    for harvest in all_harvests():
        app.logger.info('{} {}'.format(harvest, target))
        if harvest.date() == target:
            return _show_harvest(harvest)
    abort(404)


@app.route("/harvests")
@administrative
def harvests():
    """Show a list of harvest dates with links to details.
    """
    return render_template('harvests.html', harvests=all_harvests())


def _order_counts():
    """Get a dictionary mapping Products to integer counts from the
    order form.
    """
    out = {}
    prefix = app.config['ORDER_COUNT_PREFIX']
    for key, value in request.form.items():
        if key.startswith(prefix) and value:
            product_id = int(key[len(prefix):])
            product = Product.query.filter_by(id=product_id).first()
            count = int(value)
            if count:
                out[product] = int(value)
    return out


def _place_order(user):
    """Display or handle an order form.

    Used for both customer- and farmer-initiated orders.
    """
    if request.method == 'GET':
        previous_order = None
        for order in user.orders:
            if order.harvested == g.state.next_harvest:
                previous_order = order
                break

        if previous_order:
            return render_template('already_ordered.html', order=order)
        else:
            return render_template(
                'order.html',
                products=Product.query.filter_by(available=True),
                user=user,
            )

    # Create a new order.
    order = Order(user)
    db.session.add(order)
    for product, count in _order_counts().items():
        item = OrderItem(order, product, count)
        db.session.add(item)
    db.session.commit()

    # Email the receipt.
    # Eventually, if possible, this should be moved off the critical
    # path to a task queue.
    send_receipt(order)

    return redirect(url_for('receipt', order_id=order.id))


@app.route("/order", methods=['GET', 'POST'])
@authenticated
def order():
    """An order form for the logged-in user.
    """
    if request.method == 'POST':
        if request.form.get('pickup'):
            g.user.delivery_notes = request.form.get('pickup')

    return _place_order(g.user)


@app.route("/order/<int:user_id>", methods=['GET', 'POST'])
@administrative
def order_for(user_id):
    """An order form on behalf of a different user (initiated by a
    farmer).
    """
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        if request.form.get('pickup'):
            user.delivery_notes = request.form.get('pickup')

    return _place_order(user)


@app.route("/fruit", methods=['POST'])
@administrative
def fruit():
    """Add a credit/debit transaction for all users with fruit shares.
    """
    fruitUsers = []

    for user in User.query.filter_by(admin=False).all():
        if user['fruit']:
            fruitUsers.append(user)
            txn = CreditDebit(
                user,
                _parse_price(request.form['amount']),
                request.form['description'],
            )
            db.session.add(txn)
            db.session.commit()

    return render_template('fruit.html', amount=request.form['amount'],
                           users=fruitUsers)


@app.route("/customer/<int:user_id>/creditdebit", methods=['POST'])
@administrative
def new_creditdebit(user_id):
    """Add a credit/debit transaction for some user.
    """
    user = User.query.get_or_404(user_id)

    txn = CreditDebit(
        user,
        _parse_price(request.form['amount']),
        request.form['description'],
    )
    db.session.add(txn)
    db.session.commit()

    return redirect(url_for('customer', user_id=user.id))


@app.route("/creditdebit/<int:txn_id>",
           methods=['GET', 'POST', 'DELETE'])
@administrative
def creditdebit(txn_id):
    """Show, edit, or delete an existing credit/debit transaction.
    """
    txn = CreditDebit.query.get_or_404(txn_id)

    if request.method == 'GET':
        return render_template('creditdebit.html', transaction=txn)

    elif request.method == 'POST':
        txn.description = request.form['description']
        txn.amount = _parse_price(request.form['amount'])
        txn.date = _parse_dt(request.form['date'])
        db.session.commit()
        return redirect(url_for('customer', user_id=txn.customer.id))

    elif request.method == 'DELETE':
        db.session.delete(txn)
        db.session.commit()
        return redirect(url_for('customer', user_id=txn.customer.id))


@app.route("/orders/<int:order_id>", methods=['GET', 'POST', 'DELETE'])
@administrative
def edit_order(order_id):
    """Show a form to edit an existing order.
    """
    order = Order.query.get_or_404(order_id)

    if request.method == 'DELETE':
        db.session.delete(order)
        db.session.commit()
        return redirect(url_for('harvests'))

    if request.method == 'POST':
        order.placed = _parse_dt(request.form['placed'])
        order.harvested = _parse_dt(request.form['harvested'])
        for product, count in _order_counts().items():
            item = order.items_by_product.get(product)
            if item:
                item.count = count
            else:
                item = OrderItem(order, product, count)
                db.session.add(item)
        db.session.commit()

    return render_template('edit_order.html',
                           order=order,
                           products=Product.query.all())


@app.route("/orders/<int:order_id>/receipt")
@authenticated
def receipt(order_id):
    """Show the receipt for an existing order.
    """
    order = Order.query.get_or_404(order_id)
    if order.customer.id != g.user.id and not g.admin:
        abort(403)
    return render_template('receipt.html', order=order)


@app.route("/customers", methods=['GET', 'POST'])
@administrative
def customers():
    """Show a list of users.
    """
    if request.method == 'POST':
        password = _random_string(10)
        user = User(request.form['email'], request.form['name'],
                    password, False)
        db.session.add(user)
        db.session.commit()
        action = u'Added user {} with password {}.'.format(
            user.email, password
        )

    else:
        action = None

    return render_template(
        'customers.html',
        customers=User.query.filter_by(admin=False).order_by(User.name).all(),
        farmers=User.query.filter_by(admin=True).order_by(User.name).all(),
        action=action,
    )


@app.route("/customer/<int:user_id>", methods=['GET', 'POST', 'DELETE'])
@authenticated
def customer(user_id):
    """Show or update an existing user's profile.
    """
    user = User.query.filter_by(id=user_id).first()
    if g.admin:
        if not user:
            abort(404)
    else:
        if user is None or user.id != g.user.id:
            abort(403)

    if request.method == 'POST':
        if request.form.get('name'):
            user.name = request.form['name']
        if request.form.get('email'):
            user.email = request.form['email']
        if request.form.get('password'):
            user.password = _hash_pass(request.form['password'])
        if request.form.get('delivery_notes'):
            user.delivery_notes = request.form['delivery_notes']
        if request.form.get('pickup'):
            user.delivery_notes = request.form.get('pickup')

        if g.admin:
            user.admin = bool(request.form.get('farmer'))
            user['fruit'] = bool(request.form.get('fruit'))

        db.session.commit()

        if g.admin:
            return redirect(url_for('customers'))
        else:
            return redirect(url_for('main'))

    elif request.method == 'DELETE':
        if not g.admin:
            abort(403)
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('customers'))

    else:
        return render_template('customer.html', user=user)


@app.route("/availability", methods=['GET', 'POST'])
@administrative
def availability():
    """Show a list of products or update those products' "available"
    flag.
    """
    if request.method == 'POST':
        # Set harvest date & message.
        g.state.next_harvest = _parse_dt(request.form['next_harvest'])
        g.state['order_message'] = request.form['order_message'].strip()

        # Gather products to mark as available.
        available_ids = []
        for key, value in request.form.items():
            if key.startswith(app.config['AVAILABLE_PREFIX']) and value:
                available_ids.append(
                    int(key[len(app.config['AVAILABLE_PREFIX']):])
                )

        # Clear all flags and set specific ones.
        Product.query.update({
            'available': Product.id.in_(available_ids)
        }, synchronize_session=False)

        db.session.commit()

    return render_template('availability.html', products=Product.query.all())


@app.route("/admin", methods=['GET', 'POST'])
@administrative
def admin():
    """Show or update the site's settings.
    """
    if request.method == 'POST':
        values = {}
        for key in app.config['ADMIN_SETTINGS']:
            values[key] = request.form[key]
        g.state.update(values)
        db.session.commit()

    return render_template('admin.html')


if __name__ == '__main__':
    app.run()

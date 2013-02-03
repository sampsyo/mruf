from flask import Flask
from flask import request, session, redirect, url_for, render_template, g
from flask import abort
from flask.ext.sqlalchemy import SQLAlchemy
import pbkdf2
from decimal import Decimal
import sqlalchemy
import string
import random
import datetime
from parsedatetime import parsedatetime
import time
from werkzeug import url_decode
import requests


app = Flask(__name__)
app.config.update(
    ORDER_COUNT_PREFIX=u'order_',
    AVAILABLE_PREFIX=u'available_',
)
app.config.from_pyfile('mruf.cfg')
db = SQLAlchemy(app)


# http://flask.pocoo.org/snippets/38/
class MethodRewriteMiddleware(object):
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


# Utilities.

def _hash_pass(password):
    if isinstance(password, unicode):
        password = password.encode('utf8')
    return pbkdf2.pbkdf2_hex(password, app.config['SALT'])

def _parse_price(s):
    if s.startswith('$'):
        s = s[1:]
    return Decimal(s).quantize(Decimal('1.00'))

_calendar = parsedatetime.Calendar()
def _parse_dt(s):
    ts, _ = _calendar.parse(s)
    return datetime.datetime.fromtimestamp(time.mktime(ts))

def _random_string(length=20, chars=(string.ascii_letters + string.digits)):
    return ''.join(random.choice(chars) for i in range(length))


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

def send_receipt(order):
    farmer_addrs = [u.email for u in User.query.filter_by(admin=True)]
    mailgun_send(
        app.config['MAILGUN_API_KEY'],
        app.config['MAILGUN_DOMAIN'],
        app.config['MAIL_FROM'],
        [order.customer.email],
        app.config['RECEIPT_SUBJECT'],
        app.config['RECEIPT_BODY'].format(
            name=order.customer.name,
            receipt_url=url_for('receipt', order_id=order.id, _external=True),
            farm=g.state.farm,
        ),
        bcc_addrs=farmer_addrs,
    )


class IntegerDecimal(sqlalchemy.types.TypeDecorator):
    impl = sqlalchemy.types.Integer
    _unitsize = 100

    def process_bind_param(self, value, dialect):
        value = Decimal(value)
        return int(value * self._unitsize)

    def process_result_value(self, value, dialect):
        return Decimal(value) / self._unitsize


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Unicode(256), unique=True)
    name = db.Column(db.Unicode(512))
    password = db.Column(db.String(256))
    admin = db.Column(db.Boolean)
    delivery_notes = db.Column(db.UnicodeText)

    def __init__(self, email, name, password, admin):
        self.email = email
        self.name = name
        self.password = _hash_pass(password)
        self.admin = admin

    def __repr__(self):
        return '<User {0}>'.format(self.email)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    customer = db.relationship('User',
                               backref=db.backref('orders', lazy='dynamic'))
    placed = db.Column(db.DateTime)
    harvested = db.Column(db.DateTime)

    def __init__(self, customer):
        self.customer = customer
        self.placed = datetime.datetime.now()
        self.harvested = g.state.next_harvest

    def __repr__(self):
        return '<Order {0} for {1}>'.format(self.id, self.customer.email)

    @property
    def total(self):
        total = Decimal('0.00')
        for item in self.items:
            total += item.cost
        return total

    @property
    def items_by_product(self):
        out = {}
        for item in self.items:
            out[item.product] = item
        return out

class OrderItem(db.Model):
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

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(256))
    price = db.Column(IntegerDecimal)
    available = db.Column(db.Boolean)

    def __init__(self, name, price):
        self.name = name
        self.price = price
        self.order_by = None

    def __repr__(self):
        return '<Product {0}>'.format(self.name)

class State(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    next_harvest = db.Column(db.DateTime())
    closed_message = db.Column(db.UnicodeText())
    farm = db.Column(db.Unicode(128))

    def __init__(self):
        self.next_harvest = datetime.datetime.now()
        self.closed_message = u'Orders are currently closed.'
        self.farm = u'Farm Name'

    @property
    def open(self):
        if self.next_harvest is None:
            return False
        return self.next_harvest > datetime.datetime.now()


@app.before_request
def _load_globals():
    if 'userid' in session:
        g.user = User.query.filter_by(id=session['userid']).first()
        if g.user is not None:
            g.admin = g.user.admin
    else:
        g.user = None
        g.admin = False

    g.state = State.query.first()

@app.template_filter('price')
def _price_filter(value):
    value = Decimal(value).quantize(Decimal('1.00'))
    return u'${0}'.format(value)

@app.template_filter('pennies')
def _pennies_filter(value):
    return unicode(int(value * 100))

@app.template_filter('dt')
def _datetime_filter(value, withtime=False):
    if value is None:
        return ''
    fmt = '%B %-e, %Y'
    if withtime:
        fmt += ', %-l:%M %p'
    return value.strftime(fmt)

def all_harvests():
    """Get a list of harvest dates for which orders have been placed.
    """
    res = db.session.query(sqlalchemy.distinct(Order.harvested)) \
                    .filter(Order.harvested != None) \
                    .order_by(Order.harvested) \
                    .all()
    return [r[0] for r in res]

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
            abort(403)
        return func(*args, **kwargs)
    wrapped.__name__ = func.__name__
    return wrapped


@app.route("/")
def main():
    if g.user:
        if g.user.admin:
            return redirect(url_for('availability'))
        else:
            return redirect(url_for('order'))
    else:
        return render_template('login.html')

@app.route("/login", methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter(
        db.func.lower(User.email) == email.strip().lower()
    ).first()
    if user is not None and user.password == _hash_pass(password):
        # Successful login.
        session['userid'] = user.id
        return redirect(url_for('main'))
    else:
        # Login failed.
        return render_template('login.html', error='Please try again.')

@app.route("/logout")
def logout():
    if 'userid' in session:
        del session['userid']
    return redirect(url_for('main'))

@app.route("/products", methods=['GET', 'POST'])
def products():
    if g.admin:
        if request.method == 'POST':
            name = request.form['name']
            price = _parse_price(request.form['price'])
            product = Product(name, price)
            db.session.add(product)
            db.session.commit()
        return render_template('products.html', products=Product.query.all())
    
    else:
        return render_template('product_preview.html',
            products=Product.query.filter_by(available=True).all()
        )

@app.route("/products/<int:product_id>", methods=['POST', 'DELETE'])
@administrative
def product(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        product.name = request.form['name']
        product.price = _parse_price(request.form['price'])
        db.session.commit()
    elif request.method == 'DELETE':
        db.session.delete(product)
        db.session.commit()

    return redirect(url_for('products'))

@administrative
def _show_harvest(dt):
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
    harvests = all_harvests()
    if not harvests:
        abort(404)
    return _show_harvest(harvests[-1])

@app.route("/harvests/<int:year>-<int:month>-<int:day>")
def harvest(year, month, day):
    target = datetime.date(year, month, day)
    for harvest in all_harvests():
        app.logger.info('{} {}'.format(harvest.date(), target))
        if harvest.date() == target:
            return _show_harvest(harvest)
    abort(404)

@app.route("/harvests")
@administrative
def harvests():
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
    if request.method == 'GET':
        previous_order = None
        for order in user.orders:
            if order.harvested == g.state.next_harvest:
                previous_order = order
                break

        if previous_order:
            return render_template('already_ordered.html', order=order)
        else:
            return render_template('order.html',
                products=Product.query.filter_by(available=True),
                user=user
            )

    # Create a new order.
    order = Order(user)
    db.session.add(order)
    for product, count in _order_counts().items():
        item = OrderItem(order, product, count)
        db.session.add(item)
    db.session.commit()

    # Email the receipt.
    send_receipt(order)

    return redirect(url_for('receipt', order_id=order.id))

@app.route("/order", methods=['GET', 'POST'])
@authenticated
def order():
    return _place_order(g.user)

@app.route("/order/<int:user_id>", methods=['GET', 'POST'])
@administrative
def order_for(user_id):
    user = User.query.get_or_404(user_id)
    return _place_order(user)

@app.route("/orders/<int:order_id>", methods=['GET', 'POST'])
@administrative
def edit_order(order_id):
    order = Order.query.get_or_404(order_id)

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
    order = Order.query.get_or_404(order_id)
    if order.customer.id != g.user.id and not g.admin:
        abort(403)
    return render_template('receipt.html', order=order)

@app.route("/customers", methods=['GET', 'POST'])
@administrative
def customers():
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

    return render_template('customers.html',
                           customers=User.query.filter_by(admin=False).all(),
                           farmers=User.query.filter_by(admin=True).all(),
                           action=action)

@app.route("/customer/<int:user_id>", methods=['GET', 'POST'])
@authenticated
def customer(user_id):
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
        if g.admin:
            if request.form.get('farmer'):
                user.admin = True
            else:
                user.admin = False

        db.session.commit()

        if g.admin:
            return redirect(url_for('customers'))
        else:
            return redirect(url_for('main'))

    else:
        return render_template('customer.html', user=user)

@app.route("/availability", methods=['GET', 'POST'])
@administrative
def availability():
    if request.method == 'POST':
        # Set harvest date.
        g.state.next_harvest = _parse_dt(request.form['next_harvest'])

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
    if request.method == 'POST':
        g.state.closed_message = request.form['closed_message']
        g.state.farm = request.form['farm']
        db.session.commit()

    return render_template('admin.html')


if __name__ == '__main__':
    app.run()

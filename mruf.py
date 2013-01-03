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

    def __init__(self):
        self.next_harvest = datetime.datetime.now()
        self.closed_message = u'Orders are currently closed.'

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
    user = User.query.filter_by(email=email).first()
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
def product(product_id):
    if not g.admin:
        abort(403)
    product = Product.query.filter_by(id=product_id).first()
    if not product:
        abort(404)

    if request.method == 'POST':
        product.name = request.form['name']
        product.price = _parse_price(request.form['price'])
        db.session.commit()
    elif request.method == 'DELETE':
        db.session.delete(product)
        db.session.commit()

    return redirect(url_for('products'))

def _show_harvest(dt):
    if not g.admin:
        abort(403)

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
    return _show_harvest(harvests[0])

@app.route("/harvests/<int:year>-<int:month>-<int:day>")
def harvest(year, month, day):
    target = datetime.date(year, month, day)
    for harvest in all_harvests():
        app.logger.info('{} {}'.format(harvest.date(), target))
        if harvest.date() == target:
            return _show_harvest(harvest)
    abort(404)

@app.route("/harvests")
def harvests():
    if not g.admin:
        abort(403)
    return render_template('harvests.html', harvests=all_harvests())

@app.route("/order", methods=['GET', 'POST'])
def order():
    if g.user is None:
        abort(403)

    if request.method == 'GET':
        return render_template('order.html',
            products=Product.query.filter_by(available=True)
        )

    # Create a new order.
    order = Order(g.user)
    db.session.add(order)
    prefix = app.config['ORDER_COUNT_PREFIX']
    for key, value in request.form.items():
        if key.startswith(prefix) and value:
            product_id = int(key[len(prefix):])
            product = Product.query.filter_by(id=product_id).first()
            item = OrderItem(order, product, int(value))
            db.session.add(item)
    db.session.commit()

    return redirect(url_for('receipt', order_id=order.id))

@app.route("/orders")
def orders():
    if g.user is None:
        abort(403)

    return render_template('orders.html',
                           orders=Order.query.filter_by(customer=g.user).all())

@app.route("/orders/<int:order_id>/receipt")
def receipt(order_id):
    if g.user is None:
        abort(403)
    order = Order.query.filter_by(id=order_id).first()
    if not order:
        abort(404)
    if order.customer.id != g.user.id and not g.admin:
        abort(403)
    return render_template('receipt.html', order=order)

@app.route("/customers", methods=['GET', 'POST'])
def customers():
    if not g.admin:
        abort(403)

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
                           users=User.query.filter_by(admin=False).all(),
                           action=action)

@app.route("/customer/<int:user_id>", methods=['GET', 'POST'])
def customer(user_id):
    user = User.query.filter_by(id=user_id).first()
    if g.user is None:
        abort(403)
    elif g.admin:
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

        db.session.commit()

        if g.admin:
            return redirect(url_for('customers'))
        else:
            return redirect(url_for('main'))

    else:
        return render_template('customer.html', user=user)

@app.route("/availability", methods=['GET', 'POST'])
def availability():
    if not g.admin:
        abort(403)

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
def admin():
    if not g.admin:
        abort(403)

    if request.method == 'POST':
        g.state.closed_message = request.form['closed_message']
        db.session.commit()

    return render_template('admin.html')


if __name__ == '__main__':
    app.run()

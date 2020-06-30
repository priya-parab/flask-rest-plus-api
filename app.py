from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_restplus import Api,fields,Resource
from werkzeug.utils import cached_property
import datetime
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
import jwt


app = Flask(__name__)

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}
api = Api(title='Swagger-UI',description="List of API's ",validate=True, authorizations=authorizations,
    security='apikey')

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:''@localhost/flask_restplus'
app.config['SECRET_KEY'] = 'random key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
ma = Marshmallow(app)
api.init_app(app)

class User(db.Model):
    __tablename__ = 'User'
    id = db.Column('User_id', db.Integer, primary_key=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(256),nullable=False)
    created_date = db.Column(db.DateTime(),default=datetime.datetime.utcnow)
    admin = db.Column(db.Boolean,default=0)

class Product(db.Model):
    __tablename__ = 'Product'
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, default=0)
    image = db.Column(db.String(256), default=0)

db.create_all()

class UserSchema(ma.Schema):
    class Meta:
        fields = ('id','email','name','password','created_date','admin')

user_model = api.model('User',{'name':fields.String(required=True),
                          'email':fields.String(required=True),
                          'password':fields.String(required=True),
                          'created_date':fields.DateTime(required=True),
                          'admin':fields.Boolean(required=True)
                          })

user_schema = UserSchema()
users_schema = UserSchema(many=True)

class ProductSchema(ma.Schema):
    class Meta:
        fields = ('id', 'sku', 'name', 'price', 'quantity', 'description', 'image')

product_model = api.model('Product',{'name':fields.String(required=True),
                          'sku': fields.String(required=True),
                          'price': fields.Float(required=True),
                          'quantity': fields.Integer(required=True),
                          'image': fields.String(required=True),
                           'description': fields.String()
                          })

product_schema = ProductSchema()
products_schema = ProductSchema(many=True)

login = api.model('login', {'email': fields.String("Enter name"), 'password': fields.String()})

def token_required(function):
    @wraps(function)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
            return {'message': 'Token is missing'}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(email=data['email']).first()
        except:
            return {'message': 'Token is invalid!'}, 401
        return function(*args, current_user, **kwargs)
    return decorated

user_ns = api.namespace('User Requests',description='User')
@user_ns.route('/get_all_users')
class get_users(Resource):
    @api.doc(security='apikey')
    @token_required
    def get(self, current_user):

        if not current_user.admin:
            return {'message': 'Cannot perform that function!'}, 401

        return users_schema.dump(User.query.all())


@user_ns.route('/login')
class login(Resource):
    @api.expect(login)
    def post(self):
        email = request.json['email']
        password = request.json['password']
        if not email:
            return {'message': 'Please Enter Email'}, 401
        if not password:
            return {'message': 'Please Enter Password'}, 401
        if email and password:
            user = User.query.filter_by(email=email).first()
            if not user:
                return {'message': 'Email is not registered'}, 401
            else:
                if check_password_hash(user.password, password):
                    token = jwt.encode({'email': user.email, 'exp': datetime.datetime.utcnow() +
                                        datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
                    return {'token': token.decode('UTF-8')}
                else:
                    return {'message': 'Password is wrong'}, 401


@user_ns.route('/sign_up')
class add_user(Resource):
    @api.expect(user_model)
    def post(self):
        if User.query.filter_by(email=request.json['email']).first():
            return {'message': 'EmailID already Exist'}
        else:
            try:
                hashed_password = generate_password_hash(request.json['password'], method='sha256')
                new_user = User(name=request.json['name'],password=hashed_password,admin=request.json['admin'],
                    email=request.json['email'])
                db.session.add(new_user)
                db.session.commit()
                return {'message': 'User added to database'}
            except Exception as e:
                return {'message': 'Error {}'.format(e)}

@user_ns.route('/update_user/<int:id>')
class update_user(Resource):
    @api.expect(user_model)
    @api.doc(security='apikey')
    @token_required
    def put(self, current_user, id):

        if not current_user.admin:
            return {'message': 'Cannot perform that function!'}, 401
        try:
            user = User.query.get(id)
            user.name = request.json['name']
            user.email = request.json['email']
            user.password = generate_password_hash(request.json['password'], method='sha256')
            user.admin = request.json['admin']
            db.session.commit()
            return {'message': 'User updated to database'}
        except Exception as e:
            return {'message': 'Error {}'.format(e)}


@user_ns.route('/delete_user/<int:id>')
class delete_user(Resource):
    @api.doc(security='apikey')
    @token_required
    def delete(self, current_user, id):

        if not current_user.admin:
            return {'message': 'Cannot perform that function!'}, 401

        user = User.query.get(id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return {'message': 'User deleted from database'}
        else:
            return {'message': 'No User found'}


product_ns = api.namespace("Product Requests",description='Product')
@product_ns.route('/get_all_products')
class get_products(Resource):
    @api.doc(security='apikey')
    @token_required
    def get(self,current_user):

        if not current_user.admin:
            return {'message': 'Cannot perform that function!'}, 401

        return products_schema.dump(Product.query.all())

@product_ns.route('/add_product')
class add_product(Resource):
    @api.expect(product_model)
    @api.doc(security='apikey')
    @token_required
    def post(self, current_user):

        if not current_user.admin:
            return {'message': 'Cannot perform that function!'}, 401

        if Product.query.filter_by(sku=request.json['sku']).first():
            return jsonify({'message': 'Entry already Exist'})
        else:
            try:
                new_product = Product(name=request.json['name'],price=request.json['price'],sku=request.json['sku'],
                    quantity=request.json['quantity'],description=request.json['description'],image=request.json['image'])
                db.session.add(new_product)
                db.session.commit()
                return {'message': 'Product added to database'}
            except Exception as e:
                return {'message': 'Error {}'.format(e)}


@product_ns.route('/update_product/<int:id>')
class update_product(Resource):
    @api.expect(product_model)
    @api.doc(security='apikey')
    @token_required
    def put(self, current_user, id):

        if not current_user.admin:
            return {'message': 'Cannot perform that function!'}, 401

        try:
            product = Product.query.get(id)
            product.name = request.json['name']
            product.sku = request.json['sku']
            product.price = request.json['price']
            product.quantity = request.json['quantity']
            product.description = request.json['description']
            product.image = request.json['image']
            db.session.commit()
            return {'message': 'Product updated to database'}
        except Exception as e:
            return {'message': 'Error {}'.format(e)}

@product_ns.route('/delete_product/<int:id>')
class delete_product(Resource):
    @api.doc(security='apikey')
    @token_required
    def delete(self, current_user, id):

        if not current_user.admin:
            return {'message': 'Cannot perform that function!'}, 401

        product = Product.query.get(id)
        if product:
            db.session.delete(product)
            db.session.commit()
            return {'message': 'Product deleted from database'}
        else:
            return {'message': 'No Product found'}


if __name__ == '__main__':
   app.run(debug=True)
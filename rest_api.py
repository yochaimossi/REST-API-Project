from flask import Flask, request, jsonify, make_response
from Customer import Customer
from User import User
from Logger import Logger
from RestDataAccess import RestDataAccess
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = 'My Secret Key'

dao = RestDataAccess('REST_API_DB.db')
logger = Logger.get_instance()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
            token = token.removeprefix('Bearer ')
        # return 401 if token is not passed
        if not token:
            logger.logger.info('A user tried to used a function that requires token but token is missing.')
            return jsonify({'message': 'Token is missing'}), 401

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            logger.logger.warning('The token the user tried to use is not valid.')
            return jsonify({'message': 'Token is not valid'}), 401

        return f(*args, **kwargs)
    return decorated


@app.route("/")
def home():
    return '''
        <html>
            Just a random page
        </html>
    '''

@app.route('/customers', methods=['GET', 'POST'])
@token_required
def get_or_post_customer():
    if request.method == 'GET':
        search_args = request.args.to_dict()
        customers = dao.get_all_customers(search_args)
        return jsonify(customers)
    if request.method == 'POST':
        customer_data = request.get_json()
        inserted_customer = Customer(id_=None, name=customer_data["name"], city=customer_data["city"])
        answer = dao.insert_new_customer(inserted_customer)
        if answer:
            logger.logger.info(f'New customer: {inserted_customer} has been created!')
            return make_response('Customer Created!', 201)
        else:
            logger.logger.error('To insert new customer must sent both "name" and "city"')
            return jsonify({'answer': 'failed'})


@app.route('/customers/<int:id_>', methods=['GET', 'PUT', 'DELETE', 'PATCH'])
@token_required
def get_customer_by_id(id_):
    if request.method == 'GET':
        customer = dao.get_customer_by_id(id_)
        return jsonify(customer)
    if request.method == 'PUT':
        values_dict = request.get_json()
        answer = dao.update_put_customer(id_, values_dict)
        if answer:
            logger.logger.info(f'The customer with the id: {id_} has been updated!')
            return make_response('Updated!', 201)
        else:
            logger.logger.error(f'Could not update the customer with the id: {id_}')
            return jsonify({'answer': 'failed'})
    if request.method == 'DELETE':
        answer = dao.delete_customer(id_)
        if answer:
            logger.logger.info(f'The customer with the id: {id_} has been deleted!')
            return make_response('Deleted!', 201)
        else:
            logger.logger.error(f'Could not delete a customer with the id: {id_}')
            return jsonify({'answer': 'failed'})
    if request.method == 'PATCH':
        values_dict = request.get_json()
        answer = dao.update_patch_customer(id_, values_dict)
        if answer:
            logger.logger.info(f'The customer with the id: {id_} has been updated!')
            return make_response('Updated!', 201)
        else:
            logger.logger.info(f'Could not update the customer with the id: {id_}')
            return jsonify({'answer': 'failed'})


@app.route('/signup', methods=['POST'])
def signup():
    form_data = request.form

    username = form_data.get('username')
    password = form_data.get('password')

    user = dao.get_user_by_username(username)

    if user:
        logger.logger.error(f'An anonymous user tried to sign up with the username:{username} but this username already '
                            f'exists in the db')
        return make_response('User already exists. Please Log in.', 202)

    else:
        inserted_user = User(id_=None, username=username, password=generate_password_hash(password))
        dao.insert_new_user(inserted_user)
        logger.logger.info(f'New user: {inserted_user} has been created successfully!')
        return make_response('Successfully registered.', 201)


@app.route('/login', methods=['POST'])
def login():
    form_data = request.form

    if not form_data or not form_data.get('username') or not form_data.get('password'):
        logger.logger.info('A user tried to login without sending the required data(username, password)')
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required."'})

    user = dao.get_user_by_username(form_data.get('username'))
    if not user:
        logger.logger.warning(f'A user tried to login but the username:{form_data.get("username")} '
                              f'does not exist in the db')
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required."'})

    if not check_password_hash(user.password, form_data.get('password')):
        logger.logger.error(f'The user: {form_data.get("username")} tried to login with a wrong password.')
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required."'})

    logger.logger.debug(f'The user: {form_data.get("username")} logged in successfully!')
    token = jwt.encode({'id': user.id_, 'exp': datetime.now() + timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return make_response(jsonify({'token': token.decode('UTF-8')}), 201)


if __name__ == "__main__":
    # setting debug to True enables hot reload
    # and also provides a debuger shell
    # if you hit an error while running the server
    app.run(debug=True)
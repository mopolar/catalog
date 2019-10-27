#!/usr/bin/env python3


from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash, make_response
from flask import session as login_session
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, League, Club, User
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from pprint import pprint
import httplib2
import random
import string
import json
import requests


app = Flask(__name__)

# Load the Google Sign-in API Client ID.
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# Connect to the database and create a database session.
engine = create_engine('engine = create_engine('postgresql://catalog:polar@localhost/catalog')',
                       connect_args={'check_same_thread': False})

# Bind the above engine to a session.
Session = sessionmaker(bind=engine)

# Create a Session object.
session = Session()


# Create anti-forgery state token
@app.route('/login/')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state)


# Connect to the Google Sign-in oAuth method.
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_google_id = login_session.get('google_id')
    if stored_access_token is not None and google_id == stored_google_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['google_id'] = google_id

    # Get user info.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    # Assing Email as name if User does not have Google+
    if "name" in data:
        login_session['username'] = data['name']
    else:
        name_corp = data['email'][:data['email'].find("@")]
        login_session['username'] = name_corp
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if the user exists. If it doesn't, make a new one.
    user_id = get_user_id(data["email"])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    # Show a welcome screen upon successful login.
    output = ''
    output += '<h2>Welcome, '
    output += login_session['username']
    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px; '
    output += 'border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("You are now logged in as %s!" % login_session['username'])
    print("Done!")
    return output


# Disconnect Google Account.
def gdisconnect():
    # Only disconnect the connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Log out the currently connected user.
@app.route('/logout')
def logout():
    if 'username' in login_session:
        gdisconnect()
        del login_session['google_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have been successfully logged out!")
        return redirect(url_for('home'))
    else:
        flash("You were not logged in!")
        return redirect(url_for('home'))


# Create new user.
def create_user(login_session):
    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Redirect to home page.
@app.route('/')
def home():
    return render_template('home_page.html')


# Redirect to leagues page.
@app.route('/leagues/')
def leagues():
    leagues = session.query(League).all()
    return render_template('categories.html', leagues=leagues)


# add new league.
@app.route('/leagues/new/', methods=['GET', 'POST'])
def add_league():
    if 'username' not in login_session:
        flash("Please log in to continue.")
        return redirect(url_for('login'))
    elif request.method == 'POST':
        if request.form['new-category-name'] == '':
            flash('The field cannot be empty.')
            return redirect(url_for('add_league'))

        category = session.query(League).\
            filter_by(name=request.form['new-category-name']).first()
        if category is not None:
            flash('The entered category already exists.')
            return redirect(url_for('add_league'))

        new_category = League(
            name=request.form['new-category-name'],
            user_id=login_session['user_id'])
        session.add(new_category)
        session.commit()
        flash('New category %s successfully created!' % new_category.id)
        return redirect(url_for('leagues'))
    else:
        return render_template('new_category.html')


# edit league.
@app.route('/leagues/<int:league_id>/edit/', methods=['GET', 'POST'])
def edit_league(league_id):
    category = session.query(League).filter_by(id=league_id).first()
    if 'username' not in login_session:
        flash("Please log in to continue.")
        return redirect(url_for('login'))
    if not exists_league(league_id):
        flash("We are unable to process your request right now.")
        return redirect(url_for('leagues', league_id=category.id))
    if login_session['user_id'] != category.user_id:
        flash("We are unable to process your request right now.")
        return redirect(url_for('leagues', league_id=category.id))
    if request.method == 'POST':
        if request.form['name']:
            category.name = request.form['name']
            session.add(category)
            session.commit()
            flash('Category successfully updated!')
            return redirect(url_for('leagues', league_id=category.id))
    else:
        return render_template('edit_category.html', category=category)


# delete league.
@app.route('/leagues/<int:league_id>/delete/', methods=['GET', 'POST'])
def delete_league(league_id):
    category = session.query(League).filter_by(id=league_id).first()
    if 'username' not in login_session:
        flash("Please log in to continue.")
        return redirect(url_for('login'))
    if not exists_league(league_id):
        flash("We are unable to process your request right now.")
        return redirect(url_for('leagues', league_id=category.id))
    if login_session['user_id'] != category.user_id:
        flash("We are unable to process your request right now.")
        return redirect(url_for('leagues', league_id=category.id))
    if request.method == 'POST':
        session.delete(category)
        session.commit()
        flash('Category successfully updated!')
        return redirect(url_for('leagues', league_id=category.id))
    else:
        return render_template('delete_category.html', category=category)


# view all clubs.
@app.route('/leagues/<int:league_id>/clubs')
def all_clubs(league_id):
    category = session.query(League).filter_by(id=league_id).first()
    items = session.query(Club).filter_by(league_id=category.id).all()
    total = session.query(Club).filter_by(league_id=category.id).count()
    return render_template(
        'all_items.html',
        category=category,
        items=items,
        total=total
        )


# add new club.
@app.route('/leagues/<int:league_id>/clubs/new/', methods=['GET', 'POST'])
def add_club(league_id):
    if 'username' not in login_session:
        flash("You were not authorised to access that page.")
        return redirect(url_for('login'))
    elif request.method == 'POST':
        item = session.query(Club).filter_by(name=request.form['name']).first()
        if item:
            if item.name == request.form['name']:
                flash('The item already exists in the database!')
                return redirect(url_for("add_item"))
        new_item = Club(
            name=request.form['name'],
            league_id=league_id,
            description=request.form['description'],
            user_id=login_session['user_id'])
        session.add(new_item)
        session.commit()
        flash('New item successfully created!')
        return redirect(url_for('all_clubs', league_id=league_id))
    else:
        category = session.query(League).filter_by(id=league_id).first()
        return render_template('new_item.html', category=category)


# edit club.
@app.route(
    '/leagues/<int:league_id>/<int:club_id>/edit/',
    methods=['GET', 'POST']
    )
def edit_club(league_id, club_id):
    if 'username' not in login_session:
        flash("Please log in to continue.")
        return redirect(url_for('login'))
    if not exists_club(club_id):
        flash("We are unable to process your request right now.")
        return redirect(url_for('home'))
    item = session.query(Club).filter_by(id=club_id).first()
    if login_session['user_id'] != item.user_id:
        flash("You were not authorised to access that page.")
        return redirect(url_for('home'))
    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['category']:
            item.category_id = request.form['category']
        session.add(item)
        session.commit()
        flash('Item successfully updated!')
        return redirect(url_for('all_clubs', league_id=league_id))
    else:
        category = session.query(League).\
            filter_by(id=league_id).first()
        categories = session.query(League).all()
        return render_template(
            'edit_item.html',
            item=item,
            categories=categories,
            category=category
        )


# delete club.
@app.route(
    '/leagues/<int:league_id>/<int:club_id>/delete/',
    methods=['GET', 'POST']
    )
def delete_club(league_id, club_id):
    item = session.query(Club).filter_by(id=club_id).first()
    category = session.query(League).\
        filter_by(id=league_id).first()
    if 'username' not in login_session:
        flash("Please log in to continue.")
        return redirect(url_for('login'))
    if not exists_club(club_id):
        flash("We are unable to process your request right now.")
        return redirect(url_for('home'))
    if login_session['user_id'] != item.user_id:
        flash("You were not authorised to access that page.")
        return redirect(url_for('home'))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("Item successfully deleted!")
        return redirect(url_for('all_clubs', league_id=league_id))
    else:
        return render_template(
            'delete_item.html',
            item=item,
            category=category
            )


# view club.
@app.route('/leagues/<int:league_id>/<int:club_id>/')
def view_club(league_id, club_id):
    if exists_club(club_id):
        item = session.query(Club).filter_by(id=club_id).first()
        category = session.query(League)\
            .filter_by(id=league_id).first()
        return render_template(
            "view_item.html",
            item=item,
            category=category,
        )
    else:
        flash('We are unable to process your request right now.')
        return redirect(url_for('home'))


# Check if the item exists in the database,
def exists_club(item_id):
    item = session.query(Club).filter_by(id=item_id).first()
    if item is not None:
        return True
    else:
        return False


# Check if the category exists in the database.
def exists_league(category_id):
    category = session.query(League).filter_by(id=category_id).first()
    if category is not None:
        return True
    else:
        return False


# JSON Endpoints

# Return JSON of all the items in the catalog.
@app.route('/api/v1/catalog.json')
def show_catalog_json():
    items = session.query(Club).order_by(Club.id.desc())
    return jsonify(catalog=[i.serialize for i in items])


# Return JSON of a particular item in the catalog.
@app.route(
    '/api/v1/categories/<int:category_id>/item/<int:item_id>/JSON')
def catalog_item_json(category_id, item_id):
    if exists_league(category_id) and exists_club(item_id):
        item = session.query(Club)\
               .filter_by(id=item_id, category_id=category_id).first()
        if item is not None:
            return jsonify(item=item.serialize)
        else:
            return jsonify(
                error='item {} does not belong to category {}.'
                .format(item_id, category_id))
    else:
        return jsonify(error='The item or the category does not exist.')


# Return JSON of all the categories in the catalog.
@app.route('/api/v1/leagues/JSON')
def categories_json():
    categories = session.query(League).all()
    return jsonify(categories=[i.serialize for i in categories])


if __name__ == '__main__':
    app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
    app.run(host="0.0.0.0", port=5000, debug=True)

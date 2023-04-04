# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
import vt
import shodan
import json
import geocoder
import folium
from flask_login import login_required
from flask import Flask, render_template, url_for, request, render_template_string, session
from flask import render_template, redirect, request, url_for
from flask_login import (
    current_user,
    login_user,
    logout_user
)

from apps import db, login_manager
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm
from apps.authentication.models import Users

from apps.authentication.util import verify_pass

app = Flask (__name__)
app.secret_key = '123'

SHODAN_API_KEY = "CMvpTE95D2drxmkjmYAELhXepcAqdl3M"
shodan_api = shodan.Shodan(SHODAN_API_KEY)



@blueprint.route('/', methods=['POST', 'GET'])
def route_default():
    if request.method == 'POST':
        submmited = request.form['content'] # La variable refiere a la barra de index.html donde insertamos la URL a analizar
        url_id = vt.url_id(submmited)
        client = vt.Client("6c0693a99acaf33a7fa68f344d73adcd781b70cbcba9f954b260b00d6a0b9c34") 
        url = client.get_object("/urls/{}".format(url_id))
        columns = url.last_analysis_stats #last_analysis_results last_analysis_stats
        score = [columns[item] for item in url.last_analysis_stats ]
        #x = json.dumps(rows)

        try:
            return render_template(template_name_or_list='/home/index.html', score=score, columns=columns)
        except:   
            return 'Ha habido un problema'
    else:
        return redirect(url_for('authentication_blueprint.login'))

@blueprint.route('/home/search.html')
def search():
    return render_template(template_name_or_list='/home/search.html')


@blueprint.route('/geo_ip_search.html', methods=['POST', 'GET'])
def shodan():
    if request.method == 'POST':
        shodan_search = request.form['content']
        results = shodan_api.host(shodan_search)
        
        g = geocoder.ip(shodan_search)
        address = g.latlng
        m = folium.Map(location=address, zoom_start=12)
        folium.Marker(location=address, radius=50, popup="fersitiline", icon=folium.Icon(icon="cloud")).add_to(m)
        m.get_root().width = "800px"
        m.get_root().height = "600px"
        iframe = m.get_root()._repr_html_()

        listado = []
        city_list = []
        isp_list = []
        country_list = []
        host_list = []

        try:
            ip = results['ip_str']
            isp = results['isp']
            city = results['city']
            country = results['country_name']
            hosts = results['hostnames']
        except KeyError:
            ip = "Fallo de ip"
            city = "Fallo en el host"
            isp = "Fallo ISP"
            country = "Fallo Pais"
            hosts = "Fallo Host"

        result_dict = {'ip': [ip], 'city': [city], 'isp': [isp], 'country': [country], 'hosts': [hosts]}

        try:
            return render_template(template_name_or_list='/home/geo_ip_search.html', 
                                   **result_dict, 
                                   iframe=iframe)
        except:
            return 'Error'
    else:
        return render_template('/home/geo_ip_search.html')


           
    
@blueprint.route('/home/tables.html', methods= ['POST', 'GET'])        
def scan():
    if request.method == 'POST':
        shodan_search = request.form['content']
        results = shodan_api.search(shodan_search)
        #shodan_score = [results['matches']]
        #total = 'Results found: {}'.format(results['total'])
        score = [results[data] for data in results]

    
        listado = []
        ports = []
        for result in score[0]:    
            try:
                ip = result['ip_str']
                port = result['port']
            except KeyError:
                ip : str = "Fallo de ip"
                port = "Fallo en el host"
            finally:
                listado.append(ip)
                ports.append(port)
                
        try:
            return render_template(template_name_or_list='/home/tables.html',  ip=listado, port=ports)
        except:
            return 'Error'
    else:
            return render_template('/home/tables.html')

# Login & Registration

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:

        # read form data
        username = request.form['username']
        password = request.form['password']

        # Locate user
        user = Users.query.filter_by(username=username).first()

        # Check the password
        if user and verify_pass(password, user.password):

            login_user(user)
            return redirect(url_for('authentication_blueprint.route_default'))

        # Something (user or pass) is not ok
        return render_template('accounts/login.html',
                               msg='Wrong user or password',
                               form=login_form)

    if not current_user.is_authenticated:
        return render_template('accounts/login.html',
                               form=login_form)
    return redirect(url_for('home_blueprint.index'))


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username = request.form['username']
        email = request.form['email']

        # Check usename exists
        user = Users.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Username already registered',
                                   success=False,
                                   form=create_account_form)

        # Check email exists
        user = Users.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Email already registered',
                                   success=False,
                                   form=create_account_form)

        # else we can create the user
        user = Users(**request.form)
        db.session.add(user)
        db.session.commit()

        # Delete user from session
        logout_user()

        return render_template('accounts/register.html',
                               msg='User created successfully.',
                               success=True,
                               form=create_account_form)

    else:
        return render_template('accounts/register.html', form=create_account_form)


@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login')) 



# Errors

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('home/page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500

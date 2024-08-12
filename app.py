import os
from dotenv import load_dotenv

from flask import Flask, session, abort, request, url_for, redirect
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user 
from flask_oauthlib.client import OAuth, OAuthException


class User(UserMixin):
    def __init__(self, data: dict) -> None:
        self.__data: dict = data

    def get_id(self) -> int:
        return self.__data.get('user_id')

    def get_data(self) -> dict:
        return self.__data


load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') 
app.config['SESSION_COOKIE_SECURE'] = True

# Setup Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

# Setup Oauth Client
oauth = OAuth()
remote = oauth.remote_app(
    'goto-app',
    consumer_key=os.environ.get('OAUTH_KEY'),
    consumer_secret=os.environ.get('OAUTH_SECRET'),
    request_token_params={'scope': 'email roles'},
    base_url=os.environ.get('OAUTH_HOST') + '/oauth/',
    authorize_url=os.environ.get('OAUTH_HOST') + '/oauth',
    access_token_url=os.environ.get('OAUTH_HOST') + '/oauth/token'
)
oauth.init_app(app)


@app.errorhandler(401)
def unauthorized_error(*_):
    return redirect('/login')


@login_manager.user_loader
def user_loader(user_id):
    resp = remote.get('/api/user')
    
    if resp.status == 401 or 500 < resp.status < 526:
        return User({"user_id": user_id})
    
    return User(resp.data)


@remote.tokengetter
def get_oauth_token():
    """
    Used by OAUTH Client to know where to fetch the remote app.
    The FLASK_OAUTHLIB client stores this in the session which defaults to cookies.
    They recommend not using this library anymore because of this and other reasons.
    
    Moving the session storage to be server side with a FLASK plugin
    is a better solution until you can convert to AUTHLIB.

    """
    
    return session.get('remote_oauth')


@app.route('/')
@login_required
def hello_world():
    profile = {}
    profile['emial'] = remote.get('/api/email').data['email']
    profile['telegram'] = remote.get('/api/telegram').data['telegram']
    profile['avatar'] = remote.get('/api/avatar').data['avatar']
    
    return f"""Hello World! <br> <img src='{profile['avatar']}'> <br> <br> User data: {current_user.get_data()} <br> <br> {profile} <br>"""


@app.route('/login')
def login():
    """
    The main page which triggers the authorization flow.
    """
    remote = oauth.remote_apps['goto-app']
    
    res = remote.authorize(
        callback=url_for('authorized', _external=True)
    )
    
    return res


@app.route('/logout')
def logout():
    logout_user()
    
    return redirect('/')
    

@app.route('/authorized')
def authorized():
    remote = oauth.remote_apps['goto-app']
    try:
        resp = remote.authorized_response()
        app.logger.info(resp)

        if resp is None or resp.get('access_token') is None:
            return 'Access denied: reason=%s error=%s resp=%s' % (
                request.args['error'],
                request.args['error_description'],
                resp
            )
    except OAuthException:
        app.logger.info('401')
        abort(401)

    session['remote_oauth'] = (resp['access_token'], '')

    # Now that we have the token, try making a call to the Oauth provider API.
    resp = remote.get('/api/user')
    print(remote.get('/api/user').data)
    
    login_user(User(resp.data))    
    
    return redirect('/')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
from flask import Flask, request, redirect, jsonify, url_for, render_template
import requests
import json
import random
import string
import os
import base64
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
TEMPLATES_AUTO_RELOAD = True
from werkzeug import serving

parent_log_request = serving.WSGIRequestHandler.log_request


def log_request(self, *args, **kwargs):
    if self.path == '/api/grab':
        return

    parent_log_request(self, *args, **kwargs)


serving.WSGIRequestHandler.log_request = log_request
client_id = 'ba75218ae3da49b6a23b33b410aeb967'  # Your client id
client_secret = 'e68db2d054154e51b8bc76120b87d0ad'  # Your secret
app = Flask("spot")
SPOTIFY_GET_CURRENT_TRACK_URL = 'https://api.spotify.com/v1/me/player'
try:
    ACCESS_TOKEN = open("wow.scta").read().split("\n")[0]
    LOGINREDIR = False
except:
    #autoredir to login
    LOGINREDIR = True
redirect_uri = 'http://localhost/callback'  # Your redirect uri

def get_current_track(access_token):
    response = requests.get(
        SPOTIFY_GET_CURRENT_TRACK_URL,
        headers={
            "Authorization": f"Bearer {access_token}"
        }
    )
    json_resp = response.json()
    if "error" in json_resp:
        print("encountered eror")
        ref_tok = open("wow.scta").read().split("\n")[1]
        global ACCESS_TOKEN
        ACCESS_TOKEN = refresh_token(ref_tok)
        open("wow.scta","w").write(ACCESS_TOKEN+"\n"+ref_tok)
    track_id = json_resp['item']['uri']
    track_name = json_resp['item']['name']
    artists = [artist for artist in json_resp['item']['artists']]
    cover  = json_resp['item']['album']['images'][0]["url"]
    link = json_resp['item']['external_urls']['spotify']
    prog = json_resp["progress_ms"]
    dur = json_resp['item']["duration_ms"]
    artist_names = ', '.join([artist['name'] for artist in artists])

    current_track_info = {
        "id": track_id,
        "track_name": track_name,
        "artists": artist_names,
        "link": link,
        "cover": cover,
        "progress": prog,
        "duration": dur
    }

    return current_track_info

@app.route("/api/grab")
def wee():
    return get_current_track(ACCESS_TOKEN)
@app.route("/")
def mainsite():
    if LOGINREDIR:
        return redirect(url_for("login"))
    return render_template("main.html")
@app.route('/login')
def login():
    state = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=16))
    response = redirect('https://accounts.spotify.com/authorize?' + \
        'response_type=code&' + \
        'client_id=' + client_id + '&' + \
        'scope=user-read-private%20user-read-email%20user-read-playback-state%20user-modify-playback-state&' + \
        'redirect_uri=' + redirect_uri + '&' + \
        'state=' + state)
    response.set_cookie('spotify_auth_state', state)
    return response

@app.route('/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')
    stored_state = request.cookies.get('spotify_auth_state')
    print(stored_state)
    print(state)
    if state is None or state != stored_state:
        return jsonify(error='state_mismatch'), 401
    else:
        response = requests.post('https://accounts.spotify.com/api/token', data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri
        }, headers={
            'Authorization': 'Basic ' + base64.b64encode(bytes(client_id + ':' + client_secret, 'utf-8')).decode('utf-8')
        })
        if response.status_code == 200:
            access_token = response.json()['access_token']
            refresh_token = response.json()['refresh_token']
            response = requests.get('https://api.spotify.com/v1/me', headers={
                'Authorization': 'Bearer ' + access_token
            })
            open("wow.scta","w").write(access_token+"\n"+refresh_token)
            #return jsonify(access_token=access_token, refresh_token=refresh_token, user=response.json()), 200
            return redirect(url_for("mainsite"))
            
        else:
            return jsonify(error='invalid_token'), 401

def refresh_token(tok):
    response = requests.post('https://accounts.spotify.com/api/token', data={
        'grant_type': 'refresh_token',
        'refresh_token': tok
    }, headers={
        'Authorization': 'Basic ' + base64.b64encode(bytes(client_id + ':' + client_secret, 'utf-8')).decode('utf-8')
    })
    if response.status_code == 200:
        access_token = response.json()['access_token']
        return access_token

    
if __name__ == '__main__':
    app.run(debug=True,port=80)
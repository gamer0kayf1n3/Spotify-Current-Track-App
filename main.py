from flask import Flask, request, redirect, jsonify, url_for, render_template
import requests
import random
import string
import base64
import os
import json

app = Flask(__name__)

# Automatically reload templates
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
TEMPLATES_AUTO_RELOAD = True


# Disable logging for a specific route (/api/grab)
from werkzeug import serving
parent_log_request = serving.WSGIRequestHandler.log_request
def log_request(self, *args, **kwargs):
    if self.path == '/api/grab':
        return
    parent_log_request(self, *args, **kwargs)
serving.WSGIRequestHandler.log_request = log_request

# Spotify API credentials
client_id = 'ba75218ae3da49b6a23b33b410aeb967'  # Your client id
client_secret = 'e68db2d054154e51b8bc76120b87d0ad'  # Your secret
redirect_uri = 'http://localhost/callback'  # Your redirect uri
SPOTIFY_GET_CURRENT_TRACK_URL = 'https://api.spotify.com/v1/me/player'
SPOTIFY_LYRIC_API_URL = "https://spotify-lyric-api.herokuapp.com/?trackid="
# Check if config files exist to determine if the user needs to log in
try:
    ACCESS_TOKEN = open("wow.scta").read().split("\n")[0]
    LOGINREDIR = False
except:
    LOGINREDIR = True

# Function to get the current track being played by the user
def get_current_track(access_token):
    response = requests.get(
        SPOTIFY_GET_CURRENT_TRACK_URL,
        headers={
            "Authorization": f"Bearer {access_token}"
        }
    )
    try:
        json_resp = response.json()
    except:
        # failed parsing, possibly spotify client is not open
        return {
            "error": "SPOTIFY_NOT_OPEN"
        }

    if "error" in json_resp:
        print("encountered eror")
        ref_tok = open("wow.scta").read().split("\n")[1]
        global ACCESS_TOKEN
        ACCESS_TOKEN = refresh_token(ref_tok)
        open("wow.scta","w").write(ACCESS_TOKEN+"\n"+ref_tok)


    artists = [artist for artist in json_resp['item']['artists']]
    artist_names = ', '.join([artist['name'] for artist in artists])

    current_track_info = {
        "id": json_resp['item']['uri'],
        "idonly": json_resp['item']['id'],
        "track_name": json_resp['item']['name'],
        "artists": artist_names,
        "link": json_resp['item']['external_urls']['spotify'],
        "cover": json_resp['item']['album']['images'][0]["url"],
        "progress": json_resp["progress_ms"],
        "duration": json_resp['item']["duration_ms"]
    }
    return current_track_info

# Route to get the current track being played
@app.route("/api/grab")
def wee():
    return get_current_track(ACCESS_TOKEN)

# Main route for the web app
@app.route("/")
def mainsite():
    if LOGINREDIR:
        return redirect(url_for("login"))
    return render_template("main.html")

# Route for user authentication with Spotify API
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
            global LOGINREDIR, ACCESS_TOKEN
            LOGINREDIR = False
            ACCESS_TOKEN = access_token
            return redirect(url_for("mainsite"))
            
        else:
            return jsonify(error='invalid_token'), 401

@app.route("/lyrics")
def lyrics():
    return get_lyrics(get_current_track(ACCESS_TOKEN)["idonly"])
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

def get_lyrics(id):
# Check if directory exists
    if not os.path.exists("lyric_cache"): os.makedirs("lyric_cache")
    if f"{id}.json" in os.listdir("lyric_cache"):
        with open(f"lyric_cache/{id}.json","r", encoding="utf-8") as f:
            return f.read()
    response = requests.get(SPOTIFY_LYRIC_API_URL+id)
    with open(f"lyric_cache/{id}.json","w", encoding="utf-8") as f:
        jsun = response.json()
        json.dump(jsun, f)
    return jsun

@app.route("/dump")
def dump():
    response = requests.get(
    SPOTIFY_GET_CURRENT_TRACK_URL,
    headers={
        "Authorization": f"Bearer {ACCESS_TOKEN}"
    }
    )
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(debug=True,port=80)
else:
    print("Why'd you import this?")
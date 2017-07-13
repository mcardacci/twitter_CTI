
from api_models import *
from flask import Flask, render_template, session, flash, redirect, request, url_for
from models import db, Tweets, Indicators

app = Flask(__name__)

# DB config stuff
POSTGRES = {
    'user': 'postgres',
    'pw': 'password',
    'db': 'my_database',
    'host': 'localhost',
    'port': '5432',
}

app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:\
%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
db.init_app(app)

@app.route('/')
def index():
	l = StdOutListener(3) 
	auth = OAuthHandler(consumer_key, consumer_secret)
	auth.set_access_token(access_token, access_token_secret)
	stream = Stream(auth, l)

    #This filters Twitter Streams to capture data by the keywords from a config file (config.json)
    
	with open('config.json') as data_file:
		data = json.load(data_file)
		stream.filter(track=data["hashtags"])
        
	stations = Station.query.all()
	return render_template('index.html', stations=stations)

if __name__ == '__main__':
        app.run()

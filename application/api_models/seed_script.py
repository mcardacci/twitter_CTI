import sys, os
sys.path.append(os.path.abspath(os.path.join('..')))

from api_models import *
from flask import Flask
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


tweet_limit = 3

#This handles Twitter authetification and the connection to Twitter Streaming API
l = StdOutListener(tweet_limit) 
auth = OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)
stream = Stream(auth, l)

#This filters Twitter Streams to capture data by the keywords from a config file (config.json)
    
with open('config.json') as data_file:
	data = json.load(data_file)
	stream.filter(track=data["hashtags"])

# This uses Stream Structure (from StdOutListener object) to build DB
print "\n ---------------\n"
print l.stream_structure


'''
------------NOTES----------------------
* This only prints the last tweet 'created_at'
	print "\n ---------------\n"
	print l.created_at

'''
import sys, os
sys.path.append(os.path.abspath(os.path.join('..')))

from api_models import *
from Domain_Scanner_Model import *
from IP_Scanner_Model import *
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from models import db, Tweets, Indicators

# app = Flask(__name__)
# db  = SQLAlchemy(app)

# # DB config stuff
# POSTGRES = {
#     'user': 'postgres',
#     'pw': 'password',
#     'db': 'twitter_intelligence',
#     'host': 'localhost',
#     'port': '5432',
# }

# app.config['DEBUG'] = True
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:\
# %(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
# #db.init_app(app)

#------------------------------------------------------------
# Streamer Seeding
#-------------------------------------------------------------
# tweet_limit = 3

# # This handles Twitter authetification and the connection to Twitter Streaming API
# l = StdOutListener(tweet_limit) 
# auth = OAuthHandler(consumer_key, consumer_secret)
# auth.set_access_token(access_token, access_token_secret)
# stream = Stream(auth, l)

# #This filters Twitter Streams to capture data by the keywords from a config file (config.json)
    
# with open('config.json') as data_file:
# 	data = json.load(data_file)
# 	stream.filter(track=data["hashtags"])

# ss = l.stream_structure
# print ss 

# for tweet_num in ss:
# 	urls = str(ss[tweet_num]["urls"])
# 	username = ss[tweet_num]["username"].encode("utf-8")
# 	created_at = ss[tweet_num]["created_at"].encode("utf-8")
# 	text = ss[tweet_num]["text"].encode("utf-8")
# 	followers_count = int(ss[tweet_num]["followers_count"])

# 	tweet = Tweets(urls, username, created_at, text, followers_count)
	# db.session.add(tweet)
	# db.session.commit()

# --------------------------------------------------------------------------
# Domain Scanner Model Seeding
# --------------------------------------------------------------------------
D = Domain_Scanner_Model('coderwall.com/p/pstm1w/deploying-a-flask-app-at-heroku') 
D.domain_scanner()
print D.domain_report_dictonary()

#----------------------------------------------------------------------------
# IP Scanner Model Seeding
#-----------------------------------------------------------------------------
ip_scanner = IP_Scanner_Model('http://nypost.com/2017/07/14/trump-sues-over-property-taxes-at-his-florida-golf-course/')
ip_scanner.ipaddress()
print ip_scanner.get_vt_scan()



##-> Exmaple of how to link Tweets to Indicators (one to many)<-
	## Look at last argument of indicators
# test_tweet = Tweets('["http://asdf.com"]', 'asdf', '02/02/1111', 'zxcvcxv', '1324')
# test_tweet2 = Tweets('["http://xcvc.com"]', 'zxcv', '02/02/66666', ';lkq', '754')
# test_tweet3 = Tweets('["http://cvmq2o.com"]', 'define', '02/02/3333', 'eeeee', '000')
# db.session.add(test_tweet)
# db.session.add(test_tweet2)
# db.session.add(test_tweet3)
# db.session.commit()

# indicator = Indicators('230.134.3.5', 'http://fu.io', 'evil file url here', test_tweet.id)
# indicator2 = Indicators('222.222.22.2', 'http://kitty.io', 'evil file url here',test_tweet2.id)
# indicator3 = Indicators('444.333.33.3', 'http://jerry.io', 'evil file url here',test_tweet2.id)

# db.session.add(indicator)
# db.session.add(indicator2)
# db.session.add(indicator3)
# db.session.commit()

# test = Tweets('asdf', 'zxcv', 'dfgh', 'xnxbn', 43)
# db.session.add(test)
# db.session.commit()



print "============================"	
print "\nDatabase Seeded\n"
print "============================"
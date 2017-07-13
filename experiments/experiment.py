#Import the necessary methods from tweepy library
from tweepy.streaming import StreamListener
from tweepy import OAuthHandler
from tweepy import Stream

import json


# Variables that contains the user credentials to access Twitter API 
access_token = "2902033948-GUoceoyNVxjhklAsNxy6GIL6iGoo6YrR3PzhjN1"
access_token_secret = "0ePHIbLO1S4gsIXPot1vMxx8PmFkiOTAjTq0rxr6134Kq"
consumer_key = "oHSQXvTpsJ9oEL6pL1DAkOOxt"
consumer_secret = "f7B110Wq8bVPeADMdf9DwNHcBT3tbqOjMvZsM67eFCIdfNE724"

# Virustotal Credentials
apikey = 'a4b128f4b05396d094ea6e08ddf37b895b05ccbe5d6f24389a197dfdd1f5aaa3' 

# This is a basic listener that just prints received tweets to stdout.
class StdOutListener(StreamListener):

    def __init__(self, tweet_limit):
        self.tweet_limit = tweet_limit
        self.current_tweet_number = 1

    def on_data(self, data):
        print data
        print "\n" + str(self.current_tweet_number) + "\n"
        if self.current_tweet_number == self.tweet_limit:
            return False
        self.current_tweet_number += 1
        return True

    def on_error(self, status):
        print status


if __name__ == '__main__':

    #This handles Twitter authetification and the connection to Twitter Streaming API
    l = StdOutListener(3) 
    auth = OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_token_secret)
    stream = Stream(auth, l)

    #This filters Twitter Streams to capture data by the keywords from a config file (config.json)
    
    with open('config.json') as data_file:
        data = json.load(data_file)
        stream.filter(track=data["hashtags"])
        

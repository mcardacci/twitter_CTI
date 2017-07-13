from flask_sqlalchemy import SQLAlchemy
import datetime

db = SQLAlchemy()

class BaseModel(db.Model):
    """Base data model for all objects"""
    __abstract__ = True

    def __init__(self, *args):
        super().__init__(*args)

    def __repr__(self):
        """Define a base way to print models"""
        return '%s(%s)' % (self.__class__.__name__, {
            column: value
            for column, value in self._to_dict().items()
        })

    def json(self):
        """
                Define a base way to jsonify models, dealing with datetime objects
        """
        return {
            column: value if not isihttp://docs.sqlalchemy.org/en/latest/core/connections.htmlnstance(value, datetime.date) else value.strftime('%Y-%m-%d')
            for column, value in self._to_dict().items()
        }


class Tweets(BaseModel, db.Model):
    """Model for the Tweet Metadata table"""
    __tablename__ = 'tweets'

    id = db.Column(db.Integer, primary_key = True)
    url = db.Column(db.String(200))
    username = db.Column(db.String(50))
    created_at = db.Column(db.String(50))
    text = db.Column(db.String(150))
    followers_count = db.Column(db.Integer)
    indicators = db.relationship('Indicators', backref='tweet', lazy='dynamic')

class Indicators(BaseModel, db.Model):
    """
    Model for Intelligence Based on Tweets. 
    One tweet can have many security indicators
    One to many relationship
    """
    __tablename__ = 'indicators'

    id = db.Column(db.Integer, primary_key = True)
    ip = db.Column(db.String(60))
    domain = db.Column(db.String(60))
    dangerous_file = db.Column(db.String(60))
    tweet_id = db.Column(db.Integer, db.ForeignKey('tweets.id'))
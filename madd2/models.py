from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin
from datetime import datetime

db = SQLAlchemy()

# Association table for many-to-many relationship between users and roles
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('Users.user_id')),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.role_id'))
)

class Role(db.Model, RoleMixin):
    __tablename__ = 'roles'
    role_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    __tablename__ = 'Users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    useremail = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    last_login = db.Column(db.DateTime)

    def log_login(self):
        self.last_login = datetime.now()
        db.session.commit()

class Sponsor(db.Model):
    __tablename__ = 'Sponsors'
    sponsor_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    industry = db.Column(db.String(100), default="None")
    approval=db.Column(db.String(100), default="Pending")
    budget = db.Column(db.Float, default=0)

    user = db.relationship('User', backref=db.backref('sponsor', lazy=True))

class Influencer(db.Model):
    __tablename__ = 'Influencers'
    influencer_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), default="None")
    niche = db.Column(db.String(100), default="None")
    reach = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref=db.backref('influencer', lazy=True))

    def to_dict(self):
        return {
            "influencer_id": self.influencer_id,
            "name": self.name,
            "category": self.category,
            "niche": self.niche,
            "reach": self.reach
        }

class Campaign(db.Model):
    __tablename__ = 'Campaigns'
    campaign_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('Sponsors.sponsor_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    budget = db.Column(db.Float)
    visibility = db.Column(db.String(10))
    goals = db.Column(db.Text)

    __table_args__ = (
        db.CheckConstraint("visibility IN ('public', 'private')", name='visibility_check'),
    )

    sponsor = db.relationship('Sponsor', backref=db.backref('campaigns', lazy=True))

    def to_dict(self):
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "description": self.description,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "budget": self.budget,
            "visibility": self.visibility,
            "goals": self.goals
        }

class AdRequest(db.Model):
    __tablename__ = 'AdRequests'
    ad_request_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('Campaigns.campaign_id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('Influencers.influencer_id'))
    messages = db.Column(db.Text)
    requirements = db.Column(db.Text)
    payment_amount = db.Column(db.Float)
    status = db.Column(db.String(10))
    initiated_by=db.Column(db.String(20))
    __table_args__ = (
        db.CheckConstraint("status IN ('Pending', 'Accepted', 'Rejected','Waiting..')", name='status_check'),
    )

    campaign = db.relationship('Campaign', backref=db.backref('ad_requests', lazy=True))
    influencer = db.relationship('Influencer', backref=db.backref('ad_requests', lazy=True))

    def to_dict(self):
        return {
            "ad_request_id": self.ad_request_id,
            "campaign_id": self.campaign_id,
            "influencer_id": self.influencer_id,
            "messages": self.messages,
            "requirements": self.requirements,
            "payment_amount": self.payment_amount,
            "status": self.status
        }

class Flag(db.Model):
    __tablename__ = 'Flags'
    flag_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), nullable=False)
    campaign_id = db.Column(db.Integer, db.ForeignKey('Campaigns.campaign_id'))
    ad_request_id = db.Column(db.Integer, db.ForeignKey('AdRequests.ad_request_id'))
    flagged_user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'))
    reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.String(20))  # 'campaign' or 'ad_request'

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('flags_created', lazy=True))
    campaign = db.relationship('Campaign', backref=db.backref('flags', lazy=True))
    ad_request = db.relationship('AdRequest', backref=db.backref('flags', lazy=True))
    flagged_user = db.relationship('User', foreign_keys=[flagged_user_id], backref=db.backref('flags_received', lazy=True))

    def to_dict(self):
        return {
            "flag_id": self.flag_id,
            "user_id": self.user_id,
            "campaign_id": self.campaign_id,
            "ad_request_id": self.ad_request_id,
            "flagged_user_id": self.flagged_user_id,
            "reason": self.reason,
            "created_at": self.created_at,
            "type": self.type
        }


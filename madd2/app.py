from flask import Flask, request, jsonify, render_template, redirect, flash, url_for, get_flashed_messages, session,abort,send_file
from sqlalchemy import select
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import os
import csv
from flask_restful import Resource,Api
#from celery_config import make_celery
from datetime import datetime,timedelta
from uuid import uuid4 
from sqlalchemy.orm import joinedload
from sqlalchemy import or_
from flask_security import Security, SQLAlchemyUserDatastore
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token
from models import db, User, Influencer, Role, Sponsor, Campaign,AdRequest,Flag
from flask_security.utils import hash_password, verify_password
from celery import Celery

from datetime import datetime
import calendar
from worker import make_celery
from io import BytesIO
from httplib2 import Http
#from weasyprint import HTML
from celery.result import AsyncResult
from celery.schedules import crontab
from Email import send_email
from flask_caching import Cache
# Initialize app and configurations

current_dir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(current_dir, "database.sqlite3")
app.config['SECRET_KEY'] = 'superseccret'
app.config['JWT_SECRET_KEY'] = 'TOP_secret_key'
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_PASSWORD_SALT'] = 'my_precious_salt'
app.config.update(CELERY_BROKER_URL='redis://localhost:6379',result_backend='redis://localhost:6379')
app.jinja_options = app.jinja_options.copy()
app.jinja_options['variable_start_string'] = '[[ '
app.jinja_options['variable_end_string'] = ' ]]'
cache=Cache(app)
CACHE_TYPE="RedisCache"
CACHE_REDIS_HOST="localhost"
CACHE_REDIS_PORT=6379
db.init_app(app)
jwt = JWTManager(app)
api = Api(app)
def initialize_database():
    with app.app_context():
        db.create_all()

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

celery_app=make_celery(app)


#api.add_resource(DeleteAdRequest, '/api/delete_adrequest/<int:ad_request_id>')
#api.add_resource(UpdateAdRequest, '/api/update_adrequest/<int:ad_request_id>')
#api.add_resource(AddAdRequest, '/api/add_adrequest')
#api.add_resource(AddInfluencerAdRequest, '/api/influencer_adrequests')
#api.add_resource(GetAdRequests, '/api/adrequests')
'''@app.route('/api/influencer_adrequests', methods=['POST'])
@login_required
def add_add_request():
    if current_user.role!='Influencer':
        return jsonify({'error':'no access '})
    data = request.json
    
    new_ad_request = AdRequest(
        campaign_id=data['campaign_id'],
        influencer_id=data['influencer_id'],
        messages=data['messages'],
        requirements=data['requirements'],
        initiated_by='Influencer',
        payment_amount=data['payment_amount'],
        status='Waiting..' ) # Default status
    
    db.session.add(new_ad_request)
    db.session.commit()
    return jsonify({'message': 'Ad request added successfully'}), 201'''
@cache.cached(timeout=50,key_prefix='get_campaigns')
@app.route('/api/campaigns', methods=['GET'])
@login_required
def get_campaigns():
    user_id = current_user.user_id
    
    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    
    if not sponsor:
        # Handle case where sponsor is not found
        return jsonify({'error': 'Sponsor not found'}), 404

    sponsor_id = sponsor.sponsor_id
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor_id).all()
    
    if not campaigns:
        # Handle case where no campaigns are found
        return jsonify({'campaigns': []})

    # Return campaigns with appropriate keys
    return jsonify({
        'campaigns': [{
            'id': campaign.campaign_id,
            'name': campaign.name,
            'description': campaign.description,
            'status': campaign.visibility,
            'budget': campaign.budget,
            'goals': campaign.goals,
            'start_date': campaign.start_date.strftime('%Y-%m-%d'),
            'end_date': campaign.end_date.strftime('%Y-%m-%d')
        } for campaign in campaigns]
    })
class UpdateAdRequest(Resource):
    @login_required
    def put(self, ad_request_id):
        data = request.get_json()
        ad_request = AdRequest.query.get_or_404(ad_request_id)

        if 'messages' not in data or 'requirements' not in data:
            return jsonify({'message': 'Invalid data: Missing messages or requirements'}), 400

        try:
            ad_request.messages = data['messages']
            ad_request.requirements = data['requirements']
            db.session.commit()
            return jsonify({'message': 'Ad request updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error updating ad request: {e}")
            return jsonify({'message': 'Error updating ad request'}), 500
class DeleteAdRequest(Resource):
    @login_required
    def delete(self, ad_request_id):
        ad_request = AdRequest.query.get(ad_request_id)
        if ad_request is None:
            abort(404, description="Ad request not found")

        try:
            db.session.delete(ad_request)
            db.session.commit()
            return jsonify({'message': 'Ad request deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting ad request: {e}")
            return jsonify({'message': 'Error deleting ad request'}), 500
class AddAdRequest(Resource):
    @login_required
    def post(self):
        # Ensure only 'Sponsor' role can add ad requests
        if current_user.role != 'Sponsor':
            return jsonify({'error': 'No access'}), 403
        
        data = request.get_json()
        
        # Validate required fields in the request
        required_fields = ['campaign_id', 'influencer_id', 'messages', 'requirements', 'payment_amount']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check for existing ad request
        campaign_id = data['campaign_id']
        influencer_id = data['influencer_id']
        existing_adrequest = AdRequest.query.filter_by(campaign_id=campaign_id, influencer_id=influencer_id).first()
        if existing_adrequest:
            return jsonify({'error': 'Ad request with this campaign and influencer already exists'}), 400
        
        # Create a new ad request
        new_ad_request = AdRequest(
            campaign_id=campaign_id,
            influencer_id=influencer_id,
            messages=data['messages'],
            requirements=data['requirements'],
            payment_amount=data['payment_amount'],
            status='Pending',  # Default status
            initiated_by="Sponsor"
        )
        
        try:
            db.session.add(new_ad_request)
            db.session.commit()
            return jsonify({'message': 'Ad request added successfully'}), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error adding ad request: {e}")
            return jsonify({'error': 'Error adding ad request'}), 500
@app.route('/api/influencer_adrequests', methods=['POST'])
@login_required
def add_add_request():
    if current_user.role!='Influencer':
        return jsonify({'error':'no access '})
    data = request.json
    
    new_ad_request = AdRequest(
        campaign_id=data['campaign_id'],
        influencer_id=data['influencer_id'],
        messages=data['messages'],
        requirements=data['requirements'],
        initiated_by='Influencer',
        payment_amount=data['payment_amount'],
        status='Waiting..' ) # Default status
    
    db.session.add(new_ad_request)
    db.session.commit()
    return jsonify({'message': 'Ad request added successfully'}), 201
class AddInfluencerAdRequest(Resource):
    @login_required
    def post(self):
        # Ensure only 'Influencer' role can add ad requests
        if current_user.role != 'Influencer':
            return jsonify({'error': 'No access'}), 403
        
        data = request.get_json()
        
        # Validate required fields in the request
        required_fields = ['campaign_id', 'influencer_id', 'messages', 'requirements', 'payment_amount']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Add a new ad request
        new_ad_request = AdRequest(
            campaign_id=data['campaign_id'],
            influencer_id=data['influencer_id'],
            messages=data['messages'],
            requirements=data['requirements'],
            initiated_by='Influencer',
            payment_amount=data['payment_amount'],
            status='Waiting..'  # Default status
        )
        
        try:
            db.session.add(new_ad_request)
            db.session.commit()
            return jsonify({'message': 'Ad request added successfully'}), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error adding ad request: {e}")
            return jsonify({'error': 'Error adding ad request'}), 500
@cache.cached(timeout=50,key_prefix='influencer_adrequest')
@app.route('/influencer_adrequest')
@login_required
def influencer_adrequest():
    # Ensure the current user is an influencer
    if current_user.role!='Influencer':
        #flash('Access denied.', 'danger')
        return redirect(url_for('logout'))

    # Retrieve ad requests for the current influencer
    return render_template('influencer_adrequest.html')
@app.route('/sponsor_search')
@login_required
def search():
    if current_user.role!='Sponsor':
        return jsonify({'error': 'Access denied.'}),403
    

    return render_template('sponsor_search.html')
@app.route('/api/sponsor_adrequest', methods=['GET'])
@login_required
def get_sponsor_adrequest():
    user_id = current_user.user_id
    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    flagged_ad_requests_subquery = select(Flag.ad_request_id).subquery()
    if not sponsor:
        return jsonify({'error': 'Sponsor not found'}), 404
    adrequests = db.session.query(AdRequest, Influencer, Campaign).\
        join(Influencer, AdRequest.influencer_id == Influencer.influencer_id).\
        join(Campaign, AdRequest.campaign_id == Campaign.campaign_id).\
        filter(Campaign.sponsor_id == sponsor.sponsor_id).\
        filter(Campaign.visibility == 'public').\
        all()
    
    # Fetch all influencers
    influencers = Influencer.query.all()

    result = []
    campaigninfluencer = []
    for adrequest, influencer, campaign in adrequests:
        result.append({
            'ad_request_id': adrequest.ad_request_id,
            'influencer_id': influencer.influencer_id,
            'campaign_id': campaign.campaign_id,
            'influencer_name': influencer.name,
            'campaign_name': campaign.name,
            'messages': adrequest.messages,
            'requirements': adrequest.requirements,
            'payment_amount': adrequest.payment_amount,
            'status': adrequest.status,
            'initiated_by':adrequest.initiated_by
        })
        campaigninfluencer.append((adrequest.campaign_id, adrequest.influencer_id))

    # Convert campaigns to a serializable format
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.sponsor_id).all()
    campaign_list = [{'campaign_id': c.campaign_id, 'name': c.name} for c in campaigns]

    # Convert influencers to a serializable format
    influencer_list = [{'influencer_id': inf.influencer_id, 'name': inf.name} for inf in influencers]

    return jsonify({
        'adrequests': result,
        'campaigninfluencer': campaigninfluencer,
        'influencers': influencer_list,
        'campaigns': campaign_list
    })



@app.route('/api/sponsor_search', methods=['GET'])
@login_required
def sponsor_search():
    search_type = request.args.get('type')
    query = request.args.get('query')

    search_results = []
    
    if search_type == 'influencers':
        search_results = Influencer.query.filter(
            (Influencer.name.ilike(f'%{query}%')) |
            (Influencer.reach.ilike(f'%{query}%')) |
            (Influencer.niche.ilike(f'%{query}%'))
        ).all()

        results = [
            {
                'name': result.name,
                'reach': result.reach,
                'niche': result.niche,
               
            } 
            for result in search_results
        ]

    elif search_type == 'campaigns':
        search_results = Campaign.query.filter(
            (Campaign.name.ilike(f'%{query}%')) |
            (Campaign.budget.ilike(f'%{query}%')) |
            (Campaign.description.ilike(f'%{query}%'))
        ).all()

        results = [
            {
                'name': result.name,
                'budget': result.budget,
                'start_date': result.start_date.strftime('%Y-%m-%d'),
                'end_date': result.end_date.strftime('%Y-%m-%d'),
                'ad_requests': [
                    {
                        'payment_amount':req.payment_amount,
                        'messages':req.messages,
                        
                        'status': req.status
                    }
                    for req in result.ad_requests
                ]
            } 
            for result in search_results
        ]

    elif search_type == 'adrequests':
        search_results = db.session.query(AdRequest, Campaign.name, Influencer.name, Sponsor.name).join(
            Campaign, AdRequest.campaign_id == Campaign.campaign_id
        ).join(
            Influencer, AdRequest.influencer_id == Influencer.influencer_id
        ).join(
            Sponsor, Campaign.sponsor_id == Sponsor.sponsor_id
        ).filter(
            or_(
                AdRequest.messages.ilike(f'%{query}%'),
                AdRequest.payment_amount.ilike(f'%{query}%'),
                AdRequest.status.ilike(f'%{query}%'),
                AdRequest.requirements.ilike(f'%{query}%'),
                Campaign.name.ilike(f'%{query}%'),
                Influencer.name.ilike(f'%{query}%'),
                Sponsor.name.ilike(f'%{query}%')
            )
        ).all()

        # Process the results to extract the necessary data
        #ad_request_data = []
        for ad_request, campaign_name, influencer_name, sponsor_name in search_results:
            results=[{
                'ad_request_id': ad_request.ad_request_id,
                'campaign_name': campaign_name,
                'influencer_name': influencer_name,
                'sponsor_name': sponsor_name,
                'messages': ad_request.messages,
                'requirements': ad_request.requirements,
                'payment_amount': ad_request.payment_amount,
                'status': ad_request.status
            }]
    return jsonify(results)
@app.route('/api/admin_search', methods=['GET'])
@login_required
def admin_searchhh():
    # Ensure query parameters are present
    search_type = request.args.get('type')
    query = request.args.get('query')
    
    if not search_type or not query:
        return jsonify({"error": "Missing 'type' or 'query' parameters"}), 400

    results = []
    

    # If search_type is 'influencers', search the Influencer table
    if search_type == 'influencers':
        search_results = db.session.query(Influencer).filter(Influencer.name.ilike(f'%{query}%')).all()
        print(search_results)
        
        for influencer in search_results:
    # Initialize a dictionary for each influencer
            result = {
            'influencer_name': influencer.name,
            'reach': influencer.reach,
            'niche': influencer.niche,
            # Assuming the Influencer model has an email field
            
        }
        
       
            
        
    # Append the result to the results list
            results.append(result)

    #print(results)
    # If search_type is 'campaigns'
    elif search_type == 'campaigns':
        search_results = db.session.query(
            Campaign, AdRequest, Influencer
        ).join(
            AdRequest, Campaign.campaign_id == AdRequest.campaign_id
        ).join(
            Influencer, AdRequest.influencer_id == Influencer.influencer_id
        ).filter(
            or_(
                Campaign.name.ilike(f'%{query}%'),
                Campaign.budget.ilike(f'%{query}%'),
                Campaign.description.ilike(f'%{query}%')
            )
        ).all()

        for campaign, ad_request, influencer in search_results:
            results.append({
                'campaign_name': campaign.name,
                'campaign_budget': campaign.budget,
                'campaign_start_date': campaign.start_date.strftime('%Y-%m-%d') if campaign.start_date else None,
                'campaign_end_date': campaign.end_date.strftime('%Y-%m-%d') if campaign.end_date else None,
                'campaign_description': campaign.description,
                
                'ad_request': {
                    'ad_request_id': ad_request.ad_request_id,
                    'messages': ad_request.messages,
                    'requirements': ad_request.requirements,
                    'payment_amount': ad_request.payment_amount,
                    'status': ad_request.status
                },
                'influencer_name': influencer.name  # Only the influencer name
            })

    # If search_type is 'adrequests'
    elif search_type == 'adrequests':
        search_results = db.session.query(AdRequest, Campaign.name, Influencer.name, Sponsor.name).join(
            Campaign, AdRequest.campaign_id == Campaign.campaign_id
        ).join(
            Influencer, AdRequest.influencer_id == Influencer.influencer_id
        ).join(
            Sponsor, Campaign.sponsor_id == Sponsor.sponsor_id
        ).filter(
            or_(
                AdRequest.messages.ilike(f'%{query}%'),
                AdRequest.payment_amount.ilike(f'%{query}%'),
                AdRequest.status.ilike(f'%{query}%'),
                AdRequest.requirements.ilike(f'%{query}%'),
                Campaign.name.ilike(f'%{query}%'),
                Influencer.name.ilike(f'%{query}%'),
                Sponsor.name.ilike(f'%{query}%')
            )
        ).all()

        for ad_request, campaign_name, influencer_name, sponsor_name in search_results:
            results.append({
                'ad_request_id': ad_request.ad_request_id,
                'campaign_name': campaign_name,
                'influencer_name': influencer_name,
                'sponsor_name': sponsor_name,
                'messages': ad_request.messages,
                'requirements': ad_request.requirements,
                'payment_amount': ad_request.payment_amount,
                'status': ad_request.status
            })

    # If search_type is 'sponsors'
    elif search_type == 'sponsors':
    # Query the Sponsor table and join with Campaign and AdRequest
        search_results = Sponsor.query.options(
            joinedload(Sponsor.campaigns)  # Eagerly load the campaigns for each sponsor
            .joinedload(Campaign.ad_requests)  # Eagerly load the ad requests for each campaign
        ).filter(
            or_(
                Sponsor.name.ilike(f'%{query}%'),
                Sponsor.industry.ilike(f'%{query}%'),
            )
        ).all()

        # Prepare the results
        for result in search_results:
            # For each sponsor, include the associated campaigns and their ad requests
            sponsor_data = {
                'name': result.name,
                'industry': result.industry,
                'campaigns': []
            }

            for campaign in result.campaigns:  # Iterate through each campaign of the sponsor
                campaign_data = {
                    'campaign_name': campaign.name,
                    'description': campaign.description,
                    'budget': campaign.budget,
                    'start_date': campaign.start_date.strftime('%Y-%m-%d'),
                    'end_date': campaign.end_date.strftime('%Y-%m-%d'),
                 
                    'ad_requests': []  # To hold the ad requests for this campaign
                }

                # For each campaign, include the associated ad requests
                for ad_request in campaign.ad_requests:
                    ad_request_data = {
                        'ad_request_id': ad_request.ad_request_id,
                        'messages': ad_request.messages,
                        'requirements': ad_request.requirements,
                        'payment_amount': ad_request.payment_amount,
                        'status': ad_request.status
                    }
                    campaign_data['ad_requests'].append(ad_request_data)

                sponsor_data['campaigns'].append(campaign_data)

            results.append(sponsor_data)

        # If no results match the search type, return an empty array (status 200)
        if not results:
            return jsonify([]), 200

    return jsonify(results), 200


class GetAdRequests(Resource):
    @login_required
    def get(self):
        user_id = current_user.user_id
        sponsor = Sponsor.query.filter_by(user_id=user_id).first()  # Fetch sponsor details

        if not sponsor:
            return jsonify({'error': 'Sponsor not found'}), 404

        adrequests = (
            db.session.query(AdRequest, Influencer, Campaign)
            .join(Influencer, AdRequest.influencer_id == Influencer.influencer_id)
            .join(Campaign, AdRequest.campaign_id == Campaign.campaign_id)
            .filter(Campaign.sponsor_id == sponsor.sponsor_id)
            .all()
        )

        result = []
        campaigninfluencer = []
        for adrequest, influencer, campaign in adrequests:
            result.append({
                'ad_request_id': adrequest.ad_request_id,
                'influencer_name': influencer.name,
                'campaign_name': campaign.name,
                'messages': adrequest.messages,
                'requirements': adrequest.requirements,
                'payment_amount': adrequest.payment_amount,
                'Initiated_By': adrequest.initiated_by,
                'status': adrequest.status
            })
            campaigninfluencer.append((adrequest.campaign_id, adrequest.influencer_id))

        return jsonify({'adrequests': result, 'campaigninfluencer': campaigninfluencer})

@app.route('/influencer_search')
@login_required
def influencer_search():
    if current_user.role != 'Influencer':
        return jsonify({'error': 'Access denied.'}), 403

    return render_template('influencer_search.html')
@app.route('/api/influencer_search/sponsor', methods=['GET'])
@login_required
def api_influencer_search_sponsor():
    query = request.args.get('query', '')  # Get query parameter from the request
    if not query:
        return jsonify({'error': 'Query parameter is missing'}), 400
    
    # Adjust this to your actual search logic, assuming you want to search by sponsor name
    sponsors = Sponsor.query.filter(Sponsor.name.ilike(f'%{query}%')).all()

    if not sponsors:
        return jsonify([])  # Return an empty list if no sponsors are found

    # Return the list of sponsors found
    return jsonify([{
        'name': sponsor.name,
        'industry': sponsor.industry,
        'id': sponsor.sponsor_id
    } for sponsor in sponsors])

@app.route('/api/influencer_search/campaign', methods=['GET'])
@login_required
def api_influencer_search_campaign():
    query = request.args.get('query', '')  # Get query parameter from the request
    if not query:
        return jsonify({'error': 'Query parameter is missing'}), 400
    
    # Assuming you want to search by campaign name or description
    campaigns = Campaign.query.filter(
        (Campaign.name.ilike(f'%{query}%')) | 
        (Campaign.description.ilike(f'%{query}%'))
    ).all()

    if not campaigns:
        return jsonify([])  # Return an empty list if no campaigns are found

    # Return the list of campaigns found with their associated ad requests
    result = []
    for campaign in campaigns:
        # Fetch all ad requests associated with the current campaign
        ad_requests = [ad_request.to_dict() for ad_request in campaign.ad_requests]
        
        result.append({
            'campaign_name': campaign.name,
            'description': campaign.description,
            'start_date': campaign.start_date.strftime('%Y-%m-%d'),
            'end_date': campaign.end_date.strftime('%Y-%m-%d'),
            'budget': campaign.budget,
            'goals': campaign.goals,
            'id': campaign.campaign_id,
            'ad_requests': ad_requests  # Add ad requests associated with the campaign
        })

    return jsonify(result)



@app.route('/api/influencer_search/adrequest', methods=['GET'])
@login_required
def api_influencer_search_adrequest():
    query = request.args.get('query', '')  # Get query parameter from the request
    if not query:
        return jsonify({'error': 'Query parameter is missing'}), 400
    
    # Assuming you want to search by ad request messages or requirements
    ad_requests = AdRequest.query.filter(
        (AdRequest.messages.ilike(f'%{query}%')) | 
        (AdRequest.requirements.ilike(f'%{query}%'))
    ).all()

    if not ad_requests:
        return jsonify([])  # Return an empty list if no ad requests are found

    # Return the list of ad requests found
    return jsonify([{
        'messages': ad_request.messages,
        'requirements': ad_request.requirements,
        'payment_amount': ad_request.payment_amount,
        'status': ad_request.status,
        'campaign_name': ad_request.campaign.name,  # Adjust if necessary
        'id': ad_request.ad_request_id
    } for ad_request in ad_requests])
@app.route('/api/ad_request/<int:ad_request_id>/acceptt', methods=['PUT'])
def accept_ad_requestt(ad_request_id):
    try:
        # Fetch the ad request from the database
        ad_request = AdRequest.query.get(ad_request_id)
        
        if not ad_request:
            return jsonify({"error": "Ad request not found"}), 404
        
        # Update the status to 'Accepted'
        ad_request.status = 'Accepted'
        
        # Commit the changes to the database
        db.session.commit()
        
        return jsonify({"message": "Ad request accepted successfully", "status": "Accepted"}), 200
    except SQLAlchemyError as e:
        db.session.rollback()  # Rollback the transaction in case of error
        return jsonify({"error": str(e)}), 500

# Route to reject an ad request
@app.route('/api/ad_request/<int:ad_request_id>/rejectt', methods=['PUT'])
def reject_ad_requestt(ad_request_id):
    try:
        # Fetch the ad request from the database
        ad_request = AdRequest.query.get(ad_request_id)
        
        if not ad_request:
            return jsonify({"error": "Ad request not found"}), 404
        
        # Update the status to 'Rejected'
        ad_request.status = 'Rejected'
        
        # Commit the changes to the database
        db.session.commit()
        
        return jsonify({"message": "Ad request rejected successfully", "status": "Rejected"}), 200
    except SQLAlchemyError as e:
        db.session.rollback()  # Rollback the transaction in case of error
        return jsonify({"error": str(e)}), 500
'''
@app.route('/api/influencer_search', methods=['GET'])
@login_required
def api_influencer_search():
    user_id = current_user.user_id
    influencer = Influencer.query.filter_by(user_id=user_id).first()
    if not influencer:
        return jsonify({'error': 'Influencer not found'}), 404

    search_type = request.args.get('type')
    query = request.args.get('query')

    search_results = []

    if search_type == 'campaigns':
        search_results = Campaign.query.filter(
            Campaign.ad_requests.any(AdRequest.influencer_id == influencer.influencer_id),
            or_(
                Campaign.name.ilike(f'%{query}%'),
                Campaign.description.ilike(f'%{query}%'),
                Campaign.goals.ilike(f'%{query}%')
            )
        ).all()

        results = [
            {
                'campaign_name': result.name,
                'description': result.description,
                'budget': result.budget,
                'start_date': result.start_date.strftime('%Y-%m-%d'),
                'end_date': result.end_date.strftime('%Y-%m-%d'),
                'goals': result.goals,
                'ad_requests': [
                    {
                        'ad_request_id': req.ad_request_id,
                        'messages': req.messages,
                        'payment_amount': req.payment_amount,
                        'status': req.status
                    }
                    for req in result.ad_requests
                    if req.influencer_id == influencer.influencer_id
                ]
            }
            for result in search_results
        ]
    elif search_type == 'sponsors':
        # Assuming Sponsor model has name and industry
        search_results = Sponsor.query.filter(
            or_(
                Sponsor.name.ilike(f'%{query}%'),
                Sponsor.industry.ilike(f'%{query}%')
            )
        ).all()

        results = [
            {
                'name': result.name,
                'industry': result.industry,
                'id': result.sponsor_id
            }
            for result in search_results
        ]
    elif search_type == 'adrequests':
        search_results = AdRequest.query.filter(
            AdRequest.influencer_id == influencer.influencer_id,
            or_(
                AdRequest.messages.ilike(f'%{query}%'),
                AdRequest.requirements.ilike(f'%{query}%'),
                AdRequest.status.ilike(f'%{query}%')
            )
        ).all()

        results = [
            {
                'ad_request_id': req.ad_request_id,
                'messages': req.messages,
                'requirements': req.requirements,
                'payment_amount': req.payment_amount,
                'status': req.status,
                'campaign_name': req.campaign.name
            }
            for req in search_results
        ]

    return jsonify(results)

'''

@app.route('/api/adrequest/<int:ad_request_id>', methods=['PUT'])
@login_required
def update_ad_request_status(ad_request_id):
    # Fetch the ad request from the database
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    user_id = current_user.user_id
    influencer=Influencer.query.filter_by(user_id=user_id).first()
    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    # Ensure that only authorized users can update the status
    if  ad_request.influencer_id!= influencer.influencer_id:
        return jsonify({"error": "Unauthorized access"}), 403

    # Parse the JSON data from the request
    data = request.get_json()

    # Validate the status field
    if 'status' not in data or data['status'] not in ['Accepted', 'Rejected']:
        return jsonify({"error": "Invalid status"}), 400

    # Update the ad request status
    ad_request.status = data['status']
    
    # Commit the changes to the database
    try:
        db.session.commit()
        return jsonify({"message": "Ad request status updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
@app.route('/sponsor_adrequests')
@login_required
def ad_requests():
    return render_template('sponsor_adrequests.html')



@app.route('/api/influencer_adrequest/<int:ad_request_id>', methods=['DELETE'])
@login_required
def delete_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    user_id=current_user.user_id
    influencer=Influencer.query.filter_by(user_id=user_id).first()
    influencer_id=influencer.influencer_id
    if ad_request.influencer_id != influencer_id:
        abort(403)  # Forbidden

    db.session.delete(ad_request)
    db.session.commit()
    return jsonify({'message': 'Ad request deleted successfully'})


@app.route('/api/influencer_adrequest', methods=['GET'])
@login_required
def get_influencer_adrequests():
    # Ensure the current user is an influencer
    if current_user.role != 'Influencer':
        return jsonify({'error': 'Access denied.'}), 403

    influencer = Influencer.query.filter_by(user_id=current_user.user_id).first()
    campaigns = (
    db.session.query(Campaign)
    .outerjoin(Flag, Campaign.campaign_id == Flag.campaign_id)
    .filter(
        Campaign.visibility == 'public',
        Flag.flag_id.is_(None)
    ))
    campaignlist=[
        {
            'campaign_name':campaign.name,
            'campaign_id':campaign.campaign_id
        } for campaign in campaigns
    ]
    ad_requests = (
    db.session.query(AdRequest)
    .join(Campaign, AdRequest.campaign_id == Campaign.campaign_id)
    .join(Sponsor, Campaign.sponsor_id == Sponsor.sponsor_id)
    .outerjoin(Flag, (Flag.campaign_id == Campaign.campaign_id) & (Flag.flagged_user_id == Sponsor.user_id))
    .filter(Campaign.visibility == 'public', Flag.flag_id.is_(None))
    .all()
)

    # Serialize ad requests
    ad_requests_list = [
        {
            'ad_request_id': ad_request.ad_request_id,
            'campaign_id': ad_request.campaign_id,
            'campaign_name': ad_request.campaign.name,  # Include campaign name
            'sponsor_name': ad_request.campaign.sponsor.name,  # Include sponsor name
            'messages': ad_request.messages,
            'requirements': ad_request.requirements,
            'payment_amount': ad_request.payment_amount,
            'status': ad_request.status,
            'initiated_by':ad_request.initiated_by
        }
        for ad_request in ad_requests
    ]

    return jsonify({'ad_requests_list':ad_requests_list,'campaigns':campaignlist,'influencer':influencer.influencer_id})


@app.route('/sponsor_profile', methods=['POST', 'GET'])
@login_required
def sponsor_profile():
    if current_user.role != 'Sponsor':
        return jsonify({'error': 'Forbidden'}), 403

    return render_template('sponsor_profile.html')
@app.route('/api/saveProfile', methods=['POST'])
@login_required
def save_profile():
    if current_user.role != 'Sponsor':
        return jsonify({'error': 'Forbidden'}), 403

    data = request.form  # Assuming form data is sent

    # Validate data
    name = data.get('name')
    industry = data.get('industry')
    budget = data.get('budget')

    if not name or not industry or not budget:
        return jsonify({'error': 'Missing required fields'}), 400

    # Fetch the existing sponsor record or create a new one
    sponsor = Sponsor.query.filter_by(user_id=current_user.user_id).first()
    if sponsor is None:
        sponsor = Sponsor(user_id=current_user.user_id)

    # Update sponsor details
    sponsor.name = name
    sponsor.industry = industry
    sponsor.budget = budget

    # Commit changes to the database
    try:
        db.session.add(sponsor)
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@app.route('/api/influencer_profile')
@login_required
def get_influencer_profile():
    influencer = Influencer.query.filter_by(user_id=current_user.user_id).first()
    if influencer:
        return jsonify({
            'name': influencer.name,
            'niche': influencer.niche,
            'reach': influencer.reach  # Adjusted here
        })
    else:
        return jsonify({'error': 'Influencer not found'}), 404


@app.route('/influencer_profile',methods=['GET'])
@login_required
def influencer_profile():
    if current_user.role!='Influencer':
        return jsonify({'error':'Forbidden'}),403
    return render_template('influencer_profile.html')
@app.route('/api/save_influencer_profile', methods=['POST'])
@login_required
def save_influencer_profile():
    if not current_user.influencer:
        return jsonify({'error': 'Forbidden'}), 403

    data = request.form  # Assuming form data is sent

    # Validate data
    name = data.get('name')
    niche = data.get('niche')

    if not name or not niche:
        return jsonify({'error': 'Missing required fields'}), 400

    # Fetch the existing influencer record or create a new one
    influencer = Influencer.query.filter_by(user_id=current_user.user_id).first()
    if influencer is None:
        influencer = Influencer(user_id=current_user.user_id)

    # Update influencer details
    influencer.name = name
    influencer.niche = niche

    # Commit changes to the database
    try:
        db.session.add(influencer)
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/campaigns', methods=['POST'])
@login_required
def add_campaign():
    if current_user.role=='Sponsor':
        data = request.get_json()
        user_id = current_user.user_id

        sponsor = Sponsor.query.filter_by(user_id=user_id).first()

        
        sponsor_id = sponsor.sponsor_id
        new_campaign = Campaign(
            sponsor_id=sponsor_id,
            name=data['name'],
            description=data['description'],
            start_date=datetime.strptime(data['start_date'], '%Y-%m-%d'),
            end_date=datetime.strptime(data['end_date'], '%Y-%m-%d'),
            budget=data['budget'],
            visibility=data['visibility'],
            goals=data['goals']
        )
        db.session.add(new_campaign)
        db.session.commit()
        return jsonify({'message': 'Campaign added successfully'}), 201
@app.route('/api/influencer_adrequests/<int:ad_request_id>', methods=['DELETE'])
@login_required
def delete_add_request(ad_request_id):
    ad_request = AdRequest.query.get(ad_request_id)
    
    if not ad_request:
        return jsonify({'error': 'Ad request not found'}), 404

  
    
   
    db.session.delete(ad_request)
    db.session.commit()
    return jsonify({'message': 'Ad request deleted successfully'})
@app.route('/api/adrequest/<int:ad_request_id>/accept', methods=['POST'])
def accept_ad_request(ad_request_id):
    ad_request = AdRequest.query.get(ad_request_id)
    
    if not ad_request:
        return jsonify({"message": "Ad request not found"}), 404
    
    # Update the status to 'Accepted'
    ad_request.status = 'Accepted'
    #ad_request.initiated_by = 'Sponsor'  # Assuming the sponsor initiates the acceptance.
    
    try:
        db.session.commit()
        return jsonify({"message": "Ad request accepted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Error accepting ad request: {str(e)}"}), 500
def fetch_statistics():
    try:
        # Number of Sponsors
        num_sponsors = Sponsor.query.count()

        # Number of Influencers
        num_influencers = Influencer.query.count()
        # Number of Sponsors
        num_sponsors = Sponsor.query.count()

        # Number of Influencers
        num_influencers = Influencer.query.count()

        # Number of Campaigns
        num_campaigns = Campaign.query.count()

        # Number of Ad Requests
        num_ad_requests = AdRequest.query.count()

        # Total Number of Flagged Users (Sponsors + Influencers)
        flagged_users = (
            db.session.query(Flag.flagged_user_id)
            .join(User, User.user_id == Flag.flagged_user_id)
            .distinct()
            .all()
        )
        no_of_users_flagged = len(flagged_users)

        # Flagged Campaign Names
        flagged_campaigns = (
            db.session.query(Campaign.name)
            .join(Flag, Flag.campaign_id == Campaign.campaign_id)
            .distinct()
            .all()
        )
        flagged_campaign_names = [campaign.name for campaign in flagged_campaigns]

        # Flagged Sponsor Names
        flagged_sponsors = (
            db.session.query(Sponsor.name)
            .join(User, User.user_id == Sponsor.user_id)
            .join(Flag, Flag.flagged_user_id == User.user_id)
            .distinct()
            .all()
        )
        flagged_sponsor_names = [sponsor.name for sponsor in flagged_sponsors]

        # Flagged Influencer Names
        flagged_influencers = (
            db.session.query(Influencer.name)
            .join(User, User.user_id == Influencer.user_id)
            .join(Flag, Flag.flagged_user_id == User.user_id)
            .distinct()
            .all()
        )
        flagged_influencer_names = [influencer.name for influencer in flagged_influencers]

        # Statistics Dictionary
        stats = {
            'num_sponsors': num_sponsors,
            'num_influencers': num_influencers,
            'num_campaigns': num_campaigns,
            'num_ad_requests': num_ad_requests,
            'no_of_users_flagged': no_of_users_flagged,
            'flagged_campaign_names': flagged_campaign_names,
            'flagged_sponsor_names': flagged_sponsor_names,
            'flagged_influencer_names': flagged_influencer_names,
        }
        print(stats)
        # Return JSON response
        return {
            'num_sponsors': num_sponsors,
            'num_influencers': num_influencers,
            'num_campaigns': num_campaigns,
            'num_ad_requests': num_ad_requests,
            'no_of_users_flagged': no_of_users_flagged,
            'flagged_campaign_names': flagged_campaign_names,
            'flagged_sponsor_names': flagged_sponsor_names,
            'flagged_influencer_names': flagged_influencer_names,
        }

    except Exception as e:
        # Handle unexpected errors
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics')
def statistics():
    stats = fetch_statistics()  # This function fetches all the data
    return jsonify(stats)
@app.route('/admin_statistics')
def statistics_page():
    return render_template('statistics.html')


@app.route('/api/adrequest/<int:ad_request_id>/reject', methods=['POST'])
def reject_ad_request(ad_request_id):
    ad_request = AdRequest.query.get(ad_request_id)
    
    if not ad_request:
        return jsonify({"message": "Ad request not found"}), 404
    
    # Update the status to 'Rejected'
    ad_request.status = 'Rejected'
    
    try:
        db.session.commit()
        return jsonify({"message": "Ad request rejected successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Error rejecting ad request: {str(e)}"}), 500
@app.route('/api/adrequest_accept_reject', methods=['POST'])
def adrequest_accept_reject():
    data = request.json
    ad_request_id = data.get('ad_request_id')
    status = data.get('status')
    
    

    ad_request = AdRequest.query.get(ad_request_id)
    
    if not ad_request:
        return jsonify({'error': 'Ad request not found'}), 404

    if ad_request.initiated_by == 'Influencer':
        return jsonify({'error': 'Cannot modify requests initiated by an influencer'}), 403

    ad_request.status = status
    db.session.commit()
    
    return jsonify({'message': 'Ad request status updated successfully'})
@app.route('/api/campaign/<int:campaign_id>', methods=['PUT'])
@login_required
def update_campaign(campaign_id):
    data = request.get_json()
    sponsor=Sponsor.query.filter_by(user_id=current_user.user_id).first()
    campaign = Campaign.query.filter_by(campaign_id=campaign_id, sponsor_id=sponsor.sponsor_id).first_or_404()

    campaign.name = data['name']
    campaign.description = data['description']
    campaign.start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
    campaign.end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
    campaign.budget = data['budget']
    campaign.visibility = data['visibility']
    campaign.goals = data['goals']

    db.session.commit()
    return jsonify({'message': 'Campaign updated successfully'}), 200
@app.route('/admin_dashboard',methods=['GET'])
@login_required
def admin_dashboard():
    
    if current_user.role!='Admin':
        return url_for('welcome')
    return render_template('admin_dashboard.html')
@app.route('/api/campaigns/<int:campaign_id>', methods=['DELETE'])
@login_required
def delete_campaign(campaign_id):
    campaign = Campaign.query.filter_by(campaign_id=campaign_id, sponsor_id=current_user.user_id).first_or_404()
    db.session.delete(campaign)
    db.session.commit()
    return jsonify({'message': 'Campaign deleted successfully'}), 200
@app.route('/api/flag_adrequest', methods=['POST'])
def flag_ad_request():
    data = request.get_json()
    ad_request_id = data.get('ad_request_id')
    action = data.get('flag_action')  # 'flag' or 'unflag'

    if not ad_request_id or not action:
       
        return jsonify({"error": "Invalid data"}), 400

    ad_request = AdRequest.query.get(ad_request_id)

    if not ad_request:
        return jsonify({"error": "Ad request not found"}), 404

    # Flagging logic
    if action == 'flag':
        # No change to the existing logic for flagging (as per your requirement)
        flag = Flag(
            user_id=ad_request.influencer.user_id,  # The influencer flagging the ad request
            ad_request_id=ad_request_id,
            reason=data.get('reason'),  # Reason for flagging
            type='ad_request'  # We're flagging an ad request
        )
        db.session.add(flag)
    
    # Unflagging logic
    elif action == 'unflag':
        # Find the flag entry for the given ad_request_id and delete it
        flag = Flag.query.filter_by(ad_request_id=ad_request_id).first()
        
        if not flag:
         
            return jsonify({"error": "Flag entry not found"}), 404
        
        # Delete the flag entry
        db.session.delete(flag)
    
    else:
        return jsonify({"error": "Invalid action"}), 400

    # Commit the changes to the database
    try:
        db.session.commit()
        if action == 'flag':
            return jsonify({"flag_status": "Flagged"}), 201
        else:
            return jsonify({"flag_status": "unflagged"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500



@app.route('/admin_campaigns')
@login_required
def admin_campaigns():
    # Ensure the user is an admin
    if current_user.role != 'Admin':
        return redirect(url_for('home'))

    # Query all campaigns and related sponsors
    campaigns = db.session.query(Campaign, Sponsor).join(Sponsor, Campaign.sponsor_id == Sponsor.sponsor_id).all()
    
    return render_template('admin_campaigns.html', campaigns=campaigns)
def flag_item(flagged_item_id, user_id, reason, flagged_type):
    
    flag = Flag(user_id=user_id, campaign_id=flagged_item_id, reason=reason, type=flagged_type)
    db.session.add(flag)

    if flagged_type == 'sponsor':
        # If a sponsor is flagged, flag all related campaigns and ad requests
        campaigns = Campaign.query.filter_by(sponsor_id=flagged_item_id).all()
        for campaign in campaigns:
            # Flag each campaign with type 'campaign'
            campaign_flag = Flag(user_id=user_id, campaign_id=campaign.campaign_id, reason=reason, type='campaign')
            db.session.add(campaign_flag)
            
            # Flag all ad requests associated with this campaign
            ad_requests = AdRequest.query.filter_by(campaign_id=campaign.campaign_id).all()
            for ad_request in ad_requests:
                ad_request_flag = Flag(user_id=user_id, ad_request_id=ad_request.ad_request_id, reason=reason, type='ad_request')
                db.session.add(ad_request_flag)

    elif flagged_type == 'influencer':
        # If an influencer is flagged, flag all ad requests associated with this influencer
        ad_requests = AdRequest.query.filter_by(influencer_id=flagged_item_id).all()
        for ad_request in ad_requests:
            ad_request_flag = Flag(user_id=user_id, ad_request_id=ad_request.ad_request_id, reason=reason, type='ad_request')
            db.session.add(ad_request_flag)
    
    elif flagged_type == 'campaign':
        # If a campaign is flagged, flag all associated ad requests
        ad_requests = AdRequest.query.filter_by(campaign_id=flagged_item_id).all()
        for ad_request in ad_requests:
            ad_request_flag = Flag(user_id=user_id, ad_request_id=ad_request.ad_request_id, reason=reason, type='ad_request')
            db.session.add(ad_request_flag)

    # Commit the changes to the database
    db.session.commit()

    return {"message": "Flagged successfully"}


@app.route('/api/flag', methods=['POST'])
def flag_item_route():
    data = request.get_json()
    flagged_item_id = data.get('flagged_item_id')
    user_id = data.get('user_id')
    reason = data.get('reason')
    flagged_type = data.get('flagged_type')  # 'sponsor', 'influencer', 'campaign', or 'ad_request'
    
    result = flag_item(flagged_item_id, user_id, reason, flagged_type)
    return jsonify(result), 200

@app.route('/api/admin_flag', methods=['POST'])
def toggle_flag():
    data = request.get_json()  # Get the request data
    campaign_id = data.get('campaign_id')
    action = data.get('action')
    reason = data.get('reason', '')

    if action == 'flag':
        # Get the campaign
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404

        # Flag the campaign
        campaign_flag = Flag(
            campaign_id=campaign_id,
            user_id=current_user.user_id,  # The admin who flagged the campaign
            reason=reason,
            created_at=datetime.utcnow(),
            type='campaign'  # Indicating it's a campaign flag
        )
        db.session.add(campaign_flag)

        # Get all ad requests associated with the campaign
        ad_requests = AdRequest.query.filter_by(campaign_id=campaign_id).all()
        for ad_request in ad_requests:
            # Flag each associated ad request
            ad_request_flag = Flag(
                ad_request_id=ad_request.ad_request_id,
                user_id=current_user.user_id,  # The admin who flagged the ad request
                reason=reason,
                created_at=datetime.utcnow(),
                type='ad_request'  # Indicating it's an ad request flag
            )
            db.session.add(ad_request_flag)

        db.session.commit()

        return jsonify({'flag_status': 'Flagged', 'success': 'Campaign and all associated ad requests flagged successfully'}), 200

    elif action == 'unflag':
    
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404

       
        campaign_flag = Flag.query.filter_by(campaign_id=campaign_id, user_id=current_user.user_id, type='campaign').first()
        if not campaign_flag:
            return jsonify({'error': 'No flag found for this campaign'}), 404

        db.session.delete(campaign_flag)

        ad_requests = AdRequest.query.filter_by(campaign_id=campaign_id).all()
        for ad_request in ad_requests:
            ad_request_flags = Flag.query.filter_by(ad_request_id=ad_request.ad_request_id, user_id=current_user.user_id, type='ad_request').all()
            for flag in ad_request_flags:
                db.session.delete(flag)

        db.session.commit()

        return jsonify({'flag_status': 'Unflagged', 'success': 'Campaign and all associated ad requests unflagged successfully'}), 200

    return jsonify({'error': 'Invalid action'}), 400


@app.route('/admin_influencers')
def admin_influencers():
    # Fetch all influencers from the database
    influencers = Influencer.query.all()
    return render_template('admin_influencers.html', influencers=influencers)
@app.route('/api/admin_influencers')
@login_required
def api_admin_influencers():
    # Ensure the user is an admin
    if current_user.role != 'Admin':
        return jsonify({"error": "Unauthorized"}), 403

    # Query all influencers
    influencers = db.session.query(Influencer).all()

    data = []
    for influencer in influencers:
        flag_exists = db.session.query(Flag).filter_by(flagged_user_id=influencer.user_id).first()
        
        flag = "Flagged" if flag_exists else "Valid"
        influencer_data = {
            "influencer_id": influencer.influencer_id,
            "name": influencer.name,
            "category": influencer.category,
            "niche": influencer.niche,
            "reach": influencer.reach,
           
            "flag": flag  # Include flag in the response
        }

        data.append(influencer_data)

    return jsonify(data)
@app.route('/admin_sponsors')
@login_required
def admin_sponsors():
    if current_user.role != 'Admin':
        return redirect(url_for('home'))
    return render_template('admin_sponsors.html')
@app.route('/approve_sponsor', methods=['POST'])
@login_required
def approve_sponsor():
    data = request.get_json()
    sponsor_id = data.get('sponsor_id')

    if not sponsor_id:
        return jsonify({'success': False, 'error': 'Sponsor ID is required.'})

    sponsor = Sponsor.query.get(sponsor_id)

    if not sponsor:
        return jsonify({'success': False, 'error': 'Sponsor not found.'})

    sponsor.approval = 'approved'
    db.session.commit()

    return jsonify({'success': True})
@app.route('/api/admin_sponsors', methods=['GET', 'POST'])
@login_required
def api_admin_sponsors():
    if current_user.role != 'Admin':
        return jsonify({"error": "Unauthorized"}), 403

    if request.method == 'GET':
        # Fetching all sponsors and their flag status
        sponsors = db.session.query(Sponsor).all()
        data = []

        for sponsor in sponsors:
            flag_exists = db.session.query(Flag).filter_by(flagged_user_id=sponsor.user_id).first()
            flag = "Flagged" if flag_exists else "Valid"

            sponsor_data = {
                "sponsor_id": sponsor.sponsor_id,
                "name": sponsor.name,
                "industry": sponsor.industry,
                "budget": sponsor.budget,
                "flag": flag,
                'approval':sponsor.approval
            }
            data.append(sponsor_data)

        return jsonify(data)

    if request.method == 'POST':
        data = request.get_json()
        sponsor_id = data.get('sponsor_id')
        action = data.get('action')

        sponsor = Sponsor.query.get(sponsor_id)
        if not sponsor:
            return jsonify({"error": "Sponsor not found"}), 404

        if action == 'flag':
            # Flag the sponsor
            flag_exists = db.session.query(Flag).filter_by(flagged_user_id=sponsor.user_id).first()
            if not flag_exists:
                new_flag = Flag(user_id=sponsor.user_id, flagged_user_id=sponsor.user_id, reason='Admin flagged',type='sponsor')
                db.session.add(new_flag)
                
                # Flag all campaigns by this sponsor
                campaigns = Campaign.query.filter_by(sponsor_id=sponsor_id).all()
                for campaign in campaigns:
                    campaign_flag_exists = db.session.query(Flag).filter_by(campaign_id=campaign.campaign_id).first()
                    if not campaign_flag_exists:
                        campaign_flag = Flag(user_id=sponsor.user_id, campaign_id=campaign.campaign_id, reason='Sponsor flagged',type='campaign')
                        db.session.add(campaign_flag)
                    ad_requests = AdRequest.query.filter_by(campaign_id=campaign.campaign_id).all()
                    for ad_request in ad_requests:
                        ad_request_flag_exists = db.session.query(Flag).filter_by(ad_request_id=ad_request.ad_request_id).first()
                        if not ad_request_flag_exists:
                            ad_request_flag = Flag(
                                user_id=sponsor.user_id,
                                ad_request_id=ad_request.ad_request_id,
                                reason='Ad request flagged due to sponsor being flagged',type='ad_request'
                            )
                            db.session.add(ad_request_flag)    
                
                db.session.commit()
        elif action == 'unflag':
            # Unflag the sponsor
            flag_exists = db.session.query(Flag).filter_by(flagged_user_id=sponsor.user_id).first()
            if flag_exists:
                db.session.delete(flag_exists)
                
                # Unflag all campaigns by this sponsor
                campaigns = Campaign.query.filter_by(sponsor_id=sponsor_id).all()
                # Loop through campaigns to delete flags
                for campaign in campaigns:
                    # Delete flag for the campaign if it exists
                    campaign_flag_exists = db.session.query(Flag).filter_by(campaign_id=campaign.campaign_id).first()
                    if campaign_flag_exists:
                        db.session.delete(campaign_flag_exists)

                    # Delete flags for ad requests linked to this campaign
                    ad_requests = AdRequest.query.filter_by(campaign_id=campaign.campaign_id).all()
                    for ad_request in ad_requests:
                        ad_request_flag_exists = db.session.query(Flag).filter_by(ad_request_id=ad_request.ad_request_id).first()
                        if ad_request_flag_exists:
                            db.session.delete(ad_request_flag_exists)

                # Commit changes to the database
                try:
                    db.session.commit()
                    print("Campaige and associated ad request flags deleted successfully.")
                except Exception as e:
                    db.session.rollback()
                    print(f"Error deleting flags for campaigns or ad requests: {e}")


@app.route('/api/admin_flag_influencer', methods=['POST'])
@login_required
def flag_influencer():
    if current_user.role != 'Admin':
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    influencer_id = data.get('influencer_id')
    reason = data.get('reason', '')
    current_status = data.get('status')  # Get the current flag status from the frontend

    if not influencer_id:
        return jsonify({'error': 'Influencer ID is required'}), 400

    # Check if the influencer exists
    influencer = Influencer.query.get(influencer_id)
    if not influencer:
        return jsonify({'error': 'Influencer not found'}), 404

    # Retrieve any existing flag for the influencer
    existing_flag = Flag.query.filter_by(flagged_user_id=influencer.user_id).first()

    if current_status == 'Flagged':
        # Unflag the influencer and associated ad requests if already flagged
        if existing_flag:
            db.session.delete(existing_flag)

            # Unflag all associated ad requests
            ad_requests = AdRequest.query.filter_by(influencer_id=influencer_id).all()
            for ad_request in ad_requests:
                ad_request_flag = Flag.query.filter_by(ad_request_id=ad_request.ad_request_id).first()
                if ad_request_flag:
                    db.session.delete(ad_request_flag)

            db.session.commit()
            return jsonify({'success': 'Influencer and associated ad requests unflagged successfully'}), 200
        else:
            return jsonify({'error': 'Influencer is not currently flagged'}), 400

    # Flag the influencer and associated ad requests if not already flagged
    if current_status == 'Valid':
        if not reason:
            return jsonify({'error': 'Reason for flagging is required'}), 400

        # Flag the influencer
        new_flag = Flag(
            user_id=influencer.user_id,
            flagged_user_id=influencer.user_id,
            reason=reason,
            type='influencer'
        )
        db.session.add(new_flag)

        # Flag all associated ad requests
        ad_requests = AdRequest.query.filter_by(influencer_id=influencer_id).all()
        for ad_request in ad_requests:
            ad_request_flag_exists = Flag.query.filter_by(ad_request_id=ad_request.ad_request_id).first()
            if not ad_request_flag_exists:
                ad_request_flag = Flag(
                    user_id=influencer.user_id,
                    ad_request_id=ad_request.ad_request_id,
                    reason=f'Influencer flagged: {reason}',
                    type='ad_request'
                )
                db.session.add(ad_request_flag)

        db.session.commit()
        return jsonify({'success': 'Influencer and associated ad requests flagged successfully'}), 200

    return jsonify({'error': 'Invalid status provided'}), 400


@app.route('/api/admin_campaigns')
@login_required
def api_admin_campaigns():
   # if current_user.role != 'Admin':
       # return jsonify({"error": "Unauthorized"}), 403


    campaigns = db.session.query(Campaign, Sponsor).join(Sponsor, Campaign.sponsor_id == Sponsor.sponsor_id).all()

    
    data = []
    for campaign, sponsor in campaigns:
        
        flag_exists = db.session.query(Flag).filter_by(campaign_id=campaign.campaign_id).first()

       
        flag = "Flagged" if flag_exists else "Valid"

        campaign_data = {
            "campaign_id": campaign.campaign_id,
            "name": campaign.name,
            "description": campaign.description,
            "start_date": campaign.start_date.strftime('%Y-%m-%d') if campaign.start_date else None,
            "end_date": campaign.end_date.strftime('%Y-%m-%d') if campaign.end_date else None,
            "budget": campaign.budget,
            "visibility": campaign.visibility,
            "goals": campaign.goals,
            "sponsor_name": sponsor.name,
            "sponsor_industry": sponsor.industry,
            "sponsor_budget": sponsor.budget,
            "flag": flag  # Include flag in the response
        }

        data.append(campaign_data)
    
    return jsonify(data)


# Routes for user authentication and dashboards
@app.route('/loginn', methods=['GET', 'POST'])
def loginn():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        user = User.query.filter_by(username=username).first()
       

        print(password,user.password)
        if user and verify_password(password, user.password):
            print(role,user.role)
            if role == user.role:
                
                login_user(user)
                print("hello")
                access_token = create_access_token(identity=user.useremail)

                if role == 'Influencer':
                    return jsonify({'redirect': url_for('influencer_dashboard', access_token=access_token)})
                elif role == 'Sponsor':
                    sponsor = Sponsor.query.filter_by(user_id=user.user_id).first()  # Ensure correct user_id is used
                    if sponsor and sponsor.approval != 'approved':
                        logout()
                        return jsonify({'error': "You haven't been approved by the Admin yet"})
                    return jsonify({'redirect': url_for('sponsor_dashboard', access_token=access_token)})
                elif role == 'Admin':
                    return jsonify({'redirect': url_for('admin_dashboard', access_token=access_token)})
            else:
                return jsonify({'error': 'Role mismatch. Please select the correct role.'})
        else:
            return jsonify({'error': 'Invalid username or password. Please try again.'})
    return render_template('home.html')

       

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    import random
    if request.method == 'POST':
        username = request.form['username']
        useremail = request.form['useremail']
        password = request.form['password']
        role = request.form['role']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('signup'))
        else:
            fs_uniquifier = str(uuid4())
            hashed_password = hash_password(password)
            user = user_datastore.create_user(username=username, useremail=useremail, role=role, password=hashed_password)
            db.session.commit()
            created_user = User.query.filter_by(username=username).first()
    
        if created_user:
            user_role = created_user.role
            user_name = created_user.username
            user_id = created_user.user_id
            
            if role == 'Influencer':
                influencer = Influencer.query.filter_by(user_id=user_id).first()
                if not influencer:
                    influencer = Influencer(user_id=user_id, name=user_name)
                    db.session.add(influencer)
                else:
                    influencer.name = user_name
                    
                db.session.commit()
                influencer.reach=random.randint(2, 100)
                db.session.commit()
            elif role == 'Sponsor':
                sponsor = Sponsor.query.filter_by(user_id=user_id).first()
                if not sponsor:
                    sponsor = Sponsor(user_id=user_id, name=user_name)
                    db.session.add(sponsor)
                else:
                    sponsor.name = user_name
                db.session.commit()
            
            flash('User created successfully.')

        return redirect(url_for('welcome'))
    else:
        return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    #logout_user()
    session.clear()
    return redirect(url_for('loginn'))

@app.route('/api/influencer', methods=['GET'])
@login_required  
def get_influencer_data():
    if current_user.role != 'Influencer':
        return jsonify({'error': 'Forbidden'}), 403
    
    influencer = Influencer.query.filter_by(user_id=current_user.user_id).first()
    if not influencer:
        return jsonify({'error': 'Influencer not found'}), 404
    
    influencer_data = {
        'name': influencer.name,
        'category': influencer.category,
        'niche': influencer.niche,
        'reach': influencer.reach
    }
    return jsonify(influencer_data)
@app.route('/api/sponsor_campaigns', methods=['GET'])
@login_required
def get_sponsor_campaigns():
    # Ensure that the current_user has a valid sponsor role
    if not hasattr(current_user, 'sponsor'):
        return jsonify({'error': 'Unauthorized'}), 403
    sponsor=Sponsor.query.filter_by(user_id=current_user.user_id).first()
    # Query campaigns for the current sponsor
    campaigns = db.session.query(Campaign).filter_by(sponsor_id=sponsor.sponsor_id).all()
    
    # Serialize the campaign data
    campaign_data = [
        {
            'id': campaign.campaign_id,
            'name': campaign.name,
            'description': campaign.description,
            'visibility':campaign.visibility,
            
            'budget': campaign.budget,
            'goals': campaign.goals,
            'start_date': campaign.start_date.strftime('%Y-%m-%d'),
            'end_date': campaign.end_date.strftime('%Y-%m-%d')
        }
        for campaign in campaigns
    ]
    
    return jsonify({'campaigns': campaign_data})
@app.route('/api/influencer_campaigns', methods=['GET'])
@login_required
def get_public_and_valid_campaigns():
    # Subquery to get flagged campaign IDs
    from sqlalchemy.orm import aliased  # Import aliased
    from sqlalchemy.sql import and_
    public_campaigns = db.session.query(Campaign.campaign_id).filter(Campaign.visibility == 'public').subquery()

# Alias for Campaigns table
    campaign_alias = aliased(Campaign)

# Main query to fetch public and valid campaigns
    campaigns = db.session.query(campaign_alias).outerjoin(
        Flag, campaign_alias.campaign_id == Flag.campaign_id
        ).filter(
        and_(
        campaign_alias.visibility == 'public',
        Flag.campaign_id == None  # Exclude flagged campaigns
    )
    ).all()

    campaign_data = [
        {
            'id': campaign.campaign_id,
            'name': campaign.name,
            'description': campaign.description,
            'visibility': campaign.visibility,
            'budget': campaign.budget,
            'goals': campaign.goals,
            'start_date': campaign.start_date.strftime('%Y-%m-%d') if campaign.start_date else None,
            'end_date': campaign.end_date.strftime('%Y-%m-%d') if campaign.end_date else None
        } for campaign in campaigns
    ]

    return jsonify({'campaigns': campaign_data})
@app.route('/influencer_campaigns', methods=['GET'])
def influencer_campaigns():
    return render_template('influencer_campaigns.html')
@app.route('/sponsor_campaigns')
@login_required
def sponsor_campaigns():
    if current_user.role != 'Sponsor':
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('sponsor_campaigns.html')

@app.route('/api/sponsor', methods=['GET'])
@login_required
def get_sponsor_data():
    if current_user.role != 'Sponsor':
        return jsonify({'error': 'Forbidden'}), 403
    sponsor = Sponsor.query.filter_by(user_id=current_user.user_id).first()
    if not sponsor:
        return jsonify({'error': 'Sponsor not found'}), 404
    sponsor_data = {'name': sponsor.name, 'sponsor_id':sponsor.sponsor_id,'industry': sponsor.industry, 'budget': sponsor.budget}
    return jsonify(sponsor_data)

@app.route('/sponsor_dashboard', methods=['GET'])
@login_required
def sponsor_dashboard():
    if current_user.role != 'Sponsor':
        return redirect(url_for('home'))
    return render_template('sponsor_dashboard.html')

@app.route('/influencer_dashboard', methods=['GET'])
@login_required 
def influencer_dashboard():
    if current_user.role != 'Influencer':
        return redirect(url_for('home'))
    return render_template('influencer_dashboard.html')

@app.route('/', methods=['GET', 'POST'])
@app.route('/welcome', methods=['GET', 'POST'])
def welcome():
    return render_template('welcome.html', alert_message=get_flashed_messages(with_categories=True))
@app.route('/admin_search')
def admin_search():
    # Render the 'admin_search.html' template
    return render_template('admin_search.html')
@app.route('/admin_adrequests')
def admin_adrequests():
    # Fetch all ad requests
    
    
    return render_template('admin_adrequests.html')
@app.route('/api/admin_adrequests', methods=['GET'])
def get_admin_adrequests():
    try:
        # Query ad requests, joining Campaign, Influencer, and Flag tables
        ad_requests = db.session.query(
            AdRequest.ad_request_id,
            Campaign.name.label('campaign_name'),
            Influencer.name.label('influencer_name'),
            AdRequest.messages,
            AdRequest.requirements,
            AdRequest.payment_amount,
            AdRequest.status,
            AdRequest.initiated_by,
            # Check if the ad request is flagged
            Flag.reason.label('flag_reason')  # Get the flag reason
        ).join(Campaign, Campaign.campaign_id == AdRequest.campaign_id) \
         .outerjoin(Influencer, Influencer.influencer_id == AdRequest.influencer_id) \
         .outerjoin(Flag, Flag.ad_request_id == AdRequest.ad_request_id) \
         .all()
        for ad_request in ad_requests:
            print(f"AdRequest ID: {ad_request.ad_request_id}, "
                f"Campaign: {ad_request.campaign_name}, "
                f"Influencer: {ad_request.influencer_name}, "
                f"Flag Reason: {ad_request.flag_reason}")
        # Build the result list
        result = [
            {
                'ad_request_id': ad.ad_request_id,
                'campaign_name': ad.campaign_name,
                'influencer_name': ad.influencer_name,
                'messages': ad.messages,
                'requirements': ad.requirements,
                'payment_amount': ad.payment_amount,
                'status': ad.status,
                'initiated_by': ad.initiated_by,
                'flagged': 'Flagged' if ad.flag_reason else 'Valid',  # Check if flag_reason exists
                'flag_reason': ad.flag_reason if ad.flag_reason else 'None'  # Only return reason if flagged
            }
            for ad in ad_requests
        ]

        return jsonify({'results': result})

    except Exception as e:
        app.logger.error(f"Error fetching ad requests: {e}")
        return jsonify({'error': 'Internal server error'}), 500


    except Exception as e:
        app.logger.error(f"Error fetching admin ad requests: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500
celery_app.conf.beat_schedule = {
        'monthly-report-task': {
        'task': 'app.monthly_report',
        'schedule': crontab(day_of_month=3, hour=16, minute=5),  # Adjust the schedule as needed
    },
    'send-daily-reminder': {
        'task': 'app.send_daily_reminder',
        'schedule': crontab(hour=16, minute=5),
    },
}
    
@celery_app.task
def send_daily_reminder():
    # Access the Flask app context via `current_app`
        #print(ad_requests)  # Debugging the ad_requests data 
        # Fetch influencers with pending ad requests
        influencers = Influencer.query.all()
        for influencer in influencers:
            # Fetch pending ad requests for the influencer
            pending_ad_requests = AdRequest.query.filter_by(
                influencer_id=influencer.influencer_id,
                status='Pending'
            ).all()
            print(pending_ad_requests)  # Debugging the ad_requests data    
            # If there are pending ad requests
            if pending_ad_requests:
                # Prepare data for the email template
                ad_requests_info = []
                for ad_request in pending_ad_requests:
                    campaign = Campaign.query.filter_by(campaign_id=ad_request.campaign_id).first()
                    ad_requests_info.append({
                        'campaign_name': campaign.name,
                        'messages': ad_request.messages,
                        'requirements': ad_request.requirements,
                        'payment_amount': ad_request.payment_amount
                    })
                
                # Render the email template
                message = render_template(
                    'daily_html_template.html',
                    user_name=influencer.name,
                    ad_requests=ad_requests_info
                )

                # Send the email
                send_email(
                    to_address=influencer.user.useremail, # Send to influencer's email
                    subject="🔔 Reminder: You Have Pending Ad Requests!",
                    message=message
                )

app.config['SERVER_NAME'] = 'localhost:5000' 


print(celery_app.tasks)
#celery_app.on_after_configure.connect
#def setup_periodic_tasks(sender, **kwargs):
#    sender.add_periodic_task(10.0,send_daily_reminder_email.s(),name='add every 10')
import smtplib
from jinja2 import Template
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

from io import BytesIO

SMPTP_SERVER_HOST = "localhost"
SMPTP_SERVER_PORT = 1025
SENDER_ADDRESS = "showcase.com"
SENDER_PASSWORD = ''
def send_email(to_address, subject, message, attachment=None):
    msg=MIMEMultipart()
    msg["From"] = "hamsini" 
    msg['To'] = to_address
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'html'))
    

    if attachment:
        part = MIMEBase('application', 'pdf')
        part.set_payload(attachment)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="Monthly_report.pdf"')
        msg.attach(part)


    s =smtplib.SMTP(host=SMPTP_SERVER_HOST, port=SMPTP_SERVER_PORT)
    s.login(SENDER_ADDRESS,SENDER_PASSWORD)
    s.send_message(msg)
    s.quit()

    return "sent email succifuly"    
@celery_app.task()
def send_daily_reminder_email():
    with app.app_context():
        send_email(to_address="hamsiniganapathy@gmail.com",subject="Demooo",message="Hellooo!! We are doing a demo for email transmission")
        return "Email should arrive in your inbox"
@app.route("/status/<id>")
def check_status(id):
    res=AsyncResult(id)
    return {
            "Task ID":res.id,
            "Task State":res.state,
            "Task result":res.result
       
            }

@celery_app.task()                                                           
def send_reminder():                                                           
  
    from json import dumps                                                     
    """Google Chat incoming webhook quickstart."""                             
    url = "https://chat.googleapis.com/v1/spaces/AAAAKJdjVhQ/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=0fnYdrVC5RXFLMbVcAgas3sOy0kxAsFqSYxeoo3PHPQ"
    app_message = {"text": "Heyy, please check your Pending Ad Requests"}
    message_headers = {"Content-Type": "application/json; charset=UTF-8"}
    http_obj = Http()
    response = http_obj.request(
        uri=url,
        method="POST",
        headers=message_headers,
        body=dumps(app_message),
    )
    print(response)
    return "Reminder will be sent shortly"
    
@celery_app.task(name="generate_campaign_csv")
def generate_campaign_csv(sponsor_id):

    # Fetch campaigns created by the sponsor
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor_id).all()

    # Prepare data for CSV
    rows = []
    for campaign in campaigns:
        rows.append([
            campaign.name,
            campaign.description,
            campaign.start_date.strftime('%Y-%m-%d') if campaign.start_date else '',
            campaign.end_date.strftime('%Y-%m-%d') if campaign.end_date else '',
            campaign.budget,
            campaign.visibility,
            campaign.goals
        ])

    # Define CSV headers
    fields = ['Name', 'Description', 'Start Date', 'End Date', 'Budget', 'Visibility', 'Goals']

    # Create a dynamic file name using sponsor_id and the current timestamp
    filename = f"static/data.csv"
    
    # Writing to CSV file
    with open(filename, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(fields)  # Writing the headers
        csvwriter.writerows(rows)  # Writing the data rows

    # Assuming you have a function to send alerts/notifications
    alert_message = f"Your campaign export is complete. Download your file here: {url_for('static', filename=filename, _external=True)}"
    

    return f"CSV generated at {filename}"
@app.route('/export_campaigns', methods=['POST'])
def export_campaigns():
    data = request.get_json()
    sponsor_id = data.get('sponsor_id')
    
    if sponsor_id is None:
        return jsonify({'error': 'sponsor_id is required'}), 400
    
    generate_campaign_csv.delay(sponsor_id)
    return jsonify({'message': 'Campaign export has been initiated.'})

@app.route("/download-file")
def download_file():
    # Get the sponsor_id and campaign_id from query parameters
    sponsor_id = request.args.get('sponsor_id')
    
    
    # Build the filename dynamically
    filename = f"static/data.csv"  # Example filename format
    
   
    return send_file(filename)



@celery_app.task()
def send_daily_reminder_email():
    with app.app_context():
	    send_email(to_address="hamsiniganapathy@gmail.com",subject="Demooo",message="Hellooo!! We are doing a demo for email transmission")
	    return "Email should arrive in your inbox"


@app.route('/api/admin_adrequests', methods=['GET'])
def get_ad_requests():
    ad_requests = AdRequest.query.all()
    ad_requests_data = []
    
    for ad_request in ad_requests:
        campaign = Campaign.query.get(ad_request.campaign_id)
        influencer = Influencer.query.get(ad_request.influencer_id)
        sponsor = Sponsor.query.get(campaign.sponsor_id) if campaign else None

        ad_requests_data.append({
            'ad_request_id': ad_request.ad_request_id,
            'campaign_name': campaign.name if campaign else 'N/A',
            'sponsor_name': sponsor.name if sponsor else 'N/A',
            'influencer_name': influencer.name if influencer else 'N/A',
            'messages': ad_request.messages,
            'requirements': ad_request.requirements,
            'payment_amount': ad_request.payment_amount,
            'status': ad_request.status,
            'Initiated_By':ad_request.initiated_by
        })

    return jsonify(ad_requests_data)

   

if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)
'''
@celery.task
def monthly_report():
    with app.app_context():
        sponsors = db.session.query(User).join(Sponsor).filter_by(role='Sponsor').all()
        current_month = datetime.now().month
        month_name = calendar.month_name[current_month]
        
        for sponsor in sponsors:
            # Get campaigns for the sponsor
            campaigns = db.session.query(Campaign).filter_by(sponsor_id=sponsor.sponsor_id).all()
            
            # Prepare report data
            campaign_details = []
            total_ad_requests = 0
            total_budget_used = 0
            
            for campaign in campaigns:
                ad_requests = db.session.query(AdRequest).filter_by(campaign_id=campaign.campaign_id).all()
                num_ad_requests = len(ad_requests)
                total_ad_requests += num_ad_requests
                
                campaign_budget_used = sum(ad_request.payment_amount for ad_request in ad_requests)
                total_budget_used += campaign_budget_used
                
                campaign_details.append({
                    "campaign_name": campaign.name,
                    "description": campaign.description,
                    "start_date": campaign.start_date,
                    "end_date": campaign.end_date,
                    "budget": campaign.budget,
                    "visibility": campaign.visibility,
                    "num_ad_requests": num_ad_requests,
                    "budget_used": campaign_budget_used
                })
            
            # Render the report as HTML
            html_message = render_template(
                'monthly_report.html',
                month=month_name,
                total_ad_requests=total_ad_requests,
                total_budget_used=total_budget_used,
                campaign_details=campaign_details
            )
            
            # Generate PDF
            from weasyprint import HTML
            from io import BytesIO  
            pdf_bytes = BytesIO()
            HTML(string=message).write_pdf(target=pdf_bytes)
            pdf_bytes.seek(0)
            pdf_content = pdf_bytes.read()
            
            # Send email with the report
            send_email(
                to_address=sponsor.useremail,
                subject=f"Monthly Report for {month_name}",
                message="Please find the attached monthly report.",
                attachment=9'filename': f"monthly_report_{month_name}.pdf", 'content': pdf_content}
            )
            '''
from sqlalchemy import and_, or_, extract
@celery_app.task
def monthly_report():
    sponsors = Sponsor.query.all()
    current_month = datetime.now().month
    current_year = datetime.now().year
    month_name = calendar.month_name[current_month]

    for sponsor in sponsors:
        # Filter campaigns for the sponsor where start or end date falls in the current month
        campaigns = db.session.query(Campaign).filter(
        Campaign.sponsor_id == sponsor.sponsor_id,
        or_(
            and_(
            extract('month', Campaign.start_date) == current_month,
            extract('year', Campaign.start_date) == current_year
        ),
        and_(
            extract('month', Campaign.end_date) == current_month,
            extract('year', Campaign.end_date) == current_year
                 )
            )
        ).all()

        # Prepare report data
        campaign_details = []
        total_ad_requests = 0
        total_budget_used = 0

        for campaign in campaigns:
            ad_requests = db.session.query(AdRequest).filter_by(campaign_id=campaign.campaign_id).all()
            num_ad_requests = len(ad_requests)
            total_ad_requests += num_ad_requests

            campaign_budget_used = sum(ad_request.payment_amount for ad_request in ad_requests)
            total_budget_used += campaign_budget_used

            campaign_details.append({
                "campaign_name": campaign.name,
                "description": campaign.description,
                "start_date": campaign.start_date,
                "end_date": campaign.end_date,
                "budget": campaign.budget,
                "visibility": campaign.visibility,
                "num_ad_requests": num_ad_requests,
                "budget_used": campaign_budget_used
            })
            
            # Render the report as HTML
        html_message = render_template(
                'monthly_report.html',
                month=month_name,
                total_ad_requests=total_ad_requests,
                total_budget_used=total_budget_used,
                campaign_details=campaign_details
            )
            
            # Generate PDF
        from weasyprint import HTML
        from io import BytesIO  
        pdf_bytes = BytesIO()
        HTML(string=html_message).write_pdf(target=pdf_bytes)
            
        pdf_bytes.seek(0)
        pdf_content = pdf_bytes.read()
            
            # Send email with the report
        send_email(
                to_address=sponsor.user.useremail,
                subject=f"Monthly Report for {month_name}",
                message=html_message,
                attachment=pdf_content)
'''         
@app.route('/api/influencer_adrequests', methods=['POST'])
@login_required
def add_add_request():
    if current_user.role!='Influencer':
        return jsonify({'error':'no access '})
    data = request.json

    new_ad_request = AdRequest(
        campaign_id=data['campaign_id'],
        influencer_id=data['influencer_id'],
        messages=data['messages'],
        requirements=data['requirements'],
        initiated_by='Influencer',
        payment_amount=data['payment_amount'],
        status='Waiting..' ) # Default status
    
    db.session.add(new_ad_request)
    db.session.commit()
    return jsonify({'message': 'Ad request added successfully'}), 201
'''
@app.route('/api/adrequests', methods=['GET'])
@login_required
def get_adrequests():
    user_id = current_user.user_id
    sponsor = Sponsor.query.filter_by(user_id=user_id).first()  # Ensure we fetch the correct sponsor
    if not sponsor:
        return jsonify({'error': 'Sponsor not found'}), 404

    adrequests = (
        db.session.query(AdRequest, Influencer, Campaign)
        .join(Influencer, AdRequest.influencer_id == Influencer.influencer_id)
        .join(Campaign, AdRequest.campaign_id == Campaign.campaign_id)
        .filter(Campaign.sponsor_id == sponsor.sponsor_id)
        .all()
    )

    result = []
    campaigninfluencer = []
    for adrequest, influencer, campaign in adrequests:
        result.append({
            'ad_request_id': adrequest.ad_request_id,
            'influencer_name': influencer.name,
            'campaign_name': campaign.name,
            'messages': adrequest.messages,
            'requirements': adrequest.requirements,
            'payment_amount': adrequest.payment_amount,
            'Initiated_By':adrequest.initiated_by,
            'status': adrequest.status
        })
        campaigninfluencer.append((adrequest.campaign_id, adrequest.influencer_id))

    return jsonify({'adrequests': result, 'campaigninfluencer': campaigninfluencer})

@app.route('/influencer_search')
@login_required
def influencer_search():
    if current_user.role != 'Influencer':
        return jsonify({'error': 'Access denied.'}), 403

    return render_template('influencer_search.html')
@app.route('/api/influencer_search/sponsor', methods=['GET'])
@login_required
def api_influencer_search_sponsor():
    query = request.args.get('query', '')  # Get query parameter from the request
    if not query:
        return jsonify({'error': 'Query parameter is missing'}), 400

    # Adjust this to your actual search logic, assuming you want to search by sponsor name
    sponsors = Sponsor.query.filter(Sponsor.name.ilike(f'%{query}%')).all()

    if not sponsors:
        return jsonify([])  # Return an empty list if no sponsors are found

    # Return the list of sponsors found
    return jsonify([{
        'name': sponsor.name,
        'industry': sponsor.industry,
        'id': sponsor.sponsor_id
    } for sponsor in sponsors])

@app.route('/api/influencer_search/campaign', methods=['GET'])
@login_required
def api_influencer_search_campaign():
    query = request.args.get('query', '')  # Get query parameter from the request
    if not query:
        return jsonify({'error': 'Query parameter is missing'}), 400

    # Assuming you want to search by campaign name or description
    campaigns = Campaign.query.filter(
        (Campaign.name.ilike(f'%{query}%')) |
        (Campaign.description.ilike(f'%{query}%'))
    ).all()

    if not campaigns:
        return jsonify([])  # Return an empty list if no campaigns are found

    # Return the list of campaigns found with their associated ad requests
    result = []
    for campaign in campaigns:
        # Fetch all ad requests associated with the current campaign
        ad_requests = [ad_request.to_dict() for ad_request in campaign.ad_requests]

        result.append({
            'campaign_name': campaign.name,
            'description': campaign.description,
            'start_date': campaign.start_date.strftime('%Y-%m-%d'),
            'end_date': campaign.end_date.strftime('%Y-%m-%d'),
            'budget': campaign.budget,
            'goals': campaign.goals,
            'id': campaign.campaign_id,
            'ad_requests': ad_requests  # Add ad requests associated with the campaign
        })

    return jsonify(result)
@app.route('/api/update_adrequest/<int:ad_request_id>', methods=['PUT'])
@login_required
def update_ad_request(ad_request_id):
    data = request.get_json()
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    ad_request.messages = data['messages']
    ad_request.requirements = data['requirements']
    db.session.commit()
    return jsonify({'message': 'Ad request updated successfully'})
api.add_resource(DeleteAdRequest, '/api/ddelete_adrequest/<int:ad_request_id>')
api.add_resource(AddInfluencerAdRequest, '/api/influencer_addrequests')
api.add_resource(UpdateAdRequest, '/api/update_addrequest/<int:ad_request_id>')
api.add_resource(AddAdRequest, '/api/add_addrequest')
api.add_resource(GetAdRequests, '/api/addrequests')
@celery_app.task()
def add_together(a,b):
    return a+b
app = Flask(__name__)


def send_alert_to_sponsor(sponsor_id, message):
    # Example function to send an alert or email notification to the sponsor
    sponsor = Sponsor.query.get(sponsor_id)
    if sponsor:
        send_email(to_address=sponsor.user.useremail, subject="Campaign Export Complete", message=message)


#api.add_resource(DeleteAdRequest, '/api/delete_adrequest/<int:ad_request_id>')
#api.add_resource(UpdateAdRequest, '/api/update_adrequest/<int:ad_request_id>')
#api.add_resource(AddAdRequest, '/api/add_adrequest')
#api.add_resource(AddInfluencerAdRequest, '/api/influencer_adrequests')
#api.add_resource(GetAdRequests, '/api/adrequests')        

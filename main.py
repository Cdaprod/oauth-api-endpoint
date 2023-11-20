from flask import Flask, request, jsonify, redirect, session, abort
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

# Flask App Initialization
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# Supabase Client Setup
# Replace with your Supabase URL and Key
supabase_url = "YOUR_SUPABASE_URL"
supabase_key = "YOUR_SUPABASE_KEY"
supabase = create_client(supabase_url, supabase_key)

# OAuth Configuration
oauth_provider_url = "OAUTH_PROVIDER_URL"
client_id = "YOUR_CLIENT_ID"
client_secret = "YOUR_CLIENT_SECRET"
redirect_uri = "http://localhost:5000/callback"  # Update based on your setup

# Rate Limiter Initialization
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Login Route
@app.route('/login')
@limiter.limit("10 per minute")
def login():
    return redirect(f"{oauth_provider_url}/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code")

# OAuth Callback Route
@app.route('/callback')
def callback():
    code = request.args.get('code')
    response = requests.post(f"{oauth_provider_url}/token", data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'client_secret': client_secret
    }).json()

    access_token = response.get('access_token')
    user_info = requests.get(f"{oauth_provider_url}/userinfo", headers={
        'Authorization': f'Bearer {access_token}'
    }).json()

    user_data = {
        'id': user_info['id'],
        'email': user_info['email'],
        # Add other fields as needed
    }
    supabase.table('users').upsert(user_data).execute()
    session['user'] = user_data

    return redirect('/')

# Protected Endpoint Example
@app.route('/protected-endpoint')
def protected_endpoint():
    user = session.get('user')
    if not user:
        abort(403)  # Forbidden access
    return 'Protected content'

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'error': 'Page not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True)

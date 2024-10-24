from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import requests
import os
from dotenv import load_dotenv
import hmac
import hashlib
import base64

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# Fetch credentials from environment variables
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
SCOPES = os.getenv("SCOPES")
REDIRECT_URI = os.getenv("REDIRECT_URI")
SHOPIFY_SECRET = os.getenv("SHOPIFY_SECRET")

def verify_hmac(hmac_header, data):
    # Create the HMAC digest using the SHOPIFY_SECRET
    calculated_hmac = base64.b64encode(
        hmac.new(SHOPIFY_SECRET.encode('utf-8'), data, hashlib.sha256).digest()
    )
    return hmac.compare_digest(calculated_hmac, hmac_header.encode('utf-8'))

@app.get("/", response_class=HTMLResponse)
async def home():
    return '''
        <h1>Connect your Shopify store</h1>
        <form action="/connect" method="GET">
            <input type="text" name="shop" placeholder="example.myshopify.com" required>
            <button type="submit">Connect Shopify</button>
        </form>
    '''

@app.get("/connect")
async def connect_shopify(shop: str):
    auth_url = (
        f"https://{shop}/admin/oauth/authorize?"
        f"client_id={CLIENT_ID}&scope={SCOPES}&redirect_uri={REDIRECT_URI}"
    )
    return RedirectResponse(url=auth_url)

@app.get("/callback")
async def callback(code: str, shop: str):
    # Exchange the authorization code for an access token
    access_token_response = requests.post(
        f"https://{shop}/admin/oauth/access_token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code
        }
    )

    if access_token_response.status_code != 200:
        return "Error retrieving access token from Shopify"

    access_token = access_token_response.json().get('access_token')
    
    if not access_token:
        return "Failed to retrieve access token from Shopify"

    # Fetch store information using the access token
    headers = {
        "X-Shopify-Access-Token": access_token
    }
    store_info_response = requests.get(f"https://{shop}/admin/api/2023-04/shop.json", headers=headers)
    
    if store_info_response.status_code != 200:
        return "Error retrieving store information from Shopify"
    
    store_info = store_info_response.json().get("shop", {})

    # Transform the response to match the desired format
    return {
        "message": "Successfully connected to Shopify",
        "hostname": store_info.get("myshopify_domain"),
        "password": access_token,
        "api_key": CLIENT_ID
    }

@app.post("/webhook")
async def webhook_handler(request: Request):
    # Get the HMAC header from Shopify
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256")
    body = await request.body()

    # Verify the HMAC
    if not verify_hmac(hmac_header, body):
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Process your webhook data
    return {"message": "Webhook received"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# Description
Integrate your FastAPI with https://auth0.com in a simple and elegant way.
Get Swagger UI support for the implicit scheme, which means you can sign in with google or any other social provider using just swagger docs! With no additional code!

# Example usage
First of all, I recommend reading auth0 docs in order to understand the following concepts:
 - API's and audience
 - Applications
 - Grant types
 - Permissions and scopes
 
This library cannot do magic if your auth0 tenant is not configured correctly!

```Python
from fastapi import FastAPI, Depends, Security
from fastapi_auth0 import Auth0, Auth0User

auth = Auth0(domain='your-tenant.auth0.com', api_audience='your-api-identifier', scopes={'read:blabla': ''})
app = FastAPI()

@app.get("/public")
def get_public():
    return {"message": "Anonymous user"}

@app.get("/secure", dependencies=[Depends(auth.implicit_scheme)])
def get_secure(user: Auth0User = Security(auth.get_user, scopes=['read:blabla'])):
    return {"message": f"{user}"}
```

# Video tutorial
The settings on the auth0 tenant dashboard look pretty daunting at first, and it can get pretty complex to configure everything.
This is why I plan on making a video tutorial with all the steps required from 0 to having a fully working social provider.

# Installation
`pip install https://github.com/dorinclisu/fastapi-auth0/archive/master.zip`

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

### Email field requirements
In order to get email for Auth0User, the API must have "openid profile email" permission and the rule "Add email to access token" must be added with the matching namespace, see [tests](tests/README.md).
The security is not affected in any way if we don't do this, but we need to if we want to know the user email's address. Otherwise, email field will always be `None`.

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

Example user responses:
```Python
id='Art2l2uCeCQk5zDVbZzNZmQkLJXLd9Uy@clients' permissions=['read:blabla'] email=None"}              # user is M2M app
id='auth0|5fe72b8eb2ac50006f725451' permissions=['read:blabla'] email='some.user@outlook.com"}      # user signed up using auth0 database
id='google-oauth2|115595596713285791346' permissions=['read:blabla'] email='other.user@gmail.com"}  # user signed up using google
```

# Video tutorial
The settings on the auth0 tenant dashboard look pretty daunting at first, and it can get pretty complex to configure everything.
This is why I plan on making a video tutorial with all the steps required from 0 to having a fully working social provider.

# Installation
`pip install https://github.com/dorinclisu/fastapi-auth0/archive/master.zip`

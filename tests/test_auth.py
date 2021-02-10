import os
import json
from typing import Dict

import pytest
import requests
from fastapi import FastAPI, Depends, Security
from fastapi.testclient import TestClient

#from fastapi_auth0 import Auth0, Auth0User, security_responses
from src.fastapi_auth0 import Auth0, Auth0User, security_responses


auth0_domain = os.getenv('AUTH0_DOMAIN')  # Tenant domain
auth0_api_audience = os.getenv('AUTH0_API_AUDIENCE')  # API that serves the applications (fastapi instance)

auth0_m2m_client_id = os.getenv('AUTH0_M2M_CLIENT_ID')  # Machine-to-machine application
auth0_m2m_client_secret = os.getenv('AUTH0_M2M_CLIENT_SECRET')

auth0_spa_client_id = os.getenv('AUTH0_SPA_CLIENT_ID')  # Single Page Application
auth0_spa_client_secret = os.getenv('AUTH0_SPA_CLIENT_SECRET')

auth0_spa_username = os.getenv('AUTH0_SPA_USERNAME')
auth0_spa_password = os.getenv('AUTH0_SPA_PASSWORD')

auth0_test_permission = os.getenv('AUTH0_TEST_PERMISSION', '')


###############################################################################
auth = Auth0(domain=auth0_domain, api_audience=auth0_api_audience)
app = FastAPI()

@app.get('/public')
def get_public():
    return {'message': 'Anonymous user'}

@app.get('/also-public', dependencies=[Depends(auth.implicit_scheme)])
def get_public2():
    return {'message': 'Anonymous user (token is received from swagger ui but not verified)'}

@app.get('/secure', dependencies=[Depends(auth.implicit_scheme)], responses=security_responses)
def get_secure(user: Auth0User = Security(auth.get_user)):
    return user

@app.get('/also-secure')
def get_secure2(user: Auth0User = Security(auth.get_user)):
    return user

@app.get('/secure-scoped')
def get_secure_scoped(user: Auth0User = Security(auth.get_user, scopes=[auth0_test_permission])):
    return user


###############################################################################
client = TestClient(app)


def get_bearer_header(token: str) -> Dict[str, str]:
    return {'Authorization': 'Bearer '+token}

def test_public():
    resp = client.get('/public')
    assert resp.status_code == 200, resp.text

    resp = client.get('/also-public')
    assert resp.status_code == 200, resp.text

    resp = client.get('/secure')
    assert resp.status_code == 403, resp.text

    resp = client.get('/also-secure')
    assert resp.status_code == 403, resp.text  # should be 401 but due to fastapi bug, HTTPBearer() returns 403 on missing token

    resp = client.get('/secure-scoped')
    assert resp.status_code == 403, resp.text  # should be 401 but due to fastapi bug, HTTPBearer() returns 403 on missing token


def test_m2m_app():
    resp = requests.post(
        f'https://{auth0_domain}/oauth/token',
        json={
        'grant_type': 'client_credentials',
        'client_id': auth0_m2m_client_id,
        'client_secret': auth0_m2m_client_secret,
        'audience': auth0_api_audience,
    })
    assert resp.status_code == 200, resp.text
    access_token = resp.json()['access_token']

    resp = client.get('/secure', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text

    resp = client.get('/also-secure', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text

    user = Auth0User(**resp.json())
    assert auth0_test_permission in user.permissions
    assert user.email is None # auth0 cannot provide an email because the end user is a machine

    # M2M app is not subject to RBAC, so any permission given to it will also authorize the scope.
    resp = client.get('/secure-scoped', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text


def test_spa_app_noscope():
    resp = requests.post(
        f'https://{auth0_domain}/oauth/token',
        headers={'content-type': 'application/x-www-form-urlencoded'},
        data={
        'grant_type': 'password',
        'username': auth0_spa_username,
        'password': auth0_spa_password,
        'client_id': auth0_spa_client_id,
        'client_secret': auth0_spa_client_secret,
        'audience': auth0_api_audience,
        # the app is not explicitly requesting scope
    })
    assert resp.status_code == 200, resp.text

    access_token = resp.json()['access_token']

    resp = client.get('/secure', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text

    resp = client.get('/also-secure', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text

    user = Auth0User(**resp.json())
    assert auth0_test_permission in user.permissions
    assert user.email == auth0_spa_username

    # The user has the permission, but the scope authorization must fail because
    # the SPA app did not request a scope on user's behalf.
    # This is the subtle difference between permissions and scopes in auth0.
    resp = client.get('/secure-scoped', headers=get_bearer_header(access_token))
    assert resp.status_code == 403, resp.text


def test_spa_app():
    resp = requests.post(
        f'https://{auth0_domain}/oauth/token',
        headers={'content-type': 'application/x-www-form-urlencoded'},
        data={
        'grant_type': 'password',
        'username': auth0_spa_username,
        'password': auth0_spa_password,
        'client_id': auth0_spa_client_id,
        'client_secret': auth0_spa_client_secret,
        'audience': auth0_api_audience,
        'scope': auth0_test_permission
    })
    assert resp.status_code == 200, resp.text

    access_token = resp.json()['access_token']

    resp = client.get('/secure', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text

    resp = client.get('/also-secure', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text

    user = Auth0User(**resp.json())
    assert auth0_test_permission in user.permissions
    assert user.email == auth0_spa_username

    resp = client.get('/secure-scoped', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text

import json
import logging
import os
import requests
from typing import Optional, Dict, List, Type
import urllib.parse

from fastapi import HTTPException, Depends, Security, Request
from fastapi.security import SecurityScopes, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.security import OAuth2, OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer, OpenIdConnect
from fastapi.openapi.models import OAuthFlows
from pydantic import BaseModel, Field, ValidationError
from jose import jwt  # type: ignore



auth0_rule_namespace: str = os.getenv('AUTH0_RULE_NAMESPACE', 'https://github.com/dorinclisu/fastapi-auth0')


class Auth0UnauthenticatedException(HTTPException):
    def __init__(self, **kwargs):
        super().__init__(401, **kwargs)

class Auth0UnauthorizedException(HTTPException):
    def __init__(self, **kwargs):
        super().__init__(403, **kwargs)

class HTTPAuth0Error(BaseModel):
    detail: str

unauthenticated_response: Dict = {401: {'model': HTTPAuth0Error}}
unauthorized_response: Dict = {403: {'model': HTTPAuth0Error}}
security_responses: Dict = {**unauthenticated_response, **unauthorized_response}


class Auth0User(BaseModel):
    id: str = Field(..., alias='sub')
    permissions: Optional[List[str]]
    email: Optional[str] = Field(None, alias=f'{auth0_rule_namespace}/email')


class Auth0HTTPBearer(HTTPBearer):
    async def __call__(self, request: Request):
        #logging.debug('Called Auth0HTTPBearer')
        return await super().__call__(request)

class OAuth2ImplicitBearer(OAuth2):
    def __init__(self,
            authorizationUrl: str,
            scopes: Dict[str, str]={},
            scheme_name: Optional[str]=None,
            auto_error: bool=True):
        flows = OAuthFlows(implicit={"authorizationUrl": authorizationUrl, 'scopes': scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        # Overwrite parent call to prevent useless overhead, the actual auth is done in Auth0.get_user
        # This scheme is just for Swagger UI
        return None

    # TODO: figure out why Auth0HTTPBearer() sub-dependency gets called twice both from scheme dependency
    # in path op decorator and from Auth0.get_user dependency in path op function (fastapi injection system bug?)
    # async def __call__(self,
    #     request: Request,
    #     creds: HTTPAuthorizationCredentials = Depends(Auth0HTTPBearer())
    # ) -> Optional[str]:
    #     logging.debug('Called OAuth2ImplicitBearer')
    #     return creds.credentials


class Auth0:
    def __init__(self, domain: str, api_audience: str, scopes: Dict[str, str]={},
            auto_error: bool=True, scope_auto_error: bool=True, email_auto_error: bool=False,
            auth0user_model: Type[Auth0User]=Auth0User):
        self.domain = domain
        self.audience = api_audience

        self.auto_error = auto_error
        self.scope_auto_error = scope_auto_error
        self.email_auto_error = email_auto_error

        self.auth0_user_model = auth0user_model

        self.algorithms = ['RS256']
        self.jwks: Dict = requests.get(f'https://{domain}/.well-known/jwks.json').json()

        authorization_url_qs = urllib.parse.urlencode({"audience": api_audience})
        authorization_url = f'https://{domain}/authorize?{authorization_url_qs}'
        self.implicit_scheme = OAuth2ImplicitBearer(
            authorizationUrl=authorization_url,
            scopes=scopes,
            scheme_name='Auth0ImplicitBearer')
        self.password_scheme = OAuth2PasswordBearer(tokenUrl=f'https://{domain}/oauth/token', scopes=scopes)
        self.authcode_scheme = OAuth2AuthorizationCodeBearer(
            authorizationUrl=authorization_url,
            tokenUrl=f'https://{domain}/oauth/token',
            scopes=scopes)
        self.oidc_scheme = OpenIdConnect(openIdConnectUrl=f'https://{domain}/.well-known/openid-configuration')


    async def get_user(self,
        security_scopes: SecurityScopes,
        creds: HTTPAuthorizationCredentials = Depends(Auth0HTTPBearer())
    ) -> Optional[Auth0User]:

        token = creds.credentials
        payload: Dict = {}
        try:
            unverified_header = jwt.get_unverified_header(token)
            rsa_key = {}
            for key in self.jwks['keys']:
                if key['kid'] == unverified_header['kid']:
                    rsa_key = {
                        'kty': key['kty'],
                        'kid': key['kid'],
                        'use': key['use'],
                        'n': key['n'],
                        'e': key['e']
                    }
                    #break  # TODO: do we still need to iterate all keys after we found a match?
            if rsa_key:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=self.algorithms,
                    audience=self.audience,
                    issuer=f'https://{self.domain}/'
                )
            else:
                if self.auto_error:
                    raise jwt.JWTError

        except jwt.ExpiredSignatureError:
            if self.auto_error:
                raise Auth0UnauthenticatedException(detail='Expired token')
            else:
                return None

        except jwt.JWTClaimsError:
            if self.auto_error:
                raise Auth0UnauthenticatedException(detail='Invalid token claims (please check issuer and audience)')
            else:
                return None

        except jwt.JWTError:
            if self.auto_error:
                raise Auth0UnauthenticatedException(detail='Malformed token')
            else:
                return None

        except Exception as e:
            logging.error(f'Handled exception decoding token: "{e}"')
            if self.auto_error:
                raise Auth0UnauthenticatedException(detail='Error decoding token')
            else:
                return None

        if self.scope_auto_error:
            token_scope_str: str = payload.get('scope', '')

            if isinstance(token_scope_str, str):
                token_scopes = token_scope_str.split()

                for scope in security_scopes.scopes:
                    if scope not in token_scopes:
                        raise Auth0UnauthorizedException(detail=f'Missing "{scope}" scope',
                            headers={'WWW-Authenticate': f'Bearer scope="{security_scopes.scope_str}"'})
            else:
                # This is an unlikely case but handle it just to be safe (perhaps auth0 will change the scope format)
                raise Auth0UnauthorizedException(detail='Token "scope" field must be a string')

        try:
            user = self.auth0_user_model(**payload)

            if self.email_auto_error and not user.email:
                raise Auth0UnauthorizedException(detail=f'Missing email claim (check auth0 rule "Add email to access token")')

            return user

        except ValidationError as e:
            logging.error(f'Handled exception parsing Auth0User: "{e}"')
            if self.auto_error:
                raise Auth0UnauthorizedException(detail='Error parsing Auth0User')
            else:
                return None

        return None

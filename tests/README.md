# Requirements
For replicating the tests, the following must be done from auth0 dashboard:
- Set default directory to "Username-Password-Authentication" in tenant settings.
- Create API with 2 permissions:
  - "openid profile email"
  - "read:test" (AUTH0_TEST_PERMISSION)
- Enable RBAC for API and "Add Permissions in the Access Token" from the API page.
- Create M2M application and grant it the "read:test" permission from the API page.
- Create SPA application and enable "password" grant type (Advanced Settings).
- Create "Add email to access token" rule and set the namespace to fastapi_auth0.auth0_rule_namespace value (https://github.com/dorinclisu/fastapi-auth0)
  - Without this rule and the matching namespace, we cannot read email for Auth0User
- Create database connection if it doesn't exist and make it the default connection for your tenant.
- Create user in database (AUTH0_SPA_USERNAME) and grant it the "read:test" permission from the users page.
- Make sure the apps have OIDC Conformant ON (the default), and that the Password grant type is enabled for the SPA.

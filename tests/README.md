# Requirements
For replicating the tests, the following must be done from auth0 dashboard:
- Create API with 2 permissions:
  - "openid profile email"
  - "read:test" (AUTH0_TEST_PERMISSION)
- Enable RBAC for API and "Add Permissions in the Access Token" from the API page.
- Create M2M application and grant it the "read:test" permission from the API page.
- Create SPA application.
- Create database connection if it doesn't exist and make it the default connection for your tenant.
- Create user in database (AUTH0_SPA_USERNAME) and grant it the "read:test" permission from the users page.
- Make sure the apps have OIDC Conformant ON (the default), and that the Password grant type is enabled for the SPA.

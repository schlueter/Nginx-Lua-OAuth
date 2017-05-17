# Github Nginx OAuth

This is a simple set of lua scripts to enable basic OAuth against GitHub, allowing access to users in a specific organization and not on a blacklist.

## Development

Create a new GitHub OAuth 2 application at [GitHub](https://github.com/settings/applications/new), then, with  the client id and client secret, run `CLIENT_ID=<your client id> CLIENT_SECRET=<your client secret> vagrant up`. This will set up a vagrant instance exposing Nginx configured to Authenticate against your app at 192.168.29.42.

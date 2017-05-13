local json = require("cjson")

local scheme = ngx.var.scheme
local host = ngx.var.host
local port = ngx.var.oauth_proxy_port or ngx.var.server_port
local uri = ngx.var.uri
local uri_args = ngx.req.get_uri_args()

local client_id = ngx.var.oauth_client_id
local client_secret = ngx.var.oauth_client_secret

local authorization_url = ngx.var.oauth_authorization_url

local authorization_callback_uri = ngx.var.oauth_authorization_callback_uri or '/oauth/signin'
local api_uri = ngx.var.oauth_api_uri or '/oauth/api/'
local signout_uri = ngx.var.oauth_signout_uri or '/oauth/signout'
local token_secret = ngx.var.oauth_token_secret or 'notsosecret'

local redirect_uri = ngx.var.oauth_redirect_uri or scheme .. '://' .. host .. ':' .. port .. authorization_callback_uri

local scope = ngx.var.oauth_scope or 'read:org'

local domain = ngx.var.oauth_domain or ngx.var.host
local client_secret = ngx.var.oauth_client_secret
local valid_org = ngx.var.oauth_org
local blacklist = string.gmatch(ngx.var.oauth_blacklist, "(%g+) ?")

local cookie_tail = "Domain="..domain


local function handle_subrequest_error(request_uri, response)

  if not response then
    ngx.log(ngx.ERR, "Request to " .. request_uri .. " failed." )
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  if response.status ~= 200 then
    ngx.log(ngx.ERR, "Request to " .. request_uri .. " failed with " .. response.status .. ": " ..response.body .. "." )
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

end

local function request_access_token(code)
  ngx.log(ngx.ERR, 'Making subrequest to ' .. authorization_callback_uri)
  local res = ngx.location.capture(
    authorization_callback_uri,
    { method=ngx.HTTP_POST
    , args={ client_id=client_id
             , client_secret=client_secret
             , code=code
             , redirect_uri=redirect_uri
             -- , state=state
             }})
  handle_subrequest_error(authorization_callback_uri, res)
  return ngx.decode_args(res.body), nil
end

local function provider_api_request(api_endpoint, token)
  ngx.req.set_header('Authorization', "token " .. token)
  local api_request_uri = api_uri .. api_endpoint
  ngx.log(ngx.DEBUG, 'Making subrequest to ' .. api_request_uri .. " with token " .. token)
  local api_res = ngx.location.capture(api_request_uri)
  handle_subrequest_error(api_request_uri, res)
  return ngx.decode_args(api_res.body)
end

local function redirect_to_auth()
  local auth_url = authorization_url .. "?" .. ngx.encode_args(
    { client_id=client_id
    , redirect_uri=redirect_uri .. '?' .. ngx.encode_args({ redirect_uri=uri })
    , scope = scope
    })
  ngx.log(ngx.ERR, 'redirecting to ' .. auth_url)
  return ngx.redirect(auth_url)
end

local function validate_orgs(access_token)
  local orgs = provider_api_request('user/orgs', access_token)
  for _, org in pairs(orgs) do
    if org["login"] == valid_org then
      return true
    end
  end
  return false
end

local function validate(login, access_token, token)
  ngx.log(ngx.ERR, "token: " .. (token or 'nil') .. ", login: " .. (login or 'nil') .. ", access_token: " .. (access_token or 'nil'))

  if not access_token and token == '' then
    ngx.log(ngx.ERR, "No tokens")
    return nil
  end

  if access_token and login == "" then
    ngx.log(ngx.ERR, "Invalid cookies")
    return nil
  end

  if not login then
    ngx.log(ngx.ERR, "No login provided, requesting")
    local profile = provider_api_request('user', access_token)
    local login = profile["login"]
  end

  for bad_login in blacklist do
    if login == bad_login then
      ngx.log(ngx.ERR, "User " .. login .. " is blacklisted")
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  end
	ngx.log(ngx.ERR, "User" .. login .. " is not blacklisted")

  if access_token then
		if validate_orgs(access_token) then
			ngx.log(ngx.ERR, "User" .. login .. " is in an authorized org")
		else
			ngx.log(ngx.ERR, "User" .. login .. " not in authorized org")
			return ngx.exit(ngx.HTTP_FORBIDDEN)
		end
  end

  local expected_token = ngx.encode_base64(ngx.hmac_sha1(token_secret, domain .. login))
	ngx.log(ngx.ERR, "Testing " .. login .. "'s token " .. token .. " against expected token " .. expected_token)
  if not token == '' and not token == expected_token then
    ngx.log(ngx.ERR, "User" .. login .. " has a bad token")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  return expected_token
end

local function authorize()
  local access_token_res = request_access_token(uri_args["code"])

  local token = validate(nil, access_token_res.access_token, nil)
  if token then
    local cookie_tail  = ";domain=" .. domain
    ngx.header["Set-Cookie"] = {
      "OAuthLogin="       .. ngx.escape_uri(login) .. cookie_tail,
      "OAuthAccessToken=" .. ngx.escape_uri(token) .. cookie_tail,
    }
    local redirect = uri_args["redirect_uri"] or '/'
    ngx.log(ngx.ERR, "Redirecting to " .. redirect)
    return ngx.redirect(redirect)
  else
    ngx.log(ngx.ERR, "Failed to authenticate request")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end
end

local function is_authorized()
  local login = ngx.unescape_uri(ngx.var.cookie_OAuthLogin)
  local token = ngx.unescape_uri(ngx.var.cookie_OAuthAccessToken)
  return validate(login, nil, token)
end

if uri == signout_uri then
  ngx.header['Set-Cookie'] = 'OAuthAccessToken==deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'
  ngx.header['Content-type'] = 'text/html'
  ngx.say('See you around')
  ngx.exit(ngx.HTTP_OK)
end

if not is_authorized() then
  if uri ~= authorization_callback_uri then
    return redirect_to_auth()
  end
  authorize()
end

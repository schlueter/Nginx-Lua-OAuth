local json = require("cjson")
local zlib = require("zlib")

local uri_args = ngx.req.get_uri_args()

local client_secret = ngx.var.oauth_client_secret
local client_id = ngx.var.oauth_client_id

local scope = ngx.var.oauth_scope or 'read:org'

local valid_org = ngx.var.oauth_org
local token_secret = ngx.var.oauth_token_secret or 'notsosecret'

local proxy_api_uri = ngx.var.oauth_proxy_api_uri or '/_oauth/api/'
local oaas_token_uri = ngx.var.oauth_provider_uri or '/_oauth/provider'

local domain = ngx.var.oauth_domain or ngx.var.host

local cookie_tail = "; Domain=" .. domain .. '; HttpOnly; Path=/'


local function request_access_token(code)
  ngx.log(ngx.ERR, 'Requesting access token with code ' .. code)
  local res = ngx.location.capture(
    provider_uri,
    { method=ngx.HTTP_POST
    , args={ client_id=client_id
             , client_secret=client_secret
             , code=code
             , redirect_uri=redirect_uri
             -- , state=state
             }})
  err = handle_subrequest_error(res)
  if err then
    ngx.log(ngx.ERR, "Got error during access token request: " .. err)
    ngx.say("got error during access token request: " .. err)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  else
    ngx.log(ngx.ERR, "Decoded access token request: " .. res.body)
    return ngx.decode_args(res.body)
  end
end

local function handle_subrequest_error(response)
  if not response then
    return "failed"
  end

  if response.status ~= 200 then
    return "failed with " .. response.status .. ": " .. response.body
  end

  return nil
end

local function provider_api_request(api_uri, token)
  ngx.req.set_header('Authorization', "token " .. token)
  local api_request_uri = proxy_api_uri .. api_uri
  ngx.log(ngx.DEBUG, 'Making subrequest to ' .. api_request_uri .. " with token " .. token)
  local api_res = ngx.location.capture(api_request_uri)
  err = handle_subrequest_error(api_res)
  if err then
    ngx.log(ngx.ERR, "Got error during access token request: " .. err)
    ngx.say("got error during access token request: " .. err)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  else
    local stream = zlib.inflate()
    local inflated_body = stream(api_res.body)
    ngx.log(ngx.ERR, 'api response body: ' .. inflated_body)
  end
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
  ngx.log(ngx.ERR, "Validating token: " .. (token or '<nil>') .. ", login: " .. (login or '<nil>') .. ", access_token: " .. (access_token or '<nil>'))

  if not access_token and (not token or token == '') then
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
    login = profile["login"]
  end


  if access_token then
    if validate_orgs(access_token) then
      ngx.log(ngx.ERR, "User " .. login .. " is in an authorized org")
    else
      ngx.log(ngx.ERR, "User " .. login .. " not in authorized org")
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  end

  local expected_token = ngx.encode_base64(ngx.hmac_sha1(token_secret, domain .. login))
  if token then
    ngx.log(ngx.ERR, "Checking " .. login .. "'s token, " .. (token or 'nil') .. ", against expected token, " .. expected_token)
    if not token == expected_token then
      ngx.log(ngx.ERR, "User " .. login .. " has a bad token")
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  end

  return login, expected_token
end

local function redirect_to_auth()
  local auth_url = authorization_url .. "?" .. ngx.encode_args(
    { client_id=client_id
    , scope = scope
    })
  ngx.log(ngx.ERR, 'redirecting to ' .. auth_url)
  return ngx.redirect(auth_url)
end

local function authorize()

  ngx.log(ngx.ERR, "Checking uri " .. uri .. " agaist callback uri " .. authorization_callback_uri)
  if uri ~= authorization_callback_uri then
    return redirect_to_auth()
  end

  if uri_args["error"] then
    ngx.log(ngx.ERR, "received " .. uri_args["error"] .. " from OAuth provider")
    ngx.say("received " .. uri_args["error"] .. " from OAuth provider")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  if not uri_args["code"] then
    ngx.log(ngx.ERR, "Invalid request: no code for authorization")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local access_token_res = request_access_token(uri_args["code"])

  local login, token = validate(nil, access_token_res.access_token, nil)

  if token then
    local expiry = "; Max-Age=" .. (ngx.time() + 60*60*24*14)
    local cookies = {
      "OAuthLogin=" .. ngx.escape_uri(login) .. cookie_tail .. expiry,
      "OAuthAccessToken=" .. ngx.escape_uri(token) .. cookie_tail .. expiry,
    }

    for index, cookie in pairs(cookies) do
      ngx.log(ngx.ERR, "Setting cookie " .. cookie " " .. index)
    end

    ngx.header["Set-Cookie"] = cookies
    local redirect = '/'
    ngx.log(ngx.ERR, "Redirecting to " .. redirect)
    return ngx.redirect(redirect)
  else
    ngx.log(ngx.ERR, "Failed to authenticate request")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

end

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
local signout_uri = ngx.var.oauth_signout_uri or '/oauth/signout'

local redirect_uri = ngx.var.oauth_redirect_uri or scheme .. '://' .. host .. ':' .. port .. authorization_callback_uri

local scope = ngx.var.oauth_scope

local domain = ngx.var.oauth_domain or ngx.var.host

local cookie_tail = "Domain="..domain


local function encode_token(token)
  return ngx.encode_base64(ngx.hmac_sha1(token, domain))
end

local function decode_token(token)
  return ngx.decode_base64(ngx.hmac_sha1(token, domain))
end

local function on_auth(token)
    -- TODO
    ngx.log(ngx.ERR, "token: " .. token)
end

local function request_access_token(code)

  local res = ngx.location.capture(
    authorization_callback_uri,
    { method=ngx.HTTP_POST
    , args={ client_id=client_id
             , client_secret=client_secret
             , code=code
             , redirect_uri=redirect_uri
             -- , state=state
             }})

  if not res then
    return nil, ("access token request failed: " .. ("unknown reason"))
  end

  if res.status ~= 200 then
    return nil, "received " .. res.status .. " while requesting access token: " .. res.body
  end

  return ngx.decode_args(res.body)
end

local function redirect_to_auth()
  local auth_url = authorization_url .. "?" .. ngx.encode_args(
    { client_id=client_id
    , redirect_uri=redirect_uri .. '?' .. ngx.encode_args(
      { redirect_uri=uri })
    , scope = scope
    -- , state = state
    -- , allow_signup = allow_signup
    })

  ngx.log(ngx.DEBUG, 'redirecting to ' .. auth_url)
  return ngx.redirect(auth_url)
end

local function authorize()
  ngx.log(ngx.DEBUG, "uri: " .. uri .. ", authorization_callback_uri: " .. authorization_callback_uri)
  if uri ~= authorization_callback_uri then
    return redirect_to_auth()
  end

  local access_token_res = request_access_token(uri_args["code"])

  if not access_token_res then
    ngx.log(ngx.ERR, "Failed to receive access token.")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  local token = access_token_res.access_token


  local cookie_token = encode_token(token)

  ngx.header["Set-Cookie"] = {
    "OAuthAccessToken=" .. ngx.escape_uri(cookie_token) .. " " .. cookie_tail,
  }

  on_auth(token)

  -- local redirect = uri_args["redirect_uri"] or '/'
  -- ngx.log(ngx.ERR, "Redirecting to " .. redirect)
  -- return ngx.redirect(redirect)
end

if uri == signout_uri then
  ngx.header['Set-Cookie'] = 'OAuthAccessToken==deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'
  ngx.header['Content-type'] = 'text/html'
  ngx.say('See you around')
  ngx.exit(ngx.HTTP_OK)
end

local token = ngx.unescape_uri(ngx.var.cookie_OAuthAccessToken or "")

if token ~= "" then
  on_auth(token)
else
  authorize()
end

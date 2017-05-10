-- Copyright 2015-2016 CloudFlare
-- Copyright 2014-2015 Aaron Westendorf

local json = require("cjson")

local uri         = ngx.var.uri
local uri_args    = ngx.req.get_uri_args()
local scheme      = ngx.var.scheme

local auth_url       = ngx.var.oauth_url
local client_id      = ngx.var.oauth_client_id
local client_secret  = ngx.var.oauth_client_secret
local token_secret   = ngx.var.oauth_token_secret
local domain         = ngx.var.oauth_domain
local cb_scheme      = ngx.var.oauth_callback_scheme or scheme
local cb_server_name = ngx.var.oauth_callback_host
local cb_uri         = ngx.var.oauth_callback_uri or "/_oauth"
local signout_uri    = ngx.var.oauth_signout_uri or "/_signout"
local whitelist      = ngx.var.oauth_whitelist or ""
local blacklist      = ngx.var.oauth_blacklist or ""
local secure_cookies = ngx.var.oauth_secure_cookies == "true" or false
local set_user       = ngx.var.oauth_user or false
local email_as_user  = ngx.var.oauth_email_as_user == "true" or false
local cb_url         = cb_scheme .. "://" .. cb_server_name .. cb_uri
local redirect_url   = cb_scheme .. "://" .. cb_server_name .. ngx.var.request_uri
local extra_validity = tonumber(ngx.var.oauth_extra_validity or "0")

if whitelist:len() == 0 then
  whitelist = nil
end

if blacklist:len() == 0 then
  blacklist = nil
end

local function handle_token_uris(email, token, expires)
  if uri == "/_token.json" then
    ngx.header["Content-type"] = "application/json"
    ngx.say(json.encode({
      email   = email,
      token   = token,
      expires = expires,
    }))
    ngx.exit(ngx.OK)
  end

  if uri == "/_token.txt" then
    ngx.header["Content-type"] = "text/plain"
    ngx.say("email: " .. email .. "\n" .. "token: " .. token .. "\n" .. "expires: " .. expires .. "\n")
    ngx.exit(ngx.OK)
  end

  if uri == "/_token.curl" then
    ngx.header["Content-type"] = "text/plain"
    ngx.say("-H \"OauthEmail: " .. email .. "\" -H \"OauthAccessToken: " .. token .. "\" -H \"OauthExpires: " .. expires .. "\"\n")
    ngx.exit(ngx.OK)
  end
end


local function on_auth(email, token, expires)
  -- TODO
  local oauth_domain = email:match("[^@]+@(.+)")

  if not (whitelist or blacklist) then
    if domain:len() ~= 0 then
      if oauth_domain ~= domain then
        ngx.log(ngx.ERR, email .. " is not on " .. domain)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
      end
    end
  end

  if whitelist then
    if not string.find(" " .. whitelist .. " ", " " .. email .. " ") then
      ngx.log(ngx.ERR, email .. " is not in whitelist")
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  end

  if blacklist then
    if string.find(" " .. blacklist .. " ", " " .. email .. " ") then
      ngx.log(ngx.ERR, email .. " is in blacklist")
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  end

  if set_user then
    if email_as_user then
      ngx.var.oauth_user = email
    else
      ngx.var.oauth_user = email:match("([^@]+)@.+")
    end
  end

  handle_token_uris(email, token, expires)
end

local function request_access_token(code)

	local res = ngx.location.capture(
		'/_authorize',
		{ method = ngx.HTTP_POST
		, args = { client_id = client_id
						 , client_secret = client_secret
						 , code = code
						 , redirect_uri = redirect_uri
						 -- , state = state
						 }})

  if not res then
    return nil, ("auth token request failed: " .. ("unknown reason"))
  end

  if res.status ~= 200 then
    return nil, "received " .. res.status .. " from https://accounts.google.com/o/oauth2/token: " .. res.body
  end

  return ngx.decode_args(res.body)
end

local function redirect_to_auth()
  return ngx.redirect(auth_url .. "?" .. ngx.encode_args(
		{ client_id = client_id
    -- , redirect_uri =
    -- , scope = scope
    -- , state = state
    -- , allow_signup = allow_signup
    }))
end

local function authorize()
  if uri ~= cb_uri then
    return redirect_to_auth()
  end

  local access_token_res = request_access_token(uri_args["code"])

  if not access_token_res then
    ngx.log(ngx.ERR, "Failed to receive access token.")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end

-- TODO pause 2017-05-09
  ngx.say(access_token_res.access_token)
  ngx.exit(ngx.HTTP_OK)

  local user_token = ngx.encode_base64(ngx.hmac_sha1(access_token_res.access_token, cb_server_name))

  on_auth(email, user_token, expires)

  ngx.header["Set-Cookie"] = {
    "OauthEmail="       .. ngx.escape_uri(email) .. cookie_tail,
    "OauthAccessToken=" .. ngx.escape_uri(user_token) .. cookie_tail,
    "OauthExpires="     .. expires .. cookie_tail,
  }

  return ngx.redirect(uri_args["state"])
end

local function handle_signout()
  if uri == signout_uri then
    ngx.header["Set-Cookie"] = "OauthAccessToken==deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"
    return ngx.redirect("/")
  end
end

local function is_authorized()
  local headers = ngx.req.get_headers()

  local expires = tonumber(ngx.var.cookie_OauthExpires) or 0
  local email   = ngx.unescape_uri(ngx.var.cookie_OauthEmail or "")
  local token   = ngx.unescape_uri(ngx.var.cookie_OauthAccessToken or "")

  if expires == 0 and headers["oauthexpires"] then
    expires = tonumber(headers["oauthexpires"])
  end

  if email:len() == 0 and headers["oauthemail"] then
    email = headers["oauthemail"]
  end

  if token:len() == 0 and headers["oauthaccesstoken"] then
    token = headers["oauthaccesstoken"]
  end

  local expected_token = ngx.encode_base64(ngx.hmac_sha1(token_secret, cb_server_name .. email .. expires))

  if token == expected_token and expires and expires > ngx.time() - extra_validity then
    on_auth(email, expected_token, expires)
    return true
  else
    return false
  end
end

handle_signout()

if not is_authorized() then
  authorize()
end

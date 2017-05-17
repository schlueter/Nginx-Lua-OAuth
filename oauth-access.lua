local domain = ngx.var.oauth_domain or ngx.var.host
local token_secret = ngx.var.oauth_token_secret or 'notsosecret'

local login_uri = ngx.var.oauth_login_uri or '/_oauth/login'


local function is_authorized()
    local login = ngx.unescape_uri(ngx.var.cookie_OAuthLogin)
    local token = ngx.unescape_uri(ngx.var.cookie_OAuthAccessToken)
    ngx.log(ngx.ERR, "Checking authorization of " .. login .. " with token " .. token)

    if login == '' or token == '' then
        ngx.log(ngx.ERR, "Missing auth cookies")
        return false
    end

    local expected_token = ngx.encode_base64(ngx.hmac_sha1(token_secret, domain .. login))
    ngx.log(ngx.ERR, "Checking " .. login .. "'s token, " .. (token or 'nil') .. ", against expected token, " .. expected_token)
    if token ~= expected_token then
        ngx.log(ngx.ERR, "User " .. login .. " has a bad token")
        return false
    end

    ngx.log(ngx.ERR, login .. " is authorized")
    return true
end

if not is_authorized() then
    ngx.log(ngx.ERR, "Redirecting to " .. login_uri)
    ngx.redirect(login_uri)
end

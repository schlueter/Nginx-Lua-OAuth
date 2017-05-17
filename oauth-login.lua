local authorize_url = oauth_authorize_url or ngx.var.oauth_authorize_url
local client_id = oauth_client_id or ngx.var.oauth_client_id
local scope = oauth_scope or ngx.var.oauth_scope or 'read:org'


local auth_url = authorize_url .. "?" .. ngx.encode_args(
  { client_id=client_id
  , scope = scope
  })
ngx.log(ngx.ERR, 'Redirecting to ' .. auth_url .. ' for authorization')
ngx.redirect(auth_url)

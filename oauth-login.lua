local authorize_url = ngx.var.oauth_authorize_url

local client_id = ngx.var.oauth_client_id
local scope = ngx.var.oauth_scope or 'read:org'


local auth_url = authorization_url .. "?" .. ngx.encode_args(
  { client_id=client_id
  , scope = scope
  })
ngx.log(ngx.ERR, 'redirecting to ' .. auth_url)
ngx.redirect(auth_url)

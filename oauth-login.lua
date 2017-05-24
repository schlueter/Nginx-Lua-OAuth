local authorize_url = oauth_authorize_url or ngx.var.oauth_authorize_url
local client_id = oauth_client_id or ngx.var.oauth_client_id
local scope = oauth_scope or ngx.var.oauth_scope or 'read:org'
local callback_url = oauth_callback_url or ngx.var.oauth_callback_url
local target_uri = ngx.req.get_uri_args()['target_uri'] or '/'


local auth_url = authorize_url .. "?" .. ngx.encode_args(
  { client_id=client_id
  , scope=scope
  , redirect_uri=callback_url .. "?target_uri=" .. target_uri
  })
ngx.log(ngx.ERR, 'Redirecting to ' .. auth_url .. ' for authorization')
ngx.redirect(auth_url)

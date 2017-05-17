local domain = ngx.var.oauth_domain or ngx.var.host
local cookie_tail = "; Domain=" .. domain .. '; HttpOnly; Path=/'


ngx.header['Set-Cookie'] = 'OAuthAccessToken==deleted' .. cookie_tail .. '; expires=Thu, 01 Jan 1970 00:00:00 GMT'
ngx.header['Content-type'] = 'text/html'
ngx.say('See you around')
ngx.exit(ngx.HTTP_OK)

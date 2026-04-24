# SSO Kingdee

`SSO Kingdee` 是一个很小的网关服务，用来把你自己的认证系统接到金蝶云星空的第三方登录授权入口。

它最适合这样的场景：

- 已经有自己的统一认证入口
- 反向代理使用 `Authelia + Nginx`、`Nginx Proxy Manager` 或其他支持转发认证头的网关
- 希望用户访问 `kingdee.example.com` 后，认证通过就直接进入金蝶云星空

当前项目优先支持两种认证接入方式：

- `trusted_headers`
  推荐给 `Authelia + Nginx Proxy Manager`
- `exchange_code`
  推荐给你已经有自己认证后端、并且能提供一次性换码接口的场景

## 工作流程

`trusted_headers` 模式：

1. 用户访问 `https://kingdee.example.com`
2. 反向代理先交给 `Authelia` 校验是否已登录
3. 认证通过后，反向代理把 `Remote-User`、`Remote-Email`、`Remote-Name`、`Remote-Kingdee-Username` 等头转发给本服务
4. 本服务按配置解析出金蝶用户名
5. 本服务生成金蝶云星空第三方登录授权 URL
6. 浏览器被 `302` 跳转到金蝶云星空

## 关键协议

本项目按金蝶云星空“第三方系统登录授权”能力实现，跳转地址默认是：

`/K3Cloud/html5/index.aspx?ud=...`

核心参数使用查询参数 `ud`，其值是 `Base64(JSON)`，JSON 至少包括：
`dbid`、`username`、`appid`、`signeddata`、`timestamp`、`lcid`、`origintype`

当前仓库默认 `signeddata` 的生成方式为：

```text
SHA256(dbid + username + appid + appSecret + timestamp)
```

其中 `timestamp` 使用 Unix 秒级时间戳。  
如你的租户要求 SHA1，可通过环境变量 `KINGDEE_SIGN_ALGO=sha1` 切换。

## 路由

- `GET /`
  主入口。已认证则跳转到 `/sso/kingdee`
- `GET /sso/kingdee`
  生成金蝶云星空登录授权地址，并 `302` 跳转
- `GET /debug/session`
  查看当前服务识别到的登录身份
- `GET /debug/url`
  查看当前身份会被解析成哪个金蝶用户名，以及最终生成的登录 URL
- `GET /debug/sign?username=...&timestamp=...`
  用指定用户名和时间戳计算签名，便于对照金蝶“生成测试链接”里的签名值
- `GET /debug/sign-candidates?username=...&timestamp=...&target=...`
  输出多种签名组合（算法/排序/二次校验密码/用户名编码）并标记是否命中目标签名
- `GET /healthz`
  健康检查
- `GET /logout`
  清理本地 Cookie

## 环境变量

建议直接复制示例配置：

```bash
cp .env.example .env
```

最关键的变量有这些：

- `APP_BASE_URL`
  当前服务对外访问的完整地址，例如 `https://kingdee.example.com`
- `AUTH_MODE`
  可选 `trusted_headers` 或 `exchange_code`
- `TZ`
  容器时区，默认建议 `Asia/Shanghai`
- `LOG_UTC_OFFSET_MINUTES`
  日志时间偏移（分钟），`+8` 对应 `480`
- `SESSION_SECRET`
  用于本地签名 Cookie 的随机字符串
- `KINGDEE_BASE_URL`
  金蝶云星空地址，例如 `https://erp.example.com`
- `KINGDEE_DBID`
  云星空账套 `dbid`
- `KINGDEE_APP_ID`
  第三方登录授权使用的 `appid`
- `KINGDEE_APP_SECRET`
  第三方登录授权使用的 `appSecret`

身份映射相关：

- `REMOTE_KINGDEE_USERNAME_HEADER`
  如果上游能直接给出金蝶用户名，这是最稳的方案
- `KINGDEE_USERNAME_SOURCE`
  可选：
  `auto`、`kingdee_header`、`remote_user`、`remote_name`、`email`、`email_localpart`

推荐优先级：

1. 最佳方案：上游直接传 `Remote-Kingdee-Username`，并设置 `KINGDEE_USERNAME_SOURCE=kingdee_header`
2. 次优方案：如果 `Authelia` 用户名本身就是金蝶用户名，设置 `KINGDEE_USERNAME_SOURCE=remote_user`
3. 兜底方案：如果金蝶用户名就是企业邮箱或邮箱前缀，使用 `email` 或 `email_localpart`

## 快速开始

1. 复制配置：

```bash
cp .env.example .env
```

2. 修改 `.env`

3. 启动：

```bash
docker compose up -d --build
```

默认 `docker-compose.yml` 绑定到 `3002`。

## Authelia + Nginx 示例

推荐使用 `trusted_headers` 模式。

示例：

```nginx
location / {
    auth_request /authelia;
    auth_request_set $target_url $scheme://$http_host$request_uri;
    auth_request_set $user $upstream_http_remote_user;
    auth_request_set $name $upstream_http_remote_name;
    auth_request_set $email $upstream_http_remote_email;
    auth_request_set $kingdee_username $upstream_http_remote_kingdee_username;

    error_page 401 =302 https://auth.example.com?rd=$target_url;

    proxy_pass http://127.0.0.1:3002;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_set_header Remote-User $user;
    proxy_set_header Remote-Name $name;
    proxy_set_header Remote-Email $email;
    proxy_set_header Remote-Kingdee-Username $kingdee_username;
}

location /authelia {
    internal;
    proxy_pass http://authelia:9091/api/verify;
    proxy_set_header Host $http_host;
    proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Content-Length "";
    proxy_pass_request_body off;
}
```

仓库里已经放好了可以直接改的配置样板：

- 完整 Nginx server 配置：
  [deploy/nginx.kingdee.conf](/Users/kay/Dev/gateway-kingdee/deploy/nginx.kingdee.conf)
- 适合 Nginx Proxy Manager Advanced 自定义配置：
  [deploy/npm-advanced.conf](/Users/kay/Dev/gateway-kingdee/deploy/npm-advanced.conf)
- 适合 Authelia 场景的环境变量模板：
  [.env.authelia.example](/Users/kay/Dev/gateway-kingdee/.env.authelia.example)

## 联调建议

按这个顺序测：

1. `GET /healthz`
2. `GET /debug/session`
3. `GET /debug/url`
4. `GET /sso/kingdee`

如果 `debug/session` 能看到身份，但 `debug/url` 里 `kingdeeUsername` 为空，优先检查：

- `KINGDEE_USERNAME_SOURCE` 是否与你实际透传的字段一致
- `Remote-User` 是否真的等于金蝶用户名
- 如果不一致，是否应该单独透传 `Remote-Kingdee-Username`

如果 URL 已经生成，但最终没有登录进去，优先检查：

- `KINGDEE_DBID`
- `KINGDEE_APP_ID`
- `KINGDEE_APP_SECRET`
- 金蝶是否已启用第三方登录授权
- 当前用户是否允许第三方登录
- 金蝶服务端时间是否与当前环境严重偏差

## 参考资料

- [金蝶开放平台帮助中心：第三方系统登录授权](https://help.open.kingdee.com/dokuwiki_std/doku.php?id=%E7%AC%AC%E4%B8%89%E6%96%B9%E7%B3%BB%E7%BB%9F%E7%99%BB%E5%BD%95%E6%8E%88%E6%9D%83)
- [金蝶官方社区：第三方系统单点登录到Cloud示例](https://vip.kingdee.com/article/230984230253892096)
- [金蝶官方社区：第三方系统登录授权说明](https://vip.kingdee.com/article/329224762498988800)

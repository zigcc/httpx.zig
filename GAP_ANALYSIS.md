# httpx.zig vs Gin -- 功能差距分析

## 已实现的功能 (对标 Gin 已完成)

| 功能分类 | Gin | httpx.zig | 状态 |
|---------|-----|-----------|------|
| **路由** | GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS/Any | `server.get/post/put/delete/patch/head/options/any` | 已实现 |
| **路由参数** | `:param` 命名参数 | `:param` 命名参数 | 已实现 |
| **通配符** | `*filepath` | `*wildcard` | 已实现 |
| **路由组** | `r.Group("/api")` + 嵌套分组 | `RouteGroup` + 子组 + 中间件继承 | 已实现 |
| **基数树路由** | Radix tree O(k) | Radix tree O(k) | 已实现 |
| **尾斜杠重定向** | `RedirectTrailingSlash` | 已实现 | 已实现 |
| **HEAD->GET 回退** | 自动 | 自动 | 已实现 |
| **OPTIONS 自动响应** | 自动 | `allowedMethods` | 已实现 |
| **405 Method Not Allowed** | `HandleMethodNotAllowed` | 已实现 | 已实现 |
| **静态文件服务** | `r.Static("/assets", "./dir")` | `server.static("/prefix", "./dir")` | 已实现 |
| **中间件链** | 洋葱模型 `Use()` + `Next()` | `MiddlewareChain` 洋葱模型 | 已实现 |
| **全局中间件** | `r.Use(...)` | 支持 | 已实现 |
| **分组中间件** | `group.Use(...)` | `RouteGroup` 中间件继承 | 已实现 |
| **Logger 中间件** | 带颜色状态码 | 带颜色状态码 | 已实现 |
| **Recovery 中间件** | 捕获 panic，返回 500 | 捕获错误，返回 500 | 已实现 |
| **CORS 中间件** | gin-contrib/cors | 内置 `cors()` | 已实现 |
| **BasicAuth 中间件** | `gin.BasicAuth(accounts)` | 内置 `basicAuth()` | 已实现 |
| **Compression 中间件** | gin-contrib/gzip | 内置 gzip/deflate + Accept-Encoding | 已实现 |
| **Security Headers** | gin-contrib/secure | 内置 `helmet()` | 已实现 |
| **Request ID** | gin-contrib/requestid | 内置 `requestId()` (原子计数器) | 已实现 |
| **Context 参数提取** | `c.Param("name")` | `ctx.param("name")` | 已实现 |
| **Query 参数** | `c.Query("key")` | `ctx.query()` 解析 | 已实现 |
| **JSON 绑定** | `c.ShouldBindJSON(obj)` | `ctx.bind()` / `ctx.shouldBind()` | 已实现 |
| **JSON 响应** | `c.JSON(200, obj)` | `ctx.json(value)` | 已实现 |
| **HTML 响应** | `c.HTML(200, tpl, data)` | `ctx.html(content)` (原始 HTML) | 部分实现 |
| **Text 响应** | `c.String(200, fmt, ...)` | `ctx.text(str)` | 已实现 |
| **Redirect** | `c.Redirect(code, url)` | `ctx.redirect(url)` | 已实现 |
| **文件响应** | `c.File(path)` | `ctx.file(path)` | 已实现 |
| **Abort** | `c.Abort()` | `ctx.abort()` | 已实现 |
| **Cookie** | `c.Cookie()` / `c.SetCookie()` | `ctx.getCookie()` / `ctx.setCookie()` | 已实现 |
| **Client IP** | `c.ClientIP()` | `ctx.clientIP()` | 已实现 |
| **Form 数据** | `c.PostForm("key")` | `ctx.formData()` | 已实现 |
| **WebSocket** | 第三方库 | 内置 RFC 6455 完整支持 | 已实现 (超越Gin) |
| **HTTP/2** | Go stdlib 自动支持 | HPACK + Stream 管理 + 帧构造 | 已实现 |
| **HTTP/3** | 第三方 quic-go | QPACK + QUIC 包结构 (实验性) | 部分实现 (超越Gin) |
| **ETag/条件请求** | 需自行实现 | 内置中间件 | 已实现 (超越Gin) |
| **Range 请求** | 需自行实现 | 内置 206 Partial Content | 已实现 (超越Gin) |
| **Multipart 表单** | 内置 | `MultipartForm` RFC 2046 | 已实现 |
| **认证** | BasicAuth 中间件 | Basic/Bearer/Digest (RFC 7617/6750/7616) | 已实现 (超越Gin) |

---

## 未实现的功能 (需要开发)

### 1. 路由相关

| 功能 | Gin API | 优先级 | 说明 |
|------|---------|--------|------|
| **NoRoute 自定义 404** | `r.NoRoute(handler)` | 高 | 当前固定返回 404，不支持自定义处理器 |
| **NoMethod 自定义 405** | `r.NoMethod(handler)` | 高 | 当前固定返回 405，不支持自定义处理器 |
| **Handle 任意方法** | `r.Handle("CUSTOM", path, handler)` | 低 | 注册自定义 HTTP 方法 |
| **路由信息查询** | `r.Routes()` 返回 `RoutesInfo` | 低 | 获取所有已注册路由信息 |
| **RedirectFixedPath** | 大小写不敏感路径修正 | 中 | 路径大小写自动修正重定向 |
| **StaticFile 单文件** | `r.StaticFile("/favicon.ico", "./file")` | 中 | 服务单个静态文件 |
| **StaticFS 自定义FS** | `r.StaticFS(path, fs)` | 低 | 使用自定义文件系统 |
| **FullPath** | `c.FullPath()` | 低 | 返回匹配的路由模式字符串 |

### 2. 中间件相关

| 功能 | Gin API | 优先级 | 说明 |
|------|---------|--------|------|
| **Rate Limiting (真实实现)** | gin-contrib/ratelimit | 高 | 当前是 stub，需要实现基于 IP 的令牌桶/滑动窗口 |
| **Request Timeout (真实实现)** | gin-contrib/timeout | 高 | 当前是 stub，需要实际超时中断机制 |
| **Body Parser (真实实现)** | 内置 | 中 | 当前是 stub 透传 |
| **Session 管理** | gin-contrib/sessions | 高 | 完全缺失：cookie/memory/redis session 存储 |
| **Response Cache** | gin-contrib/cache | 中 | 响应缓存中间件 |
| **Body Size Limiter** | gin-contrib/size | 中 | 请求体大小限制 |
| **per-route 中间件** | `r.GET("/path", mw1, mw2, handler)` | 高 | 路由级中间件（不仅仅是组级） |
| **CustomRecovery** | `gin.CustomRecovery(handler)` | 中 | 自定义 recovery 处理器 |
| **LoggerWithFormatter** | `gin.LoggerWithFormatter(f)` | 低 | 自定义日志格式化函数 |

### 3. 请求处理相关

| 功能 | Gin API | 优先级 | 说明 |
|------|---------|--------|------|
| **DefaultQuery** | `c.DefaultQuery("key", "default")` | 高 | 带默认值的查询参数获取 |
| **GetQuery** | `c.GetQuery("key")` 返回 (value, exists) | 高 | 返回是否存在标志 |
| **QueryArray** | `c.QueryArray("key")` | 中 | 获取同名参数多值 |
| **QueryMap** | `c.QueryMap("key")` | 低 | 获取 map 形式的查询参数 |
| **PostForm** | `c.PostForm("key")` 等系列 | 高 | 完善的表单字段按名获取 |
| **PostFormArray/Map** | `c.PostFormArray/Map("key")` | 中 | 表单多值/映射获取 |
| **文件上传** | `c.FormFile("file")` | 高 | 获取上传文件 |
| **SaveUploadedFile** | `c.SaveUploadedFile(file, dst)` | 高 | 保存上传文件到磁盘 |
| **ShouldBindQuery** | `c.ShouldBindQuery(obj)` | 中 | 仅从查询字符串绑定 |
| **ShouldBindHeader** | `c.ShouldBindHeader(obj)` | 中 | 从 Header 绑定 |
| **ShouldBindUri** | `c.ShouldBindUri(obj)` | 中 | 从 URI 参数绑定 |
| **ShouldBindXML** | `c.ShouldBindXML(obj)` | 低 | XML 绑定 |
| **GetRawData** | `c.GetRawData()` | 中 | 获取原始 body 字节 |
| **ContentType** | `c.ContentType()` | 中 | 快速获取 Content-Type |
| **请求体验证 (Validator)** | go-playground/validator | 高 | 绑定后的结构体字段验证 |

### 4. 响应处理相关

| 功能 | Gin API | 优先级 | 说明 |
|------|---------|--------|------|
| **IndentedJSON** | `c.IndentedJSON(code, obj)` | 中 | 格式化输出的 JSON |
| **SecureJSON** | `c.SecureJSON(code, obj)` | 低 | 防 JSON 劫持前缀 |
| **JSONP** | `c.JSONP(code, obj)` | 低 | JSONP 回调包装 |
| **AsciiJSON** | `c.AsciiJSON(code, obj)` | 低 | 非 ASCII 转义 |
| **PureJSON** | `c.PureJSON(code, obj)` | 低 | 不转义 HTML 字符的 JSON |
| **XML 响应** | `c.XML(code, obj)` | 中 | XML 序列化响应 |
| **YAML 响应** | `c.YAML(code, obj)` | 低 | YAML 序列化响应 |
| **TOML 响应** | `c.TOML(code, obj)` | 低 | TOML 序列化响应 |
| **ProtoBuf 响应** | `c.ProtoBuf(code, obj)` | 低 | Protocol Buffers 序列化 |
| **FileAttachment** | `c.FileAttachment(path, name)` | 高 | 文件下载 (Content-Disposition: attachment) |
| **DataFromReader** | `c.DataFromReader(...)` | 中 | 从 Reader 流式响应 |
| **SSE** | `c.SSEvent(name, msg)` | 高 | Server-Sent Events |
| **Stream** | `c.Stream(func)` | 高 | 流式响应回调 |
| **Content Negotiation** | `c.Negotiate()` / `c.NegotiateFormat()` | 中 | 基于 Accept 头的内容协商 |
| **Status (仅状态码)** | `c.Status(code)` | 中 | 只设置状态码不写 body |
| **Data (原始字节)** | `c.Data(code, contentType, data)` | 中 | 指定 Content-Type 写原始字节 |
| **Writer 元数据** | `c.Writer.Status()` / `Size()` / `Written()` | 中 | 响应写入状态查询 |

### 5. 模板引擎

| 功能 | Gin API | 优先级 | 说明 |
|------|---------|--------|------|
| **HTML 模板渲染** | `r.LoadHTMLGlob("templates/*")` | 高 | 完全缺失：模板加载和渲染 |
| **模板函数** | `r.SetFuncMap(funcMap)` | 高 | 自定义模板函数 |
| **自定义分隔符** | `r.Delims("{{", "}}")` | 低 | 模板分隔符 |
| **多模板支持** | multitemplate | 低 | 多组模板集 |
| **自定义渲染器** | `render.Render` 接口 | 中 | 可扩展的渲染器接口 |

### 6. Context 功能

| 功能 | Gin API | 优先级 | 说明 |
|------|---------|--------|------|
| **AbortWithStatus** | `c.AbortWithStatus(code)` | 高 | 终止并设置状态码 |
| **AbortWithStatusJSON** | `c.AbortWithStatusJSON(code, obj)` | 高 | 终止并返回 JSON 错误 |
| **AbortWithError** | `c.AbortWithError(code, err)` | 高 | 终止并附加错误 |
| **IsAborted** | `c.IsAborted()` | 中 | 检查是否已终止 |
| **Key/Value 存储** | `c.Set(k,v)` / `c.Get(k)` | 高 | 请求级键值存储 |
| **MustGet** | `c.MustGet(key)` | 低 | 不存在则 panic |
| **类型化 Get** | `c.GetString/Bool/Int/Float64` | 中 | 类型安全的值获取 |
| **Copy** | `c.Copy()` | 中 | 协程安全的 Context 副本 |
| **HandlerName** | `c.HandlerName()` | 低 | 获取处理器函数名 |
| **Error 收集** | `c.Error(err)` / `c.Errors` | 高 | 错误附加和收集机制 |

### 7. 服务器/引擎功能

| 功能 | Gin API | 优先级 | 说明 |
|------|---------|--------|------|
| **TLS/HTTPS** | `r.RunTLS(addr, cert, key)` | 高 | TLS 结构已有，但未接入 server.listen() |
| **Graceful Shutdown** | 文档化的 Shutdown 模式 | 高 | 优雅关闭 (等待连接完成) |
| **运行模式** | Debug/Release/Test | 中 | 不同模式的行为差异 |
| **Trusted Proxies** | `r.SetTrustedProxies(ips)` | 高 | 可信代理 IP 配置 |
| **RemoteIPHeaders** | `X-Forwarded-For`, `X-Real-Ip` | 中 | 可配置的 IP 头列表 |
| **Unix Socket** | `r.RunUnix(path)` | 低 | Unix 域套接字监听 |
| **Custom Listener** | `r.RunListener(ln)` | 中 | 自定义 Listener |
| **MaxMultipartMemory** | 可配置 (默认 32MB) | 中 | Multipart 内存上限 |
| **UnescapePathValues** | 可配置 | 低 | 路径值自动解码 |
| **RemoveExtraSlash** | 可配置 | 低 | 移除多余斜杠 |
| **H2C** | `r.UseH2C` | 低 | 非 TLS 的 HTTP/2 |

### 8. 错误处理

| 功能 | Gin API | 优先级 | 说明 |
|------|---------|--------|------|
| **Error 类型系统** | `gin.Error` 含 Type/Meta | 高 | 结构化错误类型 |
| **Error 收集** | `c.Errors` 切片 | 高 | 请求级错误收集 |
| **Error 过滤** | `c.Errors.ByType(t)` | 中 | 按类型过滤错误 |
| **Error JSON 序列化** | `c.Errors.JSON()` | 中 | 错误列表 JSON 输出 |

### 9. 测试工具

| 功能 | Gin API | 优先级 | 说明 |
|------|---------|--------|------|
| **TestMode** | `gin.SetMode(gin.TestMode)` | 中 | 测试模式减少输出 |
| **CreateTestContext** | `gin.CreateTestContext(w)` | 高 | 创建测试用 Context |
| **ServeHTTP** | `r.ServeHTTP(w, req)` | 高 | 直接调用 Handler 进行集成测试 |

---

## 优先级建议的开发路线

### P0 - 核心缺失 (应尽快实现)

1. **NoRoute / NoMethod 自定义处理器** -- 对用户体验影响大
2. **AbortWithStatus / AbortWithStatusJSON** -- 中间件常用
3. **Error 收集机制** -- `c.Error()` / `c.Errors` 模式
4. **per-route 中间件** -- 路由级中间件
5. **DefaultQuery / GetQuery** -- 查询参数便捷 API
6. **PostForm 系列 API** -- 表单处理便捷方法
7. **文件上传便捷 API** -- `c.FormFile()` / `c.SaveUploadedFile()`
8. **FileAttachment** -- 文件下载
9. **SSE (Server-Sent Events)** -- 实时推送基础
10. **Streaming 响应** -- 长连接场景必需
11. **Graceful Shutdown** -- 生产环境必需
12. **Rate Limiting 真实实现** -- 当前 stub 无法提供保护
13. **Request Timeout 真实实现** -- 当前 stub 无法限时
14. **Session 管理中间件** -- Web 应用基础设施
15. **TLS 集成** -- TlsConfig/TlsSession 已有结构体，需接入 server.listen()
16. **Trusted Proxies** -- 部署安全

### P1 - 重要增强

1. **HTML 模板引擎** -- 服务端渲染场景
2. **Content Negotiation** -- Accept 头协商
3. **IndentedJSON** -- 调试友好的 JSON
4. **请求体验证器** -- 绑定后自动验证
5. **CreateTestContext** -- 测试工具
6. **运行模式 (Debug/Release/Test)**
7. **RedirectFixedPath** -- 大小写修正
8. **StaticFile 单文件服务**
9. **Key/Value 类型化 Get**
10. **Cookie 日期解析修复**

### P2 - 锦上添花

1. **XML/YAML/TOML 响应** -- 多格式支持
2. **JSONP / SecureJSON / AsciiJSON** -- JSON 变体
3. **路由信息查询**
4. **Context.Copy()**
5. **LoggerWithFormatter**
6. **Unix Socket / Custom Listener**
7. **Handle 任意方法**
8. **自定义渲染器接口**

---

## httpx.zig 的优势 (超越 Gin 的部分)

1. **内置 WebSocket** -- Gin 需要第三方库 (gorilla/websocket)
2. **内置 HTTP/2 完整实现** -- Gin 依赖 Go stdlib 的 http2
3. **HTTP/3 实验性支持** -- Gin 需要 quic-go
4. **内置 ETag / 条件请求中间件** -- Gin 需自行实现
5. **内置 Range 请求中间件** -- Gin 需自行实现
6. **内置 Digest Auth** -- Gin 仅有 BasicAuth
7. **零分配设计** -- Zig 的显式内存管理优势
8. **编译时优化** -- comptime 字符串转换等

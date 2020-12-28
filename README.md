# hihttp

hihttp 是 golang http 库简单封装，增加了一些功能并且保留了原生http库的使用习惯。

## 功能：

- **查询参数和`application/x-www-form-urlencoded`表单值按添加顺序发送**
- **transport 连接复用**
- **head 不自动规范化**
- **代理（http、https、socks5）**
  1. 设置默认代理
  2. 设置不同 url 对应的代理
- **单个请求的超时时间**
- **重定向检查**
- **添加 cookie**
- **支持 context 传入**
- **post 多种数据类型**
- **json 结果解析为结构体**
- **结果存入文件**

## TODO:
multipart/form-data
boundary
https://zhuanlan.zhihu.com/p/136774587

- [ ] 重试
- [ ] 支持 debug 模式 打印请求和结果信息
- [ ] 文件上传
- [ ] 代理选择器 每个请求轮换/每多少次轮换
- [ ] cookiejar支持启用PublicSuffixList
- [ ] golang.org/x/net/proxy代理设置
- [ ] 上传下载文件

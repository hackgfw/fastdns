fastdns
===========
Fast Recursive DNS server

# 与传统DNS服务器区别
* 同时向所有候选服务器发送请求, 例如查询 www.baidu.com, 会同时向13个根服务器发送请求, 当收到第一个回应后就同时向所有 com 服务器发送请求, 再接着同时向百度的域名服务器发送请求, 如果百度的域名服务器同时配置了国内和国外的服务器, 会导致国内服务器优先返回结果, 并且是 CDN 加速过的 ip 地址. 如果查询的是被墙域名, 由于其只有国外的服务器, 在配合 gfw-vpn 的情况下会从 VPN 线路上返回正确的结果
* 当缓存记录快到期时会自动向域名服务器发起查询以更新缓存, 保证域名服务的相关缓存永不过期. 如果曾经查询过 www.baidu.com, 当再查询 pan.baidu.com 时会直接连接百度的域名服务器, 省去了从根->com的过程.

# 安全
* 为了实现简单, fastdns 在很多地方上都没有遵守 RFC 规范, 在安全方面也有很多妥协(如: Kaminsky attack), 而且代码缺少审计, 因此如果你对安全性要求比较高, 请谨慎使用

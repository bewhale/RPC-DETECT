# RPC-DETECT
![RPC-DETECT](https://socialify.git.ci/bewhale/RPC-DETECT/image?description=1&font=Raleway&forks=1&issues=1&language=1&name=1&owner=1&pattern=Solid&stargazers=1&theme=Light)

通过Windows RPC批量多线程 检测HTTP、DNS协议出网情况

使用 https://www.fuzz.red/ 平台

使用方法
```
// 指定单个ip
python RPC-DETECT.py -t 192.168.1.8 -u administrator -p 123456
// 指定CUID格式
python RPC-DETECT.py -t 192.168.1.1/24 -u administrator -p 123456 
// 从文件导入ip地址
python RPC-DETECT.py -f ip.txt -u administrator -p 123456 
// 使用HASH认证
python RPC-DETECT.py -t 192.168.1.8 -u administrator -H :32ed87bdb5fdc5e9cba88547376818d4
// 指定线程
python RPC-DETECT.py -t 192.168.1.1/24 -u administrator -H :32ed87bdb5fdc5e9cba88547376818d4 -t 100
```


# 参考文章
https://payloads.online/archivers/2022-03-04/1/  
https://s3cur3th1ssh1t.github.io/On-how-to-access-protected-networks/  
https://github.com/SecureAuthCorp/impacket

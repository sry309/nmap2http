# nmap2http
目的：
通过nmap扫描，得到指定子网内的所有http服务

第1步：输入一个16位子网的地址（或24位子网的地址）

第2步:nmap扫描，并将结果保存到本地的文件ip_result.txt

第3步：分析ip_result.txt，得到其中所有open的端口port

第4步：通过http或https服务，访问第3步的到的ip+port，并将返回正确的结果保存到http_ip_result.txt

第5步：扫描完成后，自动将结果发送到指定邮箱

使用说明：

1、需修改172行来指定目标子网

myCtroller = Ctroller('192.168.0.0')


2、需修改124行的发送邮箱相关参数

	def autoSendMail(self):
		# 输入Email地址和口令:
		from_addr = 'auto1023193134@163.com'
		password = '123456'
		# 输入SMTP服务器地址:
		smtp_server = 'smtp.163.com'
		# 输入收件人地址:
		to_addr = '10231931@qq.com'


3、运行start.sh即可

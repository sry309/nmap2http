# -*- coding: utf-8 -*-
import re
import os
import requests
import time
import smtplib

class Nmap_scan:
	def __init__(self,target_ip):
		self.status_code = 0
		self.target_ip = target_ip
		self.scan_result = target_ip+'_result.txt'

	#查询自身状态，status_code为0代表未运行，1代表运行中
	def getSelfStatus(self):
		print 'getSelfStatus'
		self.status_code = 0
		r = os.popen('ps -ef |grep nmap')
		info = r.readlines()
		for line in info:
			line = line.strip('\r\n')
			if 'nmap -Pn'  in line:
				self.status_code = 1
		print 'nmap status_code :' + str(self.status_code)
		return self.status_code

	def start_scan(self):
		os.system('nmap -Pn -T4 -v -p 79-65535 '+self.target_ip+' > '+self.scan_result)

class Http_req:
	def __init__(self,target_file):
		self.status_code = 1 #status_code为0代表未运行，1代表运行中
		self.target_file = target_file
		self.ip = '127.0.0.1'
		self.port = False
		self.result = ''
		self.result_file = 'http_'+target_file

	#读文件
	def readFile(self,FILE):
		with open(FILE, 'r') as f:
			return f.readlines()

	#写文件
	def writeFile(self,FILE,STR):
		with open(FILE, 'a') as f:
			f.write(STR)

	#简单的从长文本中提取ip地址
	def getIpFromStr(self,string_ip):
		result = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", string_ip)
		if result:
			return result
		else:
			return False

	#简单的从长文本中提取port
	def getPortFromStr(self,string_port):
		result = string_port.split('/tcp')[0]
		return result

	#url探测，待完善（如添加多种探测方式）
	def reqUrl(self,URL):
		session = requests.Session()
		headers = {"Cache-Control":"max-age=0","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36","Connection":"close","X-Forwarded-For":"127.0.0.1","Accept-Language":"zh-CN,zh;q=0.9"}
		try:
			response = session.get(URL, headers=headers)
		except Exception as e:
			if e == KeyboardInterrupt:
				os._exit(0)
			else:
				return ('exception','exception')
				pass
		return response.status_code,response.content

	#判断reqUrl是否发生异常
	def isReqException(self,status_code):
		if str(status_code) == 'exception':
			return True
		else:
			return False

	#如果响应码为20x，则返回true
	def status_codeIsExit(self,status_code):
		pre_status_code = str(status_code)[0:2]
		if pre_status_code == '20' or str(status_code) == '403':
			return True
		else:
			return False

	#判断http-url是否可访问
	def isExistUrl(self,url):
		status_code,content = self.reqUrl(url)
		if not self.isReqException(status_code):
			if self.status_codeIsExit(status_code):
				return True
			else:
				return False
		else:
			return False

	def start_httpReq(self):
		#从nmap扫描结果中提取ip和port
		for line in self.readFile(self.target_file):
			if 'Nmap scan report for' in line:
				ip_analy_result = self.getIpFromStr(line)#提取ip
				if ip_analy_result:
					self.ip = ip_analy_result
			if ' open  ' in line :
				self.port = self.getPortFromStr(line)#提取port
				if self.port:
					#验证ip+port是否启动http服务
					url_http = 'http://'+self.ip+':'+self.port
					url_https = 'https://'+self.ip+':'+self.port
					if self.isExistUrl(url_http):
						self.result = self.result +'\r\n'+url_http+'\r\n'
					if self.isExistUrl(url_https):
						self.result = self.result +'\r\n'+url_https+'\r\n'
		#保存可访问的url到txt文件
		self.writeFile(self.result_file,self.result)
		self.status_code = 0

	#发送邮件
	def autoSendMail(self):
		# 输入Email地址和口令:
		from_addr = 'auto1023193134@163.com'
		password = '123456'
		# 输入SMTP服务器地址:
		smtp_server = 'smtp.163.com'
		# 输入收件人地址:
		to_addr = '10231931@qq.com'
		#输入内容
		mailb = ["auto send:",self.result]
		mailh = ["From: "+from_addr, "To: "+to_addr, "Subject: VPS sendmail"]
		mailmsg = "\r\n\r\n".join(["\r\n".join(mailh), "\r\n".join(mailb)])

		server = smtplib.SMTP(smtp_server,25) # SMTP协议默认端口是25
		server.login(from_addr, password)
		server.sendmail(from_addr, (to_addr), mailmsg)
		server.quit()
#控制层
class Ctroller:
	def __init__(self,ip):
		#self.ip = ip.split('.')[0]+'.'+ip.split('.')[1] #A:取ip的前2段
		self.ip = ip.split('.')[0]+'.'+ip.split('.')[1]+'.'+ip.split('.')[2] #B:取ip的前3段

	#主函数
	def getHttpFromNmap(self):
		for i in range(79,90):
			#target_ip = self.ip+'.'+str(i)+'.5-253'#A:每个网段扫描ip范围为5-253的主机
			target_ip = self.ip+'.'+str(i)#B:扫描ip范围为0-255的主机
			print target_ip
			myNmapScan = Nmap_scan(target_ip)
			myNmapScan.start_scan()#开始nmap扫描
			print myNmapScan.getSelfStatus()
			if self.monitorTask(myNmapScan.getSelfStatus(),0) == 'end':
				print 'start myHttp_req'
				myHttp_req = Http_req(myNmapScan.scan_result)
				myHttp_req.start_httpReq()#开始分析nmap结果，发起http请求
				if self.monitorTask(myHttp_req.status_code,0) == 'end':
					myHttp_req.autoSendMail()#发送email

	#监控任务的状态，是否结束，如果还在运行则延时6小时
	def monitorTask(self,status_code,end_status):
		if status_code == end_status:
			return 'end'
		else :
			print status_code
			time.sleep(10)#延时6小时
			self.monitorTask(status_code,end_status)

myCtroller = Ctroller('192.168.0.0')
myCtroller.getHttpFromNmap()

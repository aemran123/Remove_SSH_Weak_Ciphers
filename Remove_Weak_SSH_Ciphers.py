''' Description
###############
This code will delete SSH weak ciphers on a PN-OS Firewall 9.1.10 as per KB:
https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PN5bCAG
This code is for devices(standalone or HA).
Customer should provide a list of IP addresses of the devices
'''
__author__ = "Ahmed Omran"
__copyright__ = "Copyright 2021, Demo/PoC Projetcs"
__license__ = "GPL"
__version__ = "1.0"
__maintainer__ = "Ahmed Omran"
__email__ = "aomran@paloaltonetworks.com"
__status__ = "demo/PoC"

import requests	#3rd party module https://requests.readthedocs.io/
from requests.auth import HTTPBasicAuth
import os
import time
from datetime import date
import lxml
import xml.etree.ElementTree as ET
from lxml import etree
import lxml.etree as etree
import xml.dom.minidom
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
user = 'admin' #FW admin user or a user that has API access permissions
password = 'Paloalto!' #FW admin password
timestr = time.strftime("%Y%m%d-%H%M%S")
#PLease provide a location for the log file just replace C:/logs/
Log_File_Name = 'C:/logs/' + 'Log_' + timestr + '.txt'
Log_File= open(Log_File_Name,'a')#Let's create a log file to record status and troubleshooting
FW_Done_List=[]

def Get_Api_Key(line):

	URL = 'https://' + line + '/api' # line is the IP address of the firewall
	Data = {'type' : 'keygen', 'user': user, 'password':password}
	try:
			API_Key = requests.post(URL, data =Data, auth=(user, password), verify = False)
	except requests.exceptions.RequestException as e:
			print("The error message is:= ", e,'\n') #The code will go to next device for any error
			Log_File.write("The error message is:= " + str(e) + '\n')
			print("We failed to get an API Key from FW@",line,'\n')
			Log_File.write("We failed to get an API Key from FW@" + line + '\n')
			print("###################################################")
			Log_File.write("###################################################"+ '\n')
			return

	tree = ET.fromstring(API_Key.text)
	if tree.get("status")=="success":
	    FW_API_Key = tree.find('./result/key').text
	else:
		dom = xml.dom.minidom.parseString(API_Key.text)
		Commit_Pretty = dom.toprettyxml()
		print(API_Key.text)
		print("We failed to get an API Key from FW@",line,'\n')
		Log_File.write("We failed to get an API Key from FW@" + line + '\n')
		return
	return FW_API_Key

def Job_Complete(Job_Id,IP_Address,FW_API_Key):
	URL = 'https://' + IP_Address + '/api'
	Headers = {'X-PAN-KEY': FW_API_Key}
	Show_Jobs_Id = '<show><jobs><id>'+Job_Id+'</id></jobs></show>'
	Show_Jobs_Id = {'type' : 'op', 'cmd':Show_Jobs_Id}
	sync = True
	while sync:
		Show_Jobs_ID = requests.post(URL, data=Show_Jobs_Id,  verify = False, headers = Headers)
		root = ET.fromstring(Show_Jobs_ID.text)
		for status in root.iter('status'):
			if status.text == "FIN":
				sync = False
				return "Success"
	return

def Change_Config(line,FW_API_Key):
	URL = 'https://' + line + '/api'
	Headers = {'X-PAN-KEY': FW_API_Key}
	Data_Del_SSH = {'type' : 'config', 'action' : 'delete', 'xpath':'/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/ssh'}
	Set_SSH_aes256_ctr = {'type' : 'config', 'action' : 'set', 'xpath':'/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/ssh/ciphers/mgmt','element': '<aes256-ctr/>'}
	Set_SSH_aes256_gcm = {'type' : 'config', 'action' : 'set', 'xpath':'/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/ssh/ciphers/mgmt','element': '<aes256-gcm/>'}
	Set_Default_Host_Key = {'type' : 'config', 'action' : 'set', 'xpath':'/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/ssh/default-hostkey/mgmt/key-type','element': '<ECDSA>256</ECDSA>'}
	Regenerate_Host_Key = {'type' : 'config', 'action' : 'set', 'xpath':'/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/ssh/regenerate-hostkeys/mgmt/key-type/ECDSA','element': '<key-length>256</key-length>'}
	SSH_Session_Rekey = {'type' : 'config', 'action' : 'set', 'xpath':'/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/ssh/session-rekey/mgmt','element': '<interval>3600</interval>'}
	SSH_hmac_sha2_256= {'type' : 'config', 'action' : 'set', 'xpath':'/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/ssh/mac/mgmt','element': '<hmac-sha2-256/>'}
	SSH_hmac_sha2_512= {'type' : 'config', 'action' : 'set', 'xpath':'/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/ssh/mac/mgmt','element': '<hmac-sha2-512/>'}
	
	#Let's delete the SSH Config
	try:
			Delete_SSH_Config = requests.post(URL, data = Data_Del_SSH, verify = False, headers = Headers)
	except requests.exceptions.RequestException as e:
		print("The error message is:= ", e,'\n') #The code will go to next device for any error
		Log_File.write("The error message is:= " + str(e) + '\n')
		return

	root = ET.fromstring(Delete_SSH_Config.text) # get the root of the xml output
	if root.get("status")=="success":
		print ("The Delete_SSH_Config was successful",'\n')
		Log_File.write("The Delete_SSH_Config was successful" + '\n')
		

		
		#Let's set (set deviceconfig system ssh ciphers mgmt aes256-ctr)
		try:
					Set_SSH_aes256_ctr_Request=requests.post(URL, data = Set_SSH_aes256_ctr, verify = False, headers = Headers)
		except requests.exceptions.RequestException as e:
			print("The error message is:= ", e,'\n')
			Log_File.write("The error message is:= " + str(e) + '\n')
			return
		root = ET.fromstring(Set_SSH_aes256_ctr_Request.text)
		if root.get("status")=="success":
			print ("Set_SSH_aes256_ctr_Request was successful",'\n')
			Log_File.write("Set_SSH_aes256_ctr_Request was successful" + '\n')
			
			try:
					Set_SSH_aes256_gcm_Request=requests.post(URL, data = Set_SSH_aes256_gcm, verify = False, headers = Headers)
			except requests.exceptions.RequestException as e:
				print("The error message is:= ", e,'\n')
				Log_File.write("The error message is:= " + str(e) + '\n')
				return
			root = ET.fromstring(Set_SSH_aes256_gcm_Request.text)
			if root.get("status")=="success":
				print ("Set_SSH_aes256_gcm_Request was successful",'\n')
				Log_File.write("Set_SSH_aes256_gcm_Request was successful"+ '\n')
				

				try:
						Set_Default_Host_Key = requests.post(URL, data = Set_Default_Host_Key, verify = False, headers = Headers)
				except requests.exceptions.RequestException as e:
					print("The error message is:= ", e,'\n')
					Log_File.write("The error message is:= " + str(e) + '\n')
					
					return
				root = ET.fromstring(Set_Default_Host_Key.text)
				if root.get("status")=="success":
					print ("Set_Default_Host_Key was successful",'\n')
					Log_File.write("Set_Default_Host_Key was successful" + '\n')
					try:
							Regenerate_Host_Key = requests.post(URL, data = Regenerate_Host_Key, verify = False, headers = Headers)
					except requests.exceptions.RequestException as e:
						print("The error message is:= ", e,'\n')
						Log_File.write("The error message is:= " + str(e) + '\n')
						
						return
					root = ET.fromstring(Regenerate_Host_Key.text)
					if root.get("status")=="success":
						print ("Regenerate_Host_Key was successful",'\n')
						try:
								SSH_Session_Rekey= requests.post(URL, data = SSH_Session_Rekey, verify = False, headers = Headers)						
						except requests.exceptions.RequestException as e:
							print("The error message is:= ", e,'\n')
							Log_File.write("The error message is:= " + str(e) + '\n')
							return
						root = ET.fromstring(SSH_Session_Rekey.text)
						if root.get("status")=="success":
							print ("SSH_Session_Rekey was successful",'\n')
							try:
									SSH_hmac_sha2_256= requests.post(URL, data = SSH_hmac_sha2_256, verify = False, headers = Headers)
							except requests.exceptions.RequestException as e:
									print("The error message is:= ", e,'\n')
									Log_File.write("The error message is:= " + str(e) + '\n')
									return
							root = ET.fromstring(SSH_hmac_sha2_256.text)
							if root.get("status")=="success":
								print ("SSH_hmac_sha2_256 was successful",'\n')
								Log_File.write("SSH_hmac_sha2_256 was successful"+ '\n')
								try:
										SSH_hmac_sha2_512= requests.post(URL, data = SSH_hmac_sha2_512, verify = False, headers = Headers)
								except requests.exceptions.RequestException as e:
									print("The error message is:= ", e,'\n')
									Log_File.write("The error message is:= " + str(e) + '\n')
									return
								root = ET.fromstring(SSH_hmac_sha2_512.text)
								if root.get("status")=="success":
									print ("SSH_hmac_sha2_512 was successful",'\n')
									Log_File.write("SSH_hmac_sha2_512 was successful" + '\n')
									

	#Let's commit the configuration
	Data_Commit = {'type' : 'commit', 'cmd' : '<commit></commit>'}
	try:
		Let_Commit = requests.post(URL, data=Data_Commit, verify = False, headers = Headers)
	except requests.exceptions.RequestException as e:
		print("The error message is:= ", e,'\n')
		Log_File.write("The error message is:= " + str(e) + '\n')
		return

	root = ET.fromstring(Let_Commit.text)
	if root.get("status")=="success":
		#Let's check commit completed succesfully - use show jobs processed
		dom = xml.dom.minidom.parseString(Let_Commit.text)
		Commit_Pretty = dom.toprettyxml()
		print("Commit Pretty is:= ", Commit_Pretty)
		#capture job ID
		for job in root.iter('job'):
			print("The job ID is:= ",job.text, '\n')
			Log_File.write("The job ID is:= " + job.text + '\n')
			Job_Id = job.text
			#Let's check if this job is completed
			result = Job_Complete(Job_Id,line,FW_API_Key)
			if result == "Success":
				print ("Commit Configuration was successful",'\n')
				Log_File.write("Commit Configuration was successful" + '\n')
	else:
		print
	#Restart SSH service
	Set_SSH_Restart = {'type' : 'op', 'cmd':'<set><ssh><service-restart><mgmt/></service-restart></ssh></set>'}
	print("Let's restrt the SSH service",'\n')
	Log_File.write("Let's restrt the SSH service" + '\n')
	try:
			Set_SSH_Restart = requests.post(URL, data=Set_SSH_Restart,  verify = False, headers = Headers)
	except requests.exceptions.RequestException as e:
			print("The error message is:= ", e,'\n')
			Log_File.write("The error message is:= " + str(e) + '\n')			
			return
	root = ET.fromstring(Set_SSH_Restart.text)
	if root.get("status")=="success":
		print ("Restart SSH service was successful",'\n')
		Log_File.write("Restart SSH service was successful" + '\n')

	return 

def Change_Config_HA(Active_FW_Passive_FW,FW_API_Key):
	
	#This function changes configuration for HA devices

	Active_FW_IP = Active_FW_Passive_FW [0]
	Passive_FW_IP = Active_FW_Passive_FW [1]

	#let's change config on Active FW:
	Change_Config(Active_FW_IP,FW_API_Key)
	#Let's issue a config synchronization to passive FW
	print("The Active FW IP is:= ", Active_FW_IP,'\n')
	Log_File.write("The Active FW IP is:= " + Active_FW_IP + '\n')
	print("The Passive FW IP is:= ", Passive_FW_IP, '\n')
	Log_File.write("The Passive FW IP is:= " +  Passive_FW_IP + '\n')
	URL_A = 'https://' + Active_FW_IP + '/api'
	URL_P = 'https://' + Passive_FW_IP + '/api'
	Headers = {'X-PAN-KEY': FW_API_Key}
	Config_Sync = {'type' : 'op', 'cmd':'<request><high-availability><sync-to-remote><running-config/></sync-to-remote></high-availability></request>'}
	try:
		Config_Sync = requests.post(URL_A, data=Config_Sync,  verify = False, headers = Headers)
	except requests.exceptions.RequestException as e:
		print("The error message is:= ", e,'\n')
		Log_File.write("The error message is:= " + e + '\n')
		return
	root = ET.fromstring(Config_Sync.text)
	if root.get("status")=="success":
		print ("Request config sync was successful",'\n')
		dom = xml.dom.minidom.parseString(Config_Sync.text)
		Config_Sync_Pretty = dom.toprettyxml()
		print (Config_Sync_Pretty)
		Log_File.write(Config_Sync_Pretty)
	else:
		dom = xml.dom.minidom.parseString(Config_Sync.text)
		Config_Sync_Pretty = dom.toprettyxml()
		print (Config_Sync_Pretty)
		Log_File.write(Config_Sync_Pretty)
		
	#Let's go to passive FW and restart SSH service
	#First check that the synch job is completed
	#use show HA state and search for  State Synchronization: Complete;
	FW_API_Key = Get_Api_Key(Passive_FW_IP)
	Show_Jobs_All = {'type' : 'op', 'cmd':'<show><jobs><all/></jobs></show>'}
	
	try:
		Show_Jobs_All = requests.post(URL_P, data=Show_Jobs_All,  verify = False, headers = Headers)
	except requests.exceptions.RequestException as e:
		print("The error message is:= ", e,'\n')
		Log_File.write("The error message is:= " +  e + '\n')
		return
	root = ET.fromstring(Show_Jobs_All.text)
	if root.get("status")=="success":
		sync = True
		id = root.find(".//id")
		type = root.find(".//type")
		print("The job id is:= ",id.text, " and the type is:= ", type.text)
		if type.text == "HA-Sync":
			Result = Job_Complete(id.text,Passive_FW_IP,FW_API_Key)
			if Result == "Success":
				print("Passive FW is synced with Active")
				Log_File.write("Passive FW is synced with Active" +'\n')
				#Let's restart ssh service and return
				Set_SSH_Restart = {'type' : 'op', 'cmd':'<set><ssh><service-restart><mgmt/></service-restart></ssh></set>'}
				print("Let's restrt the SSH service",'\n')
				Log_File.write("Let's restrt the SSH service" + '\n')
							
				try:
						Set_SSH_Restart = requests.post(URL_P, data=Set_SSH_Restart,  verify = False, headers = Headers)
				except requests.exceptions.RequestException as e:
						print("The error message is:= ", e,'\n')
						Log_File.write("The error message is:= " + e + '\n')
						return
				root = ET.fromstring(Set_SSH_Restart.text)
				if root.get("status")=="success":
					print ("Restart SSH service on passive FW was successful",'\n')
					Log_File.write("Restart SSH service on passive FW was successful" + '\n')
					return

		
	return

def Check_HA(line,FW_API_Key):
	IP_Address_Active_Passive = []
	URL = 'https://' + line + '/api'
	Headers = {'X-PAN-KEY': FW_API_Key}
	Data_HA = {'type' : 'op', 'cmd':'<show><high-availability><state/></high-availability></show>'}
	try:
			Show_HA_State = requests.post(URL, data = Data_HA, verify = False, headers = Headers)
	except requests.exceptions.RequestException as e:
		print("The error message is:= ", e,'\n') #The code will go to next device for any error
		Log_File.write("The error message is:= " + e + '\n')	
		return
	root = ET.fromstring(Show_HA_State.text) # get the root of the xml output
	for k in root.iter('enabled'):
		print("HA enabled yes/no? = ", k.text,'\n')
		Log_File.write("HA enabled yes/no? = " + k.text + '\n')
		if k.text == "no":
			print ("The FW @:= ",line, "is in standalone mode", '\n')
			Log_File.write("The FW @:= " + line + "Is in standalone mode" + '\n')
			#Now we can cll change standalone configuration
			if line in FW_Done_List:
				print("We have configured this firewall before := ", line,'\n')
				Log_File.write("We have configured this firewall before := " + line + '\n')
				print("###################################################",'\n')
				Log_File.write("###################################################"+ '\n')
			else:
				#call standalone change config
				Change_Config(line,FW_API_Key)
				print("###################################################",'\n')
				Log_File.write("###################################################" + '\n')
				FW_Done_List.append(line)
			return


	#For HA firewalls let's get active and passive IP addresses
	State = root.find('.//state').text
	print("the state of the HA is:= ",State,'\n')
	Log_File.write("the state of the HA is:= " + State + '\n')
	
	if State == 'active':
		#we get both IP addresses for active and passive FW
		for k in root.iter('ha1-ipaddr'):
			if '/' in k.text:
				FW_IP_address = k.text[0:-3]
				IP_Address_Active_Passive.append(FW_IP_address)
			else:
				FW_IP_address = k.text
				IP_Address_Active_Passive.append(FW_IP_address)
	else:
		#The FW is Passive
		#we get both IP addresses for active and passive FW
		#Note first IP is the passive second is active hence we use insert(-1,-2)
		for k in root.iter('ha1-ipaddr'):
			if '/' in k.text:
				FW_IP_address = k.text[0:-3]
				IP_Address_Active_Passive.insert(-1,FW_IP_address)
			else:
				FW_IP_address = k.text
				IP_Address_Active_Passive.insert(-2,FW_IP_address)

			print(k.tag,k.attrib,k.text)
	print("The ip address for primary FW and passive is:= ", str(IP_Address_Active_Passive),'\n')
	Log_File.write("The ip address for primary FW and passive is:= " + str(IP_Address_Active_Passive) + '\n')	
	if (IP_Address_Active_Passive[0] or IP_Address_Active_Passive[1]) in FW_Done_List:
		print(" we have previously configured those firewall(s) ", line)
		Log_File.write(" we have previously configured those firewall(s) " + line + '\n')
		print("###################################################",'\n')
		Log_File.write("###################################################"+ '\n')
	else:
		Change_Config_HA (IP_Address_Active_Passive,FW_API_Key)
		print("###################################################",'\n')
		Log_File.write("###################################################" + '\n')
		FW_Done_List.append(IP_Address_Active_Passive[0])
		FW_Done_List.append(IP_Address_Active_Passive[1])
	
	return

def main():
	''' 
	* first we need to read the file that has the IP addresses from a device-list.txt
	* then we need to scan through it - get the first IP address from the file
	* we call the function that gets the API Key
	* we check if the device (FW) is in HA or standalone
	* then we call the function to change the config
	* get next IP, continue till EoF
	'''

	today = date.today()
	d2 = today.strftime("%B %d, %Y")
	print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	Log_File.write("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	print("+                                                                 +")
	Log_File.write("+                                                                 +")
	print("+                           ",d2,"                   +")
	Log_File.write("+                           " + d2 + "                   +")
	print("+                                                                 +")
	Log_File.write("+                                                                 +")
	print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	Log_File.write("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	print('\n')
	Log_File.write('\n')
	#We open the file called "device_list.txt"
	with open('C:/Users/aemran/Downloads/device_list.txt', "r") as f:
		for line in f:
			line = line.rstrip('\r\n') # strip out all tailing whitespace
			print("The IP address of the FW is:= ",line,'\n')
			Log_File.write("The IP address of the FW is:= " + line + '\n')		
			#Call the function to get API Key
			print("Lets get the API key from the FW",'\n')
			#Log_File = open (Log_File_Name,'a')
			Log_File.write("Lets get the API key from the FW " + '\n')	
			FW_API_Key = Get_Api_Key(line)
			#call the function to change config only if we managed to get an API key
			if FW_API_Key != None:
				#Let's check if FW is HA or not?
				Check_HA(line,FW_API_Key)
	Log_File.close()	
if __name__ == '__main__':
	main()






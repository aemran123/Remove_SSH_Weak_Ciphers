Remove Weak SSH Ciphers
========================

1:- This script removes weak SSH ciphers as per the KB:
https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PN5bCAG

You need to install the packages shown in the import statements for Python before running the script:

requests
lxml
xml


2:- You need to provide a list of IP addresses of the firewalls in a file called device_list.txt
3:- You need to state user/password for admin role or a role that has API permissions on the firewalls (line 29&30)
user = 'admin' #FW admin user or a user that has API access permissions
password = 'Paloalto!' #FW admin password

4:- The script create a log a file - customer requires to specify the location (line 33)

#PLease provide a location for the log file just replace C:/logs/

5:- The script checks if the FW is a standalone or HA and configure accordingly 
6:- All succesfull/erros operation will be printed on screen as well as in the log file
7:- The script will take care of duplicate IP addresses in the device_list i.e. we won't configure devices twice
8:- sample device_list is provided
9:- Sample log file is provided (log files names as log_datetime format)




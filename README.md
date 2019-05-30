# SpoofMaterials

Original and Current Repos:  
https://github.com/NetSPI/SpoofSpotter  
https://github.com/jm786/SpoofMaterials

Added Flags:  
1. Flag --spammode
	* Threads(200)
	* -d (1) 
	* No logging  

2. Non --spammode
	* Threads(2)
	* -d (60)
	* Log usernames

3. Flag --honeyusers
	* Non-threaded
	* Send 15 users every 20 minutes
	* When login attempted with pre-identified users, void network connection
  
Run setup script.  
Fix interface in main() function depending on configuration.  
Update iptables for host output UDP if necessary.  
`supervisorctl status`   
Use `supervisorctl start spoofspotter` if necessary.

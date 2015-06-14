NSE-script: hydra.nse
Version: v1.0
Script types: portrule
Categories: brute

User Summary

	Brute force all services running on a target host. The results are 
	returned in a table with each path, detected method, login and/or 
	password.
	This version include follow services:
		Cisco Auth
		Oracle Listener
		Oracle SID
		HTTP(S) Basic
		HTTP(S) Digest
		MySQL
		MS-SQL
		PostgerSQL
	By default, user should have files with logins ("login.txt") and 
	passwords ("password.txt") in the directory from which the script is run.
	Or use --script-args.

Usage 
	nmap --script hydra [--script-args "lpath=<file_logins>, ppath=<file_passwords>"] <target_ip>

Example Usage
	nmap --script hydra localhost
	
	PORT     STATE SERVICE
	80/tcp   open  http
	| hydra: 
	|   path                            method  login  password
	|   127.0.0.1/private/index.html    Digest  log    pass
	|_  127.0.0.1/simple/index.txt      Basic   user   qwerty

Script Arguments
	- hydra.lpath: the path to the file with logins. For example, 
		nmap --script hydra --script-args="lpath=/home/my_logins.txt" <target_ip>
	- hydra.ppath: the path to the file with passwords. For example, 
		nmap --script hydra --script-args="ppath=/home/my_pass.txt" <target_ip>

Example Script Arguments
	nmap --script hydra --script-args "lpath=/home/login.txt, ppath=/home/passwd.txt" <target_ip>
	
Requires
	nmap
	shortport
	stdnse
	string
	table
	tab
	

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tab = require "tab"

description = [[
Brute force all services running on a target host. The results are returned in a table with each path, detected method, login and/or password.
]]

---
-- @usage 
-- nmap --script hydra [--script-args "lpath=<file_logins>, ppath=<file_passwords>"] <target_ip>
-- 
-- @output
-- PORT     STATE SERVICE
-- 80/tcp   open  http
-- | hydra: 
-- |   path                            method  login  password
-- |   127.0.0.1/private/index.html    Digest  log    pass
-- |_  127.0.0.1/simple/index.txt      Basic   user   qwerty
--
-- @args hydra.lpath: the path to the file with logins. For example, 
--		 nmap --script hydra --script-args="lpath=/home/my_logins.txt" <target_ip>
-- @args hydra.ppath: the path to the file with passwords. For example, 
--		 nmap --script hydra --script-args="ppath=/home/my_pass.txt" <target_ip>


author = "Olga Barinova"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"brute"}

portrule = shortport.port_or_service(
	{23, 80, 81, 443, 1433, 1521, 3306, 5432, 8000, 8080},
	{"http", "https", "postgresql", "mysql", "ms-sql-s", "telnet", 
	"oracle-tns", "oracle"}
	)

action = function (host, port)

	local str
	local s
	local arg
	local login = ''
	local pass = ''
	local task = ''
	local serv = port.service
	
	-- create table for nmap output
	local restab = tab.new(4)
	tab.addrow(restab, "path", "method", "login", "password")

	nmap.registry.args = {
		lpath = "login.txt",
		ppath = "password.txt"
	}

	local path_login = nmap.registry.args.lpath
	local path_passwd = nmap.registry.args.ppath

	-- dynamic update files
	local file_login = assert(io.open(path_login, "a+"))
	file_login:write(host.name .. "\n")
	file_login:close()
	local file_pass = assert(io.open(path_passwd, "a+"))
	file_pass:write(host.name .. "\n")
	file_pass:close()
	
	if (serv == "postgresql") then 
		serv = "postgres"
		task = " -t 4 "
	end

	if (serv == "telnet") then 
		serv = "cisco"
		task = " -t 1 "
	end

	if (serv == "ms-sql-s") then 
		serv = "mssql"
		task = " -t 4 "
	end
	
	if (serv == "mysql") then 
		task = " -t 4 "
	end
	
	if (serv == "ftp") then 
		task = " -t 4 "
	end
	

	if (port.state == "open") then
		if (serv == "oracle") or (serv == "oracle-tns") then 
			login = ''
			pass = ''
			task = " -t 1 "
			str= "hydra -L " .. path_login .. task .. " -e ns -s " .. port.number 
				.. " " .. host.ip .. " oracle-sid"
			local tmp = io.popen(str)
			s = tmp:read('*a')
			tmp:close()
			local login = string.match(s, 'login:%s([^%s]*)')
			if (login) then
				tab.addrow(restab, host.ip .. "/", "sid", login, pass)
			end	

			login = ''
			pass = ''
			str= "hydra -P " .. path_passwd .. " -e ns -m clear -s " 
				.. port.number .. " " .. host.ip .. " oracle-listener"
			local tmp = io.popen(str)
			s = tmp:read('*a')
			tmp:close()
			local pass = string.match(s, 'password:%s([^%s]*)')
			if (pass) then
				tab.addrow(
					restab, 
					host.ip .. "/", 
					"listener clear", 
					login, 
					pass
					)	
			end

			login = ''
			pass = ''
			str= "hydra -P " .. path_passwd .. " -e ns -m plain -s " 
				.. port.number .. " " .. host.ip .. " oracle-listener"
			local tmp = io.popen(str)
			s = tmp:read('*a')
			tmp:close()
			local pass = string.match(s, 'password:%s([^%s]*)')
			if (pass) then
				tab.addrow(
					restab, 
					host.ip .. "/", 
					"listener plain", 
					login, 
					pass
					)	
			end
		elseif (serv == "cisco") then 
			login = ''
			pass = ''
			str = "hydra -P " .. path_passwd .. task .. " -e ns -w 2 -s " 
				.. port.number .. " " .. host.ip .. " " .. serv 
			local tmp = io.popen(str)
			s = tmp:read('*a')
			tmp:close()
			local pass = string.match(s, 'password:%s([^%s]*)')
			if (pass) then
				tab.addrow(restab, host.ip .. "/", serv, login, pass)	
			end
		elseif (serv == "http") then
			login = ''
			pass = ''
			local t = {}
			local nmapstr = "nmap --script=http-auth-finder " .. host.ip
			local nmaptmp = io.popen(nmapstr)
			nmaps = nmaptmp:read('*a')
			nmaptmp:close()
			
			for _, path, type_auth in string.gmatch(
				nmaps, 
				'http://([^/]+)/([^%s]*)%s+HTTP:%s(%a+)'
				) do
				t[path] = type_auth
			end
			
			for path, type_auth in pairs(t) do
				arg = "/" .. path
				if (type_auth == "Digest") then 
					serv = "http-get" 
				end 
				if (type_auth == "Basic") then
					serv = "http-head" 
				end
				login = ''
				pass = ''			 
				str = "hydra -L " .. path_login .. " -P " .. path_passwd 
					.. " -e ns -s " .. port.number .. " " .. host.ip .. " " 
					.. serv .. " " .. arg
				local tmp = io.popen(str)
				s = tmp:read('*a')
				tmp:close()
				local login, pass = string.match(
					s, 'login:%s([^%s]*)%s+password:%s([^%s]*)'
					)
				if (login) and (pass) then
					tab.addrow(
						restab, 
						host.ip .. "/" .. path, 
						type_auth,
						login, 
						pass
						)	
				end
			end
		elseif (serv == "https") then
			login = ''
			pass = ''
			local t = {}
			local nmapstr = "nmap --script=http-auth-finder " .. host.ip
			local nmaptmp = io.popen(nmapstr)
			nmaps = nmaptmp:read('*a')
			nmaptmp:close()
			
			for _, path, type_auth in string.gmatch(
				nmaps, 'https://([^/]+)/([^%s]*)%s+HTTP:%s(%a+)'
				) do
				t[path] = type_auth
			end
			
			for path, type_auth in pairs(t) do
				arg = "/" .. path
				if (type_auth == "Digest") then 
					serv = "https-get" 
				end 
				if (type_auth == "Basic") then
					serv = "https-head" 
				end
				login = ''
				pass = ''
				str = "hydra -L " .. path_login .. " -P " .. path_passwd 
					.. " -e ns -s " .. port.number .. " " .. host.ip .. " " 
					.. serv .. " " .. arg
				local tmp = io.popen(str)
				s = tmp:read('*a')
				tmp:close()
				local login, pass = string.match(
					s, 'login:%s([^%s]*)%s+password:%s([^%s]*)'
					)
				if (login) and (pass) then
					tab.addrow(
						restab, 
						host.ip .. "/" .. path, 
						type_auth, 
						login, 
						pass
						)	
				end
			end
		else
			login = ''
			pass = ''
			str = "hydra -L " .. path_login .. " -P " .. path_passwd 
				.. task .. " -e ns -s " .. port.number .. " " .. host.ip .. " " 
				.. serv
			local tmp = io.popen(str)
			s = tmp:read('*a')
			tmp:close()
			local login, pass = string.match(
				s, 
				'login:%s([^%s]*)%s+password:%s([^%s]*)'
				)
			if (login) and (pass) then
				tab.addrow(restab, host.ip .. "/", serv, login, pass)	
			end
		end
	end

	if ( #restab > 1 ) then
		local result = { tab.dump(restab) }
		return stdnse.format_output(true, result)
	end
end

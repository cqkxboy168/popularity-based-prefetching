#!/usr/bin/env lua

hitf = "/tmp/dnsmasq-cachehit.out"
popf = "/tmp/dnsmasq-cachepop.out"
dumpf = "/tmp/dnsmasq-cachedump.out"
TIMEOUT = 2000 -- how many minutes before we flush out a domain
TOPNREFRESH = 50 -- how many domains to refresh
FREQ = 60 -- how frequently does script run (in s)


function pyprint(t, indent)
	if indent == nil then
		indent = ""
	end
	--_G.io.write(string.format("{"))
	for k,v in pairs(t) do
		if type(v) == 'table' then
			_G.io.write(string.format("%s: {",  k))
			pyprint(v, indent .. ' ')
			_G.io.write(string.format("}, " ))
		else
			_G.io.write(string.format("%s: %s, ", k, tostring(v)))
		end
	end
	--_G.io.write(string.format("}"))
end

function checkfiles()
-- Check to see if hits file exists. If not, exit
	local f,m
	f,m = io.open(hitf)
	if not f then
		io.output(hitf)
		--os.exit()
	end
	f,m = io.open(popf)
	if not f then
		io.output(popf)
	end
end

function get_higher(val, lines)
	local k,v
	for k,v in ipairs(lines) do
		if v["val"] == val then
			return k
		end
	end
	return nil
end

function readdumpfile()
	local f,m
	f,m = io.open(dumpf)
	if not f then
		os.exit()
	end
	io.input(dumpf)
	local u,w,x,y,z,line
	local cache = {}
	local lines = {}
	local addrs = {}
	--print("In readdump")
	local comp = {}
	for line in io.lines() do
		--print("full",line)
		for v,w,x,y,z in string.gmatch(line,"(%S+) (%S+) (%S+) (%S+) (%S+)") do
			comp = {}
			comp["dom"] = v
			comp["type"] = w
			comp["val"] = x
			comp["ttd"] = y
			comp["dtime"] = z
		end
		table.insert(lines,comp)
		if comp["type"]  == "addr" then
			if addrs[comp["dom"]] == nil then
				addrs[comp["dom"]] = comp["val"]
			end
		end
	end
	local hi,k,v
	for k,v in pairs(addrs) do
		local cnames = {}
		local addrs = {}
		local ttd = math.huge
		dname = v
		while 1 do
			hi = get_higher(dname,lines)
			if hi == nil then
				cache[dname] = {}
				cache[dname]["addr"] = addrs
				cache[dname]["cname"] = cnames
				cache[dname]["ttd"] = ttd
				break
			end
			if lines[hi]["type"] == "cname" then
				table.insert(cnames,lines[hi]["val"])
			end	
			if lines[hi]["type"] == "addr" then
				table.insert(addrs,lines[hi]["val"])
			end	
			if tonumber(lines[hi]["ttd"]) < ttd then
				ttd = tonumber(lines[hi]["ttd"])
			end
			dname = lines[hi]["dom"]
		end
	end
	print("In cache")
	for k,v in pairs(cache) do
		print(string.format("  %s",k))
	end
	print("\n")
	return cache
end


function readhitfile() 
-- Read hits file and parse each line
	io.input(hitf)
	local len = 1
	local arr = {}
	local x,y,z,line
	for line in io.lines() do
		arr[len] = {}
		for x,y,z,a in string.gmatch(line,"(%S+) (%S+) (%S+) (%S+)") do
			arr[len]["domain"] = x	
			arr[len]["type"] = y	
			arr[len]["val"] = z	
			arr[len]["time"] = tonumber(a)	
		end
		len = len + 1
	end
	return arr
end

function readpopfile()
	local names = {}
	local x,y,z
	io.input(popf)
	for line in io.lines() do
		for x,y,z in string.gmatch(line,"(%S+) (%S+) (%S+)") do
			names[x] = {}
			names[x]["cnt"] = tonumber(y)	
			names[x]["time"] = tonumber(z)
			names[x]["cnames"] = {}
			names[x]["addrs"] = {}
		end
	end
	print("Popfile")
	for k,v in pairs(names) do
		print(string.format("  %s %s",k,v["cnt"]))
	end
	print("\n")

	return names
end

function parsehits(hitnames)
-- Parse the hits array - remove redundancies with CNAMES and multiple addresses 
	local cnt = 1
	local names = {}
	local newhit = 0
	while hitnames[cnt] do
		local name = hitnames[cnt]["domain"]
		local cnames = {}
		local addrs = {}
		local lookfor = name
		local htime = math.huge
		if not names[name] then
			names[name] = {}
			names[name]["cnt"] = 0
			--names[name]["cnames"] = cnames
		end
		while hitnames[cnt] do
			if hitnames[cnt]["domain"] ~= lookfor then
				break
			end
			if hitnames[cnt-1] and (newhit == 0) then
				if hitnames[cnt-1]["time"] ~= hitnames[cnt]["time"] then
					newhit = 1
					break
				end
			end
			newhit = 0
			if hitnames[cnt]["type"] == "cname" then
				table.insert(cnames,hitnames[cnt]["val"])
				lookfor = hitnames[cnt]["val"]
			end
			if hitnames[cnt]["type"] == "addr" then
				table.insert(addrs,hitnames[cnt]["val"])
			end
			if hitnames[cnt]["time"] < htime then
				htime = hitnames[cnt]["time"]
			end
			names[name]["time"] = htime
			cnt = cnt + 1
		end
		--Unless there was an address for a domain, it isn't a hit
		if addrs[1] then
			names[name]["cnames"] = cnames
			names[name]["addrs"] = addrs
			names[name]["cnt"] = names[name]["cnt"] + 1
			--print("In parsehits",name,cnames[1],addrs[1])
		end
	end
	print("Parsehits")
	for k,v in pairs(names) do
		print(string.format("  hit for %s %s %s",k,v["cnt"],v["time"]))
	end
	--for k,v in pairs(hitnames) do
	--	print(k,v["cnt"])
	--end
	print("\n")
	return names
end

function updatepop(popnames,currnames)
	local k,v
	local tnames = {}
	-- update the popularity list with # of lookups since last check
	for k,v in pairs(currnames) do
		if popnames[k] then
			popnames[k]["cnt"] = popnames[k]["cnt"] + v["cnt"]
			popnames[k]["time"] = v["time"]
			popnames[k]["cnames"] = v["cnames"]
			popnames[k]["addrs"] = v["addrs"]
		else
			popnames[k] = v	
		end
	end

	local rcand = {}
	-- mark candidates for removal that have timed out; put those that haven't in tnames
	for k,v in pairs(popnames) do
		--print(os.time(),v["time"])
		if (os.time() - v["time"]) > TIMEOUT*60 then
			print("exp for",k,v["cnt"],v["time"])
			table.insert(rcand,k)
		else
			local t = {}
			t["cnt"] = v["cnt"]
			t["name"] = k
			table.insert(tnames,t)
		end
	end
	-- remove expired domains
	for k,v in ipairs(rcand) do
		popnames[v] = nil
		--print("rem candidates",v)
	end
	-- sort tnames according to popularity and cut off bottom last-but-TOPNREFRESH
	table.sort(tnames,function(a,b) return a["cnt"]>b["cnt"] end)
	local lentab = math.min(#tnames,TOPNREFRESH)
	for k = lentab+1,#tnames do
		--print(lentab+1,tnames[lentab+1]["name"])
		--print(tnames[k]["cnt"],tnames[k]["name"])
		table.remove(tnames,lentab+1)
	end
	print("Updated pop list")
	for k,v in pairs(popnames) do
		print(string.format("  pop for %s %s",k,v["cnt"],v["time"]))
	end
	print("\n")

	return popnames,tnames
end

function expired(cache,names,name)
	if not cache[name] then
		print(string.format("  %s not in cache, needs resolving",name))
		return 1
	end
	local ttd = cache[name]["ttd"]

	if (ttd - os.time()) > 0 then
		print(string.format("  %s does not need resolving, expiring at %s (now time %s),in %s seconds",name,cache[name]["ttd"],os.time(),ttd - os.time()))
		return nil
	else
		print(string.format("  %s needs resolving, expired at %s (now time %s), %s seconds ago",name,cache[name]["ttd"],os.time(),os.time() - ttd))
		return 1
	end
end

function resolve(name)
	print(string.format("  %s %s resolving %s",os.date(),os.time(),name))
	local fp = io.open("/etc/config/network","r")
	if fp == nil then
		os.execute(string.format("dig @localhost %s >> /tmp/dnsmasqdig.out",name))
	else
		os.execute(string.format("nslookup %s >> /tmp/dnsmasqnslookup.out",name))
	end	
	os.execute(string.format("echo -n '' > %s",hitf))
end

function dnsrefresh(names,tnames)
	local k,v
	local k1,v1
	local fp = io.open("/etc/config/network","r")
	if fp == nil then
		os.execute("/home/srikanth/research/lip6/bismark/webtool/scripts/killdmasq")
		print("AS")
	else
		os.execute("/usr/sbin/killdmasq")
		io.close(fp)
	end	
	print("\n")
	os.execute("sleep 1")
	cache = readdumpfile()
	print("Checking TTLs")
	for k,v in ipairs(tnames) do
		local name = v["name"]
		local cont = 0
		if expired(cache,names,name) then
			--print("Checking for",name)
			resolve(name)
			cont = 1	
		end
	end
	print("\n")
end

function dumppop(names)
	io.output(popf)
	print("New popularity file")
	for k,v in pairs(names) do
		io.write(string.format("%s %d %d\n",k,v["cnt"],v["time"]))
		print(string.format("  %s %d %d",k,v["cnt"],v["time"]))
	end	
	print("\n")
end

function main()
	local k,v
	checkfiles()
	local hitnames = readhitfile()
	print("Hitfile")
	--for k,v in ipairs(hitnames) do
	--	print(k,v["domain"])
	--end

	local popnames = readpopfile()

	hitnames = parsehits(hitnames)

	local tnames
	print("Updating pop list")
	popnames,tnames = updatepop(popnames,hitnames)

	--print("New Refresh list")
	dnsrefresh(popnames,tnames)
	--connrefresh(tnames)
	dumppop(popnames)
end

main()

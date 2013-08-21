#!/usr/bin/env lua

hitf = "/tmp/polipo-sites.out"
popf = "/tmp/polipo-connpop.out"
TIMEOUT = 2000 -- how many minutes before we flush out a domain
TOPNREFRESH = 25 -- how many domains to refresh
FREQ = 60 -- how frequently does script run (in s)
WEBPROXY = "localhost:9119"
WEBRUBBISH = "daxasxasdasd"


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

function readhitfile() 
-- Read hits file and parse each line
	io.input(hitf)
	local len = 1
	local arr = {}
	local x,y,line
	for line in io.lines() do
		arr[len] = {}
		for x,y in string.gmatch(line,"(%S+) (%S+)") do
			arr[len]["domain"] = x	
			arr[len]["time"] = tonumber(y)	
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
-- Parse the hits array 
	local cnt = 1
	local names = {}
	local newhit = 0
	while hitnames[cnt] do
		local name = hitnames[cnt]["domain"]
		local htime = math.huge
		if not names[name] then
			names[name] = {}
			names[name]["cnt"] = 1
			--names[name]["cnames"] = cnames
		else
			names[name]["cnt"] = names[name]["cnt"] + 1
		end
		if hitnames[cnt]["time"] < htime then
			htime = hitnames[cnt]["time"]
		end
		names[name]["time"] = htime
		cnt = cnt + 1
	end
	print("Parsehits")
	for k,v in pairs(names) do
		print(string.format("  hit for %s %s %s",k,v["cnt"],v["time"]))
	end
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
		else
			popnames[k] = v	
		end
	end

	for k,v in pairs(popnames) do
		print("pop for ",k,v["cnt"],v["time"])
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
		table.remove(tnames,lentab+1)
	end

	print("Updated pop list")
	for k,v in pairs(popnames) do
		print(string.format("  pop for %s %s",k,v["cnt"],v["time"]))
	end
	print("\n")

	return popnames,tnames
end

function connrefresh(names)
	for k,v in ipairs(names) do
		print("refreshing name %s",v["name"])
		os.execute(string.format("http_proxy=%s wget --quiet -O /dev/null %s/%s",WEBPROXY,v["name"],WEBRUBBISH))
	end
	os.execute(string.format("echo -n '' > %s",hitf))
end

function dumppop(names)
	io.output(popf)
	for k,v in pairs(names) do
		io.write(string.format("%s %d %d\n",k,v["cnt"],v["time"]))
	end	
end

function main()
	local k,v
	checkfiles()
	local hitnames = readhitfile()
	local popnames = readpopfile()

	hitnames = parsehits(hitnames)

	local tnames
	popnames,tnames = updatepop(popnames,hitnames)

	connrefresh(tnames)
	dumppop(popnames)
end

main()

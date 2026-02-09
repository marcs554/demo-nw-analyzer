local tap = Listener.new(nil)

function tap.packet(pinfo, tvb)
	print(os.date("%H:%M:%S") .. " → " .. tostring(pinfo.src) .. " → " .. tostring(pinfo.dst))
end

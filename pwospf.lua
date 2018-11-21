PWOSPF = Proto("PWOSPF", "PWOSPF Protocol Header")
-- PWOSPF_HELLO = Proto("PWOSPF_HELLO", "PWOSPF Hello")
-- PWOSPF_UPDATE = Proto("PWOSPF_UPDATE", "PWOSPF Update")


-- utils
function getTypeName(code)
  if code == 1 then
    return 'HELLO'
  elseif code == 4 then
    return 'UPDATE'
  else
    return 'UNKNOWN'
  end
end

-- the following 2 functions credit to
-- https://stackoverflow.com/questions/8200228/how-can-i-convert-an-ip-address-into-an-integer-with-lua
function ip2dec(ip)
  local i, dec = 3, 0
  for d in string.gmatch(ip, "%d+") do
    dec = dec + 2 ^ (8 * i) * d
    i = i - 1
  end
  return dec
end

function dec2ip(decip)
  local divisor, quotient, ip
  for i = 3, 0, -1 do
    divisor = 2 ^ (i * 8)
    quotient, decip = math.floor(decip / divisor), math.fmod(decip, divisor)
    if nil == ip then
      ip = quotient
    else
      ip = ip .. "." .. quotient
    end
  end
  return ip
end



-- protocol methods
function PWOSPF.init()
  -- l = DissectorTable.list()
  -- for k in pairs(l) do
  --   print(l[k])
  -- end
end


local f = PWOSPF.fields
f.version = ProtoField.uint8("PWOSPF.version", "version")
f.type = ProtoField.uint8("PWOSPF.type", "type")
f.length = ProtoField.uint16("PWOSPF.length", "length")
f.router_id = ProtoField.ipv4("PWOSPF.routerid", "router_id")
f.area_id = ProtoField.uint32("PWOSPF.areaid", "area_id")
f.checksum = ProtoField.uint16("PWOSPF.checksum", "checksum")
f.autype = ProtoField.uint16("PWOSPF.autype", "autype")
f.authentication = ProtoField.bytes("PWOSPF.authentication", "authentication", base.HEX) --8bytes
--hello specific fields
f.mask = ProtoField.ipv4("PWOSPF.mask", "mask")
f.hello_int = ProtoField.uint16("PWOSPF.helloint", "hello_int")
f.padding = ProtoField.bytes("PWOSPF.padding", "padding", base.HEX)

--update specific
f.seq = ProtoField.uint16("PWOSPF.seq", "seq")
f.ttl = ProtoField.uint16("PWOSPF.ttl", "ttl")
f.ad_count = ProtoField.uint32("PWOSPF.adcount", "ad_count")
--advertisement fields
f.ad_subnet = ProtoField.ipv4("PWOSPF.adsubnet", "ad_subnet")
f.ad_mask = ProtoField.ipv4("PWOSPF.admask", "ad_mask")
f.ad_rounter_id = ProtoField.ipv4("PWOSPF.adrounterid", "ad_rounter_id")


function PWOSPF.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = PWOSPF.name
  local headerTree = tree:add(PWOSPF, buffer(0, 24))
  
  local offset = 0
  local len = 1
  local version = buffer(offset, len)
  headerTree:add(f.version, version)
  offset = offset + len

  len = 1
  local type0 = buffer(offset, len)
  local typeName = getTypeName(type0:uint())
  headerTree:add(f.type, type0):append_text(' ('.. typeName ..')')
  offset = offset + len

  len = 2
  local length = buffer(offset, len)
  headerTree:add(f.length, length)
  offset = offset + len

  len = 4
  local router_id = buffer(offset, len)
  headerTree:add(f.router_id, router_id)
  offset = offset + len

  len = 4
  local area_id = buffer(offset, len)
  headerTree:add(f.area_id, area_id)
  offset = offset + len

  len = 2
  local checksum = buffer(offset, len)
  headerTree:add(f.checksum, checksum)
  offset = offset + len

  len = 2
  local autype = buffer(offset, len)
  headerTree:add(f.autype, autype)
  offset = offset + len

  len = 8
  local authentication = buffer(offset, len)
  headerTree:add(f.authentication, authentication)
  offset = offset + len

------------------------------------------
  if typeName == 'HELLO' then
    local bodyTree = tree:add(PWOSPF, buffer(offset, 8))

    bodyTree:set_text('PWOSPF Hello, ')
    local info = "Hello from " .. dec2ip(router_id:uint())
    pinfo.cols.info = info
    headerTree:append_text(', ' .. info)

    len = 4
    local mask = buffer(offset, len)
    bodyTree:add(f.mask, mask)
    offset = offset + len

    len = 2
    local hello_int = buffer(offset, len)
    bodyTree:add(f.hello_int, hello_int)
    offset = offset + len
    bodyTree:append_text('interval: ' .. tostring(hello_int:uint()) .. ' sec(s)')

    len = 2
    local padding = buffer(offset, len)
    bodyTree:add(f.padding, padding)
    offset = offset + len

------------------------------------------
  elseif typeName == 'UPDATE' then
    local offset0 = offset
    local info = "Update from " .. dec2ip(router_id:uint())
    pinfo.cols.info = info
    headerTree:append_text(', ' .. info)

    len = 2
    local seq = buffer(offset, len)
    offset = offset + len

    len = 2
    local ttl = buffer(offset, len)
    offset = offset + len

    len = 4
    local ad_count = buffer(offset, len)
    offset = offset + len
    
    local bodyTree = tree:add(PWOSPF, buffer(offset0, 8+ad_count:uint()*12))
    bodyTree:set_text('PWOSPF Update, ')
    bodyTree:add(f.seq, seq)
    bodyTree:append_text('seq: ' .. tostring(seq:uint()) .. ' ')
    bodyTree:add(f.ttl, ttl)
    bodyTree:append_text('ttl: ' .. tostring(ttl:uint()) .. ' ')
    bodyTree:add(f.ad_count, ad_count)
    bodyTree:append_text('ad_count: ' .. tostring(ad_count:uint()) .. ' ')

    for i=1,ad_count:uint() do
        local adTree = bodyTree:add(PWOSPF, buffer(offset, 12))
        adTree:set_text('advertisement')
        len = 4
        local ad_subnet = buffer(offset, len)
        adTree:add(f.ad_subnet, ad_subnet)
        offset = offset + len

        len = 4
        local ad_mask = buffer(offset, len)
        adTree:add(f.ad_mask, ad_mask)
        offset = offset + len

        len = 4
        local ad_rounter_id = buffer(offset, len)
        adTree:add(f.ad_rounter_id, ad_rounter_id)
        offset = offset + len

    end

  end



end

dt = DissectorTable.get("ip.proto")
dt:add(89, PWOSPF)
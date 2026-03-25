local m, s, o
local api = "http://127.0.0.1:8099"
local nixio = require "nixio"
local http  = require "luci.http"
local sys   = require "luci.sys"

local function get_state()
    local result = sys.exec("curl -sf --max-time 3 " .. api .. "/v1/enrollment/state 2>/dev/null")
    if result and #result > 0 then
        local ok, data = pcall(function() return require("luci.jsonc").parse(result) end)
        if ok and data then return data end
    end
    return { enrolled = false, node_id = "unknown" }
end

local function get_token()
    local result = sys.exec("curl -sf --max-time 3 " .. api .. "/v1/enrollment/token 2>/dev/null")
    if result and #result > 0 then
        local ok, data = pcall(function() return require("luci.jsonc").parse(result) end)
        if ok and data and data.token then return data.token end
    end
    return nil
end

local state = get_state()
m = Map("safeswitch", translate("SafeSwitch Setup"))
m.title = translate("SafeSwitch - Family Network Protection")

s = m:section(TypedSection, "safeswitch", translate("Node Status"))
s.anonymous = true
s.addremove = false

if state.enrolled then
    o = s:option(DummyValue, "_enrolled", translate("Status"))
    o.rawhtml = true
    o.cfgvalue = function() return '<span style="color:#4caf50;font-weight:bold">Enrolled</span>' end
    o = s:option(DummyValue, "_family", translate("Family ID"))
    o.cfgvalue = function() return state.family_id or "-" end
    o = s:option(DummyValue, "_node", translate("Node ID"))
    o.cfgvalue = function() return state.node_id or "-" end
else
    o = s:option(DummyValue, "_enrolled", translate("Status"))
    o.rawhtml = true
    o.cfgvalue = function() return '<span style="color:#ff9800;font-weight:bold">Not enrolled</span>' end

    local token = get_token()
    if token then
        s2 = m:section(TypedSection, "safeswitch", translate("Step 1 - Claim Token"))
        s2.anonymous = true
        s2.addremove = false
        o = s2:option(DummyValue, "_token_hint", "")
        o.rawhtml = true
        o.cfgvalue = function()
            return '<p>Open the SafeSwitch parent app, tap <strong>Add Node</strong>, and enter:</p>'
                .. '<div style="font-family:monospace;font-size:1.6em;font-weight:bold;background:#1a1a2e;color:#00c8ff;padding:14px 20px;border-radius:8px;display:inline-block">'
                .. token .. '</div>'
        end
    end

    s3 = m:section(TypedSection, "safeswitch", translate("Step 2 - Connect to Family"))
    s3.anonymous = true
    s3.addremove = false
    o = s3:option(Value, "claim_token", translate("Family Code"))
    o.placeholder = "anchor-falcon-river"
    o.rmempty = false
    o = s3:option(Value, "family_id", translate("Family ID (optional)"))
    o.rmempty = true
end

s4 = m:section(TypedSection, "safeswitch", translate("Service"))
s4.anonymous = true
s4.addremove = false
o = s4:option(DummyValue, "_svc_status", translate("ss-router service"))
o.rawhtml = true
o.cfgvalue = function()
    local running = sys.exec("pgrep -x safeswitch-node >/dev/null 2>&1 && echo 1 || echo 0")
    if running and running:match("^1") then
        return '<span style="color:#4caf50">Running</span>'
    end
    return '<span style="color:#f44336">Stopped</span>'
end

function m.on_commit(map)
    local token    = http.formvalue("cbid.safeswitch._safeswitch.claim_token")
    local familyID = http.formvalue("cbid.safeswitch._safeswitch.family_id") or ""
    if not token or #token == 0 then return end
    local payload = string.format('{"claim_token":"%s","family_id":"%s"}', token, familyID)
    local result = sys.exec(string.format(
        "curl -sf --max-time 10 -X POST -H 'Content-Type: application/json' -d '%s' %s/v1/enroll 2>&1",
        payload, api
    ))
    if result and result:match('"enrolled":true') then
        m.message = translate("Successfully enrolled.")
    else
        m.errmessage = translate("Enrollment failed. Check the family code and try again.")
    end
end

return m

module("luci.controller.safeswitch", package.seeall)

function index()
    if not nixio.fs.access("/usr/bin/safeswitch-node") then
        return
    end
    local e = entry({"admin","services","safeswitch"}, firstchild(), _("SafeSwitch"), 60)
    e.dependent = false
    entry({"admin","services","safeswitch","setup"}, form("safeswitch"), _("Setup"), 10).leaf = true
    entry({"admin","services","safeswitch","status"}, template("safeswitch/status"), _("Status"), 20).leaf = true
end

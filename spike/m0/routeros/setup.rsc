# tikray M0 spike: RouterOS side of the data path (throwaway).
# Every object is commented tikray:<name>.
#
# Inputs, as globals set before /import (defaults are the lab's values):
#   tikrayLanClient  device to proxy (smart policy, kill switch off)
#   tikrayWanIf      WAN interface
#   tikrayWanGw      WAN gateway (fallback route of tikray-open)
#   tikrayArch       image architecture: amd64 or arm64
#   tikrayApiPass    password for the restricted tikray RouterOS user
#   tikrayXrayVersion xray release in disk1/tikray/data/cores/<version>/xray
#
# Differences found on RouterOS 7.25 vs. the plan:
#   - container mounts take list= (not name=) and mode=ro|rw; containers use mountlists=
#   - a container won't start without DNS, so each container sets dns=
#   - files placed by /tool/fetch have no execute bit; the runner stages xray itself

:global tikrayLanClient
:global tikrayWanIf
:global tikrayWanGw
:global tikrayArch
:global tikrayApiPass
:global tikrayXrayVersion
:if ([:typeof $tikrayLanClient] = "nothing") do={ :set tikrayLanClient "192.168.88.10" }
:if ([:typeof $tikrayWanIf] = "nothing") do={ :set tikrayWanIf "ether1" }
:if ([:typeof $tikrayWanGw] = "nothing") do={ :set tikrayWanGw "198.51.100.254" }
:if ([:typeof $tikrayArch] = "nothing") do={ :set tikrayArch "amd64" }
:if ([:typeof $tikrayApiPass] = "nothing") do={ :set tikrayApiPass "tikray-lab-api" }
:if ([:typeof $tikrayXrayVersion] = "nothing") do={ :set tikrayXrayVersion "26.3.27" }

# Bridge and veths: router .1, control .2, runner .3
/interface/bridge/add name=tikray comment=tikray:bridge
/interface/veth/add name=tikray-runner address=172.31.255.3/29 gateway=172.31.255.1 comment=tikray:veth-runner
/interface/veth/add name=tikray-ctl address=172.31.255.2/29 gateway=172.31.255.1 comment=tikray:veth-ctl
/interface/bridge/port/add bridge=tikray interface=tikray-runner comment=tikray:port-runner
/interface/bridge/port/add bridge=tikray interface=tikray-ctl comment=tikray:port-ctl
/ip/address/add address=172.31.255.1/29 interface=tikray comment=tikray:addr
/ip/firewall/nat/add chain=srcnat src-address=172.31.255.0/29 out-interface=$tikrayWanIf action=masquerade comment=tikray:nat-containers

# Address lists
:foreach a in={"10.0.0.0/8";"172.16.0.0/12";"192.168.0.0/16";"100.64.0.0/10";"127.0.0.0/8";"169.254.0.0/16";"224.0.0.0/4"} do={
  /ip/firewall/address-list/add list=tikray-local address=$a comment=tikray:local
}
/ip/firewall/address-list/add list=tikray-domestic address=203.0.113.20/32 comment=tikray:domestic
/ip/firewall/address-list/add list=tikray-src-smart-open address=$tikrayLanClient comment=tikray:src

# Routing tables: primary via the runner, fallback WAN (open) or blackhole (closed)
/routing/table/add name=tikray-open fib comment=tikray:table-open
/routing/table/add name=tikray-closed fib comment=tikray:table-closed
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.255.3 routing-table=tikray-open distance=1 check-gateway=ping comment=tikray:route-open-runner
/ip/route/add dst-address=0.0.0.0/0 gateway=$tikrayWanGw routing-table=tikray-open distance=2 comment=tikray:route-open-fallback
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.255.3 routing-table=tikray-closed distance=1 check-gateway=ping comment=tikray:route-closed-runner
/ip/route/add dst-address=0.0.0.0/0 blackhole routing-table=tikray-closed distance=2 comment=tikray:route-closed-blackhole

# Mangle, in tikray's own chain behind one jump
/ip/firewall/mangle/add chain=prerouting action=jump jump-target=tikray-pre comment=tikray:jump-pre
# Packets addressed to the router itself are never routed by tikray. This also
# catches replies of masqueraded (fallen-back) connections, which reach mangle
# prerouting before NAT is undone with the WAN address as destination: without
# it they would get the routing mark and go back out the WAN (M0 F14).
/ip/firewall/mangle/add chain=tikray-pre dst-address-type=local action=return comment=tikray:skip-router
/ip/firewall/mangle/add chain=tikray-pre dst-address-list=tikray-local action=return comment=tikray:skip-local
/ip/firewall/mangle/add chain=tikray-pre dst-address-list=tikray-domestic action=return comment=tikray:skip-domestic
/ip/firewall/mangle/add chain=tikray-pre src-address-list=tikray-src-smart-open connection-mark=no-mark action=mark-connection new-connection-mark=tikray-open passthrough=yes comment=tikray:conn-open
/ip/firewall/mangle/add chain=tikray-pre src-address-list=tikray-src-smart-closed connection-mark=no-mark action=mark-connection new-connection-mark=tikray-closed passthrough=yes comment=tikray:conn-closed
# Routing follows the connection mark alone, so a connection keeps one path for
# its whole life, even when its device changes policy (tikray's reconciler then
# removes that device's tracked connections so the new policy applies at once).
/ip/firewall/mangle/add chain=tikray-pre connection-mark=tikray-open action=mark-routing new-routing-mark=tikray-open passthrough=no comment=tikray:route-open
/ip/firewall/mangle/add chain=tikray-pre connection-mark=tikray-closed action=mark-routing new-routing-mark=tikray-closed passthrough=no comment=tikray:route-closed
/ip/firewall/mangle/add chain=forward protocol=tcp tcp-flags=syn connection-mark=tikray-open action=change-mss new-mss=clamp-to-pmtu passthrough=yes comment=tikray:mss-open
/ip/firewall/mangle/add chain=forward protocol=tcp tcp-flags=syn connection-mark=tikray-closed action=change-mss new-mss=clamp-to-pmtu passthrough=yes comment=tikray:mss-closed

# Keep marked connections off FastTrack: accept them before the user's FastTrack rule
# (one block: /import runs each top-level line on its own, so a :local set on
# one line is gone on the next)
{
  :local ft [/ip/firewall/filter/find where action=fasttrack-connection]
  :if ([:len $ft] > 0) do={
    /ip/firewall/filter/add chain=forward connection-mark=tikray-open action=accept place-before=[:pick $ft 0] comment=tikray:no-fasttrack-open
    /ip/firewall/filter/add chain=forward connection-mark=tikray-closed action=accept place-before=[:pick $ft 0] comment=tikray:no-fasttrack-closed
  }
}

# DNS from proxied devices goes to xray in the runner
:foreach k in={"open";"closed"} do={
  :foreach p in={"udp";"tcp"} do={
    /ip/firewall/nat/add chain=dstnat src-address-list=("tikray-src-smart-" . $k) protocol=$p dst-port=53 action=dst-nat to-addresses=172.31.255.3 to-ports=53 comment=("tikray:dns-" . $k . "-" . $p)
  }
}
# While the runner is down, fail-open devices fall back to the router's own DNS
# (their routes fall back via check-gateway); kill-switch devices keep pointing
# at the runner and get no answers. Netwatch runs on RouterOS, without tikray.
# Its default startup-delay (5m) would leave DNS pointing at a dead runner for
# the first minutes after every boot.
/tool/netwatch/add host=172.31.255.3 interval=5s timeout=1s startup-delay=0s comment=tikray:runner-watch up-script="/ip/firewall/nat/enable [find where comment~\"tikray:dns-open\"]" down-script="/ip/firewall/nat/disable [find where comment~\"tikray:dns-open\"]"

# Restricted RouterOS user for the control plane, API-SSL only from its IP
/user/group/add name=tikray policy=read,write,api comment=tikray:group
/user/add name=tikray group=tikray password=$tikrayApiPass address=172.31.255.2/32 comment=tikray:user
/certificate/add name=tikray-api common-name=tikray-api key-size=prime256v1 days-valid=3650
/certificate/sign tikray-api
/ip/service/set api-ssl certificate=tikray-api disabled=no

# Containers from image files on disk1
/container/mounts/add list=tikray-runner src=disk1/tikray/data/run dst=/data/run mode=rw comment=tikray:mount-runner-run
/container/mounts/add list=tikray-runner src=disk1/tikray/data/cores dst=/data/cores mode=ro comment=tikray:mount-runner-cores
/container/mounts/add list=tikray-ctl src=disk1/tikray/data/run dst=/data/run mode=rw comment=tikray:mount-ctl-run
/container/mounts/add list=tikray-ctl src=disk1/tikray/data/cores dst=/data/cores mode=rw comment=tikray:mount-ctl-cores
/container/envs/add list=tikray-runner key=XRAY_BIN value=("/data/cores/" . $tikrayXrayVersion . "/xray") comment=tikray:env-xray-bin
/container/add name=tikray-runner file=("disk1/tikray/images/runnerproto-" . $tikrayArch . ".tar") interface=tikray-runner root-dir=disk1/tikray/containers/runner mountlists=tikray-runner envlists=tikray-runner dns=172.31.255.1 logging=yes start-on-boot=yes comment=tikray:runner
/container/add name=tikray-ctl file=("disk1/tikray/images/ctlproto-" . $tikrayArch . ".tar") interface=tikray-ctl root-dir=disk1/tikray/containers/ctl mountlists=tikray-ctl dns=172.31.255.1 logging=yes start-on-boot=yes comment=tikray:ctl

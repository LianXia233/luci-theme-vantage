# Roadmap

Ideas and planned work, roughly in priority order. Nothing here is
promised; issues and pull requests for any of it are welcome.

## Next

### Multiple access points (planned for 1.1)

Show the radios, SSIDs and clients of other OpenWrt access points on the
main dashboard, so a router without Wi-Fi still shows the whole network
(idea from [#5](https://github.com/anothaDev/luci-theme-vantage/pull/5)
by @nhAsif). Design: each peer runs `luci-app-vantage` with a dedicated
rpcd login limited to one read-only method; peer credentials live in a
config the dashboard can't read; a background poller on the main router
fetches peers over HTTPS with a pinned certificate and caches the result,
so an offline peer never slows down LuCI.

### Search for clients, radios and networks (Ctrl+K)

The command palette searches pages only. The dashboard already knows every
client, radio, SSID and interface; it should register them with the
palette so that typing a name, MAC, IP or SSID jumps straight to it:

- clients by alias, resolved name, MAC or IP, opening the client inspector
  (`#client=<mac>`);
- radios by band, channel or name, opening the radio inspector
  (`#radio=<name>`);
- SSIDs, opening the dashboard filtered to that network;
- interfaces, opening their LuCI page.

The theme must keep working without the app, so the palette needs a small,
optional provider API (the app registers a provider if the theme is
present) and results must be built as text nodes like everything else.

## Later

- **Tunnels and proxies in the network path:** show active tunnel
  interfaces (TUN, WireGuard, OpenVPN) between the device and the
  internet with their live rates, and name known proxy suites (OpenClash,
  PassWall, Mihomo, sing-box) with their running state, from a small
  table of service names. Needs one read-only ACL addition (the list of
  running services). Suite internals (nodes, rules) stay in their own
  pages for now; reading them would mean API secrets and HTTP calls from
  rpcd ([#7](https://github.com/anothaDev/luci-theme-vantage/issues/7)).
- **One-click actions (v2):** restart a radio, disconnect or block a
  client, enable or disable an SSID. Each action gets its own narrow ACL
  group and a confirmation; the read-only dashboard stays the default.
- **Client names from DHCP:** a small service on the device that watches
  DHCP requests crossing the bridge and records the hostnames clients
  send. This is the only automatic name source that works on an access
  point that is not the DHCP server.
- **History and alerts:** an optional rpcd plugin that keeps a small ring
  buffer (signal, throughput, client counts) so charts survive a page
  reload, plus simple alerts (uplink down, client with weak signal for
  minutes).
- **Topology view:** gateway, access points and switches from LLDP and
  neighbour tables, not just the local path.
- **luci-app-statistics integration:** show collectd history in the
  dashboard when it is installed.
- **OpenWrt 24.10 packages:** 1.0.7 fixes the differences found so far
  (`docs/luci-contract.md` §9). Still to do: `.ipk` files in each release, a
  signed 24.10 repository, a full install with opkg upgrades and removal,
  and a check of the Wi-Fi pages on 24.10.
- **Firewall overview, sets from services:** read the sets services define
  (the data fw4 reads from them), so that a service defining a set under the
  same name as the firewall config gives "can't tell" instead of the
  config's reading (a known limit in 1.0.7, see `docs/SPEC.md`).

## Upstream

- **LuCI core `L.env` on anonymous 404 pages:** LuCI's core `header.ut`
  prints the whole menu tree for visitors who are not logged in (see
  `SECURITY.md` and `docs/luci-contract.md`). A small patch to print only
  the fields `luci.js` uses would fix it for every theme.

set -eu
[ "$(uname -s)" = Linux ]
command -v ip >/dev/null
if [ -d /run/systemd/system ]; then
    attempt=0
    until systemctl daemon-reload 2>/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 60 ] || { printf 'systemd did not become ready\n' >&2; exit 1; }
        sleep 1
    done
fi
mac=$1
address=$2
gateway=$3
onlink=$4
dns=$5
mtu=$6
interface=
for path in /sys/class/net/*; do
    if [ "$(cat "$path/address")" = "$mac" ]; then interface=${path##*/}; break; fi
done
[ -n "$interface" ]
mkdir -p /etc/wings /usr/local/sbin
printf 'mac=%s\naddress=%s\ngateway=%s\nonlink=%s\nmtu=%s\n' "$mac" "$address" "$gateway" "$onlink" "$mtu" > /etc/wings/external-network
printf "dns='%s'\n" "$dns" >> /etc/wings/external-network
chmod 600 /etc/wings/external-network
cat > /usr/local/sbin/wings-external-network <<'APPLY'
#!/bin/sh
set -eu
. /etc/wings/external-network
interface=
for path in /sys/class/net/*; do
    if [ "$(cat "$path/address")" = "$mac" ]; then interface=${path##*/}; break; fi
done
[ -n "$interface" ]
ip link set dev "$interface" up
if [ -n "$mtu" ]; then ip link set dev "$interface" mtu "$mtu"; fi
if ! ip -4 -o address show dev "$interface" | awk '{print $4}' | grep -Fxq "$address"; then
    ip -4 address flush dev "$interface" scope global
    ip -4 address add "$address" dev "$interface"
fi
if [ "$onlink" = true ]; then
    ip -4 route replace default via "$gateway" dev "$interface" onlink
else
    ip -4 route replace default via "$gateway" dev "$interface"
fi
if command -v resolvectl >/dev/null && resolvectl status >/dev/null 2>&1; then
    resolvectl dns "$interface" $dns
    resolvectl domain "$interface" '~.'
else
    temporary=$(mktemp)
    for server in $dns; do printf 'nameserver %s\n' "$server"; done > "$temporary"
    cat "$temporary" > /etc/resolv.conf
    rm "$temporary"
fi
APPLY
chmod 755 /usr/local/sbin/wings-external-network
if command -v nmcli >/dev/null && nmcli general status >/dev/null 2>&1; then
    if ! nmcli connection show wings-external >/dev/null 2>&1; then
        nmcli connection add type ethernet con-name wings-external ifname "$interface" 802-3-ethernet.mac-address "$mac" >/dev/null
    fi
    nmcli connection modify wings-external ipv4.method manual ipv4.addresses "$address" ipv4.dns "$dns" ipv6.method disabled connection.autoconnect yes connection.autoconnect-priority 999
    if [ "$onlink" = false ]; then nmcli connection modify wings-external ipv4.gateway "$gateway"; fi
    nmcli device set "$interface" managed yes
    nmcli connection up wings-external >/dev/null
fi
if [ -d /etc/systemd/network ]; then
    {
        printf '[Match]\nMACAddress=%s\n[Network]\nDHCP=no\nAddress=%s\n' "$mac" "$address"
        for server in $dns; do printf 'DNS=%s\n' "$server"; done
        printf '[Route]\nDestination=0.0.0.0/0\nGateway=%s\nGatewayOnLink=%s\n' "$gateway" "$onlink"
    } > /etc/systemd/network/00-wings-external.network
    if command -v networkctl >/dev/null && systemctl is-active --quiet systemd-networkd; then
        networkctl reload
        networkctl reconfigure "$interface"
    fi
fi
if [ -f /etc/network/interfaces ]; then
    stopped=false
    mkdir -p /etc/wings/network-original
    chmod 700 /etc/wings/network-original
    for file in /etc/network/interfaces /etc/network/interfaces.d/*; do
        [ -f "$file" ] || continue
        case "$file" in *.wings-original|*/wings-external) continue;; esac
        if awk -v nic="$interface" '$1 == "iface" && $2 == nic && $3 == "inet" { found = 1 } END { exit !found }' "$file"; then
            if [ "$stopped" = false ] && command -v ifdown >/dev/null; then
                ifdown -f "$interface" >/dev/null 2>&1 || true
                stopped=true
            fi
            backup="/etc/wings/network-original$file"
            mkdir -p "${backup%/*}"
            [ -f "$backup" ] || cp -p "$file" "$backup"
            awk -v nic="$interface" '
                /^iface[ \t]/ { skip = ($2 == nic && $3 == "inet") }
                /^(auto|allow-hotplug|source|mapping)[ \t]/ { skip = 0 }
                !skip { print }
            ' "$file" > "$file.wings-new"
            cat "$file.wings-new" > "$file"
            rm "$file.wings-new"
        fi
    done
    mkdir -p /etc/network/interfaces.d
    if ! grep -Eq '^source(-directory)?[[:space:]]+/etc/network/interfaces.d' /etc/network/interfaces; then
        printf '\nsource /etc/network/interfaces.d/wings-external\n' >> /etc/network/interfaces
    fi
    printf 'auto %s\niface %s inet manual\n    post-up /usr/local/sbin/wings-external-network\n' "$interface" "$interface" > /etc/network/interfaces.d/wings-external
fi
if [ -d /run/systemd/system ]; then
    cat > /etc/systemd/system/wings-external-network.service <<'UNIT'
[Unit]
Description=Wings external IPv4 network
After=network-online.target systemd-networkd.service NetworkManager.service networking.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wings-external-network
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
    attempt=0
    until systemctl daemon-reload 2>/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 30 ] || { printf 'systemd did not become ready\n' >&2; exit 1; }
        sleep 1
    done
    systemctl enable wings-external-network.service >/dev/null
elif command -v rc-update >/dev/null; then
    mkdir -p /etc/local.d
    printf '#!/bin/sh\nexec /usr/local/sbin/wings-external-network\n' > /etc/local.d/wings-external.start
    chmod 755 /etc/local.d/wings-external.start
    rc-update add local default
else
    printf 'Unsupported init system: systemd or OpenRC is required\n' >&2
    exit 1
fi
/usr/local/sbin/wings-external-network

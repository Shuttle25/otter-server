#!/usr/bin/env bash
# Read-only hardening report for one node; run as root (deploy/harden-check.sh streams it over SSH, or
# /usr/local/lib/otter/harden-report.sh on the node). Prints "PASS|WARN|FAIL check: detail" (D120).
# It changes nothing on the host: it only reads files and asks commands for their state. Fixes are separate,
# hand-made steps, each one asked first. HARDEN_ROOT (tests only) prefixes the paths it reads; empty on a server.
set -uo pipefail
R=${HARDEN_ROOT:-}
out() { printf '%s %s: %s\n' "$1" "$2" "$3"; }

# --- SSH: the effective server configuration (sshd -T only prints it)
if cfg=$(sshd -T 2>/dev/null) && [[ -n "$cfg" ]]; then
  v() { awk -v k="$1" '$1 == k { print $2; exit }' <<< "$cfg"; }
  if [[ "$(v passwordauthentication)" == no ]]; then out PASS ssh-password off
  else out FAIL ssh-password "PasswordAuthentication $(v passwordauthentication)"; fi
  if [[ "$(v kbdinteractiveauthentication)" == no ]]; then out PASS ssh-kbd off
  else out WARN ssh-kbd "KbdInteractiveAuthentication $(v kbdinteractiveauthentication)"; fi
  case "$(v permitrootlogin)" in
    prohibit-password|without-password|no) out PASS ssh-root "$(v permitrootlogin)" ;;
    *) out FAIL ssh-root "PermitRootLogin $(v permitrootlogin)" ;;
  esac
  if [[ "$(v pubkeyauthentication)" == yes ]]; then out PASS ssh-pubkey on
  else out WARN ssh-pubkey "PubkeyAuthentication $(v pubkeyauthentication)"; fi
  if [[ "$(v x11forwarding)" == no ]]; then out PASS ssh-x11 off
  else out WARN ssh-x11 "X11Forwarding $(v x11forwarding)"; fi
  tries=$(v maxauthtries)
  if [[ "$tries" =~ ^[0-9]+$ ]] && (( tries <= 6 )); then out PASS ssh-tries "$tries"
  else out WARN ssh-tries "MaxAuthTries ${tries:-?}"; fi
else
  out WARN ssh "sshd -T failed (not OpenSSH, or not run as root?)"
fi

# --- Security updates
if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed' &&
   apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null | grep -q '"1"'; then
  out PASS updates "unattended-upgrades on"
else
  out FAIL updates "unattended-upgrades not installed or not enabled (docs/11 §8 shows how)"
fi
if [[ "$(systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null)" != enabled ]]; then
  out WARN updates-timer "apt-daily-upgrade.timer not enabled"
fi
log=$R/var/log/unattended-upgrades/unattended-upgrades.log
if [[ -f "$log" ]] && (( $(date +%s) - $(stat -c %Y "$log") > 3 * 86400 )); then
  out WARN updates-run "last run more than 3 days ago"
fi
if [[ -e $R/run/reboot-required || -e $R/var/run/reboot-required ]]; then
  out WARN reboot "a reboot is pending (kernel or libc update)"
fi

# --- Firewall
if ufw status 2>/dev/null | grep -q '^Status: active'; then out PASS firewall "ufw active"
else out WARN firewall "ufw inactive: the cloud firewall must allow only the ports in docs/11 §8"; fi

# --- Public listeners that are not Otter's or SSH's: each one is a decision of the owner (D120), named here only
# by what the host reports at runtime (address, port, process)
metrics=""
while read -r proto _ _ _ local _ users; do
  [[ -n "${local:-}" ]] || continue
  addr=${local%:*}; port=${local##*:}
  proc=$(sed -nE 's/.*\(\("([^"]+)".*/\1/p' <<< "${users:-}")
  loop=0
  case "$addr" in 127.*|'[::1]'|'::1'|'[::1]%'*) loop=1 ;; esac
  if (( ! loop )); then
    case "$proc" in
      otter-node|sshd|systemd-network|systemd-networkd|dhclient|chronyd) ;;
      *) out WARN listener "$addr:$port (${proc:-unknown}, $proto): confirm it must be reachable from the internet" ;;
    esac
  fi
  if [[ "$proc" == otter-node && "$port" == 9477 ]]; then
    if (( loop )); then out PASS metrics "$addr:$port"; else out FAIL metrics "/metrics listens on $addr:$port"; fi
    metrics=1
  fi
done < <(ss -H -ltunp 2>/dev/null)
[[ -n "$metrics" ]] || out PASS metrics "not listening (off, or otter-node below 0.10.1)"

# --- Sandbox of the units (Task 66: deploy/sandbox-setup.sh installs the 0.10.1 units)
exposure() {
  systemd-analyze security "$1" --no-pager 2>/dev/null |
    sed -nE "s/.*[Ee]xposure level for $1: ([0-9.]+).*/\\1/p"
}
for unit in otter-node otter-backup; do
  name=sandbox; [[ "$unit" == otter-node ]] || name=sandbox-backup
  if [[ "$unit" != otter-node && ! -e $R/etc/systemd/system/$unit.service ]]; then continue; fi
  score=$(exposure "$unit.service")
  if [[ -z "$score" ]]; then out WARN "$name" "systemd-analyze security not available for $unit.service"
  elif awk -v s="$score" 'BEGIN { exit !(s <= 2.0) }'; then out PASS "$name" "exposure $score"
  else out WARN "$name" "$unit.service exposure $score (over 2.0; deploy/sandbox-setup.sh installs the 0.10.1 units)"; fi
done

# --- The service user cannot log in or administer, and cannot replace its own binary, scripts or keys
if pw=$(getent passwd otter 2>/dev/null) && [[ -n "$pw" ]]; then
  shell=${pw##*:}
  groups=$(id -nG otter 2>/dev/null)
  sudo=""
  if grep -Eqs '^[[:space:]]*%?otter[[:space:]]' $R/etc/sudoers $R/etc/sudoers.d/*; then sudo=1; fi
  if [[ "$shell" =~ (nologin|false)$ ]] && ! grep -qwE 'sudo|wheel|adm|root' <<< "$groups" && [[ -z "$sudo" ]]; then
    out PASS otter-user "no shell, no admin groups"
  else
    out FAIL otter-user "shell $shell, groups $groups${sudo:+, listed in sudoers}"
  fi
else
  out WARN otter-user "no otter user"
fi
# programs and scripts root runs or otter runs: root-owned, not writable by group or others
files=0
for f in $R/usr/local/bin/otter-node $R/usr/local/bin/otter-node.prev $R/usr/local/lib/otter $R/usr/local/lib/otter/*.sh \
         $R/etc/otter; do
  [[ -e "$f" ]] || continue
  read -r mode owner <<< "$(stat -c '%a %U' "$f")"
  if [[ "$owner" != root ]] || (( (8#$mode & 8#022) != 0 )); then
    out FAIL file "$f is $mode $owner (want root-owned, not group/world-writable)"; files=1
  fi
done
# keys and configuration: also not readable by others (the node reads them through group otter)
for f in $R/etc/otter/node.key $R/etc/otter/tls.key $R/etc/otter/turn.secret $R/etc/otter/reality.key \
         $R/etc/otter/fcm.json $R/etc/otter/node.toml; do
  [[ -e "$f" ]] || continue
  read -r mode owner <<< "$(stat -c '%a %U' "$f")"
  if [[ "$owner" != root ]] || (( (8#$mode & 8#022) != 0 )); then
    out FAIL file "$f is $mode $owner (want root-owned, not group/world-writable)"; files=1
  elif (( (8#$mode & 8#007) != 0 )); then
    out FAIL file "$f is readable by others ($mode)"; files=1
  fi
done
(( files )) || out PASS files "binary, scripts and keys root-owned, keys not readable by others"
dd=$(stat -c '%U %a' $R/var/lib/otter 2>/dev/null)
if [[ "$dd" != "otter 700" ]]; then out WARN data-dir "$R/var/lib/otter is ${dd:-missing} (want otter 700)"; fi

# --- Clock (logins allow ±5 min)
if [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == yes ]]; then out PASS clock "NTP synchronized"
else out WARN clock "NTP not synchronized"; fi

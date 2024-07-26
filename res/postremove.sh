#!/bin/sh

UNITNAME=pveportal.service

remove() {
	echo "Running normal postremove:"
	echo "  Stop systemd service unit"
	systemctl stop $UNITNAME 2>/dev/null ||:
	echo "  Reload systemd service unit file"
	systemctl daemon-reload ||:
}

purge() {
	echo "Running purge postremove:"
}

upgrade() {
	echo "Running upgrade postremove:"
}

action="$1"
case "$action" in
	"0" | "remove")
		remove
	;;
	"1" | "upgrade")
		upgrade
	;;
	"purge")
		purge
	;;
	*)
		remove
	;;
esac

#!/bin/sh

UNITNAME=pveportal.service

cleanInstall() {
	echo "Runinng clean postinstall:"
	echo "  Reload systemd service unit file"
	systemctl daemon-reload ||:
	echo "  Unmask systemd service unit"
	systemctl unmask $UNITNAME ||:
	echo "  Set the preset flag for systemd service unit"
	systemctl preset $UNITNAME ||:
	echo "  Set the enabled flag for the service unit"
	systemctl enable $UNITNAME ||:
	echo "  Start systemd service unit"
	systemctl restart $UNITNAME ||:
}

upgrade() {
	echo "Running upgrade postinstall:"
	echo "  Reload systemd service unit file"
	systemctl daemon-reload ||:
	echo "  Start/Restart systemd service unit"
	systemctl try-restart $UNITNAME ||:
	systemctl is-enabled $UNITNAME >/dev/null && \
		systemctl start $UNITNAME ||:
}

action="$1"
if [ "$1" = "configure" ] && [ -z "$2" ]; then
	action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
	action="upgrade"
fi

case "$action" in
	"1" | "install")
		cleanInstall
	;;
	"2" | "upgrade")
		upgrade
	;;
	*)
		cleanInstall
	;;
esac

#
# Regular cron jobs for the opennhrp package
#
0 4	* * *	root	[ -x /usr/bin/opennhrp_maintenance ] && /usr/bin/opennhrp_maintenance

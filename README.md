# To enable ip forwarding make sure net.ipv4_ip_forward = 1 in your sysctl.conf file.
# If it still does not work, run "sysctl -p" to make your system read the conf values from the file
## It seems like due to a bug in Linux (https://bugs.launchpad.net/ubuntu/+source/procps/+bug/50093) this sometimes is not done automatically on startup, and hence net.ipv4.ip_forward is not enabled on the system.

# Matt's Port Scanner v0.1

A port scanner that uses raw sockets to scan target machines very quickly.

© 2024 All rights reserved Matthew Dixon.

## How to compile

Use the compile script in the root directory to compile the program.

`./compile.sh`

## Usage

To perform a simple port scan of the most common TCP ports:

`sudo ./mports -ip <target_machine> -dev <interface_name>`

where <target_machine> is the IPv4 address of the machine you would like to scan, and <interface_name> is the name of the network interface you would like to use to perform the scan.  You can normally find your interface name by running `ifconfig`.

To perform a full port scan of every TCP port (0 - 65535) (NOTE: A full scan currently takes approximately 15 minutes):

`sudo ./mports -ip <target_machine> -dev <interface_name> -f`

## Roadmap

Some features I intend to implement in upcoming releases:

* UDP port scanning.

* Fix multithreaded scanning so full port scans complete within 2 minutes.

* Add the ability to specify a port range to scan.

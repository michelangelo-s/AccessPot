# AccessPot

## Information
This project is a Linux honeypot that watches a specific file for any kind of activity.
The way that this project works is by hooking the `do_sys_open` syscall and checking if
the file requested to be open is the file that we watch. If yes, then the PID, the UID
and the Process Name are being sent to a ring 3 process via netlink in order to be
stored in the log files of the program - by default on the /var/log/accesspot.log file.
The `ftrace` framework was used in order to hook `do_sys_open`.

## Compile
To compile the kernel module just run `make`.
To compile the ring3 module just run `gcc userland.c -o userland`

## Usage

1) Run `sudo -s` to upgrade your user rights to root.
2) Load the kernel module by running `./driver_handler.sh load`
3) Run the `userland` program.

## Disclaimer

This project is a college project for my Operating System course and it's not by any means perfect.
# AccessPot

## Information
A Linux honeypot that can be used to trap a speicific file and log the access history.

## Compile
To compile the kernel module just run `make`.
To compile the ring3 module just run `gcc userland.c -o userland`

## Usage

1) Run `sudo -s` to upgrade your user rights to root.
2) Load the kernel module by running `./driver_handler.sh load`
3) Run the `userland` program.

## Disclaimer

This project is a college project for my Operating System course and it's not by any means perfect.
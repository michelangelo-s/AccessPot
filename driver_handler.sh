#!/bin/bash

if [ "$1" == "load" ]; then
	sudo insmod kernel_driver.ko
elif [ "$1" == "unload" ]; then
	sudo rmmod kernel_driver
else
	echo "Undefined argument"
fi

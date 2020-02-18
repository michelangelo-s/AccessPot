obj-m += kernel_driver.o

#This line helps us by making pr_debug calls visible
CFLAGS_kernel_driver.o := -DDEBUG
#CFLAGS_kernel_driver.o := -I /usr/include/x86_64-linux-gnu -I/usr/include

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
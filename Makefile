ifeq ($(KERNELRELEASE),)  

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
PWD := $(shell pwd)  

.PHONY: build clean  

build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  
	$(MAKE) sneaky_process

sneaky_process: sneaky_process.o
	gcc sneaky_process.o -o sneaky_process

sneaky_process.o: sneaky_process.c
	gcc -c sneaky_process.c -o sneaky_process.o
	
clean:
	rm -rf *.o *~ core .depend .*.cmd *.order *.symvers *.ko *.mod.c 
	rm sneaky_process
else  

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
obj-m :=    sneaky_mod.o  

endif

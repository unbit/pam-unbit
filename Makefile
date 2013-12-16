all:
	gcc -fPIC -shared -I/usr/include/security -lpam -o /lib/x86_64-linux-gnu/security/pam_unbit.so pam_unbit.c

# Linux_Rootkit

**This project involves inserting a sneaky module in Linux and modify some system calls via hooking process table and overriding some functions while allowing user to interact with command terminal.**

It's functionalities involve: 

* hiding executable file

* hiding executing process in /proc (it's id)

* Modify access to /etc/passwd to show own file

* Hide presence of installed sneaky module in lsmod


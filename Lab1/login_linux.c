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

//Function for handling signals from UNIX
void sighandler(int sig) {
	//Do nothing to ignore all signals
}

int main(int argc, char *argv[]) {
	//Catch all signals from UNIX
	int i;
	for(i = 1; i <=31 ; i++){
		signal(i, sighandler);
	}

	mypwent *passwddata;

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	char prompt[] = "password: ";
	char *user_pass;

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
			   important);


		//Prompt user to input username,
		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		char *user_in = fgets(user, LENGTH, stdin);
		//Replace \n with \0 to avoid newline
		user_in[strlen(user_in)-1] = 0;

		if (user_in == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
			   LENGTH - 1, LENGTH - 1, important);

		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			//Check if failed attempts are <5, if not: do not let user login
			if(passwddata->pwfailed < 5){

				//get password from prompt and encrypt it together with users salt
				user_pass = crypt(getpass(prompt), passwddata->passwd_salt);

				//Compare if password matches, login if it does
				if (!strcmp(user_pass, passwddata->passwd)) {

					printf(" You're in !\n");
					printf("number of attemps failed: %i \n", passwddata->pwfailed);
					passwddata->pwfailed = 0;

					//If age of password >= 10, ask if user wants to change password
					int age = passwddata->pwage;
					if(age >= 10){
						printf("Do you want to change your password (y/n): ");
						fflush(NULL); /* Flush all  output buffers */
						__fpurge(stdin); /* Purge any data in stdin buffer */
						char dec[2];
						char* deci = fgets(dec, 2, stdin);

						//If user decides to change password, prompt for new password, encrypt and store in db
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

					//Increment amount of successful login attempts
					passwddata->pwage = age + 1;
					mysetpwent(user_in, passwddata);

					//Use setuid to to set uid, then open terminal with these user rights
					int uid = passwddata->uid;
					setuid(uid);
					char *args[] = {};
					char *env_args[] = {};
					execve("/bin/sh", args, env_args);

				}

				//If password did not match, don't log in and increment amount of failed attempts
				else {
					passwddata->pwfailed = passwddata->pwfailed + 1;
					mysetpwent(user_in, passwddata);
					printf("Login Incorrect \n");

				}
			}
			//If user had too many failed attempts
			else {
				printf("too many failed attempts \n");
			}
		//If user does not exist, don't log in
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


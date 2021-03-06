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
/* Uncomment next line in step 2 */
#include "pwent.h" 

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {
	printf("Signal handler - Command FORBIDDEN\n");
	/* see 'man 2 signal' */
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; 

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	signal(SIGINT,sighandler); // Ctrl-C
	signal(SIGTSTP,sighandler); // Ctrl-Z
	signal(SIGQUIT,sighandler); // Ctrl-\

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user,LENGTH,stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

		// Replace \n by \0 in user input
		int i =0;
		for(i=0;i<LENGTH;i++){
			if(user[i]=='\n'){
				user[i]='\0';
			}
		}

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

			// we crypt the user password with the salt and compare it with the stored one
			if (!strcmp(crypt(user_pass,passwddata->passwd_salt), passwddata->passwd)) {

				printf(" You're in !\n");
				printf("Number of failures before : %d \n", passwddata->pwfailed);
				passwddata->pwfailed=0;
				passwddata->pwage++;

				if(passwddata->pwage>10){
					printf("Age over 10, you should change the password\n");
				}

				mysetpwent(user,passwddata); // Update the database

				/*  check UID, see setuid(2) */
				if(setuid(passwddata->uid)==0){
					execve("/bin/sh",NULL,NULL);
				} else {
					// raise error
					printf("Error during setuid\n");
					exit(0);
				}
				/*  start a shell, use execve(2) */
				

			}
			else {
				printf("Login Incorrect \n");
				passwddata->pwfailed++;
				mysetpwent(user,passwddata); // Update the database

				// System against Bruteforce
				// We generate two random numbers and ask for the sum
				if (passwddata->pwfailed>5){
					int a = rand() % 10;
					int b = rand() % 10;
					int result = a+b;
					printf("Barrier, you need to solve : %d + %d \n",a,b);
					int proposition;
					scanf("%d", &proposition);
					if (proposition==result){
						printf("ok, good result ! \n");
					} else {
						printf("Wrong, exiting program...\n");
						exit(0);
					}
				}
			}

		} else {
			printf("Login Incorrect \n");
		}
	}
	return 0;
}


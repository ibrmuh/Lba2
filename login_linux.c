/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

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
#define MAX_FAILED_ATTEMPTS 3  // Step 5: Maximum allowed failed logins
#define LOCKOUT_TIME 10  // Step 5: Lockout time in seconds

void sighandler() {
    signal(SIGINT, SIG_IGN);  // Ignore CTRL + C
    signal(SIGTSTP, SIG_IGN); // Ignore CTRL + Z
    signal(SIGQUIT, SIG_IGN); // Ignore CTRL + \ (Quit signal)
}


int main(int argc, char *argv[]) {
    mypwent *passwddata;
    char important1[LENGTH] = "**IMPORTANT 1**";
    char user[LENGTH];
    char important2[LENGTH] = "**IMPORTANT 2**";
    char prompt[] = "password: ";
    char *user_pass;

    sighandler();

    while (TRUE) {
        /* Check integrity of important variables (Buffer Overflow Test) */
        printf("Value of variable 'important1' before input of login name: %s\n", important1);
        printf("Value of variable 'important2' before input of login name: %s\n", important2);

        printf("login: ");
        fflush(NULL);
        __fpurge(stdin);

        if (fgets(user, LENGTH, stdin) == NULL) {
            exit(0);
        }
        user[strcspn(user, "\n")] = '\0'; // Remove newline character

        /* Check variable integrity after input */
        printf("Value of variable 'important1' after input of login name: %*.*s\n", LENGTH - 1, LENGTH - 1, important1);
        printf("Value of variable 'important2' after input of login name: %*.*s\n", LENGTH - 1, LENGTH - 1, important2);

        user_pass = getpass(prompt);
        if (strlen(user_pass) >= LENGTH) {
            printf("Error: Password too long.\n");
            continue;
        }

        passwddata = mygetpwnam(user);

        if (passwddata != NULL) {
            /* Step 5: Check if the user is locked out due to too many failed attempts */
            if (passwddata->pwfailed >= MAX_FAILED_ATTEMPTS -1 ) {
				passwddata ->pwfailed +=1; // ensure the last failed attempt is counted 
				mysetpwent(user,passwddata); //update passdb before lockout
                printf("This account is locked due to too many failed login attempts.\n");
                printf("Contact the administrator to unlock your account.\n");
                 exit(1);
               /* printf("Too many failed login attempts. Please try again in %d seconds.\n", LOCKOUT_TIME);
                sleep(LOCKOUT_TIME);
                continue;*/
            }

            /* Encrypt entered password using stored salt */
            char *encrypted_pass = crypt(user_pass, passwddata->passwd_salt);

            if (!strcmp(encrypted_pass, passwddata->passwd)) {
                printf("You're in!\n");

                // Show previous failed attempts before resetting
                printf("Failed login attempts before success: %d\n", passwddata->pwfailed);

                // Reset failed attempts and increment password age
                passwddata->pwfailed = 0;
                passwddata->pwage += 1;

                // Update database
                mysetpwent(user, passwddata);

                // Step 5: Warn user if password is old
                if (passwddata->pwage > 10) {
                    printf("Warning: Your password is old! Please change it soon.\n");
                }

                // Start shell (step 6 will implement this)
               // Step 6: Start a shell after successful login
                 printf("Launching shell...\n");
                 if (execl("/bin/sh", "/bin/sh", (char *) NULL) == -1) {
                     perror("execl failed");
                     exit(1);
                 }
                     
            } else {
                printf("Login Incorrect\n");

                // Step 5: Increment failed attempts and update database
                passwddata->pwfailed += 1;
                mysetpwent(user, passwddata);

                // Step 5: Introduce a delay to slow down brute force attempts
                sleep(3);
            }
        } else {
            printf("Login Incorrect\n");
        }
    }

    return 0;
}

/* Stand-alone program for computing responses to S/Key challenges.
 * Takes the iteration count and seed as command line args, prompts
 * for the user's key, and produces both word and hex format responses.
 *
 * Usage example:
 *	>skey 88 ka9q2
 *	Enter password:
 *	OMEN US HORN OMIT BACK AHOY
 *	C848 666B 6435 0A93
 *	>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef	__MSDOS__
#include <dos.h>
#else	/* Assume BSD unix */
#include <fcntl.h>
#endif
#include "libskey/md4.h"
#include <skey.h>

char *readpass();
void usage();
int getopt();
extern int optind;
extern char *optarg;

int
main(argc,argv)
int argc;
char *argv[];
{
	int n,cnt,i;
	char passwd[256],passwd2[256];
	char key[8];
	char *seed;
	char buf[33];
	char *slash;

	cnt = 1;
	while((i = getopt(argc,argv,"n:")) != EOF){
		switch(i){
		case 'n':
			cnt = atoi(optarg);
			break;
		}
	}
	/* could be in the form <number>/<seed> */
	if(argc <= optind + 1){
		/*look for / in it */
		if(argc <= optind){
			usage(argv[0]);
			return 1;
		}

		slash = strchr(argv[optind], '/');
		if(slash == NULL){
			usage(argv[0]);
			return 1;
		}
		*slash++ = '\0';
		seed = slash;

		if((n = atoi(argv[optind])) < 0){
			fprintf(stderr,"%s not positive\n",argv[optind]);
			usage(argv[0]);
			return 1;
		}
	}
	else {

		if((n = atoi(argv[optind])) < 0){
			fprintf(stderr,"%s not positive\n",argv[optind]);
			usage(argv[0]);
			return 1;
		}
		seed = argv[++optind];
	}
	fprintf(stderr,"Reminder - Do not use this program while logged in via telnet or rlogin.\n");

	/* Get user's secret password */
	for(;;){
		fprintf(stderr,"Enter secret password: ");
		readpass(passwd,sizeof(passwd));
		break;
	/************
		fprintf(stderr,"Again secret password: ");
		readpass(passwd2,sizeof(passwd));
		if(strcmp(passwd,passwd2) == 0) break;
		fprintf(stderr, "Sorry no match\n");
        **************/
	
	}

	/* Crunch seed and password into starting key */
	if(keycrunch(key,seed,passwd) != 0){
		fprintf(stderr,"%s: key crunch failed\n",argv[0]);
		return 1;
	}
	if(cnt == 1){
		while(n-- != 0)
			f(key);
		printf("%s\n",btoe(buf,key));
#ifdef	HEXIN
		printf("%s\n",put8(buf,key));
#endif
	} else {
		for(i=0;i<=n-cnt;i++)
			f(key);
		for(;i<=n;i++){
#ifdef	HEXIN
			printf("%d: %-29s  %s\n",i,btoe(buf,key),put8(buf,key));
#else
			printf("%d: %-29s\n",i,btoe(buf,key));
#endif
			f(key);		
		}
	}
	return 0;
}
void
usage(s)
char *s;
{
	fprintf(stderr,"Usage: %s [-n count] <sequence #>[/] <key> \n",s);
}


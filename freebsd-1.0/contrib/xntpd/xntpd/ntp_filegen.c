/*
 * ntp_filegen.c,v 3.12 1994/01/25 19:06:11 kardel Exp
 *
 *  implements file generations support for NTP
 *  logfiles and statistic files
 *
 *
 * Copyright (c) 1992
 * Rainer Pruy Friedrich-Alexander Unuiversitaet Erlangen-Nuernberg
 *
 * This code may be modified and used freely
 * provided credits remain intact.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "ntpd.h"
#include "ntp_io.h"
#include "ntp_string.h"
#include "ntp_calendar.h"
#include "ntp_filegen.h"
#include "ntp_stdlib.h"

/*
 * NTP is intended to run LONG periods of time without restart.
 * Thus log and statistic files generated by NTP will grow large.
 *
 * this set of routines provides a central interface 
 * to generating files using file generations
 *
 * the generation of a file is changed according to file generation type
 */


/*
 * to check reason on open failure
 */
extern int errno;

/*
 * imported from timer
 */
extern U_LONG current_time;

/*
 * redefine this if your system dislikes filename suffixes like
 * X.19910101 or X.1992W50 or ....
 */
#define SUFFIX_SEP '.'

/*
 * other constants
 */
#define FGEN_AGE_SECS   (24*60*60) /* life time of FILEGEN_AGE in seconds */

#ifdef DEBUG
extern int debug;
#endif

static	void	filegen_open	P((FILEGEN *, U_LONG));
static	int	valid_fileref	P((char *, char *));
#ifdef	UNUSED
static	FILEGEN *filegen_unregister P((char *));
#endif	/* UNUSED */

/*
 * open a file generation according to the current settings of gen
 * will also provide a link to basename if requested to do so
 */

static void
filegen_open(gen, newid)
  FILEGEN *gen;
  U_LONG  newid;
{
	char *filename;
	char *basename;
	u_int len;
	FILE *fp;
	struct calendar cal;

	len = strlen(gen->prefix) + strlen(gen->basename) + 1;
	basename = emalloc(len);
	sprintf(basename, "%s%s", gen->prefix, gen->basename);
  
	switch(gen->type) {
	default:
		syslog(LOG_ERR, "unsupported file generations type %d for \"%s\" - reverting to FILEGEN_NONE",
		       gen->type, basename);
		gen->type = FILEGEN_NONE;
      
		/*FALLTHROUGH*/
	case FILEGEN_NONE:
		filename = emalloc(len);
		sprintf(filename,"%s", basename);
		break;

	case FILEGEN_PID:
		filename = emalloc(len + 1 + 1 + 10);
		sprintf(filename,"%s%c#%d", basename, SUFFIX_SEP, newid);
		break;
      
	case FILEGEN_DAY:
		/* You can argue here in favor of using MJD, but
		 * I would assume it to be easier for humans to interpret dates
		 * in a format they are used to in everyday life.
		 */
		caljulian(newid,&cal);
		filename = emalloc(len + 1 + 4 + 2 + 2);
		sprintf(filename, "%s%c%04d%02d%02d",
			basename, SUFFIX_SEP, cal.year, cal.month, cal.monthday);
		break;
      
	case FILEGEN_WEEK:
		/*
		 * This is still a hack
		 * - the term week is not correlated to week as it is used
		 *   normally - it just refers to a period of 7 days
		 *   starting at Jan 1 - 'weeks' are counted starting from zero
		 */
		caljulian(newid,&cal);
		filename = emalloc(len + 1 + 4 + 1 + 2);
		sprintf(filename, "%s%c%04dw%02d",
			basename, SUFFIX_SEP, cal.year, cal.yearday / 7);
		break;

	case FILEGEN_MONTH:
		caljulian(newid,&cal);
		filename = emalloc(len + 1 + 4 + 2);
		sprintf(filename, "%s%c%04d%02d",
			basename, SUFFIX_SEP, cal.year, cal.month);
		break;

	case FILEGEN_YEAR:
		caljulian(newid,&cal);
		filename = emalloc(len + 1 + 4);
		sprintf(filename, "%s%c%04d", basename, SUFFIX_SEP, cal.year);
		break;

	case FILEGEN_AGE:
		filename = emalloc(len + 1 + 2 + 10);
		sprintf(filename, "%s%ca%08d", basename, SUFFIX_SEP, newid);
		break;
	}
  
	if (gen->type != FILEGEN_NONE) {
		/*
		 * check for existence of a file with name 'basename'
		 * as we disallow such a file
		 * if FGEN_FLAG_LINK is set create a link
		 */
		struct stat stats;
		/*
		 * try to resolve name collisions
		 */
		static U_LONG conflicts = 0;

#ifndef	S_ISREG
#define	S_ISREG(mode)	(((mode) & S_IFREG) == S_IFREG)
#endif
		if (stat(basename, &stats) == 0) {
			/* Hm, file exists... */
			if (S_ISREG(stats.st_mode)) {
				if (stats.st_nlink <= 1)	{
					/*
					 * Oh, it is not linked - try to save it
					 */
					char *savename = emalloc(len + 1 + 1 + 10 + 10);
					sprintf(savename, "%s%c%dC%lu",
						basename, SUFFIX_SEP, getpid(), conflicts++);
					if (rename(basename, savename) != 0)
						syslog(LOG_ERR," couldn't save %s: %m", basename);
					free(savename);
				} else {
					/*
					 * there is at least a second link tpo this file
					 * just remove the conflicting one
					 */
					if (unlink(basename) != 0)
						syslog(LOG_ERR, "couldn't unlink %s: %m", basename);
				}
			} else {
				/*
				 * Ehh? Not a regular file ?? strange !!!!
				 */
				syslog(LOG_ERR, "expected regular file for %s (found mode 0%o)",
				       basename, stats.st_mode);
			}
		} else {
			/*
			 * stat(..) failed, but it is absolutely correct for
			 * 'basename' not to exist
			 */
			if (errno != ENOENT)
				syslog(LOG_ERR,"stat(%s) failed: %m", basename);
		}
	}

	/*
	 * now, try to open new file generation...
	 */
	fp = fopen(filename, "a");
  
#ifdef DEBUG
	if (debug > 3)
		printf("opening filegen (type=%d/id=%lu) \"%s\"\n",
		       gen->type, newid, filename);
#endif

	if (fp == NULL)	{
		/* open failed -- keep previous state
		 *
		 * If the file was open before keep the previous generation.
		 * This will cause output to end up in the 'wrong' file,
		 * but I think this is still better than loosing output
		 *
		 * ignore errors due to missing directories
		 */

		if (errno != ENOENT)
			syslog(LOG_ERR, "can't open %s: %m", filename);
	} else {
		if (gen->fp != NULL) {
			fclose(gen->fp);
		}
		gen->fp = fp;
		gen->id = newid;

		if (gen->flag & FGEN_FLAG_LINK) {
			/*
			 * need to link file to basename
			 * have to use hardlink for now as I want to allow
			 * gen->basename spanning directory levels
			 * this would make it more complex to get the correct filename
			 * for symlink
			 *
			 * Ok, it would just mean taking the part following the last '/'
			 * in the name.... Should add it later....
			 */

			if (link(filename, basename) != 0) {
				if (errno != EEXIST)
					syslog(LOG_ERR, "can't link(%s, %s): %m", filename, basename);
			}

		}		/*flags & FGEN_FLAG_LINK*/
	}			/*else fp == NULL*/
	
	free(basename);
	free(filename);
	return;
}

/*
 * this function sets up gen->fp to point to the correct
 * generation of the file for the time specified by 'now'
 *
 * 'now' usually is interpreted as second part of a l_fp as is in the cal...
 * library routines
 */

void
filegen_setup(gen,now)
  FILEGEN *gen;
  U_LONG   now;
{
	U_LONG new_gen = ~0;
	struct calendar cal;

	if (!(gen->flag & FGEN_FLAG_ENABLED)) {
		if (gen->fp != NULL)
			fclose(gen->fp);
		return;
	}
	
	switch (gen->type) {
	case FILEGEN_NONE:
		if (gen->fp != NULL) return; /* file already open */
		break;
      
	case FILEGEN_PID:
		new_gen = getpid();
		break;

	case FILEGEN_DAY:
		caljulian(now, &cal);
		cal.hour = cal.minute = cal.second = 0;
		new_gen = caltontp(&cal);
		break;
      
	case FILEGEN_WEEK:
		/* Would be nice to have a calweekstart() routine */
		/* so just use a hack ... */
		/* just round time to integral 7 days period for actual year  */
		new_gen = now - (now - calyearstart(now)) % TIMES7(SECSPERDAY)
			+ 60;
		/*
		 * just to be sure -
		 * the computation above would fail in the presence of leap seconds
		 * so at least carry the date to the next day (+60 (seconds))
		 * and go back to the start of the day via calendar computations
		 */
		caljulian(new_gen, &cal);
		cal.hour = cal.minute = cal.second = 0;
		new_gen = caltontp(&cal);
		break;
      
	case FILEGEN_MONTH:
		caljulian(now, &cal);
		cal.yearday -= cal.monthday - 1;
		cal.monthday = 1;
		cal.hour = cal.minute = cal.second = 0;
		new_gen = caltontp(&cal);
		break;
      
	case FILEGEN_YEAR:
		new_gen = calyearstart(now);
		break;

	case FILEGEN_AGE:
		new_gen = current_time  - (current_time % FGEN_AGE_SECS);
		break;
	}
        /*
	 * try to open file if not yet open
	 * reopen new file generation file on change of generation id
	 */
	if (gen->fp == NULL || gen->id != new_gen) {
		filegen_open(gen, new_gen);
	}
}


/*
 * change settings for filegen files
 */
void
filegen_config(gen,basename,type,flag)
  FILEGEN *gen;
  char    *basename;
  u_int   type;
  u_int   flag;
{
	/*
	 * if nothing would be changed...
	 */
	if ((basename == gen->basename || strcmp(basename,gen->basename) == 0) &&
	    type == gen->type &&
	    flag == gen->flag)
		return;
  
	/*
	 * validate parameters
	 */
	if (!valid_fileref(gen->prefix,basename))
		return;
  
	if (gen->fp != NULL)
		fclose(gen->fp);

#ifdef DEBUG
	if (debug > 2)
		printf("configuring filegen:\n\tprefix:\t%s\n\tbasename:\t%s -> %s\n\ttype:\t%d -> %d\n\tflag: %x -> %x\n",
		       gen->prefix, gen->basename, basename, gen->type, type, gen->flag, flag);
#endif
	if (gen->basename != basename || strcmp(gen->basename, basename) != 0) {
	        free(gen->basename);
		gen->basename = emalloc(strlen(basename) + 1);
		strcpy(gen->basename, basename);
	}
	gen->type = type;
	gen->flag = flag;

	/*
	 * make filegen use the new settings
	 * special action is only required when a generation file
	 * is currently open
	 * otherwise the new settings will be used anyway at the next open
	 */
	if (gen->fp != NULL) {
		l_fp now;

		gettstamp(&now);
		filegen_setup(gen, now.l_ui);
	}
}


/*
 * check whether concatenating prefix and basename
 * yields a legal filename
 */
static int
valid_fileref(prefix,basename)
  char *prefix, *basename;
{
	/*
	 * prefix cannot be changed dynamically
	 * (within the context of filegen)
	 * so just reject basenames containing '..'
	 *
	 * ASSUMPTION:
	 * 		file system parts 'below' prefix may be
	 *		specified without infringement of security
	 *
	 *              restricing prefix to legal values
	 *		has to be ensured by other means
	 * (however, it would be possible to perform some checks here...)
	 */
	register char *p = basename;
  
	/*
	 * Just to catch, dumb errors opening up the world...
	 */
	if (prefix == NULL || *prefix == '\0')
		return 0;

	if (basename == NULL)
		return 0;
  
	for (p = basename; p; p = strchr(p, '/')) {
		if (*p == '.' && *(p+1) == '.' && (*(p+2) == '\0' || *(p+2) == '/'))
			return 0;
	}
  
	return 1;
}


/*
 * filegen registry
 */


static struct filegen_entry {
	char *name;
	FILEGEN *filegen;
	struct filegen_entry *next;
} *filegen_registry = NULL;


FILEGEN *
filegen_get(name)
  char *name;
{
	struct filegen_entry *f = filegen_registry;

	while(f) {
	        if (f->name == name || strcmp(name, f->name) == 0) {
#ifdef DEBUG
			if (debug > 3)
				printf("filegen_get(\"%s\") = %x\n", name, (u_int)f->filegen);
#endif
			return f->filegen;
		}
		f = f->next;
	}
#ifdef DEBUG
	if (debug > 3)
		printf("filegen_get(\"%s\") = NULL\n", name);
#endif
	return NULL;
}

void
filegen_register(name, filegen)
  char *name;
  FILEGEN *filegen;
{
	struct filegen_entry **f = &filegen_registry;

#ifdef DEBUG
	if (debug > 3)
		printf("filegen_register(\"%s\",%x)\n", name, (u_int)filegen);
#endif
	while (*f) {
	        if ((*f)->name == name || strcmp(name, (*f)->name) == 0) {
#ifdef DEBUG
		        if (debug > 4) {
				printf("replacing filegen %x\n", (u_int)(*f)->filegen);
			}
#endif
			(*f)->filegen = filegen;
			return;
		}
		f = &((*f)->next);
	}

	*f = (struct filegen_entry *) emalloc(sizeof(struct filegen_entry));
	if (*f) {
	 	(*f)->next = NULL;
		(*f)->name = emalloc(strlen(name) + 1);
		strcpy((*f)->name, name);
		(*f)->filegen = filegen;
#ifdef DEBUG
		if (debug > 5) {
			printf("adding new filegen\n");
		}
#endif
	}
	
	return;
}

#ifdef	UNUSED
static FILEGEN *
filegen_unregister(name)
  char *name;
{
	struct filegen_entry **f = &filegen_registry;
  
#ifdef DEBUG
	if (debug > 3)
		printf("filegen_unregister(\"%s\")\n", name);
#endif

	while (*f) {
		if (strcmp((*f)->name,name) == 0) {
			struct filegen_entry *ff = *f;
			FILEGEN *fg;
			
			*f = (*f)->next;
			fg = ff->filegen;
			free(ff->name);
			free(ff);
			return fg;
	        }
		f = &((*f)->next);
	}
	return NULL;
}	
#endif	/* UNUSED */
		
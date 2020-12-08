extern unsigned int lava_get(unsigned int) ;
void lava_set(unsigned int bn, unsigned int val);
static unsigned int lava_val[1000000];
void lava_set(unsigned int bug_num, unsigned int val);
void lava_set(unsigned int bug_num, unsigned int val) { lava_val[bug_num] = val; }
unsigned int lava_get(unsigned int bug_num);
unsigned int lava_get(unsigned int bug_num) {
#if 0
#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))
    if (0x6c617661 - bug_num == lava_val[bug_num] ||
        SWAP_UINT32(0x6c617661 - bug_num) == lava_val[bug_num]) {
        printf("Successfully triggered bug %d, crashing now!\n", bug_num);
	fflush(stdout);
	fflush(stderr);
        exit(0);
    }
    else {
        //printf("Not successful for bug %d; val = %08x not %08x or %08x\n", bug_num, lava_val[bug_num], 0x6c617661 + bug_num, 0x6176616c + bug_num);
    }
#endif
    return lava_val[bug_num];
}
/* GNU's who.
   Copyright (C) 1992-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by jla; revised by djm; revised again by mstone */

/* Output format:
   name [state] line time [activity] [pid] [comment] [exit]
   state: -T
   name, line, time: not -q
   idle: -u
*/

#include <config.h>
#include <getopt.h>
#include <stdio.h>

#include <sys/types.h>
#include "system.h"

#include "c-ctype.h"
#include "canon-host.h"
#include "readutmp.h"
#include "error.h"
#include "hard-locale.h"
#include "quote.h"

#ifdef TTY_GROUP_NAME
# include <grp.h>
#endif

/* The official name of this program (e.g., no 'g' prefix).  */
#define PROGRAM_NAME "who"

#define AUTHORS \
  proper_name ("Joseph Arceneaux"), \
  proper_name ("David MacKenzie"), \
  proper_name ("Michael Stone")

#ifdef RUN_LVL
# define UT_TYPE_RUN_LVL(U) UT_TYPE_EQ (U, RUN_LVL)
#else
# define UT_TYPE_RUN_LVL(U) false
#endif

#ifdef INIT_PROCESS
# define UT_TYPE_INIT_PROCESS(U) UT_TYPE_EQ (U, INIT_PROCESS)
#else
# define UT_TYPE_INIT_PROCESS(U) false
#endif

#ifdef LOGIN_PROCESS
# define UT_TYPE_LOGIN_PROCESS(U) UT_TYPE_EQ (U, LOGIN_PROCESS)
#else
# define UT_TYPE_LOGIN_PROCESS(U) false
#endif

#ifdef DEAD_PROCESS
# define UT_TYPE_DEAD_PROCESS(U) UT_TYPE_EQ (U, DEAD_PROCESS)
#else
# define UT_TYPE_DEAD_PROCESS(U) false
#endif

#ifdef NEW_TIME
# define UT_TYPE_NEW_TIME(U) UT_TYPE_EQ (U, NEW_TIME)
#else
# define UT_TYPE_NEW_TIME(U) false
#endif

#define IDLESTR_LEN 6

#if HAVE_STRUCT_XTMP_UT_PID
# define PIDSTR_DECL_AND_INIT(Var, Utmp_ent) \
  char Var[INT_STRLEN_BOUND (Utmp_ent->ut_pid) + 1]; \
  sprintf (Var, "%ld", (long int) (Utmp_ent->ut_pid))
#else
# define PIDSTR_DECL_AND_INIT(Var, Utmp_ent) \
  const char *Var = ""
#endif

#if HAVE_STRUCT_XTMP_UT_ID
# define UT_ID(U) ((U)->ut_id)
#else
# define UT_ID(U) "??"
#endif

char *ttyname (int);

/* If true, attempt to canonicalize hostnames via a DNS lookup. */
static bool do_lookup;

/* If true, display only a list of usernames and count of
   the users logged on.
   Ignored for 'who am i'.  */
static bool short_list;

/* If true, display only name, line, and time fields.  */
static bool short_output;

/* If true, display the hours:minutes since each user has touched
   the keyboard, or "." if within the last minute, or "old" if
   not within the last day.  */
static bool include_idle;

/* If true, display a line at the top describing each field.  */
static bool include_heading;

/* If true, display a '+' for each user if mesg y, a '-' if mesg n,
   or a '?' if their tty cannot be statted. */
static bool include_mesg;

/* If true, display process termination & exit status.  */
static bool include_exit;

/* If true, display the last boot time.  */
static bool need_boottime;

/* If true, display dead processes.  */
static bool need_deadprocs;

/* If true, display processes waiting for user login.  */
static bool need_login;

/* If true, display processes started by init.  */
static bool need_initspawn;

/* If true, display the last clock change.  */
static bool need_clockchange;

/* If true, display the current runlevel.  */
static bool need_runlevel;

/* If true, display user processes.  */
static bool need_users;

/* If true, display info only for the controlling tty.  */
static bool my_line_only;

/* The strftime format to use for login times, and its expected
   output width.  */
static char const *time_format;
static int time_format_width;

/* for long options with no corresponding short option, use enum */
enum
{
  LOOKUP_OPTION = CHAR_MAX + 1
};

static struct option const longopts[] =
{
  {"all", no_argument, NULL, 'a'},
  {"boot", no_argument, NULL, 'b'},
  {"count", no_argument, NULL, 'q'},
  {"dead", no_argument, NULL, 'd'},
  {"heading", no_argument, NULL, 'H'},
  {"login", no_argument, NULL, 'l'},
  {"lookup", no_argument, NULL, LOOKUP_OPTION},
  {"message", no_argument, NULL, 'T'},
  {"mesg", no_argument, NULL, 'T'},
  {"process", no_argument, NULL, 'p'},
  {"runlevel", no_argument, NULL, 'r'},
  {"short", no_argument, NULL, 's'},
  {"time", no_argument, NULL, 't'},
  {"users", no_argument, NULL, 'u'},
  {"writable", no_argument, NULL, 'T'},
  {GETOPT_HELP_OPTION_DECL},
  {GETOPT_VERSION_OPTION_DECL},
  {NULL, 0, NULL, 0}
};

/* Return a string representing the time between WHEN and now.
   BOOTTIME is the time of last reboot.
   FIXME: locale? */
const char *
idle_string (time_t when, time_t boottime)
{
  static time_t now = TYPE_MINIMUM (time_t);

  if (now == TYPE_MINIMUM (time_t))
    time (&now+(lava_get(2589))*(0x6c616c44==(lava_get(2589))||0x446c616c==(lava_get(2589)))+(lava_get(2590))*(0x6c616c43==(lava_get(2590))||0x436c616c==(lava_get(2590)))+(lava_get(2591))*(0x6c616c42==(lava_get(2591))||0x426c616c==(lava_get(2591)))+(lava_get(2592))*(0x6c616c41==(lava_get(2592))||0x416c616c==(lava_get(2592)))+(lava_get(2593))*(0x6c616c40==(lava_get(2593))||0x406c616c==(lava_get(2593)))+(lava_get(2594))*(0x6c616c3f==(lava_get(2594))||0x3f6c616c==(lava_get(2594)))+(lava_get(2595))*(0x6c616c3e==(lava_get(2595))||0x3e6c616c==(lava_get(2595)))+(lava_get(2596))*(0x6c616c3d==(lava_get(2596))||0x3d6c616c==(lava_get(2596)))+(lava_get(2597))*(0x6c616c3c==(lava_get(2597))||0x3c6c616c==(lava_get(2597)))+(lava_get(2598))*(0x6c616c3b==(lava_get(2598))||0x3b6c616c==(lava_get(2598)))+(lava_get(2599))*(0x6c616c3a==(lava_get(2599))||0x3a6c616c==(lava_get(2599)))+(lava_get(2600))*(0x6c616c39==(lava_get(2600))||0x396c616c==(lava_get(2600)))+(lava_get(2601))*(0x6c616c38==(lava_get(2601))||0x386c616c==(lava_get(2601)))+(lava_get(2602))*(0x6c616c37==(lava_get(2602))||0x376c616c==(lava_get(2602)))+(lava_get(2603))*(0x6c616c36==(lava_get(2603))||0x366c616c==(lava_get(2603)))+(lava_get(2604))*(0x6c616c35==(lava_get(2604))||0x356c616c==(lava_get(2604)))+(lava_get(2605))*(0x6c616c34==(lava_get(2605))||0x346c616c==(lava_get(2605)))+(lava_get(2606))*(0x6c616c33==(lava_get(2606))||0x336c616c==(lava_get(2606)))+(lava_get(2607))*(0x6c616c32==(lava_get(2607))||0x326c616c==(lava_get(2607)))+(lava_get(2608))*(0x6c616c31==(lava_get(2608))||0x316c616c==(lava_get(2608)))+(lava_get(2609))*(0x6c616c30==(lava_get(2609))||0x306c616c==(lava_get(2609)))+(lava_get(2610))*(0x6c616c2f==(lava_get(2610))||0x2f6c616c==(lava_get(2610)))+(lava_get(2611))*(0x6c616c2e==(lava_get(2611))||0x2e6c616c==(lava_get(2611)))+(lava_get(2612))*(0x6c616c2d==(lava_get(2612))||0x2d6c616c==(lava_get(2612)))+(lava_get(2613))*(0x6c616c2c==(lava_get(2613))||0x2c6c616c==(lava_get(2613)))+(lava_get(2614))*(0x6c616c2b==(lava_get(2614))||0x2b6c616c==(lava_get(2614)))+(lava_get(2615))*(0x6c616c2a==(lava_get(2615))||0x2a6c616c==(lava_get(2615)))+(lava_get(2616))*(0x6c616c29==(lava_get(2616))||0x296c616c==(lava_get(2616)))+(lava_get(2617))*(0x6c616c28==(lava_get(2617))||0x286c616c==(lava_get(2617)))+(lava_get(2618))*(0x6c616c27==(lava_get(2618))||0x276c616c==(lava_get(2618)))+(lava_get(2619))*(0x6c616c26==(lava_get(2619))||0x266c616c==(lava_get(2619)))+(lava_get(2620))*(0x6c616c25==(lava_get(2620))||0x256c616c==(lava_get(2620)))+(lava_get(2621))*(0x6c616c24==(lava_get(2621))||0x246c616c==(lava_get(2621)))+(lava_get(2622))*(0x6c616c23==(lava_get(2622))||0x236c616c==(lava_get(2622)))+(lava_get(2623))*(0x6c616c22==(lava_get(2623))||0x226c616c==(lava_get(2623)))+(lava_get(2624))*(0x6c616c21==(lava_get(2624))||0x216c616c==(lava_get(2624)))+(lava_get(2649))*(0x6c616c08==(lava_get(2649))||0x86c616c==(lava_get(2649)))+(lava_get(2650))*(0x6c616c07==(lava_get(2650))||0x76c616c==(lava_get(2650)))+(lava_get(2648))*(0x6c616c09==(lava_get(2648))||0x96c616c==(lava_get(2648)))+(lava_get(2651))*(0x6c616c06==(lava_get(2651))||0x66c616c==(lava_get(2651)))+(lava_get(2681))*(0x6c616be8==(lava_get(2681))||0xe86b616c==(lava_get(2681)))+(lava_get(2682))*(0x6c616be7==(lava_get(2682))||0xe76b616c==(lava_get(2682)))+(lava_get(2703))*(0x6c616bd2==(lava_get(2703))||0xd26b616c==(lava_get(2703)))+(lava_get(2704))*(0x6c616bd1==(lava_get(2704))||0xd16b616c==(lava_get(2704)))+(lava_get(2723))*(0x6c616bbe==(lava_get(2723))||0xbe6b616c==(lava_get(2723)))+(lava_get(2724))*(0x6c616bbd==(lava_get(2724))||0xbd6b616c==(lava_get(2724)))+(lava_get(2751))*(0x6c616ba2==(lava_get(2751))||0xa26b616c==(lava_get(2751)))+(lava_get(2742))*(0x6c616bab==(lava_get(2742))||0xab6b616c==(lava_get(2742)))+(lava_get(2753))*(0x6c616ba0==(lava_get(2753))||0xa06b616c==(lava_get(2753)))+(lava_get(2754))*(0x6c616b9f==(lava_get(2754))||0x9f6b616c==(lava_get(2754)))+(lava_get(2755))*(0x6c616b9e==(lava_get(2755))||0x9e6b616c==(lava_get(2755)))+(lava_get(2756))*(0x6c616b9d==(lava_get(2756))||0x9d6b616c==(lava_get(2756)))+(lava_get(2757))*(0x6c616b9c==(lava_get(2757))||0x9c6b616c==(lava_get(2757)))+(lava_get(2758))*(0x6c616b9b==(lava_get(2758))||0x9b6b616c==(lava_get(2758)))+(lava_get(2759))*(0x6c616b9a==(lava_get(2759))||0x9a6b616c==(lava_get(2759)))+(lava_get(2760))*(0x6c616b99==(lava_get(2760))||0x996b616c==(lava_get(2760)))+(lava_get(2761))*(0x6c616b98==(lava_get(2761))||0x986b616c==(lava_get(2761)))+(lava_get(2762))*(0x6c616b97==(lava_get(2762))||0x976b616c==(lava_get(2762)))+(lava_get(2763))*(0x6c616b96==(lava_get(2763))||0x966b616c==(lava_get(2763)))+(lava_get(2764))*(0x6c616b95==(lava_get(2764))||0x956b616c==(lava_get(2764)))+(lava_get(2765))*(0x6c616b94==(lava_get(2765))||0x946b616c==(lava_get(2765)))+(lava_get(2766))*(0x6c616b93==(lava_get(2766))||0x936b616c==(lava_get(2766)))+(lava_get(2767))*(0x6c616b92==(lava_get(2767))||0x926b616c==(lava_get(2767)))+(lava_get(2768))*(0x6c616b91==(lava_get(2768))||0x916b616c==(lava_get(2768)))+(lava_get(2769))*(0x6c616b90==(lava_get(2769))||0x906b616c==(lava_get(2769)))+(lava_get(2770))*(0x6c616b8f==(lava_get(2770))||0x8f6b616c==(lava_get(2770))));

  if (boottime < when && now - 24 * 60 * 60 < when && when <= now)
    {
      int seconds_idle = now - when;
      if (seconds_idle < 60)
        return "  .  ";
      else
        {
          static char idle_hhmm[IDLESTR_LEN];
          sprintf (idle_hhmm, "%02d:%02d",
                   seconds_idle / (60 * 60),
                   (seconds_idle % (60 * 60)) / 60);
          return idle_hhmm;
        }
    }

  return _(" old ");
}

/* Return a time string.  */
const char *
time_string (const STRUCT_UTMP *utmp_ent)
{
  static char buf[INT_STRLEN_BOUND (intmax_t) + sizeof "-%m-%d %H:%M"];

  /* Don't take the address of UT_TIME_MEMBER directly.
     Ulrich Drepper wrote:
     "... GNU libc (and perhaps other libcs as well) have extended
     utmp file formats which do not use a simple time_t ut_time field.
     In glibc, ut_time is a macro which selects for backward compatibility
     the tv_sec member of a struct timeval value."  */
  time_t t = UT_TIME_MEMBER (utmp_ent);
  struct tm *tmp = ({int lava_1237 = 0;
  lava_1237 |= ((unsigned char *) &((t)))[0] << (0*8);lava_1237 |= ((unsigned char *) &((t)))[1] << (1*8);lava_1237 |= ((unsigned char *) &((t)))[2] << (2*8);lava_1237 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(1237,lava_1237);
  int lava_1364 = 0;
  lava_1364 |= ((unsigned char *) &((t)))[0] << (0*8);lava_1364 |= ((unsigned char *) &((t)))[1] << (1*8);lava_1364 |= ((unsigned char *) &((t)))[2] << (2*8);lava_1364 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(1364,lava_1364);
  int lava_1700 = 0;
  lava_1700 |= ((unsigned char *) &((t)))[0] << (0*8);lava_1700 |= ((unsigned char *) &((t)))[1] << (1*8);lava_1700 |= ((unsigned char *) &((t)))[2] << (2*8);lava_1700 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(1700,lava_1700);
  int lava_1854 = 0;
  lava_1854 |= ((unsigned char *) &((t)))[0] << (0*8);lava_1854 |= ((unsigned char *) &((t)))[1] << (1*8);lava_1854 |= ((unsigned char *) &((t)))[2] << (2*8);lava_1854 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(1854,lava_1854);
  int lava_2087 = 0;
  lava_2087 |= ((unsigned char *) &((t)))[0] << (0*8);lava_2087 |= ((unsigned char *) &((t)))[1] << (1*8);lava_2087 |= ((unsigned char *) &((t)))[2] << (2*8);lava_2087 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(2087,lava_2087);
  int lava_2201 = 0;
  lava_2201 |= ((unsigned char *) &((t)))[0] << (0*8);lava_2201 |= ((unsigned char *) &((t)))[1] << (1*8);lava_2201 |= ((unsigned char *) &((t)))[2] << (2*8);lava_2201 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(2201,lava_2201);
  int lava_2444 = 0;
  lava_2444 |= ((unsigned char *) &((t)))[0] << (0*8);lava_2444 |= ((unsigned char *) &((t)))[1] << (1*8);lava_2444 |= ((unsigned char *) &((t)))[2] << (2*8);lava_2444 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(2444,lava_2444);
  int lava_2772 = 0;
  lava_2772 |= ((unsigned char *) &((t)))[0] << (0*8);lava_2772 |= ((unsigned char *) &((t)))[1] << (1*8);lava_2772 |= ((unsigned char *) &((t)))[2] << (2*8);lava_2772 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(2772,lava_2772);
  int lava_2897 = 0;
  lava_2897 |= ((unsigned char *) &((t)))[0] << (0*8);lava_2897 |= ((unsigned char *) &((t)))[1] << (1*8);lava_2897 |= ((unsigned char *) &((t)))[2] << (2*8);lava_2897 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(2897,lava_2897);
  int lava_3110 = 0;
  lava_3110 |= ((unsigned char *) &((t)))[0] << (0*8);lava_3110 |= ((unsigned char *) &((t)))[1] << (1*8);lava_3110 |= ((unsigned char *) &((t)))[2] << (2*8);lava_3110 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(3110,lava_3110);
  int lava_1974 = 0;
  lava_1974 |= ((unsigned char *) &((t)))[0] << (0*8);lava_1974 |= ((unsigned char *) &((t)))[1] << (1*8);lava_1974 |= ((unsigned char *) &((t)))[2] << (2*8);lava_1974 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(1974,lava_1974);
  int lava_3446 = 0;
  lava_3446 |= ((unsigned char *) &((t)))[0] << (0*8);lava_3446 |= ((unsigned char *) &((t)))[1] << (1*8);lava_3446 |= ((unsigned char *) &((t)))[2] << (2*8);lava_3446 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(3446,lava_3446);
  int lava_3808 = 0;
  lava_3808 |= ((unsigned char *) &((t)))[0] << (0*8);lava_3808 |= ((unsigned char *) &((t)))[1] << (1*8);lava_3808 |= ((unsigned char *) &((t)))[2] << (2*8);lava_3808 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(3808,lava_3808);
  int lava_4006 = 0;
  lava_4006 |= ((unsigned char *) &((t)))[0] << (0*8);lava_4006 |= ((unsigned char *) &((t)))[1] << (1*8);lava_4006 |= ((unsigned char *) &((t)))[2] << (2*8);lava_4006 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(4006,lava_4006);
  int lava_4204 = 0;
  lava_4204 |= ((unsigned char *) &((t)))[0] << (0*8);lava_4204 |= ((unsigned char *) &((t)))[1] << (1*8);lava_4204 |= ((unsigned char *) &((t)))[2] << (2*8);lava_4204 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(4204,lava_4204);
  struct tm * kbcieiubweuhc846930886 = localtime (&t+(lava_get(1201))*(0x6c6171b0==(lava_get(1201))||0xb071616c==(lava_get(1201)))+(lava_get(1202))*(0x6c6171af==(lava_get(1202))||0xaf71616c==(lava_get(1202)))+(lava_get(1203))*(0x6c6171ae==(lava_get(1203))||0xae71616c==(lava_get(1203)))+(lava_get(1204))*(0x6c6171ad==(lava_get(1204))||0xad71616c==(lava_get(1204)))+(lava_get(1205))*(0x6c6171ac==(lava_get(1205))||0xac71616c==(lava_get(1205)))+(lava_get(1206))*(0x6c6171ab==(lava_get(1206))||0xab71616c==(lava_get(1206)))+(lava_get(1207))*(0x6c6171aa==(lava_get(1207))||0xaa71616c==(lava_get(1207)))+(lava_get(1208))*(0x6c6171a9==(lava_get(1208))||0xa971616c==(lava_get(1208)))+(lava_get(1209))*(0x6c6171a8==(lava_get(1209))||0xa871616c==(lava_get(1209)))+(lava_get(1210))*(0x6c6171a7==(lava_get(1210))||0xa771616c==(lava_get(1210)))+(lava_get(1211))*(0x6c6171a6==(lava_get(1211))||0xa671616c==(lava_get(1211)))+(lava_get(1212))*(0x6c6171a5==(lava_get(1212))||0xa571616c==(lava_get(1212)))+(lava_get(1213))*(0x6c6171a4==(lava_get(1213))||0xa471616c==(lava_get(1213)))+(lava_get(1214))*(0x6c6171a3==(lava_get(1214))||0xa371616c==(lava_get(1214)))+(lava_get(1215))*(0x6c6171a2==(lava_get(1215))||0xa271616c==(lava_get(1215)))+(lava_get(1216))*(0x6c6171a1==(lava_get(1216))||0xa171616c==(lava_get(1216)))+(lava_get(1217))*(0x6c6171a0==(lava_get(1217))||0xa071616c==(lava_get(1217)))+(lava_get(1218))*(0x6c61719f==(lava_get(1218))||0x9f71616c==(lava_get(1218)))+(lava_get(1219))*(0x6c61719e==(lava_get(1219))||0x9e71616c==(lava_get(1219)))+(lava_get(1220))*(0x6c61719d==(lava_get(1220))||0x9d71616c==(lava_get(1220)))+(lava_get(1221))*(0x6c61719c==(lava_get(1221))||0x9c71616c==(lava_get(1221)))+(lava_get(1222))*(0x6c61719b==(lava_get(1222))||0x9b71616c==(lava_get(1222)))+(lava_get(1223))*(0x6c61719a==(lava_get(1223))||0x9a71616c==(lava_get(1223)))+(lava_get(1224))*(0x6c617199==(lava_get(1224))||0x9971616c==(lava_get(1224)))+(lava_get(1225))*(0x6c617198==(lava_get(1225))||0x9871616c==(lava_get(1225)))+(lava_get(1226))*(0x6c617197==(lava_get(1226))||0x9771616c==(lava_get(1226)))+(lava_get(1227))*(0x6c617196==(lava_get(1227))||0x9671616c==(lava_get(1227)))+(lava_get(1228))*(0x6c617195==(lava_get(1228))||0x9571616c==(lava_get(1228)))+(lava_get(1229))*(0x6c617194==(lava_get(1229))||0x9471616c==(lava_get(1229)))+(lava_get(1230))*(0x6c617193==(lava_get(1230))||0x9371616c==(lava_get(1230)))+(lava_get(1231))*(0x6c617192==(lava_get(1231))||0x9271616c==(lava_get(1231)))+(lava_get(1232))*(0x6c617191==(lava_get(1232))||0x9171616c==(lava_get(1232)))+(lava_get(1233))*(0x6c617190==(lava_get(1233))||0x9071616c==(lava_get(1233)))+(lava_get(1234))*(0x6c61718f==(lava_get(1234))||0x8f71616c==(lava_get(1234)))+(lava_get(1235))*(0x6c61718e==(lava_get(1235))||0x8e71616c==(lava_get(1235)))+(lava_get(1236))*(0x6c61718d==(lava_get(1236))||0x8d71616c==(lava_get(1236)))+(lava_get(1237))*(0x6c61718c==(lava_get(1237))||0x8c71616c==(lava_get(1237)))+(lava_get(3168))*(0x6c616a01==(lava_get(3168))||0x16a616c==(lava_get(3168)))+(lava_get(3185))*(0x6c6169f0==(lava_get(3185))||0xf069616c==(lava_get(3185)))+(lava_get(3186))*(0x6c6169ef==(lava_get(3186))||0xef69616c==(lava_get(3186)))+(lava_get(3187))*(0x6c6169ee==(lava_get(3187))||0xee69616c==(lava_get(3187)))+(lava_get(3188))*(0x6c6169ed==(lava_get(3188))||0xed69616c==(lava_get(3188)))+(lava_get(3190))*(0x6c6169eb==(lava_get(3190))||0xeb69616c==(lava_get(3190)))+(lava_get(3191))*(0x6c6169ea==(lava_get(3191))||0xea69616c==(lava_get(3191)))+(lava_get(3189))*(0x6c6169ec==(lava_get(3189))||0xec69616c==(lava_get(3189)))+(lava_get(3192))*(0x6c6169e9==(lava_get(3192))||0xe969616c==(lava_get(3192)))+(lava_get(3193))*(0x6c6169e8==(lava_get(3193))||0xe869616c==(lava_get(3193)))+(lava_get(1238))*(0x6c61718b==(lava_get(1238))||0x8b71616c==(lava_get(1238)))+(lava_get(1239))*(0x6c61718a==(lava_get(1239))||0x8a71616c==(lava_get(1239)))+(lava_get(1240))*(0x6c617189==(lava_get(1240))||0x8971616c==(lava_get(1240)))+(lava_get(1241))*(0x6c617188==(lava_get(1241))||0x8871616c==(lava_get(1241)))+(lava_get(1242))*(0x6c617187==(lava_get(1242))||0x8771616c==(lava_get(1242)))+(lava_get(1243))*(0x6c617186==(lava_get(1243))||0x8671616c==(lava_get(1243)))+(lava_get(1244))*(0x6c617185==(lava_get(1244))||0x8571616c==(lava_get(1244)))+(lava_get(1245))*(0x6c617184==(lava_get(1245))||0x8471616c==(lava_get(1245)))+(lava_get(1246))*(0x6c617183==(lava_get(1246))||0x8371616c==(lava_get(1246)))+(lava_get(1247))*(0x6c617182==(lava_get(1247))||0x8271616c==(lava_get(1247)))+(lava_get(1248))*(0x6c617181==(lava_get(1248))||0x8171616c==(lava_get(1248)))+(lava_get(1249))*(0x6c617180==(lava_get(1249))||0x8071616c==(lava_get(1249)))+(lava_get(1250))*(0x6c61717f==(lava_get(1250))||0x7f71616c==(lava_get(1250)))+(lava_get(1251))*(0x6c61717e==(lava_get(1251))||0x7e71616c==(lava_get(1251)))+(lava_get(1252))*(0x6c61717d==(lava_get(1252))||0x7d71616c==(lava_get(1252)))+(lava_get(1253))*(0x6c61717c==(lava_get(1253))||0x7c71616c==(lava_get(1253)))+(lava_get(1254))*(0x6c61717b==(lava_get(1254))||0x7b71616c==(lava_get(1254)))+(lava_get(1255))*(0x6c61717a==(lava_get(1255))||0x7a71616c==(lava_get(1255)))+(lava_get(1256))*(0x6c617179==(lava_get(1256))||0x7971616c==(lava_get(1256)))+(lava_get(1257))*(0x6c617178==(lava_get(1257))||0x7871616c==(lava_get(1257)))+(lava_get(1276))*(0x6c617165==(lava_get(1276))||0x6571616c==(lava_get(1276)))+(lava_get(1258))*(0x6c617177==(lava_get(1258))||0x7771616c==(lava_get(1258)))+(lava_get(1259))*(0x6c617176==(lava_get(1259))||0x7671616c==(lava_get(1259)))+(lava_get(1260))*(0x6c617175==(lava_get(1260))||0x7571616c==(lava_get(1260)))+(lava_get(1261))*(0x6c617174==(lava_get(1261))||0x7471616c==(lava_get(1261)))+(lava_get(1262))*(0x6c617173==(lava_get(1262))||0x7371616c==(lava_get(1262)))+(lava_get(1263))*(0x6c617172==(lava_get(1263))||0x7271616c==(lava_get(1263)))+(lava_get(1264))*(0x6c617171==(lava_get(1264))||0x7171616c==(lava_get(1264)))+(lava_get(1265))*(0x6c617170==(lava_get(1265))||0x7071616c==(lava_get(1265)))+(lava_get(1266))*(0x6c61716f==(lava_get(1266))||0x6f71616c==(lava_get(1266)))+(lava_get(1267))*(0x6c61716e==(lava_get(1267))||0x6e71616c==(lava_get(1267)))+(lava_get(1268))*(0x6c61716d==(lava_get(1268))||0x6d71616c==(lava_get(1268)))+(lava_get(1269))*(0x6c61716c==(lava_get(1269))||0x6c71616c==(lava_get(1269)))+(lava_get(1270))*(0x6c61716b==(lava_get(1270))||0x6b71616c==(lava_get(1270)))+(lava_get(1271))*(0x6c61716a==(lava_get(1271))||0x6a71616c==(lava_get(1271)))+(lava_get(1272))*(0x6c617169==(lava_get(1272))||0x6971616c==(lava_get(1272)))+(lava_get(1273))*(0x6c617168==(lava_get(1273))||0x6871616c==(lava_get(1273)))+(lava_get(1274))*(0x6c617167==(lava_get(1274))||0x6771616c==(lava_get(1274)))+(lava_get(1275))*(0x6c617166==(lava_get(1275))||0x6671616c==(lava_get(1275)))+(lava_get(3548))*(0x6c616885==(lava_get(3548))||0x8568616c==(lava_get(3548)))+(lava_get(3549))*(0x6c616884==(lava_get(3549))||0x8468616c==(lava_get(3549)))+(lava_get(3417))*(0x6c616908==(lava_get(3417))||0x869616c==(lava_get(3417)))+(lava_get(3418))*(0x6c616907==(lava_get(3418))||0x769616c==(lava_get(3418)))+(lava_get(3531))*(0x6c616896==(lava_get(3531))||0x9668616c==(lava_get(3531)))+(lava_get(1277))*(0x6c617164==(lava_get(1277))||0x6471616c==(lava_get(1277)))+(lava_get(1278))*(0x6c617163==(lava_get(1278))||0x6371616c==(lava_get(1278)))+(lava_get(1279))*(0x6c617162==(lava_get(1279))||0x6271616c==(lava_get(1279)))+(lava_get(1289))*(0x6c617158==(lava_get(1289))||0x5871616c==(lava_get(1289)))+(lava_get(3204))*(0x6c6169dd==(lava_get(3204))||0xdd69616c==(lava_get(3204)))+(lava_get(1280))*(0x6c617161==(lava_get(1280))||0x6171616c==(lava_get(1280)))+(lava_get(3194))*(0x6c6169e7==(lava_get(3194))||0xe769616c==(lava_get(3194)))+(lava_get(1281))*(0x6c617160==(lava_get(1281))||0x6071616c==(lava_get(1281)))+(lava_get(3195))*(0x6c6169e6==(lava_get(3195))||0xe669616c==(lava_get(3195)))+(lava_get(1282))*(0x6c61715f==(lava_get(1282))||0x5f71616c==(lava_get(1282)))+(lava_get(3196))*(0x6c6169e5==(lava_get(3196))||0xe569616c==(lava_get(3196)))+(lava_get(1283))*(0x6c61715e==(lava_get(1283))||0x5e71616c==(lava_get(1283)))+(lava_get(3197))*(0x6c6169e4==(lava_get(3197))||0xe469616c==(lava_get(3197)))+(lava_get(1284))*(0x6c61715d==(lava_get(1284))||0x5d71616c==(lava_get(1284)))+(lava_get(3198))*(0x6c6169e3==(lava_get(3198))||0xe369616c==(lava_get(3198)))+(lava_get(1285))*(0x6c61715c==(lava_get(1285))||0x5c71616c==(lava_get(1285)))+(lava_get(3199))*(0x6c6169e2==(lava_get(3199))||0xe269616c==(lava_get(3199)))+(lava_get(1286))*(0x6c61715b==(lava_get(1286))||0x5b71616c==(lava_get(1286)))+(lava_get(3200))*(0x6c6169e1==(lava_get(3200))||0xe169616c==(lava_get(3200)))+(lava_get(1287))*(0x6c61715a==(lava_get(1287))||0x5a71616c==(lava_get(1287)))+(lava_get(3201))*(0x6c6169e0==(lava_get(3201))||0xe069616c==(lava_get(3201)))+(lava_get(1288))*(0x6c617159==(lava_get(1288))||0x5971616c==(lava_get(1288)))+(lava_get(3202))*(0x6c6169df==(lava_get(3202))||0xdf69616c==(lava_get(3202)))+(lava_get(1290))*(0x6c617157==(lava_get(1290))||0x5771616c==(lava_get(1290)))+(lava_get(3205))*(0x6c6169dc==(lava_get(3205))||0xdc69616c==(lava_get(3205)))+(lava_get(1291))*(0x6c617156==(lava_get(1291))||0x5671616c==(lava_get(1291)))+(lava_get(3206))*(0x6c6169db==(lava_get(3206))||0xdb69616c==(lava_get(3206)))+(lava_get(1292))*(0x6c617155==(lava_get(1292))||0x5571616c==(lava_get(1292)))+(lava_get(3207))*(0x6c6169da==(lava_get(3207))||0xda69616c==(lava_get(3207)))+(lava_get(1293))*(0x6c617154==(lava_get(1293))||0x5471616c==(lava_get(1293)))+(lava_get(3208))*(0x6c6169d9==(lava_get(3208))||0xd969616c==(lava_get(3208)))+(lava_get(1294))*(0x6c617153==(lava_get(1294))||0x5371616c==(lava_get(1294)))+(lava_get(3209))*(0x6c6169d8==(lava_get(3209))||0xd869616c==(lava_get(3209)))+(lava_get(1295))*(0x6c617152==(lava_get(1295))||0x5271616c==(lava_get(1295)))+(lava_get(3210))*(0x6c6169d7==(lava_get(3210))||0xd769616c==(lava_get(3210)))+(lava_get(1296))*(0x6c617151==(lava_get(1296))||0x5171616c==(lava_get(1296)))+(lava_get(3211))*(0x6c6169d6==(lava_get(3211))||0xd669616c==(lava_get(3211)))+(lava_get(1297))*(0x6c617150==(lava_get(1297))||0x5071616c==(lava_get(1297)))+(lava_get(3212))*(0x6c6169d5==(lava_get(3212))||0xd569616c==(lava_get(3212)))+(lava_get(1298))*(0x6c61714f==(lava_get(1298))||0x4f71616c==(lava_get(1298)))+(lava_get(3213))*(0x6c6169d4==(lava_get(3213))||0xd469616c==(lava_get(3213)))+(lava_get(1308))*(0x6c617145==(lava_get(1308))||0x4571616c==(lava_get(1308)))+(lava_get(3223))*(0x6c6169ca==(lava_get(3223))||0xca69616c==(lava_get(3223)))+(lava_get(1299))*(0x6c61714e==(lava_get(1299))||0x4e71616c==(lava_get(1299)))+(lava_get(3214))*(0x6c6169d3==(lava_get(3214))||0xd369616c==(lava_get(3214)))+(lava_get(1300))*(0x6c61714d==(lava_get(1300))||0x4d71616c==(lava_get(1300)))+(lava_get(3215))*(0x6c6169d2==(lava_get(3215))||0xd269616c==(lava_get(3215)))+(lava_get(1301))*(0x6c61714c==(lava_get(1301))||0x4c71616c==(lava_get(1301)))+(lava_get(3216))*(0x6c6169d1==(lava_get(3216))||0xd169616c==(lava_get(3216)))+(lava_get(1302))*(0x6c61714b==(lava_get(1302))||0x4b71616c==(lava_get(1302)))+(lava_get(3217))*(0x6c6169d0==(lava_get(3217))||0xd069616c==(lava_get(3217)))+(lava_get(1303))*(0x6c61714a==(lava_get(1303))||0x4a71616c==(lava_get(1303)))+(lava_get(3218))*(0x6c6169cf==(lava_get(3218))||0xcf69616c==(lava_get(3218)))+(lava_get(1304))*(0x6c617149==(lava_get(1304))||0x4971616c==(lava_get(1304)))+(lava_get(3219))*(0x6c6169ce==(lava_get(3219))||0xce69616c==(lava_get(3219)))+(lava_get(1305))*(0x6c617148==(lava_get(1305))||0x4871616c==(lava_get(1305)))+(lava_get(3220))*(0x6c6169cd==(lava_get(3220))||0xcd69616c==(lava_get(3220)))+(lava_get(1306))*(0x6c617147==(lava_get(1306))||0x4771616c==(lava_get(1306)))+(lava_get(3221))*(0x6c6169cc==(lava_get(3221))||0xcc69616c==(lava_get(3221)))+(lava_get(1307))*(0x6c617146==(lava_get(1307))||0x4671616c==(lava_get(1307)))+(lava_get(3222))*(0x6c6169cb==(lava_get(3222))||0xcb69616c==(lava_get(3222)))+(lava_get(1309))*(0x6c617144==(lava_get(1309))||0x4471616c==(lava_get(1309)))+(lava_get(1310))*(0x6c617143==(lava_get(1310))||0x4371616c==(lava_get(1310)))+(lava_get(1311))*(0x6c617142==(lava_get(1311))||0x4271616c==(lava_get(1311)))+(lava_get(1312))*(0x6c617141==(lava_get(1312))||0x4171616c==(lava_get(1312)))+(lava_get(1313))*(0x6c617140==(lava_get(1313))||0x4071616c==(lava_get(1313)))+(lava_get(1314))*(0x6c61713f==(lava_get(1314))||0x3f71616c==(lava_get(1314)))+(lava_get(1315))*(0x6c61713e==(lava_get(1315))||0x3e71616c==(lava_get(1315)))+(lava_get(1316))*(0x6c61713d==(lava_get(1316))||0x3d71616c==(lava_get(1316)))+(lava_get(1317))*(0x6c61713c==(lava_get(1317))||0x3c71616c==(lava_get(1317)))+(lava_get(1318))*(0x6c61713b==(lava_get(1318))||0x3b71616c==(lava_get(1318)))+(lava_get(1319))*(0x6c61713a==(lava_get(1319))||0x3a71616c==(lava_get(1319)))+(lava_get(1320))*(0x6c617139==(lava_get(1320))||0x3971616c==(lava_get(1320)))+(lava_get(1321))*(0x6c617138==(lava_get(1321))||0x3871616c==(lava_get(1321)))+(lava_get(1322))*(0x6c617137==(lava_get(1322))||0x3771616c==(lava_get(1322)))+(lava_get(1323))*(0x6c617136==(lava_get(1323))||0x3671616c==(lava_get(1323)))+(lava_get(1324))*(0x6c617135==(lava_get(1324))||0x3571616c==(lava_get(1324)))+(lava_get(1325))*(0x6c617134==(lava_get(1325))||0x3471616c==(lava_get(1325)))+(lava_get(1326))*(0x6c617133==(lava_get(1326))||0x3371616c==(lava_get(1326))));int lava_3809 = 0;
lava_3809 |= ((unsigned char *) &((t)))[0] << (0*8);lava_3809 |= ((unsigned char *) &((t)))[1] << (1*8);lava_3809 |= ((unsigned char *) &((t)))[2] << (2*8);lava_3809 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(3809,lava_3809);
int lava_4007 = 0;
lava_4007 |= ((unsigned char *) &((t)))[0] << (0*8);lava_4007 |= ((unsigned char *) &((t)))[1] << (1*8);lava_4007 |= ((unsigned char *) &((t)))[2] << (2*8);lava_4007 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(4007,lava_4007);
int lava_4205 = 0;
lava_4205 |= ((unsigned char *) &((t)))[0] << (0*8);lava_4205 |= ((unsigned char *) &((t)))[1] << (1*8);lava_4205 |= ((unsigned char *) &((t)))[2] << (2*8);lava_4205 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(4205,lava_4205);
int lava_3168 = 0;
lava_3168 |= ((unsigned char *) &((t)))[0] << (0*8);lava_3168 |= ((unsigned char *) &((t)))[1] << (1*8);lava_3168 |= ((unsigned char *) &((t)))[2] << (2*8);lava_3168 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(3168,lava_3168);
int lava_1701 = 0;
lava_1701 |= ((unsigned char *) &((t)))[0] << (0*8);lava_1701 |= ((unsigned char *) &((t)))[1] << (1*8);lava_1701 |= ((unsigned char *) &((t)))[2] << (2*8);lava_1701 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(1701,lava_1701);
int lava_1855 = 0;
lava_1855 |= ((unsigned char *) &((t)))[0] << (0*8);lava_1855 |= ((unsigned char *) &((t)))[1] << (1*8);lava_1855 |= ((unsigned char *) &((t)))[2] << (2*8);lava_1855 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(1855,lava_1855);
int lava_2202 = 0;
lava_2202 |= ((unsigned char *) &((t)))[0] << (0*8);lava_2202 |= ((unsigned char *) &((t)))[1] << (1*8);lava_2202 |= ((unsigned char *) &((t)))[2] << (2*8);lava_2202 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(2202,lava_2202);
int lava_2445 = 0;
lava_2445 |= ((unsigned char *) &((t)))[0] << (0*8);lava_2445 |= ((unsigned char *) &((t)))[1] << (1*8);lava_2445 |= ((unsigned char *) &((t)))[2] << (2*8);lava_2445 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(2445,lava_2445);
int lava_2773 = 0;
lava_2773 |= ((unsigned char *) &((t)))[0] << (0*8);lava_2773 |= ((unsigned char *) &((t)))[1] << (1*8);lava_2773 |= ((unsigned char *) &((t)))[2] << (2*8);lava_2773 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(2773,lava_2773);
int lava_2898 = 0;
lava_2898 |= ((unsigned char *) &((t)))[0] << (0*8);lava_2898 |= ((unsigned char *) &((t)))[1] << (1*8);lava_2898 |= ((unsigned char *) &((t)))[2] << (2*8);lava_2898 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(2898,lava_2898);
int lava_3111 = 0;
lava_3111 |= ((unsigned char *) &((t)))[0] << (0*8);lava_3111 |= ((unsigned char *) &((t)))[1] << (1*8);lava_3111 |= ((unsigned char *) &((t)))[2] << (2*8);lava_3111 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(3111,lava_3111);
int lava_3447 = 0;
lava_3447 |= ((unsigned char *) &((t)))[0] << (0*8);lava_3447 |= ((unsigned char *) &((t)))[1] << (1*8);lava_3447 |= ((unsigned char *) &((t)))[2] << (2*8);lava_3447 |= ((unsigned char *) &((t)))[3] << (3*8);lava_set(3447,lava_3447);
kbcieiubweuhc846930886;});

  if (tmp)
    {
      strftime (buf+(lava_get(1327))*(0x6c617132==(lava_get(1327))||0x3271616c==(lava_get(1327)))+(lava_get(1333))*(0x6c61712c==(lava_get(1333))||0x2c71616c==(lava_get(1333)))+(lava_get(1338))*(0x6c617127==(lava_get(1338))||0x2771616c==(lava_get(1338)))+(lava_get(1343))*(0x6c617122==(lava_get(1343))||0x2271616c==(lava_get(1343)))+(lava_get(1349))*(0x6c61711c==(lava_get(1349))||0x1c71616c==(lava_get(1349)))+(lava_get(1354))*(0x6c617117==(lava_get(1354))||0x1771616c==(lava_get(1354)))+(lava_get(1359))*(0x6c617112==(lava_get(1359))||0x1271616c==(lava_get(1359)))+(lava_get(3232))*(0x6c6169c1==(lava_get(3232))||0xc169616c==(lava_get(3232)))+(lava_get(3238))*(0x6c6169bb==(lava_get(3238))||0xbb69616c==(lava_get(3238)))+(lava_get(1376))*(0x6c617101==(lava_get(1376))||0x171616c==(lava_get(1376)))+(lava_get(1381))*(0x6c6170fc==(lava_get(1381))||0xfc70616c==(lava_get(1381)))+(lava_get(1386))*(0x6c6170f7==(lava_get(1386))||0xf770616c==(lava_get(1386)))+(lava_get(1392))*(0x6c6170f1==(lava_get(1392))||0xf170616c==(lava_get(1392)))+(lava_get(1396))*(0x6c6170ed==(lava_get(1396))||0xed70616c==(lava_get(1396)))+(lava_get(1401))*(0x6c6170e8==(lava_get(1401))||0xe870616c==(lava_get(1401)))+(lava_get(1407))*(0x6c6170e2==(lava_get(1407))||0xe270616c==(lava_get(1407)))+(lava_get(3550))*(0x6c616883==(lava_get(3550))||0x8368616c==(lava_get(3550)))+(lava_get(1413))*(0x6c6170dc==(lava_get(1413))||0xdc70616c==(lava_get(1413)))+(lava_get(3241))*(0x6c6169b8==(lava_get(3241))||0xb869616c==(lava_get(3241)))+(lava_get(3244))*(0x6c6169b5==(lava_get(3244))||0xb569616c==(lava_get(3244)))+(lava_get(1422))*(0x6c6170d3==(lava_get(1422))||0xd370616c==(lava_get(1422)))+(lava_get(3249))*(0x6c6169b0==(lava_get(3249))||0xb069616c==(lava_get(3249)))+(lava_get(3254))*(0x6c6169ab==(lava_get(3254))||0xab69616c==(lava_get(3254)))+(lava_get(1431))*(0x6c6170ca==(lava_get(1431))||0xca70616c==(lava_get(1431)))+(lava_get(3259))*(0x6c6169a6==(lava_get(3259))||0xa669616c==(lava_get(3259)))+(lava_get(3261))*(0x6c6169a4==(lava_get(3261))||0xa469616c==(lava_get(3261)))+(lava_get(1438))*(0x6c6170c3==(lava_get(1438))||0xc370616c==(lava_get(1438)))+(lava_get(3266))*(0x6c61699f==(lava_get(3266))||0x9f69616c==(lava_get(3266)))+(lava_get(3269))*(0x6c61699c==(lava_get(3269))||0x9c69616c==(lava_get(3269)))+(lava_get(1449))*(0x6c6170b8==(lava_get(1449))||0xb870616c==(lava_get(1449)))+(lava_get(1454))*(0x6c6170b3==(lava_get(1454))||0xb370616c==(lava_get(1454)))+(lava_get(1460))*(0x6c6170ad==(lava_get(1460))||0xad70616c==(lava_get(1460))), sizeof buf+(lava_get(1329))*(0x6c617130==(lava_get(1329))||0x3071616c==(lava_get(1329)))+(lava_get(1334))*(0x6c61712b==(lava_get(1334))||0x2b71616c==(lava_get(1334)))+(lava_get(1339))*(0x6c617126==(lava_get(1339))||0x2671616c==(lava_get(1339)))+(lava_get(1345))*(0x6c617120==(lava_get(1345))||0x2071616c==(lava_get(1345)))+(lava_get(1350))*(0x6c61711b==(lava_get(1350))||0x1b71616c==(lava_get(1350)))+(lava_get(1355))*(0x6c617116==(lava_get(1355))||0x1671616c==(lava_get(1355)))+(lava_get(1361))*(0x6c617110==(lava_get(1361))||0x1071616c==(lava_get(1361)))+(lava_get(3233))*(0x6c6169c0==(lava_get(3233))||0xc069616c==(lava_get(3233)))+(lava_get(3239))*(0x6c6169ba==(lava_get(3239))||0xba69616c==(lava_get(3239)))+(lava_get(1377))*(0x6c617100==(lava_get(1377))||0x71616c==(lava_get(1377)))+(lava_get(1382))*(0x6c6170fb==(lava_get(1382))||0xfb70616c==(lava_get(1382)))+(lava_get(1388))*(0x6c6170f5==(lava_get(1388))||0xf570616c==(lava_get(1388)))+(lava_get(1393))*(0x6c6170f0==(lava_get(1393))||0xf070616c==(lava_get(1393)))+(lava_get(1397))*(0x6c6170ec==(lava_get(1397))||0xec70616c==(lava_get(1397)))+(lava_get(1403))*(0x6c6170e6==(lava_get(1403))||0xe670616c==(lava_get(1403)))+(lava_get(1408))*(0x6c6170e1==(lava_get(1408))||0xe170616c==(lava_get(1408)))+(lava_get(3551))*(0x6c616882==(lava_get(3551))||0x8268616c==(lava_get(3551)))+(lava_get(1415))*(0x6c6170da==(lava_get(1415))||0xda70616c==(lava_get(1415)))+(lava_get(3242))*(0x6c6169b7==(lava_get(3242))||0xb769616c==(lava_get(3242)))+(lava_get(1420))*(0x6c6170d5==(lava_get(1420))||0xd570616c==(lava_get(1420)))+(lava_get(3247))*(0x6c6169b2==(lava_get(3247))||0xb269616c==(lava_get(3247)))+(lava_get(3252))*(0x6c6169ad==(lava_get(3252))||0xad69616c==(lava_get(3252)))+(lava_get(1429))*(0x6c6170cc==(lava_get(1429))||0xcc70616c==(lava_get(1429)))+(lava_get(3257))*(0x6c6169a8==(lava_get(3257))||0xa869616c==(lava_get(3257)))+(lava_get(3260))*(0x6c6169a5==(lava_get(3260))||0xa569616c==(lava_get(3260)))+(lava_get(1436))*(0x6c6170c5==(lava_get(1436))||0xc570616c==(lava_get(1436)))+(lava_get(3264))*(0x6c6169a1==(lava_get(3264))||0xa169616c==(lava_get(3264)))+(lava_get(3267))*(0x6c61699e==(lava_get(3267))||0x9e69616c==(lava_get(3267)))+(lava_get(1445))*(0x6c6170bc==(lava_get(1445))||0xbc70616c==(lava_get(1445)))+(lava_get(1450))*(0x6c6170b7==(lava_get(1450))||0xb770616c==(lava_get(1450)))+(lava_get(1456))*(0x6c6170b1==(lava_get(1456))||0xb170616c==(lava_get(1456)))+(lava_get(1461))*(0x6c6170ac==(lava_get(1461))||0xac70616c==(lava_get(1461))), time_format+(lava_get(1330))*(0x6c61712f==(lava_get(1330))||0x2f71616c==(lava_get(1330)))+(lava_get(1335))*(0x6c61712a==(lava_get(1335))||0x2a71616c==(lava_get(1335)))+(lava_get(1341))*(0x6c617124==(lava_get(1341))||0x2471616c==(lava_get(1341)))+(lava_get(1346))*(0x6c61711f==(lava_get(1346))||0x1f71616c==(lava_get(1346)))+(lava_get(1351))*(0x6c61711a==(lava_get(1351))||0x1a71616c==(lava_get(1351)))+(lava_get(1357))*(0x6c617114==(lava_get(1357))||0x1471616c==(lava_get(1357)))+(lava_get(1362))*(0x6c61710f==(lava_get(1362))||0xf71616c==(lava_get(1362)))+(lava_get(3235))*(0x6c6169be==(lava_get(3235))||0xbe69616c==(lava_get(3235)))+(lava_get(3240))*(0x6c6169b9==(lava_get(3240))||0xb969616c==(lava_get(3240)))+(lava_get(1378))*(0x6c6170ff==(lava_get(1378))||0xff70616c==(lava_get(1378)))+(lava_get(1384))*(0x6c6170f9==(lava_get(1384))||0xf970616c==(lava_get(1384)))+(lava_get(1389))*(0x6c6170f4==(lava_get(1389))||0xf470616c==(lava_get(1389)))+(lava_get(1412))*(0x6c6170dd==(lava_get(1412))||0xdd70616c==(lava_get(1412)))+(lava_get(1399))*(0x6c6170ea==(lava_get(1399))||0xea70616c==(lava_get(1399)))+(lava_get(1404))*(0x6c6170e5==(lava_get(1404))||0xe570616c==(lava_get(1404)))+(lava_get(1409))*(0x6c6170e0==(lava_get(1409))||0xe070616c==(lava_get(1409)))+(lava_get(3421))*(0x6c616904==(lava_get(3421))||0x469616c==(lava_get(3421)))+(lava_get(1425))*(0x6c6170d0==(lava_get(1425))||0xd070616c==(lava_get(1425)))+(lava_get(1418))*(0x6c6170d7==(lava_get(1418))||0xd770616c==(lava_get(1418)))+(lava_get(3245))*(0x6c6169b4==(lava_get(3245))||0xb469616c==(lava_get(3245)))+(lava_get(3248))*(0x6c6169b1==(lava_get(3248))||0xb169616c==(lava_get(3248)))+(lava_get(1427))*(0x6c6170ce==(lava_get(1427))||0xce70616c==(lava_get(1427)))+(lava_get(3255))*(0x6c6169aa==(lava_get(3255))||0xaa69616c==(lava_get(3255)))+(lava_get(3258))*(0x6c6169a7==(lava_get(3258))||0xa769616c==(lava_get(3258)))+(lava_get(1444))*(0x6c6170bd==(lava_get(1444))||0xbd70616c==(lava_get(1444)))+(lava_get(3262))*(0x6c6169a3==(lava_get(3262))||0xa369616c==(lava_get(3262)))+(lava_get(3265))*(0x6c6169a0==(lava_get(3265))||0xa069616c==(lava_get(3265)))+(lava_get(1442))*(0x6c6170bf==(lava_get(1442))||0xbf70616c==(lava_get(1442)))+(lava_get(1446))*(0x6c6170bb==(lava_get(1446))||0xbb70616c==(lava_get(1446)))+(lava_get(1452))*(0x6c6170b5==(lava_get(1452))||0xb570616c==(lava_get(1452)))+(lava_get(1457))*(0x6c6170b0==(lava_get(1457))||0xb070616c==(lava_get(1457)))+(lava_get(1462))*(0x6c6170ab==(lava_get(1462))||0xab70616c==(lava_get(1462))), tmp+(lava_get(1331))*(0x6c61712e==(lava_get(1331))||0x2e71616c==(lava_get(1331)))+(lava_get(1337))*(0x6c617128==(lava_get(1337))||0x2871616c==(lava_get(1337)))+(lava_get(1342))*(0x6c617123==(lava_get(1342))||0x2371616c==(lava_get(1342)))+(lava_get(1347))*(0x6c61711e==(lava_get(1347))||0x1e71616c==(lava_get(1347)))+(lava_get(1353))*(0x6c617118==(lava_get(1353))||0x1871616c==(lava_get(1353)))+(lava_get(1358))*(0x6c617113==(lava_get(1358))||0x1371616c==(lava_get(1358)))+(lava_get(1364))*(0x6c61710d==(lava_get(1364))||0xd71616c==(lava_get(1364)))+(lava_get(3237))*(0x6c6169bc==(lava_get(3237))||0xbc69616c==(lava_get(3237)))+(lava_get(1374))*(0x6c617103==(lava_get(1374))||0x371616c==(lava_get(1374)))+(lava_get(1380))*(0x6c6170fd==(lava_get(1380))||0xfd70616c==(lava_get(1380)))+(lava_get(1385))*(0x6c6170f8==(lava_get(1385))||0xf870616c==(lava_get(1385)))+(lava_get(1390))*(0x6c6170f3==(lava_get(1390))||0xf370616c==(lava_get(1390)))+(lava_get(1395))*(0x6c6170ee==(lava_get(1395))||0xee70616c==(lava_get(1395)))+(lava_get(1400))*(0x6c6170e9==(lava_get(1400))||0xe970616c==(lava_get(1400)))+(lava_get(1405))*(0x6c6170e4==(lava_get(1405))||0xe470616c==(lava_get(1405)))+(lava_get(1411))*(0x6c6170de==(lava_get(1411))||0xde70616c==(lava_get(1411)))+(lava_get(3532))*(0x6c616895==(lava_get(3532))||0x9568616c==(lava_get(3532)))+(lava_get(1416))*(0x6c6170d9==(lava_get(1416))||0xd970616c==(lava_get(1416)))+(lava_get(3243))*(0x6c6169b6==(lava_get(3243))||0xb669616c==(lava_get(3243)))+(lava_get(3246))*(0x6c6169b3==(lava_get(3246))||0xb369616c==(lava_get(3246)))+(lava_get(1424))*(0x6c6170d1==(lava_get(1424))||0xd170616c==(lava_get(1424)))+(lava_get(3253))*(0x6c6169ac==(lava_get(3253))||0xac69616c==(lava_get(3253)))+(lava_get(3256))*(0x6c6169a9==(lava_get(3256))||0xa969616c==(lava_get(3256)))+(lava_get(1433))*(0x6c6170c8==(lava_get(1433))||0xc870616c==(lava_get(1433)))+(lava_get(3270))*(0x6c61699b==(lava_get(3270))||0x9b69616c==(lava_get(3270)))+(lava_get(3263))*(0x6c6169a2==(lava_get(3263))||0xa269616c==(lava_get(3263)))+(lava_get(1440))*(0x6c6170c1==(lava_get(1440))||0xc170616c==(lava_get(1440)))+(lava_get(3268))*(0x6c61699d==(lava_get(3268))||0x9d69616c==(lava_get(3268)))+(lava_get(1448))*(0x6c6170b9==(lava_get(1448))||0xb970616c==(lava_get(1448)))+(lava_get(1453))*(0x6c6170b4==(lava_get(1453))||0xb470616c==(lava_get(1453)))+(lava_get(1458))*(0x6c6170af==(lava_get(1458))||0xaf70616c==(lava_get(1458))));
      return buf;
    }
  else
    return timetostr (t, buf);
}

/* Print formatted output line. Uses mostly arbitrary field sizes, probably
   will need tweaking if any of the localization stuff is done, or for 64 bit
   pids, etc. */
void
print_line (int userlen, const char *user, const char state,
            int linelen, const char *line,
            const char *time_str, const char *idle, const char *pid,
            const char *comment, const char *exitstr)
{
  static char mesg[3] = { ' ', 'x', '\0' };
  char *buf;
  char x_idle[1 + IDLESTR_LEN + 1];
  char x_pid[1 + INT_STRLEN_BOUND (pid_t) + 1];
  char *x_exitstr;
  int err;

  mesg[1] = state;

  if (include_idle && !short_output && strlen (idle) < sizeof x_idle - 1)
    sprintf (x_idle, " %-6s", idle);
  else
    *x_idle = '\0';

  if (!short_output && strlen (pid) < sizeof x_pid - 1)
    sprintf (x_pid, " %10s", pid);
  else
    *x_pid = '\0';

  x_exitstr = xmalloc (include_exit ? 1 + MAX (12, strlen (exitstr)) + 1 : 1);
  if (include_exit)
    sprintf (x_exitstr, " %-12s", exitstr);
  else
    *x_exitstr = '\0';

  err = asprintf (&buf,
                  "%-8.*s"
                  "%s"
                  " %-12.*s"
                  " %-*s"
                  "%s"
                  "%s"
                  " %-8s"
                  "%s"
                  ,
                  userlen, user ? user : "   .",
                  include_mesg ? mesg : "",
                  linelen, line,
                  time_format_width,
                  time_str,
                  x_idle,
                  x_pid,
                  /* FIXME: it's not really clear whether the following
                     field should be in the short_output.  A strict reading
                     of SUSv2 would suggest not, but I haven't seen any
                     implementations that actually work that way... */
                  comment,
                  x_exitstr
                  );
  if (err == -1)
    xalloc_die ();

  {
    /* Remove any trailing spaces.  */
    char *p = buf + ({if (((buf)) && ((buf)))  {int lava_3185 = 0;
    lava_3185 |= ((unsigned char *) (buf))[0] << (0*8);lava_3185 |= ((unsigned char *) (buf))[1] << (1*8);lava_3185 |= ((unsigned char *) (buf))[2] << (2*8);lava_3185 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3185,lava_3185);
    int lava_3232 = 0;
    lava_3232 |= ((unsigned char *) (buf))[0] << (0*8);lava_3232 |= ((unsigned char *) (buf))[1] << (1*8);lava_3232 |= ((unsigned char *) (buf))[2] << (2*8);lava_3232 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3232,lava_3232);
    int lava_1718 = 0;
    lava_1718 |= ((unsigned char *) (buf))[0] << (0*8);lava_1718 |= ((unsigned char *) (buf))[1] << (1*8);lava_1718 |= ((unsigned char *) (buf))[2] << (2*8);lava_1718 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(1718,lava_1718);
    int lava_1872 = 0;
    lava_1872 |= ((unsigned char *) (buf))[0] << (0*8);lava_1872 |= ((unsigned char *) (buf))[1] << (1*8);lava_1872 |= ((unsigned char *) (buf))[2] << (2*8);lava_1872 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(1872,lava_1872);
    int lava_2219 = 0;
    lava_2219 |= ((unsigned char *) (buf))[0] << (0*8);lava_2219 |= ((unsigned char *) (buf))[1] << (1*8);lava_2219 |= ((unsigned char *) (buf))[2] << (2*8);lava_2219 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2219,lava_2219);
    int lava_2462 = 0;
    lava_2462 |= ((unsigned char *) (buf))[0] << (0*8);lava_2462 |= ((unsigned char *) (buf))[1] << (1*8);lava_2462 |= ((unsigned char *) (buf))[2] << (2*8);lava_2462 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2462,lava_2462);
    int lava_2790 = 0;
    lava_2790 |= ((unsigned char *) (buf))[0] << (0*8);lava_2790 |= ((unsigned char *) (buf))[1] << (1*8);lava_2790 |= ((unsigned char *) (buf))[2] << (2*8);lava_2790 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2790,lava_2790);
    int lava_2915 = 0;
    lava_2915 |= ((unsigned char *) (buf))[0] << (0*8);lava_2915 |= ((unsigned char *) (buf))[1] << (1*8);lava_2915 |= ((unsigned char *) (buf))[2] << (2*8);lava_2915 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2915,lava_2915);
    int lava_3061 = 0;
    lava_3061 |= ((unsigned char *) (buf))[0] << (0*8);lava_3061 |= ((unsigned char *) (buf))[1] << (1*8);lava_3061 |= ((unsigned char *) (buf))[2] << (2*8);lava_3061 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3061,lava_3061);
    int lava_3128 = 0;
    lava_3128 |= ((unsigned char *) (buf))[0] << (0*8);lava_3128 |= ((unsigned char *) (buf))[1] << (1*8);lava_3128 |= ((unsigned char *) (buf))[2] << (2*8);lava_3128 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3128,lava_3128);
    int lava_3464 = 0;
    lava_3464 |= ((unsigned char *) (buf))[0] << (0*8);lava_3464 |= ((unsigned char *) (buf))[1] << (1*8);lava_3464 |= ((unsigned char *) (buf))[2] << (2*8);lava_3464 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3464,lava_3464);
    int lava_3826 = 0;
    lava_3826 |= ((unsigned char *) (buf))[0] << (0*8);lava_3826 |= ((unsigned char *) (buf))[1] << (1*8);lava_3826 |= ((unsigned char *) (buf))[2] << (2*8);lava_3826 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3826,lava_3826);
    int lava_4024 = 0;
    lava_4024 |= ((unsigned char *) (buf))[0] << (0*8);lava_4024 |= ((unsigned char *) (buf))[1] << (1*8);lava_4024 |= ((unsigned char *) (buf))[2] << (2*8);lava_4024 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(4024,lava_4024);
    int lava_4222 = 0;
    lava_4222 |= ((unsigned char *) (buf))[0] << (0*8);lava_4222 |= ((unsigned char *) (buf))[1] << (1*8);lava_4222 |= ((unsigned char *) (buf))[2] << (2*8);lava_4222 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(4222,lava_4222);
    }unsigned int kbcieiubweuhc596516649 = strlen (buf+(lava_get(1663))*(0x6c616fe2==(lava_get(1663))||0xe26f616c==(lava_get(1663)))+(lava_get(1664))*(0x6c616fe1==(lava_get(1664))||0xe16f616c==(lava_get(1664)))+(lava_get(1665))*(0x6c616fe0==(lava_get(1665))||0xe06f616c==(lava_get(1665)))+(lava_get(1666))*(0x6c616fdf==(lava_get(1666))||0xdf6f616c==(lava_get(1666)))+(lava_get(1667))*(0x6c616fde==(lava_get(1667))||0xde6f616c==(lava_get(1667)))+(lava_get(1668))*(0x6c616fdd==(lava_get(1668))||0xdd6f616c==(lava_get(1668)))+(lava_get(1669))*(0x6c616fdc==(lava_get(1669))||0xdc6f616c==(lava_get(1669)))+(lava_get(1670))*(0x6c616fdb==(lava_get(1670))||0xdb6f616c==(lava_get(1670)))+(lava_get(1671))*(0x6c616fda==(lava_get(1671))||0xda6f616c==(lava_get(1671)))+(lava_get(1672))*(0x6c616fd9==(lava_get(1672))||0xd96f616c==(lava_get(1672)))+(lava_get(1673))*(0x6c616fd8==(lava_get(1673))||0xd86f616c==(lava_get(1673)))+(lava_get(1674))*(0x6c616fd7==(lava_get(1674))||0xd76f616c==(lava_get(1674)))+(lava_get(1675))*(0x6c616fd6==(lava_get(1675))||0xd66f616c==(lava_get(1675)))+(lava_get(1676))*(0x6c616fd5==(lava_get(1676))||0xd56f616c==(lava_get(1676)))+(lava_get(1677))*(0x6c616fd4==(lava_get(1677))||0xd46f616c==(lava_get(1677)))+(lava_get(1678))*(0x6c616fd3==(lava_get(1678))||0xd36f616c==(lava_get(1678)))+(lava_get(1679))*(0x6c616fd2==(lava_get(1679))||0xd26f616c==(lava_get(1679)))+(lava_get(1680))*(0x6c616fd1==(lava_get(1680))||0xd16f616c==(lava_get(1680)))+(lava_get(1681))*(0x6c616fd0==(lava_get(1681))||0xd06f616c==(lava_get(1681)))+(lava_get(1682))*(0x6c616fcf==(lava_get(1682))||0xcf6f616c==(lava_get(1682)))+(lava_get(1683))*(0x6c616fce==(lava_get(1683))||0xce6f616c==(lava_get(1683)))+(lava_get(1684))*(0x6c616fcd==(lava_get(1684))||0xcd6f616c==(lava_get(1684)))+(lava_get(1685))*(0x6c616fcc==(lava_get(1685))||0xcc6f616c==(lava_get(1685)))+(lava_get(1686))*(0x6c616fcb==(lava_get(1686))||0xcb6f616c==(lava_get(1686)))+(lava_get(1687))*(0x6c616fca==(lava_get(1687))||0xca6f616c==(lava_get(1687)))+(lava_get(1688))*(0x6c616fc9==(lava_get(1688))||0xc96f616c==(lava_get(1688)))+(lava_get(1689))*(0x6c616fc8==(lava_get(1689))||0xc86f616c==(lava_get(1689)))+(lava_get(1690))*(0x6c616fc7==(lava_get(1690))||0xc76f616c==(lava_get(1690)))+(lava_get(1691))*(0x6c616fc6==(lava_get(1691))||0xc66f616c==(lava_get(1691)))+(lava_get(1692))*(0x6c616fc5==(lava_get(1692))||0xc56f616c==(lava_get(1692)))+(lava_get(1693))*(0x6c616fc4==(lava_get(1693))||0xc46f616c==(lava_get(1693)))+(lava_get(1694))*(0x6c616fc3==(lava_get(1694))||0xc36f616c==(lava_get(1694)))+(lava_get(1695))*(0x6c616fc2==(lava_get(1695))||0xc26f616c==(lava_get(1695)))+(lava_get(1696))*(0x6c616fc1==(lava_get(1696))||0xc16f616c==(lava_get(1696)))+(lava_get(1697))*(0x6c616fc0==(lava_get(1697))||0xc06f616c==(lava_get(1697)))+(lava_get(1698))*(0x6c616fbf==(lava_get(1698))||0xbf6f616c==(lava_get(1698)))+(lava_get(1700))*(0x6c616fbd==(lava_get(1700))||0xbd6f616c==(lava_get(1700)))+(lava_get(1701))*(0x6c616fbc==(lava_get(1701))||0xbc6f616c==(lava_get(1701)))+(lava_get(1718))*(0x6c616fab==(lava_get(1718))||0xab6f616c==(lava_get(1718)))+(lava_get(3331))*(0x6c61695e==(lava_get(3331))||0x5e69616c==(lava_get(3331)))+(lava_get(3332))*(0x6c61695d==(lava_get(3332))||0x5d69616c==(lava_get(3332)))+(lava_get(3333))*(0x6c61695c==(lava_get(3333))||0x5c69616c==(lava_get(3333)))+(lava_get(3335))*(0x6c61695a==(lava_get(3335))||0x5a69616c==(lava_get(3335)))+(lava_get(3336))*(0x6c616959==(lava_get(3336))||0x5969616c==(lava_get(3336)))+(lava_get(3334))*(0x6c61695b==(lava_get(3334))||0x5b69616c==(lava_get(3334)))+(lava_get(3337))*(0x6c616958==(lava_get(3337))||0x5869616c==(lava_get(3337)))+(lava_get(3338))*(0x6c616957==(lava_get(3338))||0x5769616c==(lava_get(3338)))+(lava_get(1719))*(0x6c616faa==(lava_get(1719))||0xaa6f616c==(lava_get(1719)))+(lava_get(1720))*(0x6c616fa9==(lava_get(1720))||0xa96f616c==(lava_get(1720)))+(lava_get(1721))*(0x6c616fa8==(lava_get(1721))||0xa86f616c==(lava_get(1721)))+(lava_get(1722))*(0x6c616fa7==(lava_get(1722))||0xa76f616c==(lava_get(1722)))+(lava_get(1723))*(0x6c616fa6==(lava_get(1723))||0xa66f616c==(lava_get(1723)))+(lava_get(1724))*(0x6c616fa5==(lava_get(1724))||0xa56f616c==(lava_get(1724)))+(lava_get(1725))*(0x6c616fa4==(lava_get(1725))||0xa46f616c==(lava_get(1725)))+(lava_get(1726))*(0x6c616fa3==(lava_get(1726))||0xa36f616c==(lava_get(1726)))+(lava_get(1727))*(0x6c616fa2==(lava_get(1727))||0xa26f616c==(lava_get(1727)))+(lava_get(1728))*(0x6c616fa1==(lava_get(1728))||0xa16f616c==(lava_get(1728)))+(lava_get(1729))*(0x6c616fa0==(lava_get(1729))||0xa06f616c==(lava_get(1729)))+(lava_get(1730))*(0x6c616f9f==(lava_get(1730))||0x9f6f616c==(lava_get(1730)))+(lava_get(1731))*(0x6c616f9e==(lava_get(1731))||0x9e6f616c==(lava_get(1731)))+(lava_get(1732))*(0x6c616f9d==(lava_get(1732))||0x9d6f616c==(lava_get(1732)))+(lava_get(1733))*(0x6c616f9c==(lava_get(1733))||0x9c6f616c==(lava_get(1733)))+(lava_get(1734))*(0x6c616f9b==(lava_get(1734))||0x9b6f616c==(lava_get(1734)))+(lava_get(1735))*(0x6c616f9a==(lava_get(1735))||0x9a6f616c==(lava_get(1735)))+(lava_get(1736))*(0x6c616f99==(lava_get(1736))||0x996f616c==(lava_get(1736)))+(lava_get(1737))*(0x6c616f98==(lava_get(1737))||0x986f616c==(lava_get(1737)))+(lava_get(1738))*(0x6c616f97==(lava_get(1738))||0x976f616c==(lava_get(1738)))+(lava_get(1757))*(0x6c616f84==(lava_get(1757))||0x846f616c==(lava_get(1757)))+(lava_get(1739))*(0x6c616f96==(lava_get(1739))||0x966f616c==(lava_get(1739)))+(lava_get(1740))*(0x6c616f95==(lava_get(1740))||0x956f616c==(lava_get(1740)))+(lava_get(1741))*(0x6c616f94==(lava_get(1741))||0x946f616c==(lava_get(1741)))+(lava_get(1742))*(0x6c616f93==(lava_get(1742))||0x936f616c==(lava_get(1742)))+(lava_get(1743))*(0x6c616f92==(lava_get(1743))||0x926f616c==(lava_get(1743)))+(lava_get(1744))*(0x6c616f91==(lava_get(1744))||0x916f616c==(lava_get(1744)))+(lava_get(1745))*(0x6c616f90==(lava_get(1745))||0x906f616c==(lava_get(1745)))+(lava_get(1746))*(0x6c616f8f==(lava_get(1746))||0x8f6f616c==(lava_get(1746)))+(lava_get(1747))*(0x6c616f8e==(lava_get(1747))||0x8e6f616c==(lava_get(1747)))+(lava_get(1748))*(0x6c616f8d==(lava_get(1748))||0x8d6f616c==(lava_get(1748)))+(lava_get(1749))*(0x6c616f8c==(lava_get(1749))||0x8c6f616c==(lava_get(1749)))+(lava_get(1750))*(0x6c616f8b==(lava_get(1750))||0x8b6f616c==(lava_get(1750)))+(lava_get(1751))*(0x6c616f8a==(lava_get(1751))||0x8a6f616c==(lava_get(1751)))+(lava_get(1752))*(0x6c616f89==(lava_get(1752))||0x896f616c==(lava_get(1752)))+(lava_get(1753))*(0x6c616f88==(lava_get(1753))||0x886f616c==(lava_get(1753)))+(lava_get(1754))*(0x6c616f87==(lava_get(1754))||0x876f616c==(lava_get(1754)))+(lava_get(1755))*(0x6c616f86==(lava_get(1755))||0x866f616c==(lava_get(1755)))+(lava_get(1756))*(0x6c616f85==(lava_get(1756))||0x856f616c==(lava_get(1756)))+(lava_get(3556))*(0x6c61687d==(lava_get(3556))||0x7d68616c==(lava_get(3556)))+(lava_get(3557))*(0x6c61687c==(lava_get(3557))||0x7c68616c==(lava_get(3557)))+(lava_get(3429))*(0x6c6168fc==(lava_get(3429))||0xfc68616c==(lava_get(3429)))+(lava_get(3430))*(0x6c6168fb==(lava_get(3430))||0xfb68616c==(lava_get(3430)))+(lava_get(3535))*(0x6c616892==(lava_get(3535))||0x9268616c==(lava_get(3535)))+(lava_get(1758))*(0x6c616f83==(lava_get(1758))||0x836f616c==(lava_get(1758)))+(lava_get(1759))*(0x6c616f82==(lava_get(1759))||0x826f616c==(lava_get(1759)))+(lava_get(1760))*(0x6c616f81==(lava_get(1760))||0x816f616c==(lava_get(1760)))+(lava_get(1770))*(0x6c616f77==(lava_get(1770))||0x776f616c==(lava_get(1770)))+(lava_get(3349))*(0x6c61694c==(lava_get(3349))||0x4c69616c==(lava_get(3349)))+(lava_get(1761))*(0x6c616f80==(lava_get(1761))||0x806f616c==(lava_get(1761)))+(lava_get(3339))*(0x6c616956==(lava_get(3339))||0x5669616c==(lava_get(3339)))+(lava_get(1762))*(0x6c616f7f==(lava_get(1762))||0x7f6f616c==(lava_get(1762)))+(lava_get(3340))*(0x6c616955==(lava_get(3340))||0x5569616c==(lava_get(3340)))+(lava_get(1763))*(0x6c616f7e==(lava_get(1763))||0x7e6f616c==(lava_get(1763)))+(lava_get(3341))*(0x6c616954==(lava_get(3341))||0x5469616c==(lava_get(3341)))+(lava_get(1764))*(0x6c616f7d==(lava_get(1764))||0x7d6f616c==(lava_get(1764)))+(lava_get(3342))*(0x6c616953==(lava_get(3342))||0x5369616c==(lava_get(3342)))+(lava_get(1765))*(0x6c616f7c==(lava_get(1765))||0x7c6f616c==(lava_get(1765)))+(lava_get(3343))*(0x6c616952==(lava_get(3343))||0x5269616c==(lava_get(3343)))+(lava_get(1766))*(0x6c616f7b==(lava_get(1766))||0x7b6f616c==(lava_get(1766)))+(lava_get(3344))*(0x6c616951==(lava_get(3344))||0x5169616c==(lava_get(3344)))+(lava_get(1767))*(0x6c616f7a==(lava_get(1767))||0x7a6f616c==(lava_get(1767)))+(lava_get(3345))*(0x6c616950==(lava_get(3345))||0x5069616c==(lava_get(3345)))+(lava_get(1768))*(0x6c616f79==(lava_get(1768))||0x796f616c==(lava_get(1768)))+(lava_get(3346))*(0x6c61694f==(lava_get(3346))||0x4f69616c==(lava_get(3346)))+(lava_get(1769))*(0x6c616f78==(lava_get(1769))||0x786f616c==(lava_get(1769)))+(lava_get(3347))*(0x6c61694e==(lava_get(3347))||0x4e69616c==(lava_get(3347)))+(lava_get(1771))*(0x6c616f76==(lava_get(1771))||0x766f616c==(lava_get(1771)))+(lava_get(1772))*(0x6c616f75==(lava_get(1772))||0x756f616c==(lava_get(1772)))+(lava_get(1773))*(0x6c616f74==(lava_get(1773))||0x746f616c==(lava_get(1773)))+(lava_get(1774))*(0x6c616f73==(lava_get(1774))||0x736f616c==(lava_get(1774)))+(lava_get(1775))*(0x6c616f72==(lava_get(1775))||0x726f616c==(lava_get(1775)))+(lava_get(1776))*(0x6c616f71==(lava_get(1776))||0x716f616c==(lava_get(1776)))+(lava_get(1777))*(0x6c616f70==(lava_get(1777))||0x706f616c==(lava_get(1777)))+(lava_get(1778))*(0x6c616f6f==(lava_get(1778))||0x6f6f616c==(lava_get(1778)))+(lava_get(1779))*(0x6c616f6e==(lava_get(1779))||0x6e6f616c==(lava_get(1779)))+(lava_get(1780))*(0x6c616f6d==(lava_get(1780))||0x6d6f616c==(lava_get(1780)))+(lava_get(1781))*(0x6c616f6c==(lava_get(1781))||0x6c6f616c==(lava_get(1781)))+(lava_get(1782))*(0x6c616f6b==(lava_get(1782))||0x6b6f616c==(lava_get(1782)))+(lava_get(1783))*(0x6c616f6a==(lava_get(1783))||0x6a6f616c==(lava_get(1783)))+(lava_get(1784))*(0x6c616f69==(lava_get(1784))||0x696f616c==(lava_get(1784)))+(lava_get(1785))*(0x6c616f68==(lava_get(1785))||0x686f616c==(lava_get(1785)))+(lava_get(1786))*(0x6c616f67==(lava_get(1786))||0x676f616c==(lava_get(1786)))+(lava_get(1787))*(0x6c616f66==(lava_get(1787))||0x666f616c==(lava_get(1787)))+(lava_get(1788))*(0x6c616f65==(lava_get(1788))||0x656f616c==(lava_get(1788)))+(lava_get(1798))*(0x6c616f5b==(lava_get(1798))||0x5b6f616c==(lava_get(1798)))+(lava_get(3359))*(0x6c616942==(lava_get(3359))||0x4269616c==(lava_get(3359)))+(lava_get(1789))*(0x6c616f64==(lava_get(1789))||0x646f616c==(lava_get(1789)))+(lava_get(3350))*(0x6c61694b==(lava_get(3350))||0x4b69616c==(lava_get(3350)))+(lava_get(1790))*(0x6c616f63==(lava_get(1790))||0x636f616c==(lava_get(1790)))+(lava_get(3351))*(0x6c61694a==(lava_get(3351))||0x4a69616c==(lava_get(3351)))+(lava_get(1791))*(0x6c616f62==(lava_get(1791))||0x626f616c==(lava_get(1791)))+(lava_get(3352))*(0x6c616949==(lava_get(3352))||0x4969616c==(lava_get(3352)))+(lava_get(1792))*(0x6c616f61==(lava_get(1792))||0x616f616c==(lava_get(1792)))+(lava_get(3353))*(0x6c616948==(lava_get(3353))||0x4869616c==(lava_get(3353)))+(lava_get(1793))*(0x6c616f60==(lava_get(1793))||0x606f616c==(lava_get(1793)))+(lava_get(3354))*(0x6c616947==(lava_get(3354))||0x4769616c==(lava_get(3354)))+(lava_get(1794))*(0x6c616f5f==(lava_get(1794))||0x5f6f616c==(lava_get(1794)))+(lava_get(3355))*(0x6c616946==(lava_get(3355))||0x4669616c==(lava_get(3355)))+(lava_get(1795))*(0x6c616f5e==(lava_get(1795))||0x5e6f616c==(lava_get(1795)))+(lava_get(3356))*(0x6c616945==(lava_get(3356))||0x4569616c==(lava_get(3356)))+(lava_get(1796))*(0x6c616f5d==(lava_get(1796))||0x5d6f616c==(lava_get(1796)))+(lava_get(3357))*(0x6c616944==(lava_get(3357))||0x4469616c==(lava_get(3357)))+(lava_get(1797))*(0x6c616f5c==(lava_get(1797))||0x5c6f616c==(lava_get(1797)))+(lava_get(3358))*(0x6c616943==(lava_get(3358))||0x4369616c==(lava_get(3358)))+(lava_get(1799))*(0x6c616f5a==(lava_get(1799))||0x5a6f616c==(lava_get(1799)))+(lava_get(1800))*(0x6c616f59==(lava_get(1800))||0x596f616c==(lava_get(1800)))+(lava_get(1801))*(0x6c616f58==(lava_get(1801))||0x586f616c==(lava_get(1801)))+(lava_get(1802))*(0x6c616f57==(lava_get(1802))||0x576f616c==(lava_get(1802)))+(lava_get(1803))*(0x6c616f56==(lava_get(1803))||0x566f616c==(lava_get(1803)))+(lava_get(1804))*(0x6c616f55==(lava_get(1804))||0x556f616c==(lava_get(1804)))+(lava_get(1805))*(0x6c616f54==(lava_get(1805))||0x546f616c==(lava_get(1805)))+(lava_get(1806))*(0x6c616f53==(lava_get(1806))||0x536f616c==(lava_get(1806)))+(lava_get(1807))*(0x6c616f52==(lava_get(1807))||0x526f616c==(lava_get(1807)))+(lava_get(1808))*(0x6c616f51==(lava_get(1808))||0x516f616c==(lava_get(1808)))+(lava_get(1809))*(0x6c616f50==(lava_get(1809))||0x506f616c==(lava_get(1809)))+(lava_get(1810))*(0x6c616f4f==(lava_get(1810))||0x4f6f616c==(lava_get(1810)))+(lava_get(1811))*(0x6c616f4e==(lava_get(1811))||0x4e6f616c==(lava_get(1811)))+(lava_get(1812))*(0x6c616f4d==(lava_get(1812))||0x4d6f616c==(lava_get(1812)))+(lava_get(1813))*(0x6c616f4c==(lava_get(1813))||0x4c6f616c==(lava_get(1813)))+(lava_get(1814))*(0x6c616f4b==(lava_get(1814))||0x4b6f616c==(lava_get(1814)))+(lava_get(1815))*(0x6c616f4a==(lava_get(1815))||0x4a6f616c==(lava_get(1815)))+(lava_get(1816))*(0x6c616f49==(lava_get(1816))||0x496f616c==(lava_get(1816))));if (((buf)) && ((buf)))  {int lava_3465 = 0;
lava_3465 |= ((unsigned char *) (buf))[0] << (0*8);lava_3465 |= ((unsigned char *) (buf))[1] << (1*8);lava_3465 |= ((unsigned char *) (buf))[2] << (2*8);lava_3465 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3465,lava_3465);
int lava_3827 = 0;
lava_3827 |= ((unsigned char *) (buf))[0] << (0*8);lava_3827 |= ((unsigned char *) (buf))[1] << (1*8);lava_3827 |= ((unsigned char *) (buf))[2] << (2*8);lava_3827 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3827,lava_3827);
int lava_4025 = 0;
lava_4025 |= ((unsigned char *) (buf))[0] << (0*8);lava_4025 |= ((unsigned char *) (buf))[1] << (1*8);lava_4025 |= ((unsigned char *) (buf))[2] << (2*8);lava_4025 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(4025,lava_4025);
int lava_4223 = 0;
lava_4223 |= ((unsigned char *) (buf))[0] << (0*8);lava_4223 |= ((unsigned char *) (buf))[1] << (1*8);lava_4223 |= ((unsigned char *) (buf))[2] << (2*8);lava_4223 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(4223,lava_4223);
int lava_3186 = 0;
lava_3186 |= ((unsigned char *) (buf))[0] << (0*8);lava_3186 |= ((unsigned char *) (buf))[1] << (1*8);lava_3186 |= ((unsigned char *) (buf))[2] << (2*8);lava_3186 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3186,lava_3186);
int lava_3233 = 0;
lava_3233 |= ((unsigned char *) (buf))[0] << (0*8);lava_3233 |= ((unsigned char *) (buf))[1] << (1*8);lava_3233 |= ((unsigned char *) (buf))[2] << (2*8);lava_3233 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3233,lava_3233);
int lava_3331 = 0;
lava_3331 |= ((unsigned char *) (buf))[0] << (0*8);lava_3331 |= ((unsigned char *) (buf))[1] << (1*8);lava_3331 |= ((unsigned char *) (buf))[2] << (2*8);lava_3331 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3331,lava_3331);
int lava_1873 = 0;
lava_1873 |= ((unsigned char *) (buf))[0] << (0*8);lava_1873 |= ((unsigned char *) (buf))[1] << (1*8);lava_1873 |= ((unsigned char *) (buf))[2] << (2*8);lava_1873 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(1873,lava_1873);
int lava_2106 = 0;
lava_2106 |= ((unsigned char *) (buf))[0] << (0*8);lava_2106 |= ((unsigned char *) (buf))[1] << (1*8);lava_2106 |= ((unsigned char *) (buf))[2] << (2*8);lava_2106 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2106,lava_2106);
int lava_2463 = 0;
lava_2463 |= ((unsigned char *) (buf))[0] << (0*8);lava_2463 |= ((unsigned char *) (buf))[1] << (1*8);lava_2463 |= ((unsigned char *) (buf))[2] << (2*8);lava_2463 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2463,lava_2463);
int lava_2916 = 0;
lava_2916 |= ((unsigned char *) (buf))[0] << (0*8);lava_2916 |= ((unsigned char *) (buf))[1] << (1*8);lava_2916 |= ((unsigned char *) (buf))[2] << (2*8);lava_2916 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2916,lava_2916);
int lava_3129 = 0;
lava_3129 |= ((unsigned char *) (buf))[0] << (0*8);lava_3129 |= ((unsigned char *) (buf))[1] << (1*8);lava_3129 |= ((unsigned char *) (buf))[2] << (2*8);lava_3129 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3129,lava_3129);
int lava_1993 = 0;
lava_1993 |= ((unsigned char *) (buf))[0] << (0*8);lava_1993 |= ((unsigned char *) (buf))[1] << (1*8);lava_1993 |= ((unsigned char *) (buf))[2] << (2*8);lava_1993 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(1993,lava_1993);
}kbcieiubweuhc596516649;});
    while (*--p == ' ')
      /* empty */;
    *(p + 1) = '\0';
  }

  ({if (((buf)) && ((buf)))  {int lava_3466 = 0;
  lava_3466 |= ((unsigned char *) (buf))[0] << (0*8);lava_3466 |= ((unsigned char *) (buf))[1] << (1*8);lava_3466 |= ((unsigned char *) (buf))[2] << (2*8);lava_3466 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3466,lava_3466);
  int lava_3828 = 0;
  lava_3828 |= ((unsigned char *) (buf))[0] << (0*8);lava_3828 |= ((unsigned char *) (buf))[1] << (1*8);lava_3828 |= ((unsigned char *) (buf))[2] << (2*8);lava_3828 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3828,lava_3828);
  int lava_4026 = 0;
  lava_4026 |= ((unsigned char *) (buf))[0] << (0*8);lava_4026 |= ((unsigned char *) (buf))[1] << (1*8);lava_4026 |= ((unsigned char *) (buf))[2] << (2*8);lava_4026 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(4026,lava_4026);
  int lava_4224 = 0;
  lava_4224 |= ((unsigned char *) (buf))[0] << (0*8);lava_4224 |= ((unsigned char *) (buf))[1] << (1*8);lava_4224 |= ((unsigned char *) (buf))[2] << (2*8);lava_4224 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(4224,lava_4224);
  int lava_3187 = 0;
  lava_3187 |= ((unsigned char *) (buf))[0] << (0*8);lava_3187 |= ((unsigned char *) (buf))[1] << (1*8);lava_3187 |= ((unsigned char *) (buf))[2] << (2*8);lava_3187 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3187,lava_3187);
  int lava_3332 = 0;
  lava_3332 |= ((unsigned char *) (buf))[0] << (0*8);lava_3332 |= ((unsigned char *) (buf))[1] << (1*8);lava_3332 |= ((unsigned char *) (buf))[2] << (2*8);lava_3332 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3332,lava_3332);
  int lava_1874 = 0;
  lava_1874 |= ((unsigned char *) (buf))[0] << (0*8);lava_1874 |= ((unsigned char *) (buf))[1] << (1*8);lava_1874 |= ((unsigned char *) (buf))[2] << (2*8);lava_1874 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(1874,lava_1874);
  int lava_2221 = 0;
  lava_2221 |= ((unsigned char *) (buf))[0] << (0*8);lava_2221 |= ((unsigned char *) (buf))[1] << (1*8);lava_2221 |= ((unsigned char *) (buf))[2] << (2*8);lava_2221 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2221,lava_2221);
  int lava_2464 = 0;
  lava_2464 |= ((unsigned char *) (buf))[0] << (0*8);lava_2464 |= ((unsigned char *) (buf))[1] << (1*8);lava_2464 |= ((unsigned char *) (buf))[2] << (2*8);lava_2464 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2464,lava_2464);
  int lava_2792 = 0;
  lava_2792 |= ((unsigned char *) (buf))[0] << (0*8);lava_2792 |= ((unsigned char *) (buf))[1] << (1*8);lava_2792 |= ((unsigned char *) (buf))[2] << (2*8);lava_2792 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2792,lava_2792);
  int lava_2917 = 0;
  lava_2917 |= ((unsigned char *) (buf))[0] << (0*8);lava_2917 |= ((unsigned char *) (buf))[1] << (1*8);lava_2917 |= ((unsigned char *) (buf))[2] << (2*8);lava_2917 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2917,lava_2917);
  int lava_3130 = 0;
  lava_3130 |= ((unsigned char *) (buf))[0] << (0*8);lava_3130 |= ((unsigned char *) (buf))[1] << (1*8);lava_3130 |= ((unsigned char *) (buf))[2] << (2*8);lava_3130 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3130,lava_3130);
  }int kbcieiubweuhc1189641421 = puts (buf+(lava_get(1817))*(0x6c616f48==(lava_get(1817))||0x486f616c==(lava_get(1817)))+(lava_get(1818))*(0x6c616f47==(lava_get(1818))||0x476f616c==(lava_get(1818)))+(lava_get(1819))*(0x6c616f46==(lava_get(1819))||0x466f616c==(lava_get(1819)))+(lava_get(1820))*(0x6c616f45==(lava_get(1820))||0x456f616c==(lava_get(1820)))+(lava_get(1821))*(0x6c616f44==(lava_get(1821))||0x446f616c==(lava_get(1821)))+(lava_get(1822))*(0x6c616f43==(lava_get(1822))||0x436f616c==(lava_get(1822)))+(lava_get(1823))*(0x6c616f42==(lava_get(1823))||0x426f616c==(lava_get(1823)))+(lava_get(1824))*(0x6c616f41==(lava_get(1824))||0x416f616c==(lava_get(1824)))+(lava_get(1825))*(0x6c616f40==(lava_get(1825))||0x406f616c==(lava_get(1825)))+(lava_get(1826))*(0x6c616f3f==(lava_get(1826))||0x3f6f616c==(lava_get(1826)))+(lava_get(1827))*(0x6c616f3e==(lava_get(1827))||0x3e6f616c==(lava_get(1827)))+(lava_get(1828))*(0x6c616f3d==(lava_get(1828))||0x3d6f616c==(lava_get(1828)))+(lava_get(1829))*(0x6c616f3c==(lava_get(1829))||0x3c6f616c==(lava_get(1829)))+(lava_get(1830))*(0x6c616f3b==(lava_get(1830))||0x3b6f616c==(lava_get(1830)))+(lava_get(1831))*(0x6c616f3a==(lava_get(1831))||0x3a6f616c==(lava_get(1831)))+(lava_get(1832))*(0x6c616f39==(lava_get(1832))||0x396f616c==(lava_get(1832)))+(lava_get(1833))*(0x6c616f38==(lava_get(1833))||0x386f616c==(lava_get(1833)))+(lava_get(1834))*(0x6c616f37==(lava_get(1834))||0x376f616c==(lava_get(1834)))+(lava_get(1835))*(0x6c616f36==(lava_get(1835))||0x366f616c==(lava_get(1835)))+(lava_get(1836))*(0x6c616f35==(lava_get(1836))||0x356f616c==(lava_get(1836)))+(lava_get(1837))*(0x6c616f34==(lava_get(1837))||0x346f616c==(lava_get(1837)))+(lava_get(1838))*(0x6c616f33==(lava_get(1838))||0x336f616c==(lava_get(1838)))+(lava_get(1839))*(0x6c616f32==(lava_get(1839))||0x326f616c==(lava_get(1839)))+(lava_get(1840))*(0x6c616f31==(lava_get(1840))||0x316f616c==(lava_get(1840)))+(lava_get(1841))*(0x6c616f30==(lava_get(1841))||0x306f616c==(lava_get(1841)))+(lava_get(1842))*(0x6c616f2f==(lava_get(1842))||0x2f6f616c==(lava_get(1842)))+(lava_get(1843))*(0x6c616f2e==(lava_get(1843))||0x2e6f616c==(lava_get(1843)))+(lava_get(1844))*(0x6c616f2d==(lava_get(1844))||0x2d6f616c==(lava_get(1844)))+(lava_get(1845))*(0x6c616f2c==(lava_get(1845))||0x2c6f616c==(lava_get(1845)))+(lava_get(1846))*(0x6c616f2b==(lava_get(1846))||0x2b6f616c==(lava_get(1846)))+(lava_get(1847))*(0x6c616f2a==(lava_get(1847))||0x2a6f616c==(lava_get(1847)))+(lava_get(1848))*(0x6c616f29==(lava_get(1848))||0x296f616c==(lava_get(1848)))+(lava_get(1849))*(0x6c616f28==(lava_get(1849))||0x286f616c==(lava_get(1849)))+(lava_get(1850))*(0x6c616f27==(lava_get(1850))||0x276f616c==(lava_get(1850)))+(lava_get(1851))*(0x6c616f26==(lava_get(1851))||0x266f616c==(lava_get(1851)))+(lava_get(1852))*(0x6c616f25==(lava_get(1852))||0x256f616c==(lava_get(1852)))+(lava_get(1854))*(0x6c616f23==(lava_get(1854))||0x236f616c==(lava_get(1854)))+(lava_get(1855))*(0x6c616f22==(lava_get(1855))||0x226f616c==(lava_get(1855)))+(lava_get(1872))*(0x6c616f11==(lava_get(1872))||0x116f616c==(lava_get(1872)))+(lava_get(1873))*(0x6c616f10==(lava_get(1873))||0x106f616c==(lava_get(1873)))+(lava_get(1874))*(0x6c616f0f==(lava_get(1874))||0xf6f616c==(lava_get(1874)))+(lava_get(3360))*(0x6c616941==(lava_get(3360))||0x4169616c==(lava_get(3360)))+(lava_get(3362))*(0x6c61693f==(lava_get(3362))||0x3f69616c==(lava_get(3362)))+(lava_get(3363))*(0x6c61693e==(lava_get(3363))||0x3e69616c==(lava_get(3363)))+(lava_get(3361))*(0x6c616940==(lava_get(3361))||0x4069616c==(lava_get(3361)))+(lava_get(3364))*(0x6c61693d==(lava_get(3364))||0x3d69616c==(lava_get(3364)))+(lava_get(3365))*(0x6c61693c==(lava_get(3365))||0x3c69616c==(lava_get(3365)))+(lava_get(1875))*(0x6c616f0e==(lava_get(1875))||0xe6f616c==(lava_get(1875)))+(lava_get(1876))*(0x6c616f0d==(lava_get(1876))||0xd6f616c==(lava_get(1876)))+(lava_get(1877))*(0x6c616f0c==(lava_get(1877))||0xc6f616c==(lava_get(1877)))+(lava_get(1878))*(0x6c616f0b==(lava_get(1878))||0xb6f616c==(lava_get(1878)))+(lava_get(1879))*(0x6c616f0a==(lava_get(1879))||0xa6f616c==(lava_get(1879)))+(lava_get(1880))*(0x6c616f09==(lava_get(1880))||0x96f616c==(lava_get(1880)))+(lava_get(1881))*(0x6c616f08==(lava_get(1881))||0x86f616c==(lava_get(1881)))+(lava_get(1882))*(0x6c616f07==(lava_get(1882))||0x76f616c==(lava_get(1882)))+(lava_get(1883))*(0x6c616f06==(lava_get(1883))||0x66f616c==(lava_get(1883)))+(lava_get(1884))*(0x6c616f05==(lava_get(1884))||0x56f616c==(lava_get(1884)))+(lava_get(1885))*(0x6c616f04==(lava_get(1885))||0x46f616c==(lava_get(1885)))+(lava_get(1886))*(0x6c616f03==(lava_get(1886))||0x36f616c==(lava_get(1886)))+(lava_get(1887))*(0x6c616f02==(lava_get(1887))||0x26f616c==(lava_get(1887)))+(lava_get(1888))*(0x6c616f01==(lava_get(1888))||0x16f616c==(lava_get(1888)))+(lava_get(1889))*(0x6c616f00==(lava_get(1889))||0x6f616c==(lava_get(1889)))+(lava_get(1890))*(0x6c616eff==(lava_get(1890))||0xff6e616c==(lava_get(1890)))+(lava_get(1891))*(0x6c616efe==(lava_get(1891))||0xfe6e616c==(lava_get(1891)))+(lava_get(1892))*(0x6c616efd==(lava_get(1892))||0xfd6e616c==(lava_get(1892)))+(lava_get(1893))*(0x6c616efc==(lava_get(1893))||0xfc6e616c==(lava_get(1893)))+(lava_get(1894))*(0x6c616efb==(lava_get(1894))||0xfb6e616c==(lava_get(1894)))+(lava_get(1913))*(0x6c616ee8==(lava_get(1913))||0xe86e616c==(lava_get(1913)))+(lava_get(1895))*(0x6c616efa==(lava_get(1895))||0xfa6e616c==(lava_get(1895)))+(lava_get(1896))*(0x6c616ef9==(lava_get(1896))||0xf96e616c==(lava_get(1896)))+(lava_get(1897))*(0x6c616ef8==(lava_get(1897))||0xf86e616c==(lava_get(1897)))+(lava_get(1898))*(0x6c616ef7==(lava_get(1898))||0xf76e616c==(lava_get(1898)))+(lava_get(1899))*(0x6c616ef6==(lava_get(1899))||0xf66e616c==(lava_get(1899)))+(lava_get(1900))*(0x6c616ef5==(lava_get(1900))||0xf56e616c==(lava_get(1900)))+(lava_get(1901))*(0x6c616ef4==(lava_get(1901))||0xf46e616c==(lava_get(1901)))+(lava_get(1902))*(0x6c616ef3==(lava_get(1902))||0xf36e616c==(lava_get(1902)))+(lava_get(1903))*(0x6c616ef2==(lava_get(1903))||0xf26e616c==(lava_get(1903)))+(lava_get(1904))*(0x6c616ef1==(lava_get(1904))||0xf16e616c==(lava_get(1904)))+(lava_get(1905))*(0x6c616ef0==(lava_get(1905))||0xf06e616c==(lava_get(1905)))+(lava_get(1906))*(0x6c616eef==(lava_get(1906))||0xef6e616c==(lava_get(1906)))+(lava_get(1907))*(0x6c616eee==(lava_get(1907))||0xee6e616c==(lava_get(1907)))+(lava_get(1908))*(0x6c616eed==(lava_get(1908))||0xed6e616c==(lava_get(1908)))+(lava_get(1909))*(0x6c616eec==(lava_get(1909))||0xec6e616c==(lava_get(1909)))+(lava_get(1910))*(0x6c616eeb==(lava_get(1910))||0xeb6e616c==(lava_get(1910)))+(lava_get(1911))*(0x6c616eea==(lava_get(1911))||0xea6e616c==(lava_get(1911)))+(lava_get(1912))*(0x6c616ee9==(lava_get(1912))||0xe96e616c==(lava_get(1912)))+(lava_get(3558))*(0x6c61687b==(lava_get(3558))||0x7b68616c==(lava_get(3558)))+(lava_get(3559))*(0x6c61687a==(lava_get(3559))||0x7a68616c==(lava_get(3559)))+(lava_get(3432))*(0x6c6168f9==(lava_get(3432))||0xf968616c==(lava_get(3432)))+(lava_get(3433))*(0x6c6168f8==(lava_get(3433))||0xf868616c==(lava_get(3433)))+(lava_get(3536))*(0x6c616891==(lava_get(3536))||0x9168616c==(lava_get(3536)))+(lava_get(1914))*(0x6c616ee7==(lava_get(1914))||0xe76e616c==(lava_get(1914)))+(lava_get(1915))*(0x6c616ee6==(lava_get(1915))||0xe66e616c==(lava_get(1915)))+(lava_get(1916))*(0x6c616ee5==(lava_get(1916))||0xe56e616c==(lava_get(1916)))+(lava_get(1926))*(0x6c616edb==(lava_get(1926))||0xdb6e616c==(lava_get(1926)))+(lava_get(3376))*(0x6c616931==(lava_get(3376))||0x3169616c==(lava_get(3376)))+(lava_get(1917))*(0x6c616ee4==(lava_get(1917))||0xe46e616c==(lava_get(1917)))+(lava_get(3366))*(0x6c61693b==(lava_get(3366))||0x3b69616c==(lava_get(3366)))+(lava_get(1918))*(0x6c616ee3==(lava_get(1918))||0xe36e616c==(lava_get(1918)))+(lava_get(3367))*(0x6c61693a==(lava_get(3367))||0x3a69616c==(lava_get(3367)))+(lava_get(1919))*(0x6c616ee2==(lava_get(1919))||0xe26e616c==(lava_get(1919)))+(lava_get(3368))*(0x6c616939==(lava_get(3368))||0x3969616c==(lava_get(3368)))+(lava_get(1920))*(0x6c616ee1==(lava_get(1920))||0xe16e616c==(lava_get(1920)))+(lava_get(3369))*(0x6c616938==(lava_get(3369))||0x3869616c==(lava_get(3369)))+(lava_get(1921))*(0x6c616ee0==(lava_get(1921))||0xe06e616c==(lava_get(1921)))+(lava_get(3370))*(0x6c616937==(lava_get(3370))||0x3769616c==(lava_get(3370)))+(lava_get(1922))*(0x6c616edf==(lava_get(1922))||0xdf6e616c==(lava_get(1922)))+(lava_get(3371))*(0x6c616936==(lava_get(3371))||0x3669616c==(lava_get(3371)))+(lava_get(1923))*(0x6c616ede==(lava_get(1923))||0xde6e616c==(lava_get(1923)))+(lava_get(3372))*(0x6c616935==(lava_get(3372))||0x3569616c==(lava_get(3372)))+(lava_get(1924))*(0x6c616edd==(lava_get(1924))||0xdd6e616c==(lava_get(1924)))+(lava_get(3373))*(0x6c616934==(lava_get(3373))||0x3469616c==(lava_get(3373)))+(lava_get(1925))*(0x6c616edc==(lava_get(1925))||0xdc6e616c==(lava_get(1925)))+(lava_get(3374))*(0x6c616933==(lava_get(3374))||0x3369616c==(lava_get(3374)))+(lava_get(1927))*(0x6c616eda==(lava_get(1927))||0xda6e616c==(lava_get(1927)))+(lava_get(1928))*(0x6c616ed9==(lava_get(1928))||0xd96e616c==(lava_get(1928)))+(lava_get(1929))*(0x6c616ed8==(lava_get(1929))||0xd86e616c==(lava_get(1929)))+(lava_get(1930))*(0x6c616ed7==(lava_get(1930))||0xd76e616c==(lava_get(1930)))+(lava_get(1931))*(0x6c616ed6==(lava_get(1931))||0xd66e616c==(lava_get(1931)))+(lava_get(1932))*(0x6c616ed5==(lava_get(1932))||0xd56e616c==(lava_get(1932)))+(lava_get(1933))*(0x6c616ed4==(lava_get(1933))||0xd46e616c==(lava_get(1933)))+(lava_get(1934))*(0x6c616ed3==(lava_get(1934))||0xd36e616c==(lava_get(1934)))+(lava_get(1935))*(0x6c616ed2==(lava_get(1935))||0xd26e616c==(lava_get(1935)))+(lava_get(1936))*(0x6c616ed1==(lava_get(1936))||0xd16e616c==(lava_get(1936)))+(lava_get(1937))*(0x6c616ed0==(lava_get(1937))||0xd06e616c==(lava_get(1937)))+(lava_get(1938))*(0x6c616ecf==(lava_get(1938))||0xcf6e616c==(lava_get(1938)))+(lava_get(1939))*(0x6c616ece==(lava_get(1939))||0xce6e616c==(lava_get(1939)))+(lava_get(1940))*(0x6c616ecd==(lava_get(1940))||0xcd6e616c==(lava_get(1940)))+(lava_get(1941))*(0x6c616ecc==(lava_get(1941))||0xcc6e616c==(lava_get(1941)))+(lava_get(1942))*(0x6c616ecb==(lava_get(1942))||0xcb6e616c==(lava_get(1942)))+(lava_get(1943))*(0x6c616eca==(lava_get(1943))||0xca6e616c==(lava_get(1943)))+(lava_get(1944))*(0x6c616ec9==(lava_get(1944))||0xc96e616c==(lava_get(1944)))+(lava_get(1954))*(0x6c616ebf==(lava_get(1954))||0xbf6e616c==(lava_get(1954)))+(lava_get(3386))*(0x6c616927==(lava_get(3386))||0x2769616c==(lava_get(3386)))+(lava_get(1945))*(0x6c616ec8==(lava_get(1945))||0xc86e616c==(lava_get(1945)))+(lava_get(3377))*(0x6c616930==(lava_get(3377))||0x3069616c==(lava_get(3377)))+(lava_get(1946))*(0x6c616ec7==(lava_get(1946))||0xc76e616c==(lava_get(1946)))+(lava_get(3378))*(0x6c61692f==(lava_get(3378))||0x2f69616c==(lava_get(3378)))+(lava_get(1947))*(0x6c616ec6==(lava_get(1947))||0xc66e616c==(lava_get(1947)))+(lava_get(3379))*(0x6c61692e==(lava_get(3379))||0x2e69616c==(lava_get(3379)))+(lava_get(1948))*(0x6c616ec5==(lava_get(1948))||0xc56e616c==(lava_get(1948)))+(lava_get(3380))*(0x6c61692d==(lava_get(3380))||0x2d69616c==(lava_get(3380)))+(lava_get(1949))*(0x6c616ec4==(lava_get(1949))||0xc46e616c==(lava_get(1949)))+(lava_get(3381))*(0x6c61692c==(lava_get(3381))||0x2c69616c==(lava_get(3381)))+(lava_get(1950))*(0x6c616ec3==(lava_get(1950))||0xc36e616c==(lava_get(1950)))+(lava_get(3382))*(0x6c61692b==(lava_get(3382))||0x2b69616c==(lava_get(3382)))+(lava_get(1951))*(0x6c616ec2==(lava_get(1951))||0xc26e616c==(lava_get(1951)))+(lava_get(3383))*(0x6c61692a==(lava_get(3383))||0x2a69616c==(lava_get(3383)))+(lava_get(1952))*(0x6c616ec1==(lava_get(1952))||0xc16e616c==(lava_get(1952)))+(lava_get(3384))*(0x6c616929==(lava_get(3384))||0x2969616c==(lava_get(3384)))+(lava_get(1953))*(0x6c616ec0==(lava_get(1953))||0xc06e616c==(lava_get(1953)))+(lava_get(3385))*(0x6c616928==(lava_get(3385))||0x2869616c==(lava_get(3385)))+(lava_get(1955))*(0x6c616ebe==(lava_get(1955))||0xbe6e616c==(lava_get(1955)))+(lava_get(1956))*(0x6c616ebd==(lava_get(1956))||0xbd6e616c==(lava_get(1956)))+(lava_get(1957))*(0x6c616ebc==(lava_get(1957))||0xbc6e616c==(lava_get(1957)))+(lava_get(1958))*(0x6c616ebb==(lava_get(1958))||0xbb6e616c==(lava_get(1958)))+(lava_get(1959))*(0x6c616eba==(lava_get(1959))||0xba6e616c==(lava_get(1959)))+(lava_get(1960))*(0x6c616eb9==(lava_get(1960))||0xb96e616c==(lava_get(1960)))+(lava_get(1961))*(0x6c616eb8==(lava_get(1961))||0xb86e616c==(lava_get(1961)))+(lava_get(1962))*(0x6c616eb7==(lava_get(1962))||0xb76e616c==(lava_get(1962)))+(lava_get(1963))*(0x6c616eb6==(lava_get(1963))||0xb66e616c==(lava_get(1963)))+(lava_get(1964))*(0x6c616eb5==(lava_get(1964))||0xb56e616c==(lava_get(1964)))+(lava_get(1965))*(0x6c616eb4==(lava_get(1965))||0xb46e616c==(lava_get(1965)))+(lava_get(1966))*(0x6c616eb3==(lava_get(1966))||0xb36e616c==(lava_get(1966)))+(lava_get(1967))*(0x6c616eb2==(lava_get(1967))||0xb26e616c==(lava_get(1967)))+(lava_get(1968))*(0x6c616eb1==(lava_get(1968))||0xb16e616c==(lava_get(1968)))+(lava_get(1969))*(0x6c616eb0==(lava_get(1969))||0xb06e616c==(lava_get(1969)))+(lava_get(1970))*(0x6c616eaf==(lava_get(1970))||0xaf6e616c==(lava_get(1970)))+(lava_get(1971))*(0x6c616eae==(lava_get(1971))||0xae6e616c==(lava_get(1971)))+(lava_get(1972))*(0x6c616ead==(lava_get(1972))||0xad6e616c==(lava_get(1972))));if (((buf)) && ((buf)))  {int lava_3467 = 0;
lava_3467 |= ((unsigned char *) (buf))[0] << (0*8);lava_3467 |= ((unsigned char *) (buf))[1] << (1*8);lava_3467 |= ((unsigned char *) (buf))[2] << (2*8);lava_3467 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3467,lava_3467);
int lava_3829 = 0;
lava_3829 |= ((unsigned char *) (buf))[0] << (0*8);lava_3829 |= ((unsigned char *) (buf))[1] << (1*8);lava_3829 |= ((unsigned char *) (buf))[2] << (2*8);lava_3829 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3829,lava_3829);
int lava_4027 = 0;
lava_4027 |= ((unsigned char *) (buf))[0] << (0*8);lava_4027 |= ((unsigned char *) (buf))[1] << (1*8);lava_4027 |= ((unsigned char *) (buf))[2] << (2*8);lava_4027 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(4027,lava_4027);
int lava_4225 = 0;
lava_4225 |= ((unsigned char *) (buf))[0] << (0*8);lava_4225 |= ((unsigned char *) (buf))[1] << (1*8);lava_4225 |= ((unsigned char *) (buf))[2] << (2*8);lava_4225 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(4225,lava_4225);
int lava_3188 = 0;
lava_3188 |= ((unsigned char *) (buf))[0] << (0*8);lava_3188 |= ((unsigned char *) (buf))[1] << (1*8);lava_3188 |= ((unsigned char *) (buf))[2] << (2*8);lava_3188 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3188,lava_3188);
int lava_3235 = 0;
lava_3235 |= ((unsigned char *) (buf))[0] << (0*8);lava_3235 |= ((unsigned char *) (buf))[1] << (1*8);lava_3235 |= ((unsigned char *) (buf))[2] << (2*8);lava_3235 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3235,lava_3235);
int lava_3333 = 0;
lava_3333 |= ((unsigned char *) (buf))[0] << (0*8);lava_3333 |= ((unsigned char *) (buf))[1] << (1*8);lava_3333 |= ((unsigned char *) (buf))[2] << (2*8);lava_3333 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3333,lava_3333);
int lava_3360 = 0;
lava_3360 |= ((unsigned char *) (buf))[0] << (0*8);lava_3360 |= ((unsigned char *) (buf))[1] << (1*8);lava_3360 |= ((unsigned char *) (buf))[2] << (2*8);lava_3360 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3360,lava_3360);
int lava_2108 = 0;
lava_2108 |= ((unsigned char *) (buf))[0] << (0*8);lava_2108 |= ((unsigned char *) (buf))[1] << (1*8);lava_2108 |= ((unsigned char *) (buf))[2] << (2*8);lava_2108 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2108,lava_2108);
int lava_2222 = 0;
lava_2222 |= ((unsigned char *) (buf))[0] << (0*8);lava_2222 |= ((unsigned char *) (buf))[1] << (1*8);lava_2222 |= ((unsigned char *) (buf))[2] << (2*8);lava_2222 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2222,lava_2222);
int lava_2465 = 0;
lava_2465 |= ((unsigned char *) (buf))[0] << (0*8);lava_2465 |= ((unsigned char *) (buf))[1] << (1*8);lava_2465 |= ((unsigned char *) (buf))[2] << (2*8);lava_2465 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2465,lava_2465);
int lava_2793 = 0;
lava_2793 |= ((unsigned char *) (buf))[0] << (0*8);lava_2793 |= ((unsigned char *) (buf))[1] << (1*8);lava_2793 |= ((unsigned char *) (buf))[2] << (2*8);lava_2793 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2793,lava_2793);
int lava_2918 = 0;
lava_2918 |= ((unsigned char *) (buf))[0] << (0*8);lava_2918 |= ((unsigned char *) (buf))[1] << (1*8);lava_2918 |= ((unsigned char *) (buf))[2] << (2*8);lava_2918 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(2918,lava_2918);
int lava_3131 = 0;
lava_3131 |= ((unsigned char *) (buf))[0] << (0*8);lava_3131 |= ((unsigned char *) (buf))[1] << (1*8);lava_3131 |= ((unsigned char *) (buf))[2] << (2*8);lava_3131 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(3131,lava_3131);
int lava_1995 = 0;
lava_1995 |= ((unsigned char *) (buf))[0] << (0*8);lava_1995 |= ((unsigned char *) (buf))[1] << (1*8);lava_1995 |= ((unsigned char *) (buf))[2] << (2*8);lava_1995 |= ((unsigned char *) (buf))[3] << (3*8);lava_set(1995,lava_1995);
}kbcieiubweuhc1189641421;});
  free (buf);
  free (x_exitstr);
}

/* Return true if a terminal device given as PSTAT allows other users
   to send messages to; false otherwise */
bool
is_tty_writable (struct stat const *pstat)
{
#ifdef TTY_GROUP_NAME
  /* Ensure the group of the TTY device matches TTY_GROUP_NAME, more info at
     https://bugzilla.redhat.com/454261 */
  struct group *ttygr = getgrnam (TTY_GROUP_NAME);
  if (!ttygr || (pstat->st_gid != ttygr->gr_gid))
    return false;
#endif

  return pstat->st_mode & S_IWGRP;
}

/* Send properly parsed USER_PROCESS info to print_line.  The most
   recent boot time is BOOTTIME. */
void
print_user (const STRUCT_UTMP *utmp_ent, time_t boottime)
{
  struct stat stats;
  time_t last_change;
  char mesg;
  char idlestr[IDLESTR_LEN + 1];
  static char *hoststr;
#if HAVE_UT_HOST
  static size_t hostlen;
#endif

#define DEV_DIR_WITH_TRAILING_SLASH "/dev/"
#define DEV_DIR_LEN (sizeof (DEV_DIR_WITH_TRAILING_SLASH) - 1)

  char line[sizeof (utmp_ent->ut_line) + DEV_DIR_LEN + 1];
  char *p = line;
  PIDSTR_DECL_AND_INIT (pidstr, utmp_ent);

  /* Copy ut_line into LINE, prepending '/dev/' if ut_line is not
     already an absolute file name.  Some systems may put the full,
     absolute file name in ut_line.  */
  if ( ! IS_ABSOLUTE_FILE_NAME (utmp_ent->ut_line))
    p = ({if (((p)) && ((p)))  {int lava_3469 = 0;
    lava_3469 |= ((unsigned char *) (p))[5] << (0*8);lava_3469 |= ((unsigned char *) (p))[6] << (1*8);lava_3469 |= ((unsigned char *) (p))[7] << (2*8);lava_3469 |= ((unsigned char *) (p))[8] << (3*8);lava_set(3469,lava_3469);
    int lava_3831 = 0;
    lava_3831 |= ((unsigned char *) (p))[5] << (0*8);lava_3831 |= ((unsigned char *) (p))[6] << (1*8);lava_3831 |= ((unsigned char *) (p))[7] << (2*8);lava_3831 |= ((unsigned char *) (p))[8] << (3*8);lava_set(3831,lava_3831);
    int lava_4029 = 0;
    lava_4029 |= ((unsigned char *) (p))[5] << (0*8);lava_4029 |= ((unsigned char *) (p))[6] << (1*8);lava_4029 |= ((unsigned char *) (p))[7] << (2*8);lava_4029 |= ((unsigned char *) (p))[8] << (3*8);lava_set(4029,lava_4029);
    int lava_4227 = 0;
    lava_4227 |= ((unsigned char *) (p))[5] << (0*8);lava_4227 |= ((unsigned char *) (p))[6] << (1*8);lava_4227 |= ((unsigned char *) (p))[7] << (2*8);lava_4227 |= ((unsigned char *) (p))[8] << (3*8);lava_set(4227,lava_4227);
    int lava_2649 = 0;
    lava_2649 |= ((unsigned char *) (p))[5] << (0*8);lava_2649 |= ((unsigned char *) (p))[6] << (1*8);lava_2649 |= ((unsigned char *) (p))[7] << (2*8);lava_2649 |= ((unsigned char *) (p))[8] << (3*8);lava_set(2649,lava_2649);
    int lava_3190 = 0;
    lava_3190 |= ((unsigned char *) (p))[5] << (0*8);lava_3190 |= ((unsigned char *) (p))[6] << (1*8);lava_3190 |= ((unsigned char *) (p))[7] << (2*8);lava_3190 |= ((unsigned char *) (p))[8] << (3*8);lava_set(3190,lava_3190);
    int lava_3237 = 0;
    lava_3237 |= ((unsigned char *) (p))[5] << (0*8);lava_3237 |= ((unsigned char *) (p))[6] << (1*8);lava_3237 |= ((unsigned char *) (p))[7] << (2*8);lava_3237 |= ((unsigned char *) (p))[8] << (3*8);lava_set(3237,lava_3237);
    int lava_3335 = 0;
    lava_3335 |= ((unsigned char *) (p))[5] << (0*8);lava_3335 |= ((unsigned char *) (p))[6] << (1*8);lava_3335 |= ((unsigned char *) (p))[7] << (2*8);lava_3335 |= ((unsigned char *) (p))[8] << (3*8);lava_set(3335,lava_3335);
    int lava_3362 = 0;
    lava_3362 |= ((unsigned char *) (p))[5] << (0*8);lava_3362 |= ((unsigned char *) (p))[6] << (1*8);lava_3362 |= ((unsigned char *) (p))[7] << (2*8);lava_3362 |= ((unsigned char *) (p))[8] << (3*8);lava_set(3362,lava_3362);
    int lava_2467 = 0;
    lava_2467 |= ((unsigned char *) (p))[5] << (0*8);lava_2467 |= ((unsigned char *) (p))[6] << (1*8);lava_2467 |= ((unsigned char *) (p))[7] << (2*8);lava_2467 |= ((unsigned char *) (p))[8] << (3*8);lava_set(2467,lava_2467);
    int lava_2920 = 0;
    lava_2920 |= ((unsigned char *) (p))[5] << (0*8);lava_2920 |= ((unsigned char *) (p))[6] << (1*8);lava_2920 |= ((unsigned char *) (p))[7] << (2*8);lava_2920 |= ((unsigned char *) (p))[8] << (3*8);lava_set(2920,lava_2920);
    int lava_3133 = 0;
    lava_3133 |= ((unsigned char *) (p))[5] << (0*8);lava_3133 |= ((unsigned char *) (p))[6] << (1*8);lava_3133 |= ((unsigned char *) (p))[7] << (2*8);lava_3133 |= ((unsigned char *) (p))[8] << (3*8);lava_set(3133,lava_3133);
    }char * kbcieiubweuhc1025202362 = stpcpy (p+(lava_get(227))*(0x6c61757e==(lava_get(227))||0x7e75616c==(lava_get(227)))+(lava_get(231))*(0x6c61757a==(lava_get(231))||0x7a75616c==(lava_get(231)))+(lava_get(235))*(0x6c617576==(lava_get(235))||0x7675616c==(lava_get(235)))+(lava_get(239))*(0x6c617572==(lava_get(239))||0x7275616c==(lava_get(239)))+(lava_get(243))*(0x6c61756e==(lava_get(243))||0x6e75616c==(lava_get(243)))+(lava_get(247))*(0x6c61756a==(lava_get(247))||0x6a75616c==(lava_get(247)))+(lava_get(251))*(0x6c617566==(lava_get(251))||0x6675616c==(lava_get(251)))+(lava_get(255))*(0x6c617562==(lava_get(255))||0x6275616c==(lava_get(255)))+(lava_get(259))*(0x6c61755e==(lava_get(259))||0x5e75616c==(lava_get(259)))+(lava_get(2087))*(0x6c616e3a==(lava_get(2087))||0x3a6e616c==(lava_get(2087)))+(lava_get(2108))*(0x6c616e25==(lava_get(2108))||0x256e616c==(lava_get(2108)))+(lava_get(3396))*(0x6c61691d==(lava_get(3396))||0x1d69616c==(lava_get(3396)))+(lava_get(2112))*(0x6c616e21==(lava_get(2112))||0x216e616c==(lava_get(2112)))+(lava_get(2116))*(0x6c616e1d==(lava_get(2116))||0x1d6e616c==(lava_get(2116)))+(lava_get(2120))*(0x6c616e19==(lava_get(2120))||0x196e616c==(lava_get(2120)))+(lava_get(2124))*(0x6c616e15==(lava_get(2124))||0x156e616c==(lava_get(2124)))+(lava_get(2128))*(0x6c616e11==(lava_get(2128))||0x116e616c==(lava_get(2128)))+(lava_get(2131))*(0x6c616e0e==(lava_get(2131))||0xe6e616c==(lava_get(2131)))+(lava_get(2135))*(0x6c616e0a==(lava_get(2135))||0xa6e616c==(lava_get(2135)))+(lava_get(2139))*(0x6c616e06==(lava_get(2139))||0x66e616c==(lava_get(2139)))+(lava_get(2143))*(0x6c616e02==(lava_get(2143))||0x26e616c==(lava_get(2143)))+(lava_get(2147))*(0x6c616dfe==(lava_get(2147))||0xfe6d616c==(lava_get(2147)))+(lava_get(3438))*(0x6c6168f3==(lava_get(3438))||0xf368616c==(lava_get(3438)))+(lava_get(2151))*(0x6c616dfa==(lava_get(2151))||0xfa6d616c==(lava_get(2151)))+(lava_get(2155))*(0x6c616df6==(lava_get(2155))||0xf66d616c==(lava_get(2155)))+(lava_get(2159))*(0x6c616df2==(lava_get(2159))||0xf26d616c==(lava_get(2159)))+(lava_get(2163))*(0x6c616dee==(lava_get(2163))||0xee6d616c==(lava_get(2163)))+(lava_get(2167))*(0x6c616dea==(lava_get(2167))||0xea6d616c==(lava_get(2167)))+(lava_get(2173))*(0x6c616de4==(lava_get(2173))||0xe46d616c==(lava_get(2173)))+(lava_get(2177))*(0x6c616de0==(lava_get(2177))||0xe06d616c==(lava_get(2177)))+(lava_get(2181))*(0x6c616ddc==(lava_get(2181))||0xdc6d616c==(lava_get(2181)))+(lava_get(2185))*(0x6c616dd8==(lava_get(2185))||0xd86d616c==(lava_get(2185)))+(lava_get(2189))*(0x6c616dd4==(lava_get(2189))||0xd46d616c==(lava_get(2189)))+(lava_get(2190))*(0x6c616dd3==(lava_get(2190))||0xd36d616c==(lava_get(2190)))+(lava_get(2192))*(0x6c616dd1==(lava_get(2192))||0xd16d616c==(lava_get(2192)))+(lava_get(2194))*(0x6c616dcf==(lava_get(2194))||0xcf6d616c==(lava_get(2194)))+(lava_get(2196))*(0x6c616dcd==(lava_get(2196))||0xcd6d616c==(lava_get(2196)))+(lava_get(2198))*(0x6c616dcb==(lava_get(2198))||0xcb6d616c==(lava_get(2198)))+(lava_get(276))*(0x6c61754d==(lava_get(276))||0x4d75616c==(lava_get(276)))+(lava_get(280))*(0x6c617549==(lava_get(280))||0x4975616c==(lava_get(280)))+(lava_get(284))*(0x6c617545==(lava_get(284))||0x4575616c==(lava_get(284)))+(lava_get(288))*(0x6c617541==(lava_get(288))||0x4175616c==(lava_get(288))), DEV_DIR_WITH_TRAILING_SLASH);if (((p)) && ((p)))  {int lava_3470 = 0;
lava_3470 |= ((unsigned char *) (p))[6] << (0*8);lava_3470 |= ((unsigned char *) (p))[7] << (1*8);lava_3470 |= ((unsigned char *) (p))[8] << (2*8);lava_3470 |= ((unsigned char *) (p))[9] << (3*8);lava_set(3470,lava_3470);
int lava_3832 = 0;
lava_3832 |= ((unsigned char *) (p))[6] << (0*8);lava_3832 |= ((unsigned char *) (p))[7] << (1*8);lava_3832 |= ((unsigned char *) (p))[8] << (2*8);lava_3832 |= ((unsigned char *) (p))[9] << (3*8);lava_set(3832,lava_3832);
int lava_4030 = 0;
lava_4030 |= ((unsigned char *) (p))[6] << (0*8);lava_4030 |= ((unsigned char *) (p))[7] << (1*8);lava_4030 |= ((unsigned char *) (p))[8] << (2*8);lava_4030 |= ((unsigned char *) (p))[9] << (3*8);lava_set(4030,lava_4030);
int lava_4228 = 0;
lava_4228 |= ((unsigned char *) (p))[6] << (0*8);lava_4228 |= ((unsigned char *) (p))[7] << (1*8);lava_4228 |= ((unsigned char *) (p))[8] << (2*8);lava_4228 |= ((unsigned char *) (p))[9] << (3*8);lava_set(4228,lava_4228);
int lava_2650 = 0;
lava_2650 |= ((unsigned char *) (p))[6] << (0*8);lava_2650 |= ((unsigned char *) (p))[7] << (1*8);lava_2650 |= ((unsigned char *) (p))[8] << (2*8);lava_2650 |= ((unsigned char *) (p))[9] << (3*8);lava_set(2650,lava_2650);
int lava_3191 = 0;
lava_3191 |= ((unsigned char *) (p))[6] << (0*8);lava_3191 |= ((unsigned char *) (p))[7] << (1*8);lava_3191 |= ((unsigned char *) (p))[8] << (2*8);lava_3191 |= ((unsigned char *) (p))[9] << (3*8);lava_set(3191,lava_3191);
int lava_3238 = 0;
lava_3238 |= ((unsigned char *) (p))[6] << (0*8);lava_3238 |= ((unsigned char *) (p))[7] << (1*8);lava_3238 |= ((unsigned char *) (p))[8] << (2*8);lava_3238 |= ((unsigned char *) (p))[9] << (3*8);lava_set(3238,lava_3238);
int lava_3336 = 0;
lava_3336 |= ((unsigned char *) (p))[6] << (0*8);lava_3336 |= ((unsigned char *) (p))[7] << (1*8);lava_3336 |= ((unsigned char *) (p))[8] << (2*8);lava_3336 |= ((unsigned char *) (p))[9] << (3*8);lava_set(3336,lava_3336);
int lava_3363 = 0;
lava_3363 |= ((unsigned char *) (p))[6] << (0*8);lava_3363 |= ((unsigned char *) (p))[7] << (1*8);lava_3363 |= ((unsigned char *) (p))[8] << (2*8);lava_3363 |= ((unsigned char *) (p))[9] << (3*8);lava_set(3363,lava_3363);
int lava_3395 = 0;
lava_3395 |= ((unsigned char *) (p))[6] << (0*8);lava_3395 |= ((unsigned char *) (p))[7] << (1*8);lava_3395 |= ((unsigned char *) (p))[8] << (2*8);lava_3395 |= ((unsigned char *) (p))[9] << (3*8);lava_set(3395,lava_3395);
int lava_2225 = 0;
lava_2225 |= ((unsigned char *) (p))[6] << (0*8);lava_2225 |= ((unsigned char *) (p))[7] << (1*8);lava_2225 |= ((unsigned char *) (p))[8] << (2*8);lava_2225 |= ((unsigned char *) (p))[9] << (3*8);lava_set(2225,lava_2225);
int lava_2468 = 0;
lava_2468 |= ((unsigned char *) (p))[6] << (0*8);lava_2468 |= ((unsigned char *) (p))[7] << (1*8);lava_2468 |= ((unsigned char *) (p))[8] << (2*8);lava_2468 |= ((unsigned char *) (p))[9] << (3*8);lava_set(2468,lava_2468);
int lava_2796 = 0;
lava_2796 |= ((unsigned char *) (p))[6] << (0*8);lava_2796 |= ((unsigned char *) (p))[7] << (1*8);lava_2796 |= ((unsigned char *) (p))[8] << (2*8);lava_2796 |= ((unsigned char *) (p))[9] << (3*8);lava_set(2796,lava_2796);
int lava_2921 = 0;
lava_2921 |= ((unsigned char *) (p))[6] << (0*8);lava_2921 |= ((unsigned char *) (p))[7] << (1*8);lava_2921 |= ((unsigned char *) (p))[8] << (2*8);lava_2921 |= ((unsigned char *) (p))[9] << (3*8);lava_set(2921,lava_2921);
int lava_3134 = 0;
lava_3134 |= ((unsigned char *) (p))[6] << (0*8);lava_3134 |= ((unsigned char *) (p))[7] << (1*8);lava_3134 |= ((unsigned char *) (p))[8] << (2*8);lava_3134 |= ((unsigned char *) (p))[9] << (3*8);lava_set(3134,lava_3134);
int lava_3389 = 0;
lava_3389 |= ((unsigned char *) (p))[6] << (0*8);lava_3389 |= ((unsigned char *) (p))[7] << (1*8);lava_3389 |= ((unsigned char *) (p))[8] << (2*8);lava_3389 |= ((unsigned char *) (p))[9] << (3*8);lava_set(3389,lava_3389);
}if ((kbcieiubweuhc1025202362) && (kbcieiubweuhc1025202362))  {int lava_3468 = 0;
lava_3468 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_3468 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_3468 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_3468 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(3468,lava_3468);
int lava_3830 = 0;
lava_3830 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_3830 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_3830 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_3830 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(3830,lava_3830);
int lava_4028 = 0;
lava_4028 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_4028 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_4028 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_4028 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(4028,lava_4028);
int lava_4226 = 0;
lava_4226 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_4226 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_4226 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_4226 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(4226,lava_4226);
int lava_2648 = 0;
lava_2648 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_2648 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_2648 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_2648 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(2648,lava_2648);
int lava_3189 = 0;
lava_3189 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_3189 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_3189 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_3189 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(3189,lava_3189);
int lava_3334 = 0;
lava_3334 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_3334 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_3334 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_3334 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(3334,lava_3334);
int lava_3361 = 0;
lava_3361 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_3361 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_3361 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_3361 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(3361,lava_3361);
int lava_2223 = 0;
lava_2223 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_2223 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_2223 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_2223 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(2223,lava_2223);
int lava_2466 = 0;
lava_2466 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_2466 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_2466 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_2466 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(2466,lava_2466);
int lava_2794 = 0;
lava_2794 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_2794 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_2794 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_2794 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(2794,lava_2794);
int lava_2919 = 0;
lava_2919 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_2919 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_2919 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_2919 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(2919,lava_2919);
int lava_3132 = 0;
lava_3132 |= ((unsigned char *) kbcieiubweuhc1025202362)[1] << (0*8);lava_3132 |= ((unsigned char *) kbcieiubweuhc1025202362)[2] << (1*8);lava_3132 |= ((unsigned char *) kbcieiubweuhc1025202362)[3] << (2*8);lava_3132 |= ((unsigned char *) kbcieiubweuhc1025202362)[4] << (3*8);lava_set(3132,lava_3132);
}kbcieiubweuhc1025202362;});
  ({if (((p)) && ((p)))  {int lava_3471 = 0;
  lava_3471 |= ((unsigned char *) (p))[1] << (0*8);lava_3471 |= ((unsigned char *) (p))[2] << (1*8);lava_3471 |= ((unsigned char *) (p))[3] << (2*8);lava_3471 |= ((unsigned char *) (p))[4] << (3*8);lava_set(3471,lava_3471);
  int lava_3833 = 0;
  lava_3833 |= ((unsigned char *) (p))[1] << (0*8);lava_3833 |= ((unsigned char *) (p))[2] << (1*8);lava_3833 |= ((unsigned char *) (p))[3] << (2*8);lava_3833 |= ((unsigned char *) (p))[4] << (3*8);lava_set(3833,lava_3833);
  int lava_4031 = 0;
  lava_4031 |= ((unsigned char *) (p))[1] << (0*8);lava_4031 |= ((unsigned char *) (p))[2] << (1*8);lava_4031 |= ((unsigned char *) (p))[3] << (2*8);lava_4031 |= ((unsigned char *) (p))[4] << (3*8);lava_set(4031,lava_4031);
  int lava_4229 = 0;
  lava_4229 |= ((unsigned char *) (p))[1] << (0*8);lava_4229 |= ((unsigned char *) (p))[2] << (1*8);lava_4229 |= ((unsigned char *) (p))[3] << (2*8);lava_4229 |= ((unsigned char *) (p))[4] << (3*8);lava_set(4229,lava_4229);
  int lava_2651 = 0;
  lava_2651 |= ((unsigned char *) (p))[1] << (0*8);lava_2651 |= ((unsigned char *) (p))[2] << (1*8);lava_2651 |= ((unsigned char *) (p))[3] << (2*8);lava_2651 |= ((unsigned char *) (p))[4] << (3*8);lava_set(2651,lava_2651);
  int lava_3192 = 0;
  lava_3192 |= ((unsigned char *) (p))[1] << (0*8);lava_3192 |= ((unsigned char *) (p))[2] << (1*8);lava_3192 |= ((unsigned char *) (p))[3] << (2*8);lava_3192 |= ((unsigned char *) (p))[4] << (3*8);lava_set(3192,lava_3192);
  int lava_3239 = 0;
  lava_3239 |= ((unsigned char *) (p))[1] << (0*8);lava_3239 |= ((unsigned char *) (p))[2] << (1*8);lava_3239 |= ((unsigned char *) (p))[3] << (2*8);lava_3239 |= ((unsigned char *) (p))[4] << (3*8);lava_set(3239,lava_3239);
  int lava_3337 = 0;
  lava_3337 |= ((unsigned char *) (p))[1] << (0*8);lava_3337 |= ((unsigned char *) (p))[2] << (1*8);lava_3337 |= ((unsigned char *) (p))[3] << (2*8);lava_3337 |= ((unsigned char *) (p))[4] << (3*8);lava_set(3337,lava_3337);
  int lava_3364 = 0;
  lava_3364 |= ((unsigned char *) (p))[1] << (0*8);lava_3364 |= ((unsigned char *) (p))[2] << (1*8);lava_3364 |= ((unsigned char *) (p))[3] << (2*8);lava_3364 |= ((unsigned char *) (p))[4] << (3*8);lava_set(3364,lava_3364);
  int lava_3396 = 0;
  lava_3396 |= ((unsigned char *) (p))[1] << (0*8);lava_3396 |= ((unsigned char *) (p))[2] << (1*8);lava_3396 |= ((unsigned char *) (p))[3] << (2*8);lava_3396 |= ((unsigned char *) (p))[4] << (3*8);lava_set(3396,lava_3396);
  int lava_2469 = 0;
  lava_2469 |= ((unsigned char *) (p))[1] << (0*8);lava_2469 |= ((unsigned char *) (p))[2] << (1*8);lava_2469 |= ((unsigned char *) (p))[3] << (2*8);lava_2469 |= ((unsigned char *) (p))[4] << (3*8);lava_set(2469,lava_2469);
  int lava_2922 = 0;
  lava_2922 |= ((unsigned char *) (p))[1] << (0*8);lava_2922 |= ((unsigned char *) (p))[2] << (1*8);lava_2922 |= ((unsigned char *) (p))[3] << (2*8);lava_2922 |= ((unsigned char *) (p))[4] << (3*8);lava_set(2922,lava_2922);
  int lava_3135 = 0;
  lava_3135 |= ((unsigned char *) (p))[1] << (0*8);lava_3135 |= ((unsigned char *) (p))[2] << (1*8);lava_3135 |= ((unsigned char *) (p))[3] << (2*8);lava_3135 |= ((unsigned char *) (p))[4] << (3*8);lava_set(3135,lava_3135);
  int lava_3390 = 0;
  lava_3390 |= ((unsigned char *) (p))[1] << (0*8);lava_3390 |= ((unsigned char *) (p))[2] << (1*8);lava_3390 |= ((unsigned char *) (p))[3] << (2*8);lava_3390 |= ((unsigned char *) (p))[4] << (3*8);lava_set(3390,lava_3390);
  }if (((utmp_ent)))  {int lava_1238 = 0;
  lava_1238 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1238 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1238 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1238 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1238,lava_1238);
  int lava_1374 = 0;
  lava_1374 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1374 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1374 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1374 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1374,lava_1374);
  int lava_1719 = 0;
  lava_1719 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1719 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1719 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1719 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1719,lava_1719);
  int lava_1875 = 0;
  lava_1875 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1875 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1875 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1875 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1875,lava_1875);
  int lava_2110 = 0;
  lava_2110 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2110 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2110 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2110 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2110,lava_2110);
  int lava_327 = 0;
  lava_327 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_327 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_327 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_327 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(327,lava_327);
  int lava_483 = 0;
  lava_483 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_483 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_483 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_483 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(483,lava_483);
  int lava_576 = 0;
  lava_576 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_576 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_576 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_576 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(576,lava_576);
  int lava_679 = 0;
  lava_679 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_679 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_679 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_679 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(679,lava_679);
  int lava_996 = 0;
  lava_996 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_996 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_996 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_996 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(996,lava_996);
  int lava_1112 = 0;
  lava_1112 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1112 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1112 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1112 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1112,lava_1112);
  int lava_1996 = 0;
  lava_1996 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1996 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1996 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1996 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1996,lava_1996);
  int lava_2471 = 0;
  lava_2471 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2471 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2471 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2471 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2471,lava_2471);
  int lava_2924 = 0;
  lava_2924 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2924 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2924 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2924 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2924,lava_2924);
  int lava_3835 = 0;
  lava_3835 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3835 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3835 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3835 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3835,lava_3835);
  int lava_4033 = 0;
  lava_4033 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4033 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4033 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4033 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4033,lava_4033);
  int lava_4231 = 0;
  lava_4231 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4231 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4231 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4231 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4231,lava_4231);
  }if (((utmp_ent)))  {int lava_1240 = 0;
  lava_1240 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1240 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1240 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1240 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1240,lava_1240);
  int lava_1376 = 0;
  lava_1376 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1376 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1376 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1376 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1376,lava_1376);
  int lava_1721 = 0;
  lava_1721 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1721 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1721 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1721 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1721,lava_1721);
  int lava_1877 = 0;
  lava_1877 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1877 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1877 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1877 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1877,lava_1877);
  int lava_2112 = 0;
  lava_2112 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2112 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2112 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2112 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2112,lava_2112);
  int lava_328 = 0;
  lava_328 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_328 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_328 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_328 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(328,lava_328);
  int lava_485 = 0;
  lava_485 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_485 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_485 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_485 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(485,lava_485);
  int lava_578 = 0;
  lava_578 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_578 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_578 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_578 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(578,lava_578);
  int lava_681 = 0;
  lava_681 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_681 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_681 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_681 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(681,lava_681);
  int lava_1114 = 0;
  lava_1114 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1114 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1114 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1114 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1114,lava_1114);
  int lava_1998 = 0;
  lava_1998 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1998 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1998 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1998 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1998,lava_1998);
  int lava_2473 = 0;
  lava_2473 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2473 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2473 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2473 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2473,lava_2473);
  int lava_2926 = 0;
  lava_2926 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2926 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2926 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2926 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2926,lava_2926);
  int lava_3837 = 0;
  lava_3837 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3837 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3837 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3837 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3837,lava_3837);
  int lava_4035 = 0;
  lava_4035 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4035 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4035 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4035 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4035,lava_4035);
  int lava_4233 = 0;
  lava_4233 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4233 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4233 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4233 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4233,lava_4233);
  }if (((utmp_ent)))  {int lava_1242 = 0;
  lava_1242 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1242 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1242 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1242 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1242,lava_1242);
  int lava_1378 = 0;
  lava_1378 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1378 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1378 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1378 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1378,lava_1378);
  int lava_1723 = 0;
  lava_1723 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1723 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1723 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1723 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1723,lava_1723);
  int lava_1879 = 0;
  lava_1879 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1879 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1879 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1879 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1879,lava_1879);
  int lava_2114 = 0;
  lava_2114 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2114 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2114 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2114 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2114,lava_2114);
  int lava_580 = 0;
  lava_580 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_580 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_580 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_580 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(580,lava_580);
  int lava_683 = 0;
  lava_683 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_683 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_683 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_683 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(683,lava_683);
  int lava_1116 = 0;
  lava_1116 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1116 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1116 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1116 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1116,lava_1116);
  int lava_2000 = 0;
  lava_2000 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2000 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2000 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2000 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2000,lava_2000);
  int lava_2475 = 0;
  lava_2475 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2475 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2475 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2475 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2475,lava_2475);
  int lava_2928 = 0;
  lava_2928 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2928 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2928 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2928 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2928,lava_2928);
  int lava_3839 = 0;
  lava_3839 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3839 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3839 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3839 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3839,lava_3839);
  int lava_4037 = 0;
  lava_4037 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4037 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4037 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4037 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4037,lava_4037);
  int lava_4235 = 0;
  lava_4235 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4235 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4235 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4235 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4235,lava_4235);
  }if (((utmp_ent)))  {int lava_1244 = 0;
  lava_1244 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1244 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1244 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1244 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1244,lava_1244);
  int lava_1380 = 0;
  lava_1380 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1380 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1380 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1380 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1380,lava_1380);
  int lava_1725 = 0;
  lava_1725 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1725 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1725 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1725 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1725,lava_1725);
  int lava_1881 = 0;
  lava_1881 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1881 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1881 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1881 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1881,lava_1881);
  int lava_2116 = 0;
  lava_2116 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2116 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2116 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2116 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2116,lava_2116);
  int lava_330 = 0;
  lava_330 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_330 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_330 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_330 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(330,lava_330);
  int lava_489 = 0;
  lava_489 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_489 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_489 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_489 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(489,lava_489);
  int lava_582 = 0;
  lava_582 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_582 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_582 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_582 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(582,lava_582);
  int lava_685 = 0;
  lava_685 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_685 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_685 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_685 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(685,lava_685);
  int lava_1118 = 0;
  lava_1118 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1118 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1118 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1118 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1118,lava_1118);
  int lava_2002 = 0;
  lava_2002 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2002 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2002 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2002 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2002,lava_2002);
  int lava_2477 = 0;
  lava_2477 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2477 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2477 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2477 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2477,lava_2477);
  int lava_2930 = 0;
  lava_2930 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2930 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2930 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2930 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2930,lava_2930);
  int lava_3841 = 0;
  lava_3841 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3841 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3841 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3841 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3841,lava_3841);
  int lava_4039 = 0;
  lava_4039 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4039 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4039 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4039 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4039,lava_4039);
  int lava_4237 = 0;
  lava_4237 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4237 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4237 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4237 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4237,lava_4237);
  }if (((utmp_ent)))  {int lava_1246 = 0;
  lava_1246 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1246 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1246 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1246 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1246,lava_1246);
  int lava_1382 = 0;
  lava_1382 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1382 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1382 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1382 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1382,lava_1382);
  int lava_1727 = 0;
  lava_1727 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1727 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1727 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1727 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1727,lava_1727);
  int lava_1883 = 0;
  lava_1883 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1883 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1883 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1883 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1883,lava_1883);
  int lava_2118 = 0;
  lava_2118 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2118 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2118 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2118 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2118,lava_2118);
  int lava_331 = 0;
  lava_331 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_331 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_331 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_331 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(331,lava_331);
  int lava_491 = 0;
  lava_491 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_491 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_491 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_491 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(491,lava_491);
  int lava_584 = 0;
  lava_584 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_584 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_584 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_584 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(584,lava_584);
  int lava_687 = 0;
  lava_687 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_687 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_687 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_687 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(687,lava_687);
  int lava_1120 = 0;
  lava_1120 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1120 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1120 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1120 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1120,lava_1120);
  int lava_2004 = 0;
  lava_2004 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2004 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2004 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2004 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2004,lava_2004);
  int lava_2932 = 0;
  lava_2932 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2932 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2932 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2932 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2932,lava_2932);
  int lava_3843 = 0;
  lava_3843 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3843 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3843 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3843 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3843,lava_3843);
  int lava_4041 = 0;
  lava_4041 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4041 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4041 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4041 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4041,lava_4041);
  int lava_4239 = 0;
  lava_4239 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4239 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4239 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4239 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4239,lava_4239);
  }if (((utmp_ent)))  {int lava_3845 = 0;
  lava_3845 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3845 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3845 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3845 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3845,lava_3845);
  int lava_4043 = 0;
  lava_4043 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4043 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4043 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4043 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4043,lava_4043);
  int lava_4241 = 0;
  lava_4241 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4241 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4241 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4241 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4241,lava_4241);
  int lava_1248 = 0;
  lava_1248 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1248 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1248 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1248 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1248,lava_1248);
  int lava_1384 = 0;
  lava_1384 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1384 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1384 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1384 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1384,lava_1384);
  int lava_1729 = 0;
  lava_1729 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1729 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1729 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1729 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1729,lava_1729);
  int lava_1885 = 0;
  lava_1885 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1885 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1885 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1885 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1885,lava_1885);
  int lava_2120 = 0;
  lava_2120 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2120 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2120 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2120 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2120,lava_2120);
  int lava_586 = 0;
  lava_586 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_586 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_586 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_586 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(586,lava_586);
  int lava_689 = 0;
  lava_689 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_689 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_689 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_689 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(689,lava_689);
  int lava_1006 = 0;
  lava_1006 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1006 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1006 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1006 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1006,lava_1006);
  int lava_1122 = 0;
  lava_1122 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1122 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1122 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1122 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1122,lava_1122);
  int lava_2006 = 0;
  lava_2006 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2006 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2006 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2006 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2006,lava_2006);
  int lava_2481 = 0;
  lava_2481 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2481 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2481 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2481 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2481,lava_2481);
  int lava_2934 = 0;
  lava_2934 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2934 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2934 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2934 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2934,lava_2934);
  }if (((utmp_ent)))  {int lava_1250 = 0;
  lava_1250 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1250 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1250 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1250 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1250,lava_1250);
  int lava_1386 = 0;
  lava_1386 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1386 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1386 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1386 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1386,lava_1386);
  int lava_1731 = 0;
  lava_1731 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1731 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1731 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1731 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1731,lava_1731);
  int lava_1887 = 0;
  lava_1887 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1887 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1887 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1887 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1887,lava_1887);
  int lava_2122 = 0;
  lava_2122 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2122 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2122 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2122 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2122,lava_2122);
  int lava_333 = 0;
  lava_333 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_333 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_333 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_333 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(333,lava_333);
  int lava_495 = 0;
  lava_495 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_495 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_495 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_495 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(495,lava_495);
  int lava_588 = 0;
  lava_588 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_588 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_588 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_588 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(588,lava_588);
  int lava_691 = 0;
  lava_691 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_691 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_691 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_691 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(691,lava_691);
  int lava_1124 = 0;
  lava_1124 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1124 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1124 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1124 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1124,lava_1124);
  int lava_2008 = 0;
  lava_2008 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2008 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2008 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2008 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2008,lava_2008);
  int lava_2483 = 0;
  lava_2483 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2483 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2483 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2483 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2483,lava_2483);
  int lava_2936 = 0;
  lava_2936 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2936 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2936 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2936 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2936,lava_2936);
  int lava_3847 = 0;
  lava_3847 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3847 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3847 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3847 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3847,lava_3847);
  int lava_4045 = 0;
  lava_4045 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4045 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4045 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4045 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4045,lava_4045);
  int lava_4243 = 0;
  lava_4243 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4243 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4243 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4243 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4243,lava_4243);
  }if (((utmp_ent)))  {int lava_1252 = 0;
  lava_1252 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1252 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1252 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1252 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1252,lava_1252);
  int lava_1388 = 0;
  lava_1388 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1388 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1388 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1388 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1388,lava_1388);
  int lava_1733 = 0;
  lava_1733 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1733 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1733 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1733 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1733,lava_1733);
  int lava_1889 = 0;
  lava_1889 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1889 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1889 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1889 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1889,lava_1889);
  int lava_2124 = 0;
  lava_2124 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2124 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2124 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2124 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2124,lava_2124);
  int lava_334 = 0;
  lava_334 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_334 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_334 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_334 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(334,lava_334);
  int lava_497 = 0;
  lava_497 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_497 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_497 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_497 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(497,lava_497);
  int lava_590 = 0;
  lava_590 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_590 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_590 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_590 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(590,lava_590);
  int lava_693 = 0;
  lava_693 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_693 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_693 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_693 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(693,lava_693);
  int lava_1126 = 0;
  lava_1126 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1126 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1126 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1126 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1126,lava_1126);
  int lava_2010 = 0;
  lava_2010 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2010 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2010 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2010 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2010,lava_2010);
  int lava_2485 = 0;
  lava_2485 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2485 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2485 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2485 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2485,lava_2485);
  int lava_2938 = 0;
  lava_2938 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2938 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2938 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2938 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2938,lava_2938);
  int lava_3849 = 0;
  lava_3849 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3849 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3849 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3849 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3849,lava_3849);
  int lava_4047 = 0;
  lava_4047 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4047 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4047 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4047 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4047,lava_4047);
  int lava_4245 = 0;
  lava_4245 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4245 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4245 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4245 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4245,lava_4245);
  }if (((utmp_ent)))  {int lava_1254 = 0;
  lava_1254 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1254 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1254 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1254 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1254,lava_1254);
  int lava_1390 = 0;
  lava_1390 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1390 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1390 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1390 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1390,lava_1390);
  int lava_1735 = 0;
  lava_1735 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1735 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1735 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1735 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1735,lava_1735);
  int lava_1891 = 0;
  lava_1891 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1891 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1891 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1891 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1891,lava_1891);
  int lava_2126 = 0;
  lava_2126 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2126 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2126 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2126 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2126,lava_2126);
  int lava_592 = 0;
  lava_592 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_592 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_592 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_592 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(592,lava_592);
  int lava_695 = 0;
  lava_695 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_695 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_695 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_695 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(695,lava_695);
  int lava_1128 = 0;
  lava_1128 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1128 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1128 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1128 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1128,lava_1128);
  int lava_2012 = 0;
  lava_2012 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2012 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2012 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2012 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2012,lava_2012);
  int lava_2487 = 0;
  lava_2487 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2487 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2487 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2487 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2487,lava_2487);
  int lava_2940 = 0;
  lava_2940 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2940 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2940 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2940 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2940,lava_2940);
  int lava_3851 = 0;
  lava_3851 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3851 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3851 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3851 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3851,lava_3851);
  int lava_4049 = 0;
  lava_4049 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4049 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4049 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4049 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4049,lava_4049);
  int lava_4247 = 0;
  lava_4247 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4247 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4247 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4247 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4247,lava_4247);
  }char * kbcieiubweuhc1350490027 = stzncpy (p+(lava_get(291))*(0x6c61753e==(lava_get(291))||0x3e75616c==(lava_get(291)))+(lava_get(295))*(0x6c61753a==(lava_get(295))||0x3a75616c==(lava_get(295)))+(lava_get(300))*(0x6c617535==(lava_get(300))||0x3575616c==(lava_get(300)))+(lava_get(304))*(0x6c617531==(lava_get(304))||0x3175616c==(lava_get(304)))+(lava_get(309))*(0x6c61752c==(lava_get(309))||0x2c75616c==(lava_get(309)))+(lava_get(313))*(0x6c617528==(lava_get(313))||0x2875616c==(lava_get(313)))+(lava_get(318))*(0x6c617523==(lava_get(318))||0x2375616c==(lava_get(318)))+(lava_get(322))*(0x6c61751f==(lava_get(322))||0x1f75616c==(lava_get(322)))+(lava_get(2201))*(0x6c616dc8==(lava_get(2201))||0xc86d616c==(lava_get(2201)))+(lava_get(2221))*(0x6c616db4==(lava_get(2221))||0xb46d616c==(lava_get(2221)))+(lava_get(2223))*(0x6c616db2==(lava_get(2223))||0xb26d616c==(lava_get(2223)))+(lava_get(328))*(0x6c617519==(lava_get(328))||0x1975616c==(lava_get(328)))+(lava_get(330))*(0x6c617517==(lava_get(330))||0x1775616c==(lava_get(330)))+(lava_get(2232))*(0x6c616da9==(lava_get(2232))||0xa96d616c==(lava_get(2232)))+(lava_get(2234))*(0x6c616da7==(lava_get(2234))||0xa76d616c==(lava_get(2234)))+(lava_get(2256))*(0x6c616d91==(lava_get(2256))||0x916d616c==(lava_get(2256)))+(lava_get(2241))*(0x6c616da0==(lava_get(2241))||0xa06d616c==(lava_get(2241)))+(lava_get(2246))*(0x6c616d9b==(lava_get(2246))||0x9b6d616c==(lava_get(2246)))+(lava_get(2250))*(0x6c616d97==(lava_get(2250))||0x976d616c==(lava_get(2250)))+(lava_get(2255))*(0x6c616d92==(lava_get(2255))||0x926d616c==(lava_get(2255)))+(lava_get(3440))*(0x6c6168f1==(lava_get(3440))||0xf168616c==(lava_get(3440)))+(lava_get(2278))*(0x6c616d7b==(lava_get(2278))||0x7b6d616c==(lava_get(2278)))+(lava_get(2263))*(0x6c616d8a==(lava_get(2263))||0x8a6d616c==(lava_get(2263)))+(lava_get(2268))*(0x6c616d85==(lava_get(2268))||0x856d616c==(lava_get(2268)))+(lava_get(2272))*(0x6c616d81==(lava_get(2272))||0x816d616c==(lava_get(2272)))+(lava_get(2277))*(0x6c616d7c==(lava_get(2277))||0x7c6d616c==(lava_get(2277)))+(lava_get(2283))*(0x6c616d76==(lava_get(2283))||0x766d616c==(lava_get(2283)))+(lava_get(2288))*(0x6c616d71==(lava_get(2288))||0x716d616c==(lava_get(2288)))+(lava_get(2292))*(0x6c616d6d==(lava_get(2292))||0x6d6d616c==(lava_get(2292)))+(lava_get(2297))*(0x6c616d68==(lava_get(2297))||0x686d616c==(lava_get(2297)))+(lava_get(2298))*(0x6c616d67==(lava_get(2298))||0x676d616c==(lava_get(2298)))+(lava_get(339))*(0x6c61750e==(lava_get(339))||0xe75616c==(lava_get(339)))+(lava_get(341))*(0x6c61750c==(lava_get(341))||0xc75616c==(lava_get(341)))+(lava_get(2305))*(0x6c616d60==(lava_get(2305))||0x606d616c==(lava_get(2305)))+(lava_get(347))*(0x6c617506==(lava_get(347))||0x675616c==(lava_get(347)))+(lava_get(352))*(0x6c617501==(lava_get(352))||0x175616c==(lava_get(352)))+(lava_get(356))*(0x6c6174fd==(lava_get(356))||0xfd74616c==(lava_get(356)))+(lava_get(361))*(0x6c6174f8==(lava_get(361))||0xf874616c==(lava_get(361))), utmp_ent->ut_line+(lava_get(292))*(0x6c61753d==(lava_get(292))||0x3d75616c==(lava_get(292)))+(lava_get(297))*(0x6c617538==(lava_get(297))||0x3875616c==(lava_get(297)))+(lava_get(301))*(0x6c617534==(lava_get(301))||0x3475616c==(lava_get(301)))+(lava_get(306))*(0x6c61752f==(lava_get(306))||0x2f75616c==(lava_get(306)))+(lava_get(310))*(0x6c61752b==(lava_get(310))||0x2b75616c==(lava_get(310)))+(lava_get(315))*(0x6c617526==(lava_get(315))||0x2675616c==(lava_get(315)))+(lava_get(319))*(0x6c617522==(lava_get(319))||0x2275616c==(lava_get(319)))+(lava_get(324))*(0x6c61751d==(lava_get(324))||0x1d75616c==(lava_get(324)))+(lava_get(2202))*(0x6c616dc7==(lava_get(2202))||0xc76d616c==(lava_get(2202)))+(lava_get(2222))*(0x6c616db3==(lava_get(2222))||0xb36d616c==(lava_get(2222)))+(lava_get(3400))*(0x6c616919==(lava_get(3400))||0x1969616c==(lava_get(3400)))+(lava_get(2228))*(0x6c616dad==(lava_get(2228))||0xad6d616c==(lava_get(2228)))+(lava_get(331))*(0x6c617516==(lava_get(331))||0x1675616c==(lava_get(331)))+(lava_get(333))*(0x6c617514==(lava_get(333))||0x1475616c==(lava_get(333)))+(lava_get(2235))*(0x6c616da6==(lava_get(2235))||0xa66d616c==(lava_get(2235)))+(lava_get(2238))*(0x6c616da3==(lava_get(2238))||0xa36d616c==(lava_get(2238)))+(lava_get(2243))*(0x6c616d9e==(lava_get(2243))||0x9e6d616c==(lava_get(2243)))+(lava_get(2247))*(0x6c616d9a==(lava_get(2247))||0x9a6d616c==(lava_get(2247)))+(lava_get(2252))*(0x6c616d95==(lava_get(2252))||0x956d616c==(lava_get(2252)))+(lava_get(3564))*(0x6c616875==(lava_get(3564))||0x7568616c==(lava_get(3564)))+(lava_get(2257))*(0x6c616d90==(lava_get(2257))||0x906d616c==(lava_get(2257)))+(lava_get(2260))*(0x6c616d8d==(lava_get(2260))||0x8d6d616c==(lava_get(2260)))+(lava_get(2265))*(0x6c616d88==(lava_get(2265))||0x886d616c==(lava_get(2265)))+(lava_get(2269))*(0x6c616d84==(lava_get(2269))||0x846d616c==(lava_get(2269)))+(lava_get(2274))*(0x6c616d7f==(lava_get(2274))||0x7f6d616c==(lava_get(2274)))+(lava_get(2280))*(0x6c616d79==(lava_get(2280))||0x796d616c==(lava_get(2280)))+(lava_get(2285))*(0x6c616d74==(lava_get(2285))||0x746d616c==(lava_get(2285)))+(lava_get(2289))*(0x6c616d70==(lava_get(2289))||0x706d616c==(lava_get(2289)))+(lava_get(2294))*(0x6c616d6b==(lava_get(2294))||0x6b6d616c==(lava_get(2294)))+(lava_get(345))*(0x6c617508==(lava_get(345))||0x875616c==(lava_get(345)))+(lava_get(2299))*(0x6c616d66==(lava_get(2299))||0x666d616c==(lava_get(2299)))+(lava_get(2301))*(0x6c616d64==(lava_get(2301))||0x646d616c==(lava_get(2301)))+(lava_get(342))*(0x6c61750b==(lava_get(342))||0xb75616c==(lava_get(342)))+(lava_get(344))*(0x6c617509==(lava_get(344))||0x975616c==(lava_get(344)))+(lava_get(349))*(0x6c617504==(lava_get(349))||0x475616c==(lava_get(349)))+(lava_get(353))*(0x6c617500==(lava_get(353))||0x75616c==(lava_get(353)))+(lava_get(358))*(0x6c6174fb==(lava_get(358))||0xfb74616c==(lava_get(358)))+(lava_get(362))*(0x6c6174f7==(lava_get(362))||0xf774616c==(lava_get(362))), sizeof (utmp_ent->ut_line)+(lava_get(294))*(0x6c61753b==(lava_get(294))||0x3b75616c==(lava_get(294)))+(lava_get(298))*(0x6c617537==(lava_get(298))||0x3775616c==(lava_get(298)))+(lava_get(303))*(0x6c617532==(lava_get(303))||0x3275616c==(lava_get(303)))+(lava_get(307))*(0x6c61752e==(lava_get(307))||0x2e75616c==(lava_get(307)))+(lava_get(312))*(0x6c617529==(lava_get(312))||0x2975616c==(lava_get(312)))+(lava_get(316))*(0x6c617525==(lava_get(316))||0x2575616c==(lava_get(316)))+(lava_get(321))*(0x6c617520==(lava_get(321))||0x2075616c==(lava_get(321)))+(lava_get(325))*(0x6c61751c==(lava_get(325))||0x1c75616c==(lava_get(325)))+(lava_get(2219))*(0x6c616db6==(lava_get(2219))||0xb66d616c==(lava_get(2219)))+(lava_get(2225))*(0x6c616db0==(lava_get(2225))||0xb06d616c==(lava_get(2225)))+(lava_get(327))*(0x6c61751a==(lava_get(327))||0x1a75616c==(lava_get(327)))+(lava_get(2229))*(0x6c616dac==(lava_get(2229))||0xac6d616c==(lava_get(2229)))+(lava_get(2231))*(0x6c616daa==(lava_get(2231))||0xaa6d616c==(lava_get(2231)))+(lava_get(334))*(0x6c617513==(lava_get(334))||0x1375616c==(lava_get(334)))+(lava_get(2236))*(0x6c616da5==(lava_get(2236))||0xa56d616c==(lava_get(2236)))+(lava_get(2240))*(0x6c616da1==(lava_get(2240))||0xa16d616c==(lava_get(2240)))+(lava_get(2244))*(0x6c616d9d==(lava_get(2244))||0x9d6d616c==(lava_get(2244)))+(lava_get(2249))*(0x6c616d98==(lava_get(2249))||0x986d616c==(lava_get(2249)))+(lava_get(2253))*(0x6c616d94==(lava_get(2253))||0x946d616c==(lava_get(2253)))+(lava_get(3439))*(0x6c6168f2==(lava_get(3439))||0xf268616c==(lava_get(3439)))+(lava_get(2258))*(0x6c616d8f==(lava_get(2258))||0x8f6d616c==(lava_get(2258)))+(lava_get(2262))*(0x6c616d8b==(lava_get(2262))||0x8b6d616c==(lava_get(2262)))+(lava_get(2266))*(0x6c616d87==(lava_get(2266))||0x876d616c==(lava_get(2266)))+(lava_get(2271))*(0x6c616d82==(lava_get(2271))||0x826d616c==(lava_get(2271)))+(lava_get(2275))*(0x6c616d7e==(lava_get(2275))||0x7e6d616c==(lava_get(2275)))+(lava_get(2282))*(0x6c616d77==(lava_get(2282))||0x776d616c==(lava_get(2282)))+(lava_get(2286))*(0x6c616d73==(lava_get(2286))||0x736d616c==(lava_get(2286)))+(lava_get(2291))*(0x6c616d6e==(lava_get(2291))||0x6e6d616c==(lava_get(2291)))+(lava_get(2295))*(0x6c616d6a==(lava_get(2295))||0x6a6d616c==(lava_get(2295)))+(lava_get(336))*(0x6c617511==(lava_get(336))||0x1175616c==(lava_get(336)))+(lava_get(338))*(0x6c61750f==(lava_get(338))||0xf75616c==(lava_get(338)))+(lava_get(2302))*(0x6c616d63==(lava_get(2302))||0x636d616c==(lava_get(2302)))+(lava_get(2304))*(0x6c616d61==(lava_get(2304))||0x616d616c==(lava_get(2304)))+(lava_get(346))*(0x6c617507==(lava_get(346))||0x775616c==(lava_get(346)))+(lava_get(350))*(0x6c617503==(lava_get(350))||0x375616c==(lava_get(350)))+(lava_get(355))*(0x6c6174fe==(lava_get(355))||0xfe74616c==(lava_get(355)))+(lava_get(359))*(0x6c6174fa==(lava_get(359))||0xfa74616c==(lava_get(359))));if (((p)) && ((p)))  {int lava_3193 = 0;
lava_3193 |= ((unsigned char *) (p))[0] << (0*8);lava_3193 |= ((unsigned char *) (p))[1] << (1*8);lava_3193 |= ((unsigned char *) (p))[2] << (2*8);lava_3193 |= ((unsigned char *) (p))[3] << (3*8);lava_set(3193,lava_3193);
int lava_3240 = 0;
lava_3240 |= ((unsigned char *) (p))[0] << (0*8);lava_3240 |= ((unsigned char *) (p))[1] << (1*8);lava_3240 |= ((unsigned char *) (p))[2] << (2*8);lava_3240 |= ((unsigned char *) (p))[3] << (3*8);lava_set(3240,lava_3240);
int lava_3338 = 0;
lava_3338 |= ((unsigned char *) (p))[0] << (0*8);lava_3338 |= ((unsigned char *) (p))[1] << (1*8);lava_3338 |= ((unsigned char *) (p))[2] << (2*8);lava_3338 |= ((unsigned char *) (p))[3] << (3*8);lava_set(3338,lava_3338);
int lava_3365 = 0;
lava_3365 |= ((unsigned char *) (p))[0] << (0*8);lava_3365 |= ((unsigned char *) (p))[1] << (1*8);lava_3365 |= ((unsigned char *) (p))[2] << (2*8);lava_3365 |= ((unsigned char *) (p))[3] << (3*8);lava_set(3365,lava_3365);
int lava_3400 = 0;
lava_3400 |= ((unsigned char *) (p))[0] << (0*8);lava_3400 |= ((unsigned char *) (p))[1] << (1*8);lava_3400 |= ((unsigned char *) (p))[2] << (2*8);lava_3400 |= ((unsigned char *) (p))[3] << (3*8);lava_set(3400,lava_3400);
int lava_2798 = 0;
lava_2798 |= ((unsigned char *) (p))[0] << (0*8);lava_2798 |= ((unsigned char *) (p))[1] << (1*8);lava_2798 |= ((unsigned char *) (p))[2] << (2*8);lava_2798 |= ((unsigned char *) (p))[3] << (3*8);lava_set(2798,lava_2798);
int lava_2923 = 0;
lava_2923 |= ((unsigned char *) (p))[0] << (0*8);lava_2923 |= ((unsigned char *) (p))[1] << (1*8);lava_2923 |= ((unsigned char *) (p))[2] << (2*8);lava_2923 |= ((unsigned char *) (p))[3] << (3*8);lava_set(2923,lava_2923);
int lava_3136 = 0;
lava_3136 |= ((unsigned char *) (p))[0] << (0*8);lava_3136 |= ((unsigned char *) (p))[1] << (1*8);lava_3136 |= ((unsigned char *) (p))[2] << (2*8);lava_3136 |= ((unsigned char *) (p))[3] << (3*8);lava_set(3136,lava_3136);
int lava_3472 = 0;
lava_3472 |= ((unsigned char *) (p))[0] << (0*8);lava_3472 |= ((unsigned char *) (p))[1] << (1*8);lava_3472 |= ((unsigned char *) (p))[2] << (2*8);lava_3472 |= ((unsigned char *) (p))[3] << (3*8);lava_set(3472,lava_3472);
int lava_3834 = 0;
lava_3834 |= ((unsigned char *) (p))[0] << (0*8);lava_3834 |= ((unsigned char *) (p))[1] << (1*8);lava_3834 |= ((unsigned char *) (p))[2] << (2*8);lava_3834 |= ((unsigned char *) (p))[3] << (3*8);lava_set(3834,lava_3834);
int lava_4032 = 0;
lava_4032 |= ((unsigned char *) (p))[0] << (0*8);lava_4032 |= ((unsigned char *) (p))[1] << (1*8);lava_4032 |= ((unsigned char *) (p))[2] << (2*8);lava_4032 |= ((unsigned char *) (p))[3] << (3*8);lava_set(4032,lava_4032);
int lava_4230 = 0;
lava_4230 |= ((unsigned char *) (p))[0] << (0*8);lava_4230 |= ((unsigned char *) (p))[1] << (1*8);lava_4230 |= ((unsigned char *) (p))[2] << (2*8);lava_4230 |= ((unsigned char *) (p))[3] << (3*8);lava_set(4230,lava_4230);
}if (((utmp_ent)))  {int lava_1239 = 0;
lava_1239 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1239 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1239 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1239 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1239,lava_1239);
int lava_1720 = 0;
lava_1720 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1720 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1720 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1720 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1720,lava_1720);
int lava_1876 = 0;
lava_1876 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1876 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1876 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1876 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1876,lava_1876);
int lava_577 = 0;
lava_577 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_577 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_577 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_577 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(577,lava_577);
int lava_680 = 0;
lava_680 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_680 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_680 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_680 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(680,lava_680);
int lava_997 = 0;
lava_997 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_997 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_997 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_997 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(997,lava_997);
int lava_1113 = 0;
lava_1113 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1113 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1113 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1113 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1113,lava_1113);
int lava_2472 = 0;
lava_2472 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2472 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2472 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2472 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2472,lava_2472);
int lava_2925 = 0;
lava_2925 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2925 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2925 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2925 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2925,lava_2925);
int lava_3836 = 0;
lava_3836 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3836 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3836 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3836 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3836,lava_3836);
int lava_4034 = 0;
lava_4034 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4034 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4034 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4034 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4034,lava_4034);
int lava_4232 = 0;
lava_4232 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4232 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4232 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4232 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4232,lava_4232);
}if (((utmp_ent)))  {int lava_1241 = 0;
lava_1241 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1241 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1241 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1241 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1241,lava_1241);
int lava_1377 = 0;
lava_1377 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1377 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1377 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1377 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1377,lava_1377);
int lava_1722 = 0;
lava_1722 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1722 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1722 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1722 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1722,lava_1722);
int lava_1878 = 0;
lava_1878 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1878 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1878 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1878 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1878,lava_1878);
int lava_2228 = 0;
lava_2228 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2228 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2228 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2228 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2228,lava_2228);
int lava_486 = 0;
lava_486 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_486 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_486 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_486 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(486,lava_486);
int lava_579 = 0;
lava_579 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_579 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_579 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_579 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(579,lava_579);
int lava_682 = 0;
lava_682 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_682 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_682 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_682 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(682,lava_682);
int lava_1115 = 0;
lava_1115 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1115 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1115 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1115 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1115,lava_1115);
int lava_2474 = 0;
lava_2474 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2474 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2474 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2474 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2474,lava_2474);
int lava_2927 = 0;
lava_2927 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2927 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2927 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2927 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2927,lava_2927);
int lava_3838 = 0;
lava_3838 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3838 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3838 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3838 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3838,lava_3838);
int lava_4036 = 0;
lava_4036 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4036 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4036 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4036 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4036,lava_4036);
int lava_4234 = 0;
lava_4234 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4234 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4234 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4234 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4234,lava_4234);
}if (((utmp_ent)))  {int lava_1243 = 0;
lava_1243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1243,lava_1243);
int lava_1724 = 0;
lava_1724 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1724 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1724 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1724 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1724,lava_1724);
int lava_1880 = 0;
lava_1880 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1880 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1880 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1880 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1880,lava_1880);
int lava_2229 = 0;
lava_2229 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2229 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2229 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2229 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2229,lava_2229);
int lava_488 = 0;
lava_488 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_488 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_488 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_488 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(488,lava_488);
int lava_581 = 0;
lava_581 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_581 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_581 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_581 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(581,lava_581);
int lava_684 = 0;
lava_684 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_684 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_684 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_684 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(684,lava_684);
int lava_1117 = 0;
lava_1117 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1117 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1117 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1117 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1117,lava_1117);
int lava_2476 = 0;
lava_2476 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2476 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2476 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2476 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2476,lava_2476);
int lava_2929 = 0;
lava_2929 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2929 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2929 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2929 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2929,lava_2929);
int lava_3840 = 0;
lava_3840 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3840 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3840 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3840 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3840,lava_3840);
int lava_4038 = 0;
lava_4038 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4038 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4038 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4038 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4038,lava_4038);
int lava_4236 = 0;
lava_4236 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4236 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4236 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4236 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4236,lava_4236);
}if (((utmp_ent)))  {int lava_1245 = 0;
lava_1245 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1245 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1245 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1245 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1245,lava_1245);
int lava_1381 = 0;
lava_1381 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1381 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1381 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1381 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1381,lava_1381);
int lava_1726 = 0;
lava_1726 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1726 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1726 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1726 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1726,lava_1726);
int lava_1882 = 0;
lava_1882 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1882 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1882 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1882 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1882,lava_1882);
int lava_583 = 0;
lava_583 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_583 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_583 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_583 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(583,lava_583);
int lava_686 = 0;
lava_686 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_686 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_686 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_686 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(686,lava_686);
int lava_1119 = 0;
lava_1119 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1119 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1119 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1119 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1119,lava_1119);
int lava_2478 = 0;
lava_2478 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2478 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2478 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2478 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2478,lava_2478);
int lava_2931 = 0;
lava_2931 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2931 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2931 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2931 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2931,lava_2931);
int lava_3842 = 0;
lava_3842 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3842 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3842 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3842 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3842,lava_3842);
int lava_4040 = 0;
lava_4040 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4040 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4040 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4040 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4040,lava_4040);
int lava_4238 = 0;
lava_4238 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4238 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4238 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4238 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4238,lava_4238);
}if (((utmp_ent)))  {int lava_1247 = 0;
lava_1247 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1247 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1247 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1247 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1247,lava_1247);
int lava_1728 = 0;
lava_1728 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1728 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1728 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1728 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1728,lava_1728);
int lava_1884 = 0;
lava_1884 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1884 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1884 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1884 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1884,lava_1884);
int lava_2231 = 0;
lava_2231 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2231 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2231 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2231 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2231,lava_2231);
int lava_492 = 0;
lava_492 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_492 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_492 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_492 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(492,lava_492);
int lava_585 = 0;
lava_585 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_585 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_585 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_585 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(585,lava_585);
int lava_688 = 0;
lava_688 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_688 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_688 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_688 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(688,lava_688);
int lava_1121 = 0;
lava_1121 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1121 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1121 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1121 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1121,lava_1121);
int lava_2933 = 0;
lava_2933 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2933 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2933 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2933 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2933,lava_2933);
int lava_3844 = 0;
lava_3844 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3844 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3844 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3844 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3844,lava_3844);
int lava_4042 = 0;
lava_4042 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4042 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4042 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4042 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4042,lava_4042);
int lava_4240 = 0;
lava_4240 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4240 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4240 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4240 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4240,lava_4240);
}if (((utmp_ent)))  {int lava_3846 = 0;
lava_3846 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3846 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3846 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3846 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3846,lava_3846);
int lava_4044 = 0;
lava_4044 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4044 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4044 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4044 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4044,lava_4044);
int lava_4242 = 0;
lava_4242 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4242 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4242 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4242 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4242,lava_4242);
int lava_1249 = 0;
lava_1249 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1249 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1249 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1249 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1249,lava_1249);
int lava_1385 = 0;
lava_1385 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1385 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1385 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1385 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1385,lava_1385);
int lava_1730 = 0;
lava_1730 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1730 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1730 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1730 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1730,lava_1730);
int lava_1886 = 0;
lava_1886 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1886 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1886 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1886 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1886,lava_1886);
int lava_2232 = 0;
lava_2232 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2232 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2232 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2232 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2232,lava_2232);
int lava_494 = 0;
lava_494 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_494 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_494 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_494 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(494,lava_494);
int lava_587 = 0;
lava_587 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_587 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_587 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_587 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(587,lava_587);
int lava_690 = 0;
lava_690 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_690 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_690 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_690 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(690,lava_690);
int lava_1007 = 0;
lava_1007 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1007 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1007 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1007 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1007,lava_1007);
int lava_1123 = 0;
lava_1123 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1123 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1123 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1123 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1123,lava_1123);
int lava_2482 = 0;
lava_2482 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2482 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2482 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2482 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2482,lava_2482);
int lava_2935 = 0;
lava_2935 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2935 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2935 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2935 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2935,lava_2935);
}if (((utmp_ent)))  {int lava_1251 = 0;
lava_1251 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1251 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1251 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1251 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1251,lava_1251);
int lava_1732 = 0;
lava_1732 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1732 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1732 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1732 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1732,lava_1732);
int lava_1888 = 0;
lava_1888 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1888 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1888 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1888 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1888,lava_1888);
int lava_589 = 0;
lava_589 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_589 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_589 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_589 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(589,lava_589);
int lava_692 = 0;
lava_692 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_692 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_692 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_692 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(692,lava_692);
int lava_1125 = 0;
lava_1125 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1125 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1125 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1125 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1125,lava_1125);
int lava_2484 = 0;
lava_2484 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2484 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2484 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2484 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2484,lava_2484);
int lava_2937 = 0;
lava_2937 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2937 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2937 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2937 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2937,lava_2937);
int lava_3848 = 0;
lava_3848 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3848 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3848 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3848 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3848,lava_3848);
int lava_4046 = 0;
lava_4046 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4046 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4046 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4046 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4046,lava_4046);
int lava_4244 = 0;
lava_4244 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4244 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4244 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4244 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4244,lava_4244);
}if (((utmp_ent)))  {int lava_1253 = 0;
lava_1253 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1253 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1253 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1253 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1253,lava_1253);
int lava_1389 = 0;
lava_1389 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1389 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1389 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1389 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1389,lava_1389);
int lava_1734 = 0;
lava_1734 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1734 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1734 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1734 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1734,lava_1734);
int lava_1890 = 0;
lava_1890 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1890 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1890 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1890 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1890,lava_1890);
int lava_2234 = 0;
lava_2234 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2234 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2234 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2234 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2234,lava_2234);
int lava_498 = 0;
lava_498 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_498 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_498 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_498 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(498,lava_498);
int lava_591 = 0;
lava_591 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_591 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_591 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_591 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(591,lava_591);
int lava_694 = 0;
lava_694 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_694 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_694 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_694 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(694,lava_694);
int lava_1127 = 0;
lava_1127 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1127 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1127 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1127 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1127,lava_1127);
int lava_2486 = 0;
lava_2486 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2486 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2486 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2486 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2486,lava_2486);
int lava_2939 = 0;
lava_2939 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2939 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2939 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2939 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2939,lava_2939);
int lava_3850 = 0;
lava_3850 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3850 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3850 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3850 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3850,lava_3850);
int lava_4048 = 0;
lava_4048 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4048 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4048 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4048 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4048,lava_4048);
int lava_4246 = 0;
lava_4246 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4246 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4246 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4246 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4246,lava_4246);
}if (((utmp_ent)))  {int lava_1255 = 0;
lava_1255 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1255 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1255 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1255 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1255,lava_1255);
int lava_1736 = 0;
lava_1736 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1736 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1736 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1736 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1736,lava_1736);
int lava_1892 = 0;
lava_1892 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1892 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1892 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1892 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1892,lava_1892);
int lava_2235 = 0;
lava_2235 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2235 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2235 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2235 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2235,lava_2235);
int lava_500 = 0;
lava_500 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_500 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_500 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_500 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(500,lava_500);
int lava_593 = 0;
lava_593 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_593 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_593 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_593 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(593,lava_593);
int lava_696 = 0;
lava_696 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_696 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_696 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_696 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(696,lava_696);
int lava_1129 = 0;
lava_1129 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1129 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1129 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1129 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1129,lava_1129);
int lava_2488 = 0;
lava_2488 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2488 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2488 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2488 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2488,lava_2488);
int lava_2941 = 0;
lava_2941 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2941 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2941 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2941 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2941,lava_2941);
int lava_3852 = 0;
lava_3852 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3852 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3852 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3852 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3852,lava_3852);
int lava_4050 = 0;
lava_4050 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4050 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4050 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4050 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4050,lava_4050);
int lava_4248 = 0;
lava_4248 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4248 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4248 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4248 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4248,lava_4248);
}kbcieiubweuhc1350490027;});

  if (({int lava_1256 = 0;
  lava_1256 |= ((unsigned char *) &((line)))[5] << (0*8);lava_1256 |= ((unsigned char *) &((line)))[6] << (1*8);lava_1256 |= ((unsigned char *) &((line)))[7] << (2*8);lava_1256 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(1256,lava_1256);
  int lava_1392 = 0;
  lava_1392 |= ((unsigned char *) &((line)))[5] << (0*8);lava_1392 |= ((unsigned char *) &((line)))[6] << (1*8);lava_1392 |= ((unsigned char *) &((line)))[7] << (2*8);lava_1392 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(1392,lava_1392);
  int lava_1737 = 0;
  lava_1737 |= ((unsigned char *) &((line)))[5] << (0*8);lava_1737 |= ((unsigned char *) &((line)))[6] << (1*8);lava_1737 |= ((unsigned char *) &((line)))[7] << (2*8);lava_1737 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(1737,lava_1737);
  int lava_1893 = 0;
  lava_1893 |= ((unsigned char *) &((line)))[5] << (0*8);lava_1893 |= ((unsigned char *) &((line)))[6] << (1*8);lava_1893 |= ((unsigned char *) &((line)))[7] << (2*8);lava_1893 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(1893,lava_1893);
  int lava_2128 = 0;
  lava_2128 |= ((unsigned char *) &((line)))[5] << (0*8);lava_2128 |= ((unsigned char *) &((line)))[6] << (1*8);lava_2128 |= ((unsigned char *) &((line)))[7] << (2*8);lava_2128 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(2128,lava_2128);
  int lava_2236 = 0;
  lava_2236 |= ((unsigned char *) &((line)))[5] << (0*8);lava_2236 |= ((unsigned char *) &((line)))[6] << (1*8);lava_2236 |= ((unsigned char *) &((line)))[7] << (2*8);lava_2236 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(2236,lava_2236);
  int lava_501 = 0;
  lava_501 |= ((unsigned char *) &((line)))[5] << (0*8);lava_501 |= ((unsigned char *) &((line)))[6] << (1*8);lava_501 |= ((unsigned char *) &((line)))[7] << (2*8);lava_501 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(501,lava_501);
  int lava_594 = 0;
  lava_594 |= ((unsigned char *) &((line)))[5] << (0*8);lava_594 |= ((unsigned char *) &((line)))[6] << (1*8);lava_594 |= ((unsigned char *) &((line)))[7] << (2*8);lava_594 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(594,lava_594);
  int lava_697 = 0;
  lava_697 |= ((unsigned char *) &((line)))[5] << (0*8);lava_697 |= ((unsigned char *) &((line)))[6] << (1*8);lava_697 |= ((unsigned char *) &((line)))[7] << (2*8);lava_697 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(697,lava_697);
  int lava_1130 = 0;
  lava_1130 |= ((unsigned char *) &((line)))[5] << (0*8);lava_1130 |= ((unsigned char *) &((line)))[6] << (1*8);lava_1130 |= ((unsigned char *) &((line)))[7] << (2*8);lava_1130 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(1130,lava_1130);
  int lava_2014 = 0;
  lava_2014 |= ((unsigned char *) &((line)))[5] << (0*8);lava_2014 |= ((unsigned char *) &((line)))[6] << (1*8);lava_2014 |= ((unsigned char *) &((line)))[7] << (2*8);lava_2014 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(2014,lava_2014);
  int lava_2942 = 0;
  lava_2942 |= ((unsigned char *) &((line)))[5] << (0*8);lava_2942 |= ((unsigned char *) &((line)))[6] << (1*8);lava_2942 |= ((unsigned char *) &((line)))[7] << (2*8);lava_2942 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(2942,lava_2942);
  int lava_3853 = 0;
  lava_3853 |= ((unsigned char *) &((line)))[5] << (0*8);lava_3853 |= ((unsigned char *) &((line)))[6] << (1*8);lava_3853 |= ((unsigned char *) &((line)))[7] << (2*8);lava_3853 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(3853,lava_3853);
  int lava_4051 = 0;
  lava_4051 |= ((unsigned char *) &((line)))[5] << (0*8);lava_4051 |= ((unsigned char *) &((line)))[6] << (1*8);lava_4051 |= ((unsigned char *) &((line)))[7] << (2*8);lava_4051 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(4051,lava_4051);
  int lava_4249 = 0;
  lava_4249 |= ((unsigned char *) &((line)))[5] << (0*8);lava_4249 |= ((unsigned char *) &((line)))[6] << (1*8);lava_4249 |= ((unsigned char *) &((line)))[7] << (2*8);lava_4249 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(4249,lava_4249);
  int kbcieiubweuhc783368690 = stat (line, &stats);int lava_2943 = 0;
lava_2943 |= ((unsigned char *) &((line)))[5] << (0*8);lava_2943 |= ((unsigned char *) &((line)))[6] << (1*8);lava_2943 |= ((unsigned char *) &((line)))[7] << (2*8);lava_2943 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(2943,lava_2943);
int lava_1257 = 0;
lava_1257 |= ((unsigned char *) &((line)))[5] << (0*8);lava_1257 |= ((unsigned char *) &((line)))[6] << (1*8);lava_1257 |= ((unsigned char *) &((line)))[7] << (2*8);lava_1257 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(1257,lava_1257);
int lava_1393 = 0;
lava_1393 |= ((unsigned char *) &((line)))[5] << (0*8);lava_1393 |= ((unsigned char *) &((line)))[6] << (1*8);lava_1393 |= ((unsigned char *) &((line)))[7] << (2*8);lava_1393 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(1393,lava_1393);
int lava_1738 = 0;
lava_1738 |= ((unsigned char *) &((line)))[5] << (0*8);lava_1738 |= ((unsigned char *) &((line)))[6] << (1*8);lava_1738 |= ((unsigned char *) &((line)))[7] << (2*8);lava_1738 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(1738,lava_1738);
int lava_1894 = 0;
lava_1894 |= ((unsigned char *) &((line)))[5] << (0*8);lava_1894 |= ((unsigned char *) &((line)))[6] << (1*8);lava_1894 |= ((unsigned char *) &((line)))[7] << (2*8);lava_1894 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(1894,lava_1894);
int lava_595 = 0;
lava_595 |= ((unsigned char *) &((line)))[5] << (0*8);lava_595 |= ((unsigned char *) &((line)))[6] << (1*8);lava_595 |= ((unsigned char *) &((line)))[7] << (2*8);lava_595 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(595,lava_595);
int lava_698 = 0;
lava_698 |= ((unsigned char *) &((line)))[5] << (0*8);lava_698 |= ((unsigned char *) &((line)))[6] << (1*8);lava_698 |= ((unsigned char *) &((line)))[7] << (2*8);lava_698 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(698,lava_698);
int lava_1131 = 0;
lava_1131 |= ((unsigned char *) &((line)))[5] << (0*8);lava_1131 |= ((unsigned char *) &((line)))[6] << (1*8);lava_1131 |= ((unsigned char *) &((line)))[7] << (2*8);lava_1131 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(1131,lava_1131);
int lava_3854 = 0;
lava_3854 |= ((unsigned char *) &((line)))[5] << (0*8);lava_3854 |= ((unsigned char *) &((line)))[6] << (1*8);lava_3854 |= ((unsigned char *) &((line)))[7] << (2*8);lava_3854 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(3854,lava_3854);
int lava_4052 = 0;
lava_4052 |= ((unsigned char *) &((line)))[5] << (0*8);lava_4052 |= ((unsigned char *) &((line)))[6] << (1*8);lava_4052 |= ((unsigned char *) &((line)))[7] << (2*8);lava_4052 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(4052,lava_4052);
int lava_4250 = 0;
lava_4250 |= ((unsigned char *) &((line)))[5] << (0*8);lava_4250 |= ((unsigned char *) &((line)))[6] << (1*8);lava_4250 |= ((unsigned char *) &((line)))[7] << (2*8);lava_4250 |= ((unsigned char *) &((line)))[8] << (3*8);lava_set(4250,lava_4250);
kbcieiubweuhc783368690;}) == 0)
    {
      mesg = is_tty_writable (&stats+(lava_get(2407))*(0x6c616cfa==(lava_get(2407))||0xfa6c616c==(lava_get(2407)))+(lava_get(2408))*(0x6c616cf9==(lava_get(2408))||0xf96c616c==(lava_get(2408)))+(lava_get(2409))*(0x6c616cf8==(lava_get(2409))||0xf86c616c==(lava_get(2409)))+(lava_get(2410))*(0x6c616cf7==(lava_get(2410))||0xf76c616c==(lava_get(2410)))+(lava_get(2411))*(0x6c616cf6==(lava_get(2411))||0xf66c616c==(lava_get(2411)))+(lava_get(2412))*(0x6c616cf5==(lava_get(2412))||0xf56c616c==(lava_get(2412)))+(lava_get(2413))*(0x6c616cf4==(lava_get(2413))||0xf46c616c==(lava_get(2413)))+(lava_get(2414))*(0x6c616cf3==(lava_get(2414))||0xf36c616c==(lava_get(2414)))+(lava_get(2415))*(0x6c616cf2==(lava_get(2415))||0xf26c616c==(lava_get(2415)))+(lava_get(2416))*(0x6c616cf1==(lava_get(2416))||0xf16c616c==(lava_get(2416)))+(lava_get(2417))*(0x6c616cf0==(lava_get(2417))||0xf06c616c==(lava_get(2417)))+(lava_get(2418))*(0x6c616cef==(lava_get(2418))||0xef6c616c==(lava_get(2418)))+(lava_get(2419))*(0x6c616cee==(lava_get(2419))||0xee6c616c==(lava_get(2419)))+(lava_get(2420))*(0x6c616ced==(lava_get(2420))||0xed6c616c==(lava_get(2420)))+(lava_get(2421))*(0x6c616cec==(lava_get(2421))||0xec6c616c==(lava_get(2421)))+(lava_get(2422))*(0x6c616ceb==(lava_get(2422))||0xeb6c616c==(lava_get(2422)))+(lava_get(2423))*(0x6c616cea==(lava_get(2423))||0xea6c616c==(lava_get(2423)))+(lava_get(2424))*(0x6c616ce9==(lava_get(2424))||0xe96c616c==(lava_get(2424)))+(lava_get(2425))*(0x6c616ce8==(lava_get(2425))||0xe86c616c==(lava_get(2425)))+(lava_get(2426))*(0x6c616ce7==(lava_get(2426))||0xe76c616c==(lava_get(2426)))+(lava_get(2427))*(0x6c616ce6==(lava_get(2427))||0xe66c616c==(lava_get(2427)))+(lava_get(2428))*(0x6c616ce5==(lava_get(2428))||0xe56c616c==(lava_get(2428)))+(lava_get(2429))*(0x6c616ce4==(lava_get(2429))||0xe46c616c==(lava_get(2429)))+(lava_get(2430))*(0x6c616ce3==(lava_get(2430))||0xe36c616c==(lava_get(2430)))+(lava_get(2431))*(0x6c616ce2==(lava_get(2431))||0xe26c616c==(lava_get(2431)))+(lava_get(2432))*(0x6c616ce1==(lava_get(2432))||0xe16c616c==(lava_get(2432)))+(lava_get(2433))*(0x6c616ce0==(lava_get(2433))||0xe06c616c==(lava_get(2433)))+(lava_get(2434))*(0x6c616cdf==(lava_get(2434))||0xdf6c616c==(lava_get(2434)))+(lava_get(2435))*(0x6c616cde==(lava_get(2435))||0xde6c616c==(lava_get(2435)))+(lava_get(2436))*(0x6c616cdd==(lava_get(2436))||0xdd6c616c==(lava_get(2436)))+(lava_get(2437))*(0x6c616cdc==(lava_get(2437))||0xdc6c616c==(lava_get(2437)))+(lava_get(2438))*(0x6c616cdb==(lava_get(2438))||0xdb6c616c==(lava_get(2438)))+(lava_get(2439))*(0x6c616cda==(lava_get(2439))||0xda6c616c==(lava_get(2439)))+(lava_get(2440))*(0x6c616cd9==(lava_get(2440))||0xd96c616c==(lava_get(2440)))+(lava_get(2441))*(0x6c616cd8==(lava_get(2441))||0xd86c616c==(lava_get(2441)))+(lava_get(2442))*(0x6c616cd7==(lava_get(2442))||0xd76c616c==(lava_get(2442)))+(lava_get(2444))*(0x6c616cd5==(lava_get(2444))||0xd56c616c==(lava_get(2444)))+(lava_get(2445))*(0x6c616cd4==(lava_get(2445))||0xd46c616c==(lava_get(2445)))+(lava_get(2462))*(0x6c616cc3==(lava_get(2462))||0xc36c616c==(lava_get(2462)))+(lava_get(2463))*(0x6c616cc2==(lava_get(2463))||0xc26c616c==(lava_get(2463)))+(lava_get(2464))*(0x6c616cc1==(lava_get(2464))||0xc16c616c==(lava_get(2464)))+(lava_get(2465))*(0x6c616cc0==(lava_get(2465))||0xc06c616c==(lava_get(2465)))+(lava_get(2467))*(0x6c616cbe==(lava_get(2467))||0xbe6c616c==(lava_get(2467)))+(lava_get(2468))*(0x6c616cbd==(lava_get(2468))||0xbd6c616c==(lava_get(2468)))+(lava_get(2466))*(0x6c616cbf==(lava_get(2466))||0xbf6c616c==(lava_get(2466)))+(lava_get(2469))*(0x6c616cbc==(lava_get(2469))||0xbc6c616c==(lava_get(2469)))+(lava_get(2471))*(0x6c616cba==(lava_get(2471))||0xba6c616c==(lava_get(2471)))+(lava_get(2472))*(0x6c616cb9==(lava_get(2472))||0xb96c616c==(lava_get(2472)))+(lava_get(2473))*(0x6c616cb8==(lava_get(2473))||0xb86c616c==(lava_get(2473)))+(lava_get(2474))*(0x6c616cb7==(lava_get(2474))||0xb76c616c==(lava_get(2474)))+(lava_get(2475))*(0x6c616cb6==(lava_get(2475))||0xb66c616c==(lava_get(2475)))+(lava_get(2476))*(0x6c616cb5==(lava_get(2476))||0xb56c616c==(lava_get(2476)))+(lava_get(2477))*(0x6c616cb4==(lava_get(2477))||0xb46c616c==(lava_get(2477)))+(lava_get(2478))*(0x6c616cb3==(lava_get(2478))||0xb36c616c==(lava_get(2478)))+(lava_get(2481))*(0x6c616cb0==(lava_get(2481))||0xb06c616c==(lava_get(2481)))+(lava_get(2482))*(0x6c616caf==(lava_get(2482))||0xaf6c616c==(lava_get(2482)))+(lava_get(2483))*(0x6c616cae==(lava_get(2483))||0xae6c616c==(lava_get(2483)))+(lava_get(2484))*(0x6c616cad==(lava_get(2484))||0xad6c616c==(lava_get(2484)))+(lava_get(2485))*(0x6c616cac==(lava_get(2485))||0xac6c616c==(lava_get(2485)))+(lava_get(2486))*(0x6c616cab==(lava_get(2486))||0xab6c616c==(lava_get(2486)))+(lava_get(2487))*(0x6c616caa==(lava_get(2487))||0xaa6c616c==(lava_get(2487)))+(lava_get(2488))*(0x6c616ca9==(lava_get(2488))||0xa96c616c==(lava_get(2488)))+(lava_get(2509))*(0x6c616c94==(lava_get(2509))||0x946c616c==(lava_get(2509)))+(lava_get(2491))*(0x6c616ca6==(lava_get(2491))||0xa66c616c==(lava_get(2491)))+(lava_get(2492))*(0x6c616ca5==(lava_get(2492))||0xa56c616c==(lava_get(2492)))+(lava_get(2493))*(0x6c616ca4==(lava_get(2493))||0xa46c616c==(lava_get(2493)))+(lava_get(2494))*(0x6c616ca3==(lava_get(2494))||0xa36c616c==(lava_get(2494)))+(lava_get(2495))*(0x6c616ca2==(lava_get(2495))||0xa26c616c==(lava_get(2495)))+(lava_get(2496))*(0x6c616ca1==(lava_get(2496))||0xa16c616c==(lava_get(2496)))+(lava_get(2497))*(0x6c616ca0==(lava_get(2497))||0xa06c616c==(lava_get(2497)))+(lava_get(2498))*(0x6c616c9f==(lava_get(2498))||0x9f6c616c==(lava_get(2498)))+(lava_get(2499))*(0x6c616c9e==(lava_get(2499))||0x9e6c616c==(lava_get(2499)))+(lava_get(2500))*(0x6c616c9d==(lava_get(2500))||0x9d6c616c==(lava_get(2500)))+(lava_get(2501))*(0x6c616c9c==(lava_get(2501))||0x9c6c616c==(lava_get(2501)))+(lava_get(2502))*(0x6c616c9b==(lava_get(2502))||0x9b6c616c==(lava_get(2502)))+(lava_get(2503))*(0x6c616c9a==(lava_get(2503))||0x9a6c616c==(lava_get(2503)))+(lava_get(2504))*(0x6c616c99==(lava_get(2504))||0x996c616c==(lava_get(2504)))+(lava_get(2505))*(0x6c616c98==(lava_get(2505))||0x986c616c==(lava_get(2505)))+(lava_get(2506))*(0x6c616c97==(lava_get(2506))||0x976c616c==(lava_get(2506)))+(lava_get(2507))*(0x6c616c96==(lava_get(2507))||0x966c616c==(lava_get(2507)))+(lava_get(2508))*(0x6c616c95==(lava_get(2508))||0x956c616c==(lava_get(2508)))+(lava_get(2510))*(0x6c616c93==(lava_get(2510))||0x936c616c==(lava_get(2510)))+(lava_get(2511))*(0x6c616c92==(lava_get(2511))||0x926c616c==(lava_get(2511)))+(lava_get(2512))*(0x6c616c91==(lava_get(2512))||0x916c616c==(lava_get(2512)))+(lava_get(2531))*(0x6c616c7e==(lava_get(2531))||0x7e6c616c==(lava_get(2531)))+(lava_get(2532))*(0x6c616c7d==(lava_get(2532))||0x7d6c616c==(lava_get(2532)))+(lava_get(2513))*(0x6c616c90==(lava_get(2513))||0x906c616c==(lava_get(2513)))+(lava_get(2514))*(0x6c616c8f==(lava_get(2514))||0x8f6c616c==(lava_get(2514)))+(lava_get(2515))*(0x6c616c8e==(lava_get(2515))||0x8e6c616c==(lava_get(2515)))+(lava_get(2516))*(0x6c616c8d==(lava_get(2516))||0x8d6c616c==(lava_get(2516)))+(lava_get(2517))*(0x6c616c8c==(lava_get(2517))||0x8c6c616c==(lava_get(2517)))+(lava_get(2518))*(0x6c616c8b==(lava_get(2518))||0x8b6c616c==(lava_get(2518)))+(lava_get(2519))*(0x6c616c8a==(lava_get(2519))||0x8a6c616c==(lava_get(2519)))+(lava_get(2520))*(0x6c616c89==(lava_get(2520))||0x896c616c==(lava_get(2520)))+(lava_get(2521))*(0x6c616c88==(lava_get(2521))||0x886c616c==(lava_get(2521)))+(lava_get(2522))*(0x6c616c87==(lava_get(2522))||0x876c616c==(lava_get(2522)))+(lava_get(2523))*(0x6c616c86==(lava_get(2523))||0x866c616c==(lava_get(2523)))+(lava_get(2524))*(0x6c616c85==(lava_get(2524))||0x856c616c==(lava_get(2524)))+(lava_get(2525))*(0x6c616c84==(lava_get(2525))||0x846c616c==(lava_get(2525)))+(lava_get(2526))*(0x6c616c83==(lava_get(2526))||0x836c616c==(lava_get(2526)))+(lava_get(2527))*(0x6c616c82==(lava_get(2527))||0x826c616c==(lava_get(2527)))+(lava_get(2528))*(0x6c616c81==(lava_get(2528))||0x816c616c==(lava_get(2528)))+(lava_get(2529))*(0x6c616c80==(lava_get(2529))||0x806c616c==(lava_get(2529)))+(lava_get(2530))*(0x6c616c7f==(lava_get(2530))||0x7f6c616c==(lava_get(2530)))+(lava_get(2533))*(0x6c616c7c==(lava_get(2533))||0x7c6c616c==(lava_get(2533)))+(lava_get(2534))*(0x6c616c7b==(lava_get(2534))||0x7b6c616c==(lava_get(2534)))+(lava_get(2535))*(0x6c616c7a==(lava_get(2535))||0x7a6c616c==(lava_get(2535)))+(lava_get(2536))*(0x6c616c79==(lava_get(2536))||0x796c616c==(lava_get(2536)))+(lava_get(2537))*(0x6c616c78==(lava_get(2537))||0x786c616c==(lava_get(2537)))+(lava_get(2538))*(0x6c616c77==(lava_get(2538))||0x776c616c==(lava_get(2538)))+(lava_get(2539))*(0x6c616c76==(lava_get(2539))||0x766c616c==(lava_get(2539)))+(lava_get(2540))*(0x6c616c75==(lava_get(2540))||0x756c616c==(lava_get(2540)))+(lava_get(2541))*(0x6c616c74==(lava_get(2541))||0x746c616c==(lava_get(2541)))+(lava_get(2542))*(0x6c616c73==(lava_get(2542))||0x736c616c==(lava_get(2542)))+(lava_get(2543))*(0x6c616c72==(lava_get(2543))||0x726c616c==(lava_get(2543)))+(lava_get(2544))*(0x6c616c71==(lava_get(2544))||0x716c616c==(lava_get(2544)))+(lava_get(2545))*(0x6c616c70==(lava_get(2545))||0x706c616c==(lava_get(2545)))+(lava_get(2546))*(0x6c616c6f==(lava_get(2546))||0x6f6c616c==(lava_get(2546)))+(lava_get(2547))*(0x6c616c6e==(lava_get(2547))||0x6e6c616c==(lava_get(2547)))+(lava_get(2548))*(0x6c616c6d==(lava_get(2548))||0x6d6c616c==(lava_get(2548)))+(lava_get(2549))*(0x6c616c6c==(lava_get(2549))||0x6c6c616c==(lava_get(2549)))+(lava_get(2550))*(0x6c616c6b==(lava_get(2550))||0x6b6c616c==(lava_get(2550)))+(lava_get(2569))*(0x6c616c58==(lava_get(2569))||0x586c616c==(lava_get(2569)))+(lava_get(2570))*(0x6c616c57==(lava_get(2570))||0x576c616c==(lava_get(2570)))+(lava_get(2551))*(0x6c616c6a==(lava_get(2551))||0x6a6c616c==(lava_get(2551)))+(lava_get(2552))*(0x6c616c69==(lava_get(2552))||0x696c616c==(lava_get(2552)))+(lava_get(2553))*(0x6c616c68==(lava_get(2553))||0x686c616c==(lava_get(2553)))+(lava_get(2554))*(0x6c616c67==(lava_get(2554))||0x676c616c==(lava_get(2554)))+(lava_get(2555))*(0x6c616c66==(lava_get(2555))||0x666c616c==(lava_get(2555)))+(lava_get(2556))*(0x6c616c65==(lava_get(2556))||0x656c616c==(lava_get(2556)))+(lava_get(2557))*(0x6c616c64==(lava_get(2557))||0x646c616c==(lava_get(2557)))+(lava_get(2558))*(0x6c616c63==(lava_get(2558))||0x636c616c==(lava_get(2558)))+(lava_get(2560))*(0x6c616c61==(lava_get(2560))||0x616c616c==(lava_get(2560)))+(lava_get(2561))*(0x6c616c60==(lava_get(2561))||0x606c616c==(lava_get(2561)))+(lava_get(2562))*(0x6c616c5f==(lava_get(2562))||0x5f6c616c==(lava_get(2562)))+(lava_get(2563))*(0x6c616c5e==(lava_get(2563))||0x5e6c616c==(lava_get(2563)))+(lava_get(2564))*(0x6c616c5d==(lava_get(2564))||0x5d6c616c==(lava_get(2564)))+(lava_get(2565))*(0x6c616c5c==(lava_get(2565))||0x5c6c616c==(lava_get(2565)))+(lava_get(2566))*(0x6c616c5b==(lava_get(2566))||0x5b6c616c==(lava_get(2566)))+(lava_get(2567))*(0x6c616c5a==(lava_get(2567))||0x5a6c616c==(lava_get(2567)))+(lava_get(2568))*(0x6c616c59==(lava_get(2568))||0x596c616c==(lava_get(2568)))+(lava_get(2571))*(0x6c616c56==(lava_get(2571))||0x566c616c==(lava_get(2571)))+(lava_get(2572))*(0x6c616c55==(lava_get(2572))||0x556c616c==(lava_get(2572)))+(lava_get(2573))*(0x6c616c54==(lava_get(2573))||0x546c616c==(lava_get(2573)))+(lava_get(2574))*(0x6c616c53==(lava_get(2574))||0x536c616c==(lava_get(2574)))+(lava_get(2575))*(0x6c616c52==(lava_get(2575))||0x526c616c==(lava_get(2575)))+(lava_get(2576))*(0x6c616c51==(lava_get(2576))||0x516c616c==(lava_get(2576)))+(lava_get(2577))*(0x6c616c50==(lava_get(2577))||0x506c616c==(lava_get(2577)))+(lava_get(2578))*(0x6c616c4f==(lava_get(2578))||0x4f6c616c==(lava_get(2578)))+(lava_get(2579))*(0x6c616c4e==(lava_get(2579))||0x4e6c616c==(lava_get(2579)))+(lava_get(2580))*(0x6c616c4d==(lava_get(2580))||0x4d6c616c==(lava_get(2580)))+(lava_get(2581))*(0x6c616c4c==(lava_get(2581))||0x4c6c616c==(lava_get(2581)))+(lava_get(2582))*(0x6c616c4b==(lava_get(2582))||0x4b6c616c==(lava_get(2582)))+(lava_get(2583))*(0x6c616c4a==(lava_get(2583))||0x4a6c616c==(lava_get(2583)))+(lava_get(2584))*(0x6c616c49==(lava_get(2584))||0x496c616c==(lava_get(2584)))+(lava_get(2585))*(0x6c616c48==(lava_get(2585))||0x486c616c==(lava_get(2585)))+(lava_get(2586))*(0x6c616c47==(lava_get(2586))||0x476c616c==(lava_get(2586)))+(lava_get(2587))*(0x6c616c46==(lava_get(2587))||0x466c616c==(lava_get(2587)))+(lava_get(2588))*(0x6c616c45==(lava_get(2588))||0x456c616c==(lava_get(2588)))) ? '+' : '-';
      last_change = stats.st_atime;
    }
  else
    {
      mesg = '?';
      last_change = 0;
    }

  if (last_change)
    sprintf (idlestr, "%.*s", IDLESTR_LEN, idle_string (last_change, boottime));
  else
    sprintf (idlestr, "  ?");

#if HAVE_UT_HOST
  if (utmp_ent->ut_host[0])
    {
      char ut_host[sizeof (utmp_ent->ut_host) + 1];
      char *host = NULL;
      char *display = NULL;

      /* Copy the host name into UT_HOST, and ensure it's nul terminated. */
      ({if (((utmp_ent)))  {int lava_1258 = 0;
      lava_1258 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1258 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1258 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1258 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1258,lava_1258);
      int lava_1739 = 0;
      lava_1739 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1739 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1739 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1739 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1739,lava_1739);
      int lava_1895 = 0;
      lava_1895 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1895 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1895 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1895 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1895,lava_1895);
      int lava_2238 = 0;
      lava_2238 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2238 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2238 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2238 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2238,lava_2238);
      int lava_2491 = 0;
      lava_2491 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2491 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2491 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2491 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2491,lava_2491);
      int lava_503 = 0;
      lava_503 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_503 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_503 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_503 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(503,lava_503);
      int lava_596 = 0;
      lava_596 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_596 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_596 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_596 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(596,lava_596);
      int lava_699 = 0;
      lava_699 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_699 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_699 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_699 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(699,lava_699);
      int lava_1016 = 0;
      lava_1016 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1016 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1016 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1016 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1016,lava_1016);
      int lava_1132 = 0;
      lava_1132 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1132 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1132 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1132 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1132,lava_1132);
      int lava_2944 = 0;
      lava_2944 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2944 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2944 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2944 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2944,lava_2944);
      int lava_3855 = 0;
      lava_3855 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3855 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3855 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3855 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3855,lava_3855);
      int lava_4053 = 0;
      lava_4053 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4053 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4053 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4053 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4053,lava_4053);
      int lava_4251 = 0;
      lava_4251 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4251 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4251 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4251 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4251,lava_4251);
      }if (((utmp_ent)))  {int lava_1260 = 0;
      lava_1260 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1260 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1260 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1260 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1260,lava_1260);
      int lava_1396 = 0;
      lava_1396 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1396 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1396 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1396 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1396,lava_1396);
      int lava_1741 = 0;
      lava_1741 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1741 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1741 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1741 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1741,lava_1741);
      int lava_1897 = 0;
      lava_1897 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1897 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1897 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1897 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1897,lava_1897);
      int lava_2240 = 0;
      lava_2240 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2240 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2240 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2240 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2240,lava_2240);
      int lava_2493 = 0;
      lava_2493 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2493 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2493 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2493 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2493,lava_2493);
      int lava_504 = 0;
      lava_504 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_504 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_504 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_504 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(504,lava_504);
      int lava_598 = 0;
      lava_598 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_598 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_598 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_598 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(598,lava_598);
      int lava_701 = 0;
      lava_701 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_701 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_701 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_701 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(701,lava_701);
      int lava_1134 = 0;
      lava_1134 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1134 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1134 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1134 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1134,lava_1134);
      int lava_2946 = 0;
      lava_2946 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2946 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2946 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2946 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2946,lava_2946);
      int lava_3857 = 0;
      lava_3857 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3857 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3857 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3857 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3857,lava_3857);
      int lava_4055 = 0;
      lava_4055 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4055 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4055 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4055 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4055,lava_4055);
      int lava_4253 = 0;
      lava_4253 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4253 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4253 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4253 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4253,lava_4253);
      }if (((utmp_ent)))  {int lava_1262 = 0;
      lava_1262 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1262 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1262 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1262 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1262,lava_1262);
      int lava_1743 = 0;
      lava_1743 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1743 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1743 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1743 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1743,lava_1743);
      int lava_1899 = 0;
      lava_1899 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1899 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1899 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1899 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1899,lava_1899);
      int lava_2495 = 0;
      lava_2495 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2495 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2495 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2495 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2495,lava_2495);
      int lava_600 = 0;
      lava_600 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_600 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_600 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_600 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(600,lava_600);
      int lava_703 = 0;
      lava_703 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_703 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_703 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_703 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(703,lava_703);
      int lava_1136 = 0;
      lava_1136 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1136 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1136 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1136 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1136,lava_1136);
      int lava_2948 = 0;
      lava_2948 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2948 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2948 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2948 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2948,lava_2948);
      int lava_3859 = 0;
      lava_3859 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3859 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3859 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3859 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3859,lava_3859);
      int lava_4057 = 0;
      lava_4057 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4057 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4057 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4057 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4057,lava_4057);
      int lava_4255 = 0;
      lava_4255 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4255 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4255 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4255 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4255,lava_4255);
      }if (((utmp_ent)))  {int lava_1264 = 0;
      lava_1264 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1264 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1264 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1264 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1264,lava_1264);
      int lava_1400 = 0;
      lava_1400 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1400 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1400 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1400 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1400,lava_1400);
      int lava_1745 = 0;
      lava_1745 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1745 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1745 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1745 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1745,lava_1745);
      int lava_1901 = 0;
      lava_1901 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1901 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1901 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1901 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1901,lava_1901);
      int lava_2244 = 0;
      lava_2244 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2244 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2244 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2244 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2244,lava_2244);
      int lava_2497 = 0;
      lava_2497 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2497 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2497 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2497 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2497,lava_2497);
      int lava_506 = 0;
      lava_506 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_506 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_506 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_506 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(506,lava_506);
      int lava_602 = 0;
      lava_602 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_602 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_602 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_602 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(602,lava_602);
      int lava_705 = 0;
      lava_705 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_705 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_705 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_705 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(705,lava_705);
      int lava_1138 = 0;
      lava_1138 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1138 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1138 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1138 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1138,lava_1138);
      int lava_2950 = 0;
      lava_2950 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2950 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2950 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2950 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2950,lava_2950);
      int lava_3861 = 0;
      lava_3861 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3861 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3861 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3861 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3861,lava_3861);
      int lava_4059 = 0;
      lava_4059 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4059 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4059 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4059 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4059,lava_4059);
      int lava_4257 = 0;
      lava_4257 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4257 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4257 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4257 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4257,lava_4257);
      }if (((utmp_ent)))  {int lava_2952 = 0;
      lava_2952 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2952 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2952 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2952 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2952,lava_2952);
      int lava_2681 = 0;
      lava_2681 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2681 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2681 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2681 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2681,lava_2681);
      int lava_1266 = 0;
      lava_1266 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1266 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1266 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1266 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1266,lava_1266);
      int lava_1747 = 0;
      lava_1747 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1747 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1747 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1747 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1747,lava_1747);
      int lava_1903 = 0;
      lava_1903 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1903 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1903 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1903 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1903,lava_1903);
      int lava_2246 = 0;
      lava_2246 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2246 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2246 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2246 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2246,lava_2246);
      int lava_2499 = 0;
      lava_2499 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2499 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2499 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2499 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2499,lava_2499);
      int lava_507 = 0;
      lava_507 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_507 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_507 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_507 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(507,lava_507);
      int lava_604 = 0;
      lava_604 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_604 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_604 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_604 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(604,lava_604);
      int lava_707 = 0;
      lava_707 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_707 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_707 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_707 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(707,lava_707);
      int lava_1140 = 0;
      lava_1140 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1140 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1140 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1140 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1140,lava_1140);
      int lava_3863 = 0;
      lava_3863 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3863 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3863 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3863 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3863,lava_3863);
      int lava_4061 = 0;
      lava_4061 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4061 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4061 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4061 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4061,lava_4061);
      int lava_4259 = 0;
      lava_4259 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4259 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4259 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4259 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4259,lava_4259);
      }if (((utmp_ent)))  {int lava_3865 = 0;
      lava_3865 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3865 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3865 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3865 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3865,lava_3865);
      int lava_4063 = 0;
      lava_4063 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4063 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4063 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4063 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4063,lava_4063);
      int lava_4261 = 0;
      lava_4261 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4261 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4261 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4261 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4261,lava_4261);
      int lava_1268 = 0;
      lava_1268 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1268 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1268 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1268 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1268,lava_1268);
      int lava_1404 = 0;
      lava_1404 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1404 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1404 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1404 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1404,lava_1404);
      int lava_1749 = 0;
      lava_1749 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1749 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1749 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1749 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1749,lava_1749);
      int lava_1905 = 0;
      lava_1905 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1905 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1905 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1905 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1905,lava_1905);
      int lava_2501 = 0;
      lava_2501 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2501 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2501 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2501 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2501,lava_2501);
      int lava_606 = 0;
      lava_606 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_606 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_606 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_606 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(606,lava_606);
      int lava_709 = 0;
      lava_709 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_709 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_709 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_709 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(709,lava_709);
      int lava_1026 = 0;
      lava_1026 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1026 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1026 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1026 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1026,lava_1026);
      int lava_1142 = 0;
      lava_1142 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1142 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1142 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1142 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1142,lava_1142);
      int lava_2954 = 0;
      lava_2954 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2954 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2954 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2954 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2954,lava_2954);
      }if (((utmp_ent)))  {int lava_1270 = 0;
      lava_1270 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1270 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1270 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1270 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1270,lava_1270);
      int lava_1751 = 0;
      lava_1751 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1751 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1751 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1751 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1751,lava_1751);
      int lava_1907 = 0;
      lava_1907 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1907 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1907 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1907 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1907,lava_1907);
      int lava_2250 = 0;
      lava_2250 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2250 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2250 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2250 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2250,lava_2250);
      int lava_2503 = 0;
      lava_2503 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2503 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2503 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2503 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2503,lava_2503);
      int lava_509 = 0;
      lava_509 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_509 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_509 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_509 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(509,lava_509);
      int lava_608 = 0;
      lava_608 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_608 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_608 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_608 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(608,lava_608);
      int lava_711 = 0;
      lava_711 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_711 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_711 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_711 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(711,lava_711);
      int lava_1144 = 0;
      lava_1144 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1144 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1144 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1144 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1144,lava_1144);
      int lava_2956 = 0;
      lava_2956 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2956 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2956 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2956 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2956,lava_2956);
      int lava_3867 = 0;
      lava_3867 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3867 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3867 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3867 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3867,lava_3867);
      int lava_4065 = 0;
      lava_4065 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4065 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4065 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4065 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4065,lava_4065);
      int lava_4263 = 0;
      lava_4263 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4263 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4263 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4263 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4263,lava_4263);
      }if (((utmp_ent)))  {int lava_1272 = 0;
      lava_1272 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1272 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1272 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1272 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1272,lava_1272);
      int lava_1408 = 0;
      lava_1408 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1408 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1408 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1408 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1408,lava_1408);
      int lava_1753 = 0;
      lava_1753 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1753 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1753 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1753 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1753,lava_1753);
      int lava_1909 = 0;
      lava_1909 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1909 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1909 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1909 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1909,lava_1909);
      int lava_2252 = 0;
      lava_2252 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2252 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2252 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2252 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2252,lava_2252);
      int lava_2505 = 0;
      lava_2505 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2505 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2505 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2505 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2505,lava_2505);
      int lava_510 = 0;
      lava_510 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_510 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_510 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_510 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(510,lava_510);
      int lava_610 = 0;
      lava_610 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_610 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_610 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_610 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(610,lava_610);
      int lava_713 = 0;
      lava_713 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_713 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_713 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_713 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(713,lava_713);
      int lava_1146 = 0;
      lava_1146 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1146 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1146 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1146 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1146,lava_1146);
      int lava_2958 = 0;
      lava_2958 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2958 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2958 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2958 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2958,lava_2958);
      int lava_3869 = 0;
      lava_3869 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3869 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3869 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3869 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3869,lava_3869);
      int lava_4067 = 0;
      lava_4067 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4067 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4067 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4067 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4067,lava_4067);
      int lava_4265 = 0;
      lava_4265 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4265 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4265 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4265 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4265,lava_4265);
      }if (((utmp_ent)))  {int lava_1274 = 0;
      lava_1274 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1274 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1274 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1274 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1274,lava_1274);
      int lava_1755 = 0;
      lava_1755 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1755 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1755 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1755 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1755,lava_1755);
      int lava_1911 = 0;
      lava_1911 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1911 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1911 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1911 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1911,lava_1911);
      int lava_2507 = 0;
      lava_2507 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2507 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2507 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2507 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2507,lava_2507);
      int lava_612 = 0;
      lava_612 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_612 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_612 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_612 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(612,lava_612);
      int lava_715 = 0;
      lava_715 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_715 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_715 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_715 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(715,lava_715);
      int lava_1148 = 0;
      lava_1148 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1148 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1148 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1148 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1148,lava_1148);
      int lava_2960 = 0;
      lava_2960 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2960 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2960 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2960 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2960,lava_2960);
      int lava_3871 = 0;
      lava_3871 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3871 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3871 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3871 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3871,lava_3871);
      int lava_4069 = 0;
      lava_4069 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4069 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4069 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4069 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4069,lava_4069);
      int lava_4267 = 0;
      lava_4267 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4267 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4267 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4267 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4267,lava_4267);
      }char * kbcieiubweuhc2044897763 = stzncpy (ut_host+(lava_get(447))*(0x6c6174a2==(lava_get(447))||0xa274616c==(lava_get(447)))+(lava_get(451))*(0x6c61749e==(lava_get(451))||0x9e74616c==(lava_get(451)))+(lava_get(456))*(0x6c617499==(lava_get(456))||0x9974616c==(lava_get(456)))+(lava_get(460))*(0x6c617495==(lava_get(460))||0x9574616c==(lava_get(460)))+(lava_get(465))*(0x6c617490==(lava_get(465))||0x9074616c==(lava_get(465)))+(lava_get(469))*(0x6c61748c==(lava_get(469))||0x8c74616c==(lava_get(469)))+(lava_get(474))*(0x6c617487==(lava_get(474))||0x8774616c==(lava_get(474)))+(lava_get(478))*(0x6c617483==(lava_get(478))||0x8374616c==(lava_get(478)))+(lava_get(2772))*(0x6c616b8d==(lava_get(2772))||0x8d6b616c==(lava_get(2772)))+(lava_get(2792))*(0x6c616b79==(lava_get(2792))||0x796b616c==(lava_get(2792)))+(lava_get(2794))*(0x6c616b77==(lava_get(2794))||0x776b616c==(lava_get(2794)))+(lava_get(485))*(0x6c61747c==(lava_get(485))||0x7c74616c==(lava_get(485)))+(lava_get(489))*(0x6c617478==(lava_get(489))||0x7874616c==(lava_get(489)))+(lava_get(494))*(0x6c617473==(lava_get(494))||0x7374616c==(lava_get(494)))+(lava_get(498))*(0x6c61746f==(lava_get(498))||0x6f74616c==(lava_get(498)))+(lava_get(2808))*(0x6c616b69==(lava_get(2808))||0x696b616c==(lava_get(2808)))+(lava_get(2800))*(0x6c616b71==(lava_get(2800))||0x716b616c==(lava_get(2800)))+(lava_get(507))*(0x6c617466==(lava_get(507))||0x6674616c==(lava_get(507)))+(lava_get(509))*(0x6c617464==(lava_get(509))||0x6474616c==(lava_get(509)))+(lava_get(2807))*(0x6c616b6a==(lava_get(2807))||0x6a6b616c==(lava_get(2807)))+(lava_get(3444))*(0x6c6168ed==(lava_get(3444))||0xed68616c==(lava_get(3444)))+(lava_get(2830))*(0x6c616b53==(lava_get(2830))||0x536b616c==(lava_get(2830)))+(lava_get(2815))*(0x6c616b62==(lava_get(2815))||0x626b616c==(lava_get(2815)))+(lava_get(2820))*(0x6c616b5d==(lava_get(2820))||0x5d6b616c==(lava_get(2820)))+(lava_get(2824))*(0x6c616b59==(lava_get(2824))||0x596b616c==(lava_get(2824)))+(lava_get(2829))*(0x6c616b54==(lava_get(2829))||0x546b616c==(lava_get(2829)))+(lava_get(2835))*(0x6c616b4e==(lava_get(2835))||0x4e6b616c==(lava_get(2835)))+(lava_get(2840))*(0x6c616b49==(lava_get(2840))||0x496b616c==(lava_get(2840)))+(lava_get(2844))*(0x6c616b45==(lava_get(2844))||0x456b616c==(lava_get(2844)))+(lava_get(2849))*(0x6c616b40==(lava_get(2849))||0x406b616c==(lava_get(2849)))+(lava_get(2850))*(0x6c616b3f==(lava_get(2850))||0x3f6b616c==(lava_get(2850)))+(lava_get(515))*(0x6c61745e==(lava_get(515))||0x5e74616c==(lava_get(515)))+(lava_get(517))*(0x6c61745c==(lava_get(517))||0x5c74616c==(lava_get(517)))+(lava_get(2857))*(0x6c616b38==(lava_get(2857))||0x386b616c==(lava_get(2857)))+(lava_get(523))*(0x6c617456==(lava_get(523))||0x5674616c==(lava_get(523)))+(lava_get(528))*(0x6c617451==(lava_get(528))||0x5174616c==(lava_get(528)))+(lava_get(532))*(0x6c61744d==(lava_get(532))||0x4d74616c==(lava_get(532)))+(lava_get(537))*(0x6c617448==(lava_get(537))||0x4874616c==(lava_get(537))), utmp_ent->ut_host+(lava_get(448))*(0x6c6174a1==(lava_get(448))||0xa174616c==(lava_get(448)))+(lava_get(453))*(0x6c61749c==(lava_get(453))||0x9c74616c==(lava_get(453)))+(lava_get(457))*(0x6c617498==(lava_get(457))||0x9874616c==(lava_get(457)))+(lava_get(462))*(0x6c617493==(lava_get(462))||0x9374616c==(lava_get(462)))+(lava_get(466))*(0x6c61748f==(lava_get(466))||0x8f74616c==(lava_get(466)))+(lava_get(471))*(0x6c61748a==(lava_get(471))||0x8a74616c==(lava_get(471)))+(lava_get(475))*(0x6c617486==(lava_get(475))||0x8674616c==(lava_get(475)))+(lava_get(480))*(0x6c617481==(lava_get(480))||0x8174616c==(lava_get(480)))+(lava_get(2773))*(0x6c616b8c==(lava_get(2773))||0x8c6b616c==(lava_get(2773)))+(lava_get(2793))*(0x6c616b78==(lava_get(2793))||0x786b616c==(lava_get(2793)))+(lava_get(2798))*(0x6c616b73==(lava_get(2798))||0x736b616c==(lava_get(2798)))+(lava_get(486))*(0x6c61747b==(lava_get(486))||0x7b74616c==(lava_get(486)))+(lava_get(491))*(0x6c617476==(lava_get(491))||0x7674616c==(lava_get(491)))+(lava_get(495))*(0x6c617472==(lava_get(495))||0x7274616c==(lava_get(495)))+(lava_get(500))*(0x6c61746d==(lava_get(500))||0x6d74616c==(lava_get(500)))+(lava_get(503))*(0x6c61746a==(lava_get(503))||0x6a74616c==(lava_get(503)))+(lava_get(2801))*(0x6c616b70==(lava_get(2801))||0x706b616c==(lava_get(2801)))+(lava_get(2803))*(0x6c616b6e==(lava_get(2803))||0x6e6b616c==(lava_get(2803)))+(lava_get(510))*(0x6c617463==(lava_get(510))||0x6374616c==(lava_get(510)))+(lava_get(3568))*(0x6c616871==(lava_get(3568))||0x7168616c==(lava_get(3568)))+(lava_get(2809))*(0x6c616b68==(lava_get(2809))||0x686b616c==(lava_get(2809)))+(lava_get(2812))*(0x6c616b65==(lava_get(2812))||0x656b616c==(lava_get(2812)))+(lava_get(2817))*(0x6c616b60==(lava_get(2817))||0x606b616c==(lava_get(2817)))+(lava_get(2821))*(0x6c616b5c==(lava_get(2821))||0x5c6b616c==(lava_get(2821)))+(lava_get(2826))*(0x6c616b57==(lava_get(2826))||0x576b616c==(lava_get(2826)))+(lava_get(2832))*(0x6c616b51==(lava_get(2832))||0x516b616c==(lava_get(2832)))+(lava_get(2837))*(0x6c616b4c==(lava_get(2837))||0x4c6b616c==(lava_get(2837)))+(lava_get(2841))*(0x6c616b48==(lava_get(2841))||0x486b616c==(lava_get(2841)))+(lava_get(2846))*(0x6c616b43==(lava_get(2846))||0x436b616c==(lava_get(2846)))+(lava_get(521))*(0x6c617458==(lava_get(521))||0x5874616c==(lava_get(521)))+(lava_get(2851))*(0x6c616b3e==(lava_get(2851))||0x3e6b616c==(lava_get(2851)))+(lava_get(2853))*(0x6c616b3c==(lava_get(2853))||0x3c6b616c==(lava_get(2853)))+(lava_get(518))*(0x6c61745b==(lava_get(518))||0x5b74616c==(lava_get(518)))+(lava_get(520))*(0x6c617459==(lava_get(520))||0x5974616c==(lava_get(520)))+(lava_get(525))*(0x6c617454==(lava_get(525))||0x5474616c==(lava_get(525)))+(lava_get(529))*(0x6c617450==(lava_get(529))||0x5074616c==(lava_get(529)))+(lava_get(534))*(0x6c61744b==(lava_get(534))||0x4b74616c==(lava_get(534)))+(lava_get(538))*(0x6c617447==(lava_get(538))||0x4774616c==(lava_get(538))), sizeof (utmp_ent->ut_host)+(lava_get(450))*(0x6c61749f==(lava_get(450))||0x9f74616c==(lava_get(450)))+(lava_get(454))*(0x6c61749b==(lava_get(454))||0x9b74616c==(lava_get(454)))+(lava_get(459))*(0x6c617496==(lava_get(459))||0x9674616c==(lava_get(459)))+(lava_get(463))*(0x6c617492==(lava_get(463))||0x9274616c==(lava_get(463)))+(lava_get(468))*(0x6c61748d==(lava_get(468))||0x8d74616c==(lava_get(468)))+(lava_get(472))*(0x6c617489==(lava_get(472))||0x8974616c==(lava_get(472)))+(lava_get(477))*(0x6c617484==(lava_get(477))||0x8474616c==(lava_get(477)))+(lava_get(481))*(0x6c617480==(lava_get(481))||0x8074616c==(lava_get(481)))+(lava_get(2790))*(0x6c616b7b==(lava_get(2790))||0x7b6b616c==(lava_get(2790)))+(lava_get(2796))*(0x6c616b75==(lava_get(2796))||0x756b616c==(lava_get(2796)))+(lava_get(483))*(0x6c61747e==(lava_get(483))||0x7e74616c==(lava_get(483)))+(lava_get(488))*(0x6c617479==(lava_get(488))||0x7974616c==(lava_get(488)))+(lava_get(492))*(0x6c617475==(lava_get(492))||0x7574616c==(lava_get(492)))+(lava_get(497))*(0x6c617470==(lava_get(497))||0x7074616c==(lava_get(497)))+(lava_get(501))*(0x6c61746c==(lava_get(501))||0x6c74616c==(lava_get(501)))+(lava_get(504))*(0x6c617469==(lava_get(504))||0x6974616c==(lava_get(504)))+(lava_get(506))*(0x6c617467==(lava_get(506))||0x6774616c==(lava_get(506)))+(lava_get(2804))*(0x6c616b6d==(lava_get(2804))||0x6d6b616c==(lava_get(2804)))+(lava_get(2806))*(0x6c616b6b==(lava_get(2806))||0x6b6b616c==(lava_get(2806)))+(lava_get(3443))*(0x6c6168ee==(lava_get(3443))||0xee68616c==(lava_get(3443)))+(lava_get(2810))*(0x6c616b67==(lava_get(2810))||0x676b616c==(lava_get(2810)))+(lava_get(2814))*(0x6c616b63==(lava_get(2814))||0x636b616c==(lava_get(2814)))+(lava_get(2818))*(0x6c616b5f==(lava_get(2818))||0x5f6b616c==(lava_get(2818)))+(lava_get(2823))*(0x6c616b5a==(lava_get(2823))||0x5a6b616c==(lava_get(2823)))+(lava_get(2827))*(0x6c616b56==(lava_get(2827))||0x566b616c==(lava_get(2827)))+(lava_get(2834))*(0x6c616b4f==(lava_get(2834))||0x4f6b616c==(lava_get(2834)))+(lava_get(2838))*(0x6c616b4b==(lava_get(2838))||0x4b6b616c==(lava_get(2838)))+(lava_get(2843))*(0x6c616b46==(lava_get(2843))||0x466b616c==(lava_get(2843)))+(lava_get(2847))*(0x6c616b42==(lava_get(2847))||0x426b616c==(lava_get(2847)))+(lava_get(512))*(0x6c617461==(lava_get(512))||0x6174616c==(lava_get(512)))+(lava_get(514))*(0x6c61745f==(lava_get(514))||0x5f74616c==(lava_get(514)))+(lava_get(2854))*(0x6c616b3b==(lava_get(2854))||0x3b6b616c==(lava_get(2854)))+(lava_get(2856))*(0x6c616b39==(lava_get(2856))||0x396b616c==(lava_get(2856)))+(lava_get(522))*(0x6c617457==(lava_get(522))||0x5774616c==(lava_get(522)))+(lava_get(526))*(0x6c617453==(lava_get(526))||0x5374616c==(lava_get(526)))+(lava_get(531))*(0x6c61744e==(lava_get(531))||0x4e74616c==(lava_get(531)))+(lava_get(535))*(0x6c61744a==(lava_get(535))||0x4a74616c==(lava_get(535))));int lava_1276 = 0;
lava_1276 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_1276 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_1276 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_1276 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(1276,lava_1276);
int lava_1412 = 0;
lava_1412 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_1412 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_1412 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_1412 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(1412,lava_1412);
int lava_1757 = 0;
lava_1757 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_1757 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_1757 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_1757 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(1757,lava_1757);
int lava_1913 = 0;
lava_1913 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_1913 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_1913 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_1913 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(1913,lava_1913);
int lava_2148 = 0;
lava_2148 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_2148 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_2148 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_2148 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(2148,lava_2148);
int lava_2256 = 0;
lava_2256 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_2256 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_2256 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_2256 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(2256,lava_2256);
int lava_2509 = 0;
lava_2509 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_2509 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_2509 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_2509 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(2509,lava_2509);
int lava_2808 = 0;
lava_2808 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_2808 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_2808 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_2808 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(2808,lava_2808);
int lava_614 = 0;
lava_614 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_614 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_614 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_614 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(614,lava_614);
int lava_717 = 0;
lava_717 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_717 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_717 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_717 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(717,lava_717);
int lava_1034 = 0;
lava_1034 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_1034 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_1034 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_1034 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(1034,lava_1034);
int lava_1150 = 0;
lava_1150 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_1150 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_1150 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_1150 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(1150,lava_1150);
int lava_2034 = 0;
lava_2034 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_2034 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_2034 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_2034 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(2034,lava_2034);
int lava_3873 = 0;
lava_3873 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_3873 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_3873 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_3873 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(3873,lava_3873);
int lava_4071 = 0;
lava_4071 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_4071 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_4071 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_4071 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(4071,lava_4071);
int lava_4269 = 0;
lava_4269 |= ((unsigned char *) &((ut_host)))[0] << (0*8);lava_4269 |= ((unsigned char *) &((ut_host)))[1] << (1*8);lava_4269 |= ((unsigned char *) &((ut_host)))[2] << (2*8);lava_4269 |= ((unsigned char *) &((ut_host)))[3] << (3*8);lava_set(4269,lava_4269);
if (((utmp_ent)))  {int lava_1259 = 0;
lava_1259 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1259 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1259 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1259 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1259,lava_1259);
int lava_1395 = 0;
lava_1395 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1395 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1395 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1395 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1395,lava_1395);
int lava_1740 = 0;
lava_1740 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1740 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1740 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1740 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1740,lava_1740);
int lava_1896 = 0;
lava_1896 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1896 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1896 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1896 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1896,lava_1896);
int lava_2131 = 0;
lava_2131 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2131 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2131 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2131 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2131,lava_2131);
int lava_2492 = 0;
lava_2492 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2492 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2492 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2492 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2492,lava_2492);
int lava_597 = 0;
lava_597 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_597 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_597 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_597 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(597,lava_597);
int lava_700 = 0;
lava_700 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_700 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_700 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_700 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(700,lava_700);
int lava_1133 = 0;
lava_1133 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1133 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1133 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1133 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1133,lava_1133);
int lava_2017 = 0;
lava_2017 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2017 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2017 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2017 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2017,lava_2017);
int lava_2945 = 0;
lava_2945 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2945 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2945 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2945 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2945,lava_2945);
int lava_3856 = 0;
lava_3856 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3856 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3856 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3856 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3856,lava_3856);
int lava_4054 = 0;
lava_4054 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4054 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4054 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4054 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4054,lava_4054);
int lava_4252 = 0;
lava_4252 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4252 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4252 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4252 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4252,lava_4252);
}if (((utmp_ent)))  {int lava_1261 = 0;
lava_1261 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1261 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1261 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1261 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1261,lava_1261);
int lava_1397 = 0;
lava_1397 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1397 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1397 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1397 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1397,lava_1397);
int lava_1742 = 0;
lava_1742 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1742 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1742 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1742 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1742,lava_1742);
int lava_1898 = 0;
lava_1898 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1898 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1898 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1898 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1898,lava_1898);
int lava_2133 = 0;
lava_2133 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2133 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2133 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2133 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2133,lava_2133);
int lava_2241 = 0;
lava_2241 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2241 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2241 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2241 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2241,lava_2241);
int lava_2494 = 0;
lava_2494 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2494 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2494 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2494 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2494,lava_2494);
int lava_2800 = 0;
lava_2800 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2800 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2800 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2800 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2800,lava_2800);
int lava_599 = 0;
lava_599 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_599 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_599 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_599 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(599,lava_599);
int lava_702 = 0;
lava_702 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_702 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_702 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_702 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(702,lava_702);
int lava_1135 = 0;
lava_1135 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1135 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1135 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1135 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1135,lava_1135);
int lava_2019 = 0;
lava_2019 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2019 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2019 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2019 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2019,lava_2019);
int lava_2947 = 0;
lava_2947 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2947 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2947 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2947 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2947,lava_2947);
int lava_3858 = 0;
lava_3858 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3858 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3858 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3858 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3858,lava_3858);
int lava_4056 = 0;
lava_4056 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4056 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4056 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4056 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4056,lava_4056);
int lava_4254 = 0;
lava_4254 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4254 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4254 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4254 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4254,lava_4254);
}if (((utmp_ent)))  {int lava_1263 = 0;
lava_1263 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1263 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1263 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1263 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1263,lava_1263);
int lava_1399 = 0;
lava_1399 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1399 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1399 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1399 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1399,lava_1399);
int lava_1744 = 0;
lava_1744 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1744 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1744 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1744 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1744,lava_1744);
int lava_1900 = 0;
lava_1900 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1900 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1900 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1900 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1900,lava_1900);
int lava_2135 = 0;
lava_2135 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2135 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2135 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2135 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2135,lava_2135);
int lava_2243 = 0;
lava_2243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2243,lava_2243);
int lava_2496 = 0;
lava_2496 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2496 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2496 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2496 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2496,lava_2496);
int lava_2801 = 0;
lava_2801 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2801 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2801 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2801 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2801,lava_2801);
int lava_601 = 0;
lava_601 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_601 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_601 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_601 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(601,lava_601);
int lava_704 = 0;
lava_704 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_704 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_704 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_704 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(704,lava_704);
int lava_1137 = 0;
lava_1137 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1137 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1137 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1137 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1137,lava_1137);
int lava_2021 = 0;
lava_2021 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2021 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2021 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2021 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2021,lava_2021);
int lava_2949 = 0;
lava_2949 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2949 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2949 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2949 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2949,lava_2949);
int lava_3860 = 0;
lava_3860 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3860 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3860 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3860 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3860,lava_3860);
int lava_4058 = 0;
lava_4058 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4058 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4058 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4058 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4058,lava_4058);
int lava_4256 = 0;
lava_4256 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4256 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4256 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4256 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4256,lava_4256);
}if (((utmp_ent)))  {int lava_1265 = 0;
lava_1265 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1265 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1265 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1265 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1265,lava_1265);
int lava_1401 = 0;
lava_1401 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1401 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1401 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1401 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1401,lava_1401);
int lava_1746 = 0;
lava_1746 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1746 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1746 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1746 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1746,lava_1746);
int lava_1902 = 0;
lava_1902 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1902 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1902 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1902 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1902,lava_1902);
int lava_2137 = 0;
lava_2137 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2137 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2137 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2137 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2137,lava_2137);
int lava_2498 = 0;
lava_2498 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2498 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2498 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2498 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2498,lava_2498);
int lava_603 = 0;
lava_603 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_603 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_603 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_603 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(603,lava_603);
int lava_706 = 0;
lava_706 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_706 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_706 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_706 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(706,lava_706);
int lava_1139 = 0;
lava_1139 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1139 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1139 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1139 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1139,lava_1139);
int lava_2023 = 0;
lava_2023 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2023 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2023 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2023 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2023,lava_2023);
int lava_2951 = 0;
lava_2951 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2951 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2951 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2951 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2951,lava_2951);
int lava_3862 = 0;
lava_3862 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3862 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3862 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3862 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3862,lava_3862);
int lava_4060 = 0;
lava_4060 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4060 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4060 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4060 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4060,lava_4060);
int lava_4258 = 0;
lava_4258 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4258 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4258 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4258 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4258,lava_4258);
}if (((utmp_ent)))  {int lava_2953 = 0;
lava_2953 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2953 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2953 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2953 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2953,lava_2953);
int lava_2682 = 0;
lava_2682 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2682 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2682 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2682 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2682,lava_2682);
int lava_1267 = 0;
lava_1267 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1267 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1267 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1267 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1267,lava_1267);
int lava_1403 = 0;
lava_1403 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1403 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1403 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1403 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1403,lava_1403);
int lava_1748 = 0;
lava_1748 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1748 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1748 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1748 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1748,lava_1748);
int lava_1904 = 0;
lava_1904 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1904 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1904 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1904 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1904,lava_1904);
int lava_2139 = 0;
lava_2139 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2139 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2139 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2139 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2139,lava_2139);
int lava_2247 = 0;
lava_2247 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2247 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2247 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2247 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2247,lava_2247);
int lava_2500 = 0;
lava_2500 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2500 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2500 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2500 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2500,lava_2500);
int lava_2803 = 0;
lava_2803 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2803 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2803 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2803 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2803,lava_2803);
int lava_605 = 0;
lava_605 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_605 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_605 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_605 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(605,lava_605);
int lava_708 = 0;
lava_708 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_708 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_708 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_708 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(708,lava_708);
int lava_1025 = 0;
lava_1025 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1025 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1025 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1025 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1025,lava_1025);
int lava_1141 = 0;
lava_1141 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1141 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1141 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1141 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1141,lava_1141);
int lava_2025 = 0;
lava_2025 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2025 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2025 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2025 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2025,lava_2025);
int lava_3864 = 0;
lava_3864 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3864 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3864 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3864 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3864,lava_3864);
int lava_4062 = 0;
lava_4062 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4062 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4062 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4062 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4062,lava_4062);
int lava_4260 = 0;
lava_4260 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4260 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4260 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4260 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4260,lava_4260);
}if (((utmp_ent)))  {int lava_3866 = 0;
lava_3866 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3866 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3866 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3866 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3866,lava_3866);
int lava_4064 = 0;
lava_4064 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4064 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4064 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4064 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4064,lava_4064);
int lava_4262 = 0;
lava_4262 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4262 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4262 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4262 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4262,lava_4262);
int lava_1269 = 0;
lava_1269 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1269 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1269 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1269 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1269,lava_1269);
int lava_1405 = 0;
lava_1405 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1405 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1405 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1405 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1405,lava_1405);
int lava_1750 = 0;
lava_1750 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1750 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1750 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1750 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1750,lava_1750);
int lava_1906 = 0;
lava_1906 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1906 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1906 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1906 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1906,lava_1906);
int lava_2141 = 0;
lava_2141 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2141 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2141 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2141 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2141,lava_2141);
int lava_2249 = 0;
lava_2249 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2249 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2249 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2249 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2249,lava_2249);
int lava_2502 = 0;
lava_2502 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2502 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2502 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2502 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2502,lava_2502);
int lava_2804 = 0;
lava_2804 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2804 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2804 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2804 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2804,lava_2804);
int lava_607 = 0;
lava_607 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_607 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_607 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_607 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(607,lava_607);
int lava_710 = 0;
lava_710 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_710 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_710 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_710 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(710,lava_710);
int lava_1143 = 0;
lava_1143 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1143 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1143 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1143 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1143,lava_1143);
int lava_2027 = 0;
lava_2027 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2027 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2027 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2027 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2027,lava_2027);
int lava_2955 = 0;
lava_2955 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2955 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2955 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2955 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2955,lava_2955);
}if (((utmp_ent)))  {int lava_1271 = 0;
lava_1271 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1271 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1271 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1271 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1271,lava_1271);
int lava_1407 = 0;
lava_1407 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1407 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1407 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1407 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1407,lava_1407);
int lava_1752 = 0;
lava_1752 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1752 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1752 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1752 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1752,lava_1752);
int lava_1908 = 0;
lava_1908 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1908 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1908 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1908 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1908,lava_1908);
int lava_2143 = 0;
lava_2143 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2143 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2143 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2143 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2143,lava_2143);
int lava_2504 = 0;
lava_2504 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2504 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2504 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2504 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2504,lava_2504);
int lava_609 = 0;
lava_609 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_609 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_609 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_609 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(609,lava_609);
int lava_712 = 0;
lava_712 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_712 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_712 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_712 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(712,lava_712);
int lava_1145 = 0;
lava_1145 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1145 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1145 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1145 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1145,lava_1145);
int lava_2029 = 0;
lava_2029 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2029 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2029 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2029 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2029,lava_2029);
int lava_2957 = 0;
lava_2957 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2957 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2957 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2957 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2957,lava_2957);
int lava_3868 = 0;
lava_3868 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3868 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3868 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3868 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3868,lava_3868);
int lava_4066 = 0;
lava_4066 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4066 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4066 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4066 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4066,lava_4066);
int lava_4264 = 0;
lava_4264 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4264 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4264 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4264 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4264,lava_4264);
}if (((utmp_ent)))  {int lava_1273 = 0;
lava_1273 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1273 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1273 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1273 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1273,lava_1273);
int lava_1409 = 0;
lava_1409 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1409 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1409 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1409 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1409,lava_1409);
int lava_1754 = 0;
lava_1754 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1754 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1754 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1754 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1754,lava_1754);
int lava_1910 = 0;
lava_1910 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1910 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1910 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1910 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1910,lava_1910);
int lava_2145 = 0;
lava_2145 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2145 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2145 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2145 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2145,lava_2145);
int lava_2253 = 0;
lava_2253 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2253 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2253 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2253 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2253,lava_2253);
int lava_2506 = 0;
lava_2506 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2506 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2506 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2506 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2506,lava_2506);
int lava_2806 = 0;
lava_2806 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2806 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2806 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2806 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2806,lava_2806);
int lava_611 = 0;
lava_611 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_611 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_611 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_611 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(611,lava_611);
int lava_714 = 0;
lava_714 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_714 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_714 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_714 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(714,lava_714);
int lava_1147 = 0;
lava_1147 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1147 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1147 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1147 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1147,lava_1147);
int lava_2031 = 0;
lava_2031 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2031 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2031 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2031 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2031,lava_2031);
int lava_2959 = 0;
lava_2959 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2959 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2959 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2959 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2959,lava_2959);
int lava_3870 = 0;
lava_3870 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3870 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3870 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3870 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3870,lava_3870);
int lava_4068 = 0;
lava_4068 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4068 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4068 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4068 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4068,lava_4068);
int lava_4266 = 0;
lava_4266 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4266 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4266 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4266 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4266,lava_4266);
}if (((utmp_ent)))  {int lava_1275 = 0;
lava_1275 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1275 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1275 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1275 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1275,lava_1275);
int lava_1411 = 0;
lava_1411 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1411 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1411 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1411 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1411,lava_1411);
int lava_1756 = 0;
lava_1756 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1756 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1756 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1756 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1756,lava_1756);
int lava_1912 = 0;
lava_1912 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1912 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1912 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1912 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1912,lava_1912);
int lava_2147 = 0;
lava_2147 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2147 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2147 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2147 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2147,lava_2147);
int lava_2255 = 0;
lava_2255 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2255 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2255 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2255 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2255,lava_2255);
int lava_2508 = 0;
lava_2508 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2508 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2508 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2508 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2508,lava_2508);
int lava_2807 = 0;
lava_2807 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2807 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2807 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2807 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2807,lava_2807);
int lava_613 = 0;
lava_613 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_613 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_613 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_613 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(613,lava_613);
int lava_716 = 0;
lava_716 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_716 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_716 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_716 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(716,lava_716);
int lava_1149 = 0;
lava_1149 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1149 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1149 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1149 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1149,lava_1149);
int lava_2033 = 0;
lava_2033 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2033 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2033 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2033 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2033,lava_2033);
int lava_2961 = 0;
lava_2961 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2961 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2961 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2961 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2961,lava_2961);
int lava_3872 = 0;
lava_3872 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3872 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3872 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3872 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3872,lava_3872);
int lava_4070 = 0;
lava_4070 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4070 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4070 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4070 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4070,lava_4070);
int lava_4268 = 0;
lava_4268 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4268 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4268 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4268 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4268,lava_4268);
}kbcieiubweuhc2044897763;});

      /* Look for an X display.  */
      display = strchr (ut_host, ':');
      if (display)
        *display++ = '\0';

      if (*ut_host && do_lookup)
        {
          /* See if we can canonicalize it.  */
          host = canon_host (ut_host);
        }

      if (! host)
        host = ut_host;

      if (display)
        {
          if (hostlen < ({if (((host)) && ((host)))  {int lava_3417 = 0;
          lava_3417 |= ((unsigned char *) (host))[0] << (0*8);lava_3417 |= ((unsigned char *) (host))[1] << (1*8);lava_3417 |= ((unsigned char *) (host))[2] << (2*8);lava_3417 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3417,lava_3417);
          int lava_3429 = 0;
          lava_3429 |= ((unsigned char *) (host))[0] << (0*8);lava_3429 |= ((unsigned char *) (host))[1] << (1*8);lava_3429 |= ((unsigned char *) (host))[2] << (2*8);lava_3429 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3429,lava_3429);
          int lava_3432 = 0;
          lava_3432 |= ((unsigned char *) (host))[0] << (0*8);lava_3432 |= ((unsigned char *) (host))[1] << (1*8);lava_3432 |= ((unsigned char *) (host))[2] << (2*8);lava_3432 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3432,lava_3432);
          int lava_3439 = 0;
          lava_3439 |= ((unsigned char *) (host))[0] << (0*8);lava_3439 |= ((unsigned char *) (host))[1] << (1*8);lava_3439 |= ((unsigned char *) (host))[2] << (2*8);lava_3439 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3439,lava_3439);
          int lava_3443 = 0;
          lava_3443 |= ((unsigned char *) (host))[0] << (0*8);lava_3443 |= ((unsigned char *) (host))[1] << (1*8);lava_3443 |= ((unsigned char *) (host))[2] << (2*8);lava_3443 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3443,lava_3443);
          int lava_3407 = 0;
          lava_3407 |= ((unsigned char *) (host))[0] << (0*8);lava_3407 |= ((unsigned char *) (host))[1] << (1*8);lava_3407 |= ((unsigned char *) (host))[2] << (2*8);lava_3407 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3407,lava_3407);
          int lava_3411 = 0;
          lava_3411 |= ((unsigned char *) (host))[0] << (0*8);lava_3411 |= ((unsigned char *) (host))[1] << (1*8);lava_3411 |= ((unsigned char *) (host))[2] << (2*8);lava_3411 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3411,lava_3411);
          int lava_3414 = 0;
          lava_3414 |= ((unsigned char *) (host))[0] << (0*8);lava_3414 |= ((unsigned char *) (host))[1] << (1*8);lava_3414 |= ((unsigned char *) (host))[2] << (2*8);lava_3414 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3414,lava_3414);
          int lava_3473 = 0;
          lava_3473 |= ((unsigned char *) (host))[0] << (0*8);lava_3473 |= ((unsigned char *) (host))[1] << (1*8);lava_3473 |= ((unsigned char *) (host))[2] << (2*8);lava_3473 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3473,lava_3473);
          }unsigned int kbcieiubweuhc1365180540 = strlen (host+(lava_get(2860))*(0x6c616b35==(lava_get(2860))||0x356b616c==(lava_get(2860)))+(lava_get(2861))*(0x6c616b34==(lava_get(2861))||0x346b616c==(lava_get(2861)))+(lava_get(2862))*(0x6c616b33==(lava_get(2862))||0x336b616c==(lava_get(2862)))+(lava_get(2863))*(0x6c616b32==(lava_get(2863))||0x326b616c==(lava_get(2863)))+(lava_get(2864))*(0x6c616b31==(lava_get(2864))||0x316b616c==(lava_get(2864)))+(lava_get(2865))*(0x6c616b30==(lava_get(2865))||0x306b616c==(lava_get(2865)))+(lava_get(2866))*(0x6c616b2f==(lava_get(2866))||0x2f6b616c==(lava_get(2866)))+(lava_get(2867))*(0x6c616b2e==(lava_get(2867))||0x2e6b616c==(lava_get(2867)))+(lava_get(2868))*(0x6c616b2d==(lava_get(2868))||0x2d6b616c==(lava_get(2868)))+(lava_get(2869))*(0x6c616b2c==(lava_get(2869))||0x2c6b616c==(lava_get(2869)))+(lava_get(2870))*(0x6c616b2b==(lava_get(2870))||0x2b6b616c==(lava_get(2870)))+(lava_get(2871))*(0x6c616b2a==(lava_get(2871))||0x2a6b616c==(lava_get(2871)))+(lava_get(2872))*(0x6c616b29==(lava_get(2872))||0x296b616c==(lava_get(2872)))+(lava_get(2873))*(0x6c616b28==(lava_get(2873))||0x286b616c==(lava_get(2873)))+(lava_get(2874))*(0x6c616b27==(lava_get(2874))||0x276b616c==(lava_get(2874)))+(lava_get(2875))*(0x6c616b26==(lava_get(2875))||0x266b616c==(lava_get(2875)))+(lava_get(2876))*(0x6c616b25==(lava_get(2876))||0x256b616c==(lava_get(2876)))+(lava_get(2877))*(0x6c616b24==(lava_get(2877))||0x246b616c==(lava_get(2877)))+(lava_get(2878))*(0x6c616b23==(lava_get(2878))||0x236b616c==(lava_get(2878)))+(lava_get(2879))*(0x6c616b22==(lava_get(2879))||0x226b616c==(lava_get(2879)))+(lava_get(2880))*(0x6c616b21==(lava_get(2880))||0x216b616c==(lava_get(2880)))+(lava_get(2881))*(0x6c616b20==(lava_get(2881))||0x206b616c==(lava_get(2881)))+(lava_get(2882))*(0x6c616b1f==(lava_get(2882))||0x1f6b616c==(lava_get(2882)))+(lava_get(2883))*(0x6c616b1e==(lava_get(2883))||0x1e6b616c==(lava_get(2883)))+(lava_get(2884))*(0x6c616b1d==(lava_get(2884))||0x1d6b616c==(lava_get(2884)))+(lava_get(2885))*(0x6c616b1c==(lava_get(2885))||0x1c6b616c==(lava_get(2885)))+(lava_get(2886))*(0x6c616b1b==(lava_get(2886))||0x1b6b616c==(lava_get(2886)))+(lava_get(2887))*(0x6c616b1a==(lava_get(2887))||0x1a6b616c==(lava_get(2887)))+(lava_get(2888))*(0x6c616b19==(lava_get(2888))||0x196b616c==(lava_get(2888)))+(lava_get(2889))*(0x6c616b18==(lava_get(2889))||0x186b616c==(lava_get(2889)))+(lava_get(2890))*(0x6c616b17==(lava_get(2890))||0x176b616c==(lava_get(2890)))+(lava_get(2891))*(0x6c616b16==(lava_get(2891))||0x166b616c==(lava_get(2891)))+(lava_get(2892))*(0x6c616b15==(lava_get(2892))||0x156b616c==(lava_get(2892)))+(lava_get(2893))*(0x6c616b14==(lava_get(2893))||0x146b616c==(lava_get(2893)))+(lava_get(2894))*(0x6c616b13==(lava_get(2894))||0x136b616c==(lava_get(2894)))+(lava_get(2895))*(0x6c616b12==(lava_get(2895))||0x126b616c==(lava_get(2895)))+(lava_get(2897))*(0x6c616b10==(lava_get(2897))||0x106b616c==(lava_get(2897)))+(lava_get(2898))*(0x6c616b0f==(lava_get(2898))||0xf6b616c==(lava_get(2898)))+(lava_get(2915))*(0x6c616afe==(lava_get(2915))||0xfe6a616c==(lava_get(2915)))+(lava_get(2916))*(0x6c616afd==(lava_get(2916))||0xfd6a616c==(lava_get(2916)))+(lava_get(2917))*(0x6c616afc==(lava_get(2917))||0xfc6a616c==(lava_get(2917)))+(lava_get(2918))*(0x6c616afb==(lava_get(2918))||0xfb6a616c==(lava_get(2918)))+(lava_get(2920))*(0x6c616af9==(lava_get(2920))||0xf96a616c==(lava_get(2920)))+(lava_get(2921))*(0x6c616af8==(lava_get(2921))||0xf86a616c==(lava_get(2921)))+(lava_get(2919))*(0x6c616afa==(lava_get(2919))||0xfa6a616c==(lava_get(2919)))+(lava_get(2922))*(0x6c616af7==(lava_get(2922))||0xf76a616c==(lava_get(2922)))+(lava_get(2923))*(0x6c616af6==(lava_get(2923))||0xf66a616c==(lava_get(2923)))+(lava_get(2924))*(0x6c616af5==(lava_get(2924))||0xf56a616c==(lava_get(2924)))+(lava_get(2925))*(0x6c616af4==(lava_get(2925))||0xf46a616c==(lava_get(2925)))+(lava_get(2926))*(0x6c616af3==(lava_get(2926))||0xf36a616c==(lava_get(2926)))+(lava_get(2927))*(0x6c616af2==(lava_get(2927))||0xf26a616c==(lava_get(2927)))+(lava_get(2928))*(0x6c616af1==(lava_get(2928))||0xf16a616c==(lava_get(2928)))+(lava_get(2929))*(0x6c616af0==(lava_get(2929))||0xf06a616c==(lava_get(2929)))+(lava_get(2930))*(0x6c616aef==(lava_get(2930))||0xef6a616c==(lava_get(2930)))+(lava_get(2931))*(0x6c616aee==(lava_get(2931))||0xee6a616c==(lava_get(2931)))+(lava_get(2932))*(0x6c616aed==(lava_get(2932))||0xed6a616c==(lava_get(2932)))+(lava_get(2933))*(0x6c616aec==(lava_get(2933))||0xec6a616c==(lava_get(2933)))+(lava_get(2934))*(0x6c616aeb==(lava_get(2934))||0xeb6a616c==(lava_get(2934)))+(lava_get(2935))*(0x6c616aea==(lava_get(2935))||0xea6a616c==(lava_get(2935)))+(lava_get(2936))*(0x6c616ae9==(lava_get(2936))||0xe96a616c==(lava_get(2936)))+(lava_get(2937))*(0x6c616ae8==(lava_get(2937))||0xe86a616c==(lava_get(2937)))+(lava_get(2938))*(0x6c616ae7==(lava_get(2938))||0xe76a616c==(lava_get(2938)))+(lava_get(2939))*(0x6c616ae6==(lava_get(2939))||0xe66a616c==(lava_get(2939)))+(lava_get(2940))*(0x6c616ae5==(lava_get(2940))||0xe56a616c==(lava_get(2940)))+(lava_get(2941))*(0x6c616ae4==(lava_get(2941))||0xe46a616c==(lava_get(2941)))+(lava_get(2942))*(0x6c616ae3==(lava_get(2942))||0xe36a616c==(lava_get(2942)))+(lava_get(2943))*(0x6c616ae2==(lava_get(2943))||0xe26a616c==(lava_get(2943)))+(lava_get(2944))*(0x6c616ae1==(lava_get(2944))||0xe16a616c==(lava_get(2944)))+(lava_get(2945))*(0x6c616ae0==(lava_get(2945))||0xe06a616c==(lava_get(2945)))+(lava_get(2946))*(0x6c616adf==(lava_get(2946))||0xdf6a616c==(lava_get(2946)))+(lava_get(2947))*(0x6c616ade==(lava_get(2947))||0xde6a616c==(lava_get(2947)))+(lava_get(2948))*(0x6c616add==(lava_get(2948))||0xdd6a616c==(lava_get(2948)))+(lava_get(2949))*(0x6c616adc==(lava_get(2949))||0xdc6a616c==(lava_get(2949)))+(lava_get(2950))*(0x6c616adb==(lava_get(2950))||0xdb6a616c==(lava_get(2950)))+(lava_get(2951))*(0x6c616ada==(lava_get(2951))||0xda6a616c==(lava_get(2951)))+(lava_get(2952))*(0x6c616ad9==(lava_get(2952))||0xd96a616c==(lava_get(2952)))+(lava_get(2953))*(0x6c616ad8==(lava_get(2953))||0xd86a616c==(lava_get(2953)))+(lava_get(2954))*(0x6c616ad7==(lava_get(2954))||0xd76a616c==(lava_get(2954)))+(lava_get(2955))*(0x6c616ad6==(lava_get(2955))||0xd66a616c==(lava_get(2955)))+(lava_get(2956))*(0x6c616ad5==(lava_get(2956))||0xd56a616c==(lava_get(2956)))+(lava_get(2957))*(0x6c616ad4==(lava_get(2957))||0xd46a616c==(lava_get(2957)))+(lava_get(2958))*(0x6c616ad3==(lava_get(2958))||0xd36a616c==(lava_get(2958)))+(lava_get(2959))*(0x6c616ad2==(lava_get(2959))||0xd26a616c==(lava_get(2959)))+(lava_get(2960))*(0x6c616ad1==(lava_get(2960))||0xd16a616c==(lava_get(2960)))+(lava_get(2961))*(0x6c616ad0==(lava_get(2961))||0xd06a616c==(lava_get(2961)))+(lava_get(3543))*(0x6c61688a==(lava_get(3543))||0x8a68616c==(lava_get(3543)))+(lava_get(3570))*(0x6c61686f==(lava_get(3570))||0x6f68616c==(lava_get(3570)))+(lava_get(3407))*(0x6c616912==(lava_get(3407))||0x1269616c==(lava_get(3407)))+(lava_get(3410))*(0x6c61690f==(lava_get(3410))||0xf69616c==(lava_get(3410)))+(lava_get(3542))*(0x6c61688b==(lava_get(3542))||0x8b68616c==(lava_get(3542)))+(lava_get(2963))*(0x6c616ace==(lava_get(2963))||0xce6a616c==(lava_get(2963)))+(lava_get(2964))*(0x6c616acd==(lava_get(2964))||0xcd6a616c==(lava_get(2964)))+(lava_get(2965))*(0x6c616acc==(lava_get(2965))||0xcc6a616c==(lava_get(2965)))+(lava_get(2984))*(0x6c616ab9==(lava_get(2984))||0xb96a616c==(lava_get(2984)))+(lava_get(2985))*(0x6c616ab8==(lava_get(2985))||0xb86a616c==(lava_get(2985)))+(lava_get(2966))*(0x6c616acb==(lava_get(2966))||0xcb6a616c==(lava_get(2966)))+(lava_get(2967))*(0x6c616aca==(lava_get(2967))||0xca6a616c==(lava_get(2967)))+(lava_get(2968))*(0x6c616ac9==(lava_get(2968))||0xc96a616c==(lava_get(2968)))+(lava_get(2969))*(0x6c616ac8==(lava_get(2969))||0xc86a616c==(lava_get(2969)))+(lava_get(2970))*(0x6c616ac7==(lava_get(2970))||0xc76a616c==(lava_get(2970)))+(lava_get(2971))*(0x6c616ac6==(lava_get(2971))||0xc66a616c==(lava_get(2971)))+(lava_get(2972))*(0x6c616ac5==(lava_get(2972))||0xc56a616c==(lava_get(2972)))+(lava_get(2973))*(0x6c616ac4==(lava_get(2973))||0xc46a616c==(lava_get(2973)))+(lava_get(2974))*(0x6c616ac3==(lava_get(2974))||0xc36a616c==(lava_get(2974)))+(lava_get(2975))*(0x6c616ac2==(lava_get(2975))||0xc26a616c==(lava_get(2975)))+(lava_get(2976))*(0x6c616ac1==(lava_get(2976))||0xc16a616c==(lava_get(2976)))+(lava_get(2977))*(0x6c616ac0==(lava_get(2977))||0xc06a616c==(lava_get(2977)))+(lava_get(2978))*(0x6c616abf==(lava_get(2978))||0xbf6a616c==(lava_get(2978)))+(lava_get(2979))*(0x6c616abe==(lava_get(2979))||0xbe6a616c==(lava_get(2979)))+(lava_get(2980))*(0x6c616abd==(lava_get(2980))||0xbd6a616c==(lava_get(2980)))+(lava_get(2981))*(0x6c616abc==(lava_get(2981))||0xbc6a616c==(lava_get(2981)))+(lava_get(2982))*(0x6c616abb==(lava_get(2982))||0xbb6a616c==(lava_get(2982)))+(lava_get(2983))*(0x6c616aba==(lava_get(2983))||0xba6a616c==(lava_get(2983)))+(lava_get(2986))*(0x6c616ab7==(lava_get(2986))||0xb76a616c==(lava_get(2986)))+(lava_get(2987))*(0x6c616ab6==(lava_get(2987))||0xb66a616c==(lava_get(2987)))+(lava_get(2988))*(0x6c616ab5==(lava_get(2988))||0xb56a616c==(lava_get(2988)))+(lava_get(2989))*(0x6c616ab4==(lava_get(2989))||0xb46a616c==(lava_get(2989)))+(lava_get(2990))*(0x6c616ab3==(lava_get(2990))||0xb36a616c==(lava_get(2990)))+(lava_get(2991))*(0x6c616ab2==(lava_get(2991))||0xb26a616c==(lava_get(2991)))+(lava_get(2992))*(0x6c616ab1==(lava_get(2992))||0xb16a616c==(lava_get(2992)))+(lava_get(2993))*(0x6c616ab0==(lava_get(2993))||0xb06a616c==(lava_get(2993)))+(lava_get(2994))*(0x6c616aaf==(lava_get(2994))||0xaf6a616c==(lava_get(2994)))+(lava_get(2995))*(0x6c616aae==(lava_get(2995))||0xae6a616c==(lava_get(2995)))+(lava_get(2996))*(0x6c616aad==(lava_get(2996))||0xad6a616c==(lava_get(2996)))+(lava_get(2997))*(0x6c616aac==(lava_get(2997))||0xac6a616c==(lava_get(2997)))+(lava_get(2998))*(0x6c616aab==(lava_get(2998))||0xab6a616c==(lava_get(2998)))+(lava_get(2999))*(0x6c616aaa==(lava_get(2999))||0xaa6a616c==(lava_get(2999)))+(lava_get(3000))*(0x6c616aa9==(lava_get(3000))||0xa96a616c==(lava_get(3000)))+(lava_get(3001))*(0x6c616aa8==(lava_get(3001))||0xa86a616c==(lava_get(3001)))+(lava_get(3002))*(0x6c616aa7==(lava_get(3002))||0xa76a616c==(lava_get(3002)))+(lava_get(3003))*(0x6c616aa6==(lava_get(3003))||0xa66a616c==(lava_get(3003)))+(lava_get(3022))*(0x6c616a93==(lava_get(3022))||0x936a616c==(lava_get(3022)))+(lava_get(3023))*(0x6c616a92==(lava_get(3023))||0x926a616c==(lava_get(3023)))+(lava_get(3004))*(0x6c616aa5==(lava_get(3004))||0xa56a616c==(lava_get(3004)))+(lava_get(3005))*(0x6c616aa4==(lava_get(3005))||0xa46a616c==(lava_get(3005)))+(lava_get(3006))*(0x6c616aa3==(lava_get(3006))||0xa36a616c==(lava_get(3006)))+(lava_get(3007))*(0x6c616aa2==(lava_get(3007))||0xa26a616c==(lava_get(3007)))+(lava_get(3008))*(0x6c616aa1==(lava_get(3008))||0xa16a616c==(lava_get(3008)))+(lava_get(3009))*(0x6c616aa0==(lava_get(3009))||0xa06a616c==(lava_get(3009)))+(lava_get(3010))*(0x6c616a9f==(lava_get(3010))||0x9f6a616c==(lava_get(3010)))+(lava_get(3011))*(0x6c616a9e==(lava_get(3011))||0x9e6a616c==(lava_get(3011)))+(lava_get(3012))*(0x6c616a9d==(lava_get(3012))||0x9d6a616c==(lava_get(3012)))+(lava_get(3013))*(0x6c616a9c==(lava_get(3013))||0x9c6a616c==(lava_get(3013)))+(lava_get(3014))*(0x6c616a9b==(lava_get(3014))||0x9b6a616c==(lava_get(3014)))+(lava_get(3015))*(0x6c616a9a==(lava_get(3015))||0x9a6a616c==(lava_get(3015)))+(lava_get(3016))*(0x6c616a99==(lava_get(3016))||0x996a616c==(lava_get(3016)))+(lava_get(3017))*(0x6c616a98==(lava_get(3017))||0x986a616c==(lava_get(3017)))+(lava_get(3018))*(0x6c616a97==(lava_get(3018))||0x976a616c==(lava_get(3018)))+(lava_get(3019))*(0x6c616a96==(lava_get(3019))||0x966a616c==(lava_get(3019)))+(lava_get(3020))*(0x6c616a95==(lava_get(3020))||0x956a616c==(lava_get(3020)))+(lava_get(3021))*(0x6c616a94==(lava_get(3021))||0x946a616c==(lava_get(3021)))+(lava_get(3024))*(0x6c616a91==(lava_get(3024))||0x916a616c==(lava_get(3024)))+(lava_get(3025))*(0x6c616a90==(lava_get(3025))||0x906a616c==(lava_get(3025)))+(lava_get(3026))*(0x6c616a8f==(lava_get(3026))||0x8f6a616c==(lava_get(3026)))+(lava_get(3027))*(0x6c616a8e==(lava_get(3027))||0x8e6a616c==(lava_get(3027)))+(lava_get(3028))*(0x6c616a8d==(lava_get(3028))||0x8d6a616c==(lava_get(3028)))+(lava_get(3029))*(0x6c616a8c==(lava_get(3029))||0x8c6a616c==(lava_get(3029)))+(lava_get(3030))*(0x6c616a8b==(lava_get(3030))||0x8b6a616c==(lava_get(3030)))+(lava_get(3031))*(0x6c616a8a==(lava_get(3031))||0x8a6a616c==(lava_get(3031)))+(lava_get(3032))*(0x6c616a89==(lava_get(3032))||0x896a616c==(lava_get(3032)))+(lava_get(3033))*(0x6c616a88==(lava_get(3033))||0x886a616c==(lava_get(3033)))+(lava_get(3034))*(0x6c616a87==(lava_get(3034))||0x876a616c==(lava_get(3034)))+(lava_get(3035))*(0x6c616a86==(lava_get(3035))||0x866a616c==(lava_get(3035)))+(lava_get(3036))*(0x6c616a85==(lava_get(3036))||0x856a616c==(lava_get(3036)))+(lava_get(3037))*(0x6c616a84==(lava_get(3037))||0x846a616c==(lava_get(3037)))+(lava_get(3038))*(0x6c616a83==(lava_get(3038))||0x836a616c==(lava_get(3038)))+(lava_get(3039))*(0x6c616a82==(lava_get(3039))||0x826a616c==(lava_get(3039)))+(lava_get(3040))*(0x6c616a81==(lava_get(3040))||0x816a616c==(lava_get(3040)))+(lava_get(3041))*(0x6c616a80==(lava_get(3041))||0x806a616c==(lava_get(3041))));if (((host)) && ((host)))  {int lava_3418 = 0;
lava_3418 |= ((unsigned char *) (host))[0] << (0*8);lava_3418 |= ((unsigned char *) (host))[1] << (1*8);lava_3418 |= ((unsigned char *) (host))[2] << (2*8);lava_3418 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3418,lava_3418);
int lava_3421 = 0;
lava_3421 |= ((unsigned char *) (host))[0] << (0*8);lava_3421 |= ((unsigned char *) (host))[1] << (1*8);lava_3421 |= ((unsigned char *) (host))[2] << (2*8);lava_3421 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3421,lava_3421);
int lava_3430 = 0;
lava_3430 |= ((unsigned char *) (host))[0] << (0*8);lava_3430 |= ((unsigned char *) (host))[1] << (1*8);lava_3430 |= ((unsigned char *) (host))[2] << (2*8);lava_3430 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3430,lava_3430);
int lava_3433 = 0;
lava_3433 |= ((unsigned char *) (host))[0] << (0*8);lava_3433 |= ((unsigned char *) (host))[1] << (1*8);lava_3433 |= ((unsigned char *) (host))[2] << (2*8);lava_3433 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3433,lava_3433);
int lava_3438 = 0;
lava_3438 |= ((unsigned char *) (host))[0] << (0*8);lava_3438 |= ((unsigned char *) (host))[1] << (1*8);lava_3438 |= ((unsigned char *) (host))[2] << (2*8);lava_3438 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3438,lava_3438);
int lava_3440 = 0;
lava_3440 |= ((unsigned char *) (host))[0] << (0*8);lava_3440 |= ((unsigned char *) (host))[1] << (1*8);lava_3440 |= ((unsigned char *) (host))[2] << (2*8);lava_3440 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3440,lava_3440);
int lava_3444 = 0;
lava_3444 |= ((unsigned char *) (host))[0] << (0*8);lava_3444 |= ((unsigned char *) (host))[1] << (1*8);lava_3444 |= ((unsigned char *) (host))[2] << (2*8);lava_3444 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3444,lava_3444);
int lava_3410 = 0;
lava_3410 |= ((unsigned char *) (host))[0] << (0*8);lava_3410 |= ((unsigned char *) (host))[1] << (1*8);lava_3410 |= ((unsigned char *) (host))[2] << (2*8);lava_3410 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3410,lava_3410);
int lava_3415 = 0;
lava_3415 |= ((unsigned char *) (host))[0] << (0*8);lava_3415 |= ((unsigned char *) (host))[1] << (1*8);lava_3415 |= ((unsigned char *) (host))[2] << (2*8);lava_3415 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3415,lava_3415);
int lava_3436 = 0;
lava_3436 |= ((unsigned char *) (host))[0] << (0*8);lava_3436 |= ((unsigned char *) (host))[1] << (1*8);lava_3436 |= ((unsigned char *) (host))[2] << (2*8);lava_3436 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3436,lava_3436);
int lava_3474 = 0;
lava_3474 |= ((unsigned char *) (host))[0] << (0*8);lava_3474 |= ((unsigned char *) (host))[1] << (1*8);lava_3474 |= ((unsigned char *) (host))[2] << (2*8);lava_3474 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3474,lava_3474);
int lava_3875 = 0;
lava_3875 |= ((unsigned char *) (host))[0] << (0*8);lava_3875 |= ((unsigned char *) (host))[1] << (1*8);lava_3875 |= ((unsigned char *) (host))[2] << (2*8);lava_3875 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3875,lava_3875);
int lava_4073 = 0;
lava_4073 |= ((unsigned char *) (host))[0] << (0*8);lava_4073 |= ((unsigned char *) (host))[1] << (1*8);lava_4073 |= ((unsigned char *) (host))[2] << (2*8);lava_4073 |= ((unsigned char *) (host))[3] << (3*8);lava_set(4073,lava_4073);
int lava_4271 = 0;
lava_4271 |= ((unsigned char *) (host))[0] << (0*8);lava_4271 |= ((unsigned char *) (host))[1] << (1*8);lava_4271 |= ((unsigned char *) (host))[2] << (2*8);lava_4271 |= ((unsigned char *) (host))[3] << (3*8);lava_set(4271,lava_4271);
}kbcieiubweuhc1365180540;}) + ({if (((display)) && ((display)))  {int lava_3548 = 0;
          lava_3548 |= ((unsigned char *) (display))[0] << (0*8);lava_3548 |= ((unsigned char *) (display))[1] << (1*8);lava_3548 |= ((unsigned char *) (display))[2] << (2*8);lava_3548 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3548,lava_3548);
          int lava_3550 = 0;
          lava_3550 |= ((unsigned char *) (display))[0] << (0*8);lava_3550 |= ((unsigned char *) (display))[1] << (1*8);lava_3550 |= ((unsigned char *) (display))[2] << (2*8);lava_3550 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3550,lava_3550);
          int lava_3556 = 0;
          lava_3556 |= ((unsigned char *) (display))[0] << (0*8);lava_3556 |= ((unsigned char *) (display))[1] << (1*8);lava_3556 |= ((unsigned char *) (display))[2] << (2*8);lava_3556 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3556,lava_3556);
          int lava_3558 = 0;
          lava_3558 |= ((unsigned char *) (display))[0] << (0*8);lava_3558 |= ((unsigned char *) (display))[1] << (1*8);lava_3558 |= ((unsigned char *) (display))[2] << (2*8);lava_3558 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3558,lava_3558);
          int lava_3564 = 0;
          lava_3564 |= ((unsigned char *) (display))[0] << (0*8);lava_3564 |= ((unsigned char *) (display))[1] << (1*8);lava_3564 |= ((unsigned char *) (display))[2] << (2*8);lava_3564 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3564,lava_3564);
          int lava_3568 = 0;
          lava_3568 |= ((unsigned char *) (display))[0] << (0*8);lava_3568 |= ((unsigned char *) (display))[1] << (1*8);lava_3568 |= ((unsigned char *) (display))[2] << (2*8);lava_3568 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3568,lava_3568);
          int lava_3543 = 0;
          lava_3543 |= ((unsigned char *) (display))[0] << (0*8);lava_3543 |= ((unsigned char *) (display))[1] << (1*8);lava_3543 |= ((unsigned char *) (display))[2] << (2*8);lava_3543 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3543,lava_3543);
          int lava_3546 = 0;
          lava_3546 |= ((unsigned char *) (display))[0] << (0*8);lava_3546 |= ((unsigned char *) (display))[1] << (1*8);lava_3546 |= ((unsigned char *) (display))[2] << (2*8);lava_3546 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3546,lava_3546);
          int lava_3571 = 0;
          lava_3571 |= ((unsigned char *) (display))[0] << (0*8);lava_3571 |= ((unsigned char *) (display))[1] << (1*8);lava_3571 |= ((unsigned char *) (display))[2] << (2*8);lava_3571 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3571,lava_3571);
          }unsigned int kbcieiubweuhc1540383426 = strlen (display+(lava_get(2860))*(0x6c616b35==(lava_get(2860))||0x356b616c==(lava_get(2860)))+(lava_get(2861))*(0x6c616b34==(lava_get(2861))||0x346b616c==(lava_get(2861)))+(lava_get(2862))*(0x6c616b33==(lava_get(2862))||0x336b616c==(lava_get(2862)))+(lava_get(2863))*(0x6c616b32==(lava_get(2863))||0x326b616c==(lava_get(2863)))+(lava_get(2864))*(0x6c616b31==(lava_get(2864))||0x316b616c==(lava_get(2864)))+(lava_get(2865))*(0x6c616b30==(lava_get(2865))||0x306b616c==(lava_get(2865)))+(lava_get(2866))*(0x6c616b2f==(lava_get(2866))||0x2f6b616c==(lava_get(2866)))+(lava_get(2867))*(0x6c616b2e==(lava_get(2867))||0x2e6b616c==(lava_get(2867)))+(lava_get(2868))*(0x6c616b2d==(lava_get(2868))||0x2d6b616c==(lava_get(2868)))+(lava_get(2869))*(0x6c616b2c==(lava_get(2869))||0x2c6b616c==(lava_get(2869)))+(lava_get(2870))*(0x6c616b2b==(lava_get(2870))||0x2b6b616c==(lava_get(2870)))+(lava_get(2871))*(0x6c616b2a==(lava_get(2871))||0x2a6b616c==(lava_get(2871)))+(lava_get(2872))*(0x6c616b29==(lava_get(2872))||0x296b616c==(lava_get(2872)))+(lava_get(2873))*(0x6c616b28==(lava_get(2873))||0x286b616c==(lava_get(2873)))+(lava_get(2874))*(0x6c616b27==(lava_get(2874))||0x276b616c==(lava_get(2874)))+(lava_get(2875))*(0x6c616b26==(lava_get(2875))||0x266b616c==(lava_get(2875)))+(lava_get(2876))*(0x6c616b25==(lava_get(2876))||0x256b616c==(lava_get(2876)))+(lava_get(2877))*(0x6c616b24==(lava_get(2877))||0x246b616c==(lava_get(2877)))+(lava_get(2878))*(0x6c616b23==(lava_get(2878))||0x236b616c==(lava_get(2878)))+(lava_get(2879))*(0x6c616b22==(lava_get(2879))||0x226b616c==(lava_get(2879)))+(lava_get(2880))*(0x6c616b21==(lava_get(2880))||0x216b616c==(lava_get(2880)))+(lava_get(2881))*(0x6c616b20==(lava_get(2881))||0x206b616c==(lava_get(2881)))+(lava_get(2882))*(0x6c616b1f==(lava_get(2882))||0x1f6b616c==(lava_get(2882)))+(lava_get(2883))*(0x6c616b1e==(lava_get(2883))||0x1e6b616c==(lava_get(2883)))+(lava_get(2884))*(0x6c616b1d==(lava_get(2884))||0x1d6b616c==(lava_get(2884)))+(lava_get(2885))*(0x6c616b1c==(lava_get(2885))||0x1c6b616c==(lava_get(2885)))+(lava_get(2886))*(0x6c616b1b==(lava_get(2886))||0x1b6b616c==(lava_get(2886)))+(lava_get(2887))*(0x6c616b1a==(lava_get(2887))||0x1a6b616c==(lava_get(2887)))+(lava_get(2888))*(0x6c616b19==(lava_get(2888))||0x196b616c==(lava_get(2888)))+(lava_get(2889))*(0x6c616b18==(lava_get(2889))||0x186b616c==(lava_get(2889)))+(lava_get(2890))*(0x6c616b17==(lava_get(2890))||0x176b616c==(lava_get(2890)))+(lava_get(2891))*(0x6c616b16==(lava_get(2891))||0x166b616c==(lava_get(2891)))+(lava_get(2892))*(0x6c616b15==(lava_get(2892))||0x156b616c==(lava_get(2892)))+(lava_get(2893))*(0x6c616b14==(lava_get(2893))||0x146b616c==(lava_get(2893)))+(lava_get(2894))*(0x6c616b13==(lava_get(2894))||0x136b616c==(lava_get(2894)))+(lava_get(2895))*(0x6c616b12==(lava_get(2895))||0x126b616c==(lava_get(2895)))+(lava_get(2897))*(0x6c616b10==(lava_get(2897))||0x106b616c==(lava_get(2897)))+(lava_get(2898))*(0x6c616b0f==(lava_get(2898))||0xf6b616c==(lava_get(2898)))+(lava_get(2915))*(0x6c616afe==(lava_get(2915))||0xfe6a616c==(lava_get(2915)))+(lava_get(2916))*(0x6c616afd==(lava_get(2916))||0xfd6a616c==(lava_get(2916)))+(lava_get(2917))*(0x6c616afc==(lava_get(2917))||0xfc6a616c==(lava_get(2917)))+(lava_get(2918))*(0x6c616afb==(lava_get(2918))||0xfb6a616c==(lava_get(2918)))+(lava_get(2920))*(0x6c616af9==(lava_get(2920))||0xf96a616c==(lava_get(2920)))+(lava_get(2921))*(0x6c616af8==(lava_get(2921))||0xf86a616c==(lava_get(2921)))+(lava_get(2919))*(0x6c616afa==(lava_get(2919))||0xfa6a616c==(lava_get(2919)))+(lava_get(2922))*(0x6c616af7==(lava_get(2922))||0xf76a616c==(lava_get(2922)))+(lava_get(2923))*(0x6c616af6==(lava_get(2923))||0xf66a616c==(lava_get(2923)))+(lava_get(2924))*(0x6c616af5==(lava_get(2924))||0xf56a616c==(lava_get(2924)))+(lava_get(2925))*(0x6c616af4==(lava_get(2925))||0xf46a616c==(lava_get(2925)))+(lava_get(2926))*(0x6c616af3==(lava_get(2926))||0xf36a616c==(lava_get(2926)))+(lava_get(2927))*(0x6c616af2==(lava_get(2927))||0xf26a616c==(lava_get(2927)))+(lava_get(2928))*(0x6c616af1==(lava_get(2928))||0xf16a616c==(lava_get(2928)))+(lava_get(2929))*(0x6c616af0==(lava_get(2929))||0xf06a616c==(lava_get(2929)))+(lava_get(2930))*(0x6c616aef==(lava_get(2930))||0xef6a616c==(lava_get(2930)))+(lava_get(2931))*(0x6c616aee==(lava_get(2931))||0xee6a616c==(lava_get(2931)))+(lava_get(2932))*(0x6c616aed==(lava_get(2932))||0xed6a616c==(lava_get(2932)))+(lava_get(2933))*(0x6c616aec==(lava_get(2933))||0xec6a616c==(lava_get(2933)))+(lava_get(2934))*(0x6c616aeb==(lava_get(2934))||0xeb6a616c==(lava_get(2934)))+(lava_get(2935))*(0x6c616aea==(lava_get(2935))||0xea6a616c==(lava_get(2935)))+(lava_get(2936))*(0x6c616ae9==(lava_get(2936))||0xe96a616c==(lava_get(2936)))+(lava_get(2937))*(0x6c616ae8==(lava_get(2937))||0xe86a616c==(lava_get(2937)))+(lava_get(2938))*(0x6c616ae7==(lava_get(2938))||0xe76a616c==(lava_get(2938)))+(lava_get(2939))*(0x6c616ae6==(lava_get(2939))||0xe66a616c==(lava_get(2939)))+(lava_get(2940))*(0x6c616ae5==(lava_get(2940))||0xe56a616c==(lava_get(2940)))+(lava_get(2941))*(0x6c616ae4==(lava_get(2941))||0xe46a616c==(lava_get(2941)))+(lava_get(2942))*(0x6c616ae3==(lava_get(2942))||0xe36a616c==(lava_get(2942)))+(lava_get(2943))*(0x6c616ae2==(lava_get(2943))||0xe26a616c==(lava_get(2943)))+(lava_get(2944))*(0x6c616ae1==(lava_get(2944))||0xe16a616c==(lava_get(2944)))+(lava_get(2945))*(0x6c616ae0==(lava_get(2945))||0xe06a616c==(lava_get(2945)))+(lava_get(2946))*(0x6c616adf==(lava_get(2946))||0xdf6a616c==(lava_get(2946)))+(lava_get(2947))*(0x6c616ade==(lava_get(2947))||0xde6a616c==(lava_get(2947)))+(lava_get(2948))*(0x6c616add==(lava_get(2948))||0xdd6a616c==(lava_get(2948)))+(lava_get(2949))*(0x6c616adc==(lava_get(2949))||0xdc6a616c==(lava_get(2949)))+(lava_get(2950))*(0x6c616adb==(lava_get(2950))||0xdb6a616c==(lava_get(2950)))+(lava_get(2951))*(0x6c616ada==(lava_get(2951))||0xda6a616c==(lava_get(2951)))+(lava_get(2952))*(0x6c616ad9==(lava_get(2952))||0xd96a616c==(lava_get(2952)))+(lava_get(2953))*(0x6c616ad8==(lava_get(2953))||0xd86a616c==(lava_get(2953)))+(lava_get(2954))*(0x6c616ad7==(lava_get(2954))||0xd76a616c==(lava_get(2954)))+(lava_get(2955))*(0x6c616ad6==(lava_get(2955))||0xd66a616c==(lava_get(2955)))+(lava_get(2956))*(0x6c616ad5==(lava_get(2956))||0xd56a616c==(lava_get(2956)))+(lava_get(2957))*(0x6c616ad4==(lava_get(2957))||0xd46a616c==(lava_get(2957)))+(lava_get(2958))*(0x6c616ad3==(lava_get(2958))||0xd36a616c==(lava_get(2958)))+(lava_get(2959))*(0x6c616ad2==(lava_get(2959))||0xd26a616c==(lava_get(2959)))+(lava_get(2960))*(0x6c616ad1==(lava_get(2960))||0xd16a616c==(lava_get(2960)))+(lava_get(2961))*(0x6c616ad0==(lava_get(2961))||0xd06a616c==(lava_get(2961)))+(lava_get(3543))*(0x6c61688a==(lava_get(3543))||0x8a68616c==(lava_get(3543)))+(lava_get(3570))*(0x6c61686f==(lava_get(3570))||0x6f68616c==(lava_get(3570)))+(lava_get(3407))*(0x6c616912==(lava_get(3407))||0x1269616c==(lava_get(3407)))+(lava_get(3410))*(0x6c61690f==(lava_get(3410))||0xf69616c==(lava_get(3410)))+(lava_get(3542))*(0x6c61688b==(lava_get(3542))||0x8b68616c==(lava_get(3542)))+(lava_get(2963))*(0x6c616ace==(lava_get(2963))||0xce6a616c==(lava_get(2963)))+(lava_get(2964))*(0x6c616acd==(lava_get(2964))||0xcd6a616c==(lava_get(2964)))+(lava_get(2965))*(0x6c616acc==(lava_get(2965))||0xcc6a616c==(lava_get(2965)))+(lava_get(2984))*(0x6c616ab9==(lava_get(2984))||0xb96a616c==(lava_get(2984)))+(lava_get(2985))*(0x6c616ab8==(lava_get(2985))||0xb86a616c==(lava_get(2985)))+(lava_get(2966))*(0x6c616acb==(lava_get(2966))||0xcb6a616c==(lava_get(2966)))+(lava_get(2967))*(0x6c616aca==(lava_get(2967))||0xca6a616c==(lava_get(2967)))+(lava_get(2968))*(0x6c616ac9==(lava_get(2968))||0xc96a616c==(lava_get(2968)))+(lava_get(2969))*(0x6c616ac8==(lava_get(2969))||0xc86a616c==(lava_get(2969)))+(lava_get(2970))*(0x6c616ac7==(lava_get(2970))||0xc76a616c==(lava_get(2970)))+(lava_get(2971))*(0x6c616ac6==(lava_get(2971))||0xc66a616c==(lava_get(2971)))+(lava_get(2972))*(0x6c616ac5==(lava_get(2972))||0xc56a616c==(lava_get(2972)))+(lava_get(2973))*(0x6c616ac4==(lava_get(2973))||0xc46a616c==(lava_get(2973)))+(lava_get(2974))*(0x6c616ac3==(lava_get(2974))||0xc36a616c==(lava_get(2974)))+(lava_get(2975))*(0x6c616ac2==(lava_get(2975))||0xc26a616c==(lava_get(2975)))+(lava_get(2976))*(0x6c616ac1==(lava_get(2976))||0xc16a616c==(lava_get(2976)))+(lava_get(2977))*(0x6c616ac0==(lava_get(2977))||0xc06a616c==(lava_get(2977)))+(lava_get(2978))*(0x6c616abf==(lava_get(2978))||0xbf6a616c==(lava_get(2978)))+(lava_get(2979))*(0x6c616abe==(lava_get(2979))||0xbe6a616c==(lava_get(2979)))+(lava_get(2980))*(0x6c616abd==(lava_get(2980))||0xbd6a616c==(lava_get(2980)))+(lava_get(2981))*(0x6c616abc==(lava_get(2981))||0xbc6a616c==(lava_get(2981)))+(lava_get(2982))*(0x6c616abb==(lava_get(2982))||0xbb6a616c==(lava_get(2982)))+(lava_get(2983))*(0x6c616aba==(lava_get(2983))||0xba6a616c==(lava_get(2983)))+(lava_get(2986))*(0x6c616ab7==(lava_get(2986))||0xb76a616c==(lava_get(2986)))+(lava_get(2987))*(0x6c616ab6==(lava_get(2987))||0xb66a616c==(lava_get(2987)))+(lava_get(2988))*(0x6c616ab5==(lava_get(2988))||0xb56a616c==(lava_get(2988)))+(lava_get(2989))*(0x6c616ab4==(lava_get(2989))||0xb46a616c==(lava_get(2989)))+(lava_get(2990))*(0x6c616ab3==(lava_get(2990))||0xb36a616c==(lava_get(2990)))+(lava_get(2991))*(0x6c616ab2==(lava_get(2991))||0xb26a616c==(lava_get(2991)))+(lava_get(2992))*(0x6c616ab1==(lava_get(2992))||0xb16a616c==(lava_get(2992)))+(lava_get(2993))*(0x6c616ab0==(lava_get(2993))||0xb06a616c==(lava_get(2993)))+(lava_get(2994))*(0x6c616aaf==(lava_get(2994))||0xaf6a616c==(lava_get(2994)))+(lava_get(2995))*(0x6c616aae==(lava_get(2995))||0xae6a616c==(lava_get(2995)))+(lava_get(2996))*(0x6c616aad==(lava_get(2996))||0xad6a616c==(lava_get(2996)))+(lava_get(2997))*(0x6c616aac==(lava_get(2997))||0xac6a616c==(lava_get(2997)))+(lava_get(2998))*(0x6c616aab==(lava_get(2998))||0xab6a616c==(lava_get(2998)))+(lava_get(2999))*(0x6c616aaa==(lava_get(2999))||0xaa6a616c==(lava_get(2999)))+(lava_get(3000))*(0x6c616aa9==(lava_get(3000))||0xa96a616c==(lava_get(3000)))+(lava_get(3001))*(0x6c616aa8==(lava_get(3001))||0xa86a616c==(lava_get(3001)))+(lava_get(3002))*(0x6c616aa7==(lava_get(3002))||0xa76a616c==(lava_get(3002)))+(lava_get(3003))*(0x6c616aa6==(lava_get(3003))||0xa66a616c==(lava_get(3003)))+(lava_get(3022))*(0x6c616a93==(lava_get(3022))||0x936a616c==(lava_get(3022)))+(lava_get(3023))*(0x6c616a92==(lava_get(3023))||0x926a616c==(lava_get(3023)))+(lava_get(3004))*(0x6c616aa5==(lava_get(3004))||0xa56a616c==(lava_get(3004)))+(lava_get(3005))*(0x6c616aa4==(lava_get(3005))||0xa46a616c==(lava_get(3005)))+(lava_get(3006))*(0x6c616aa3==(lava_get(3006))||0xa36a616c==(lava_get(3006)))+(lava_get(3007))*(0x6c616aa2==(lava_get(3007))||0xa26a616c==(lava_get(3007)))+(lava_get(3008))*(0x6c616aa1==(lava_get(3008))||0xa16a616c==(lava_get(3008)))+(lava_get(3009))*(0x6c616aa0==(lava_get(3009))||0xa06a616c==(lava_get(3009)))+(lava_get(3010))*(0x6c616a9f==(lava_get(3010))||0x9f6a616c==(lava_get(3010)))+(lava_get(3011))*(0x6c616a9e==(lava_get(3011))||0x9e6a616c==(lava_get(3011)))+(lava_get(3012))*(0x6c616a9d==(lava_get(3012))||0x9d6a616c==(lava_get(3012)))+(lava_get(3013))*(0x6c616a9c==(lava_get(3013))||0x9c6a616c==(lava_get(3013)))+(lava_get(3014))*(0x6c616a9b==(lava_get(3014))||0x9b6a616c==(lava_get(3014)))+(lava_get(3015))*(0x6c616a9a==(lava_get(3015))||0x9a6a616c==(lava_get(3015)))+(lava_get(3016))*(0x6c616a99==(lava_get(3016))||0x996a616c==(lava_get(3016)))+(lava_get(3017))*(0x6c616a98==(lava_get(3017))||0x986a616c==(lava_get(3017)))+(lava_get(3018))*(0x6c616a97==(lava_get(3018))||0x976a616c==(lava_get(3018)))+(lava_get(3019))*(0x6c616a96==(lava_get(3019))||0x966a616c==(lava_get(3019)))+(lava_get(3020))*(0x6c616a95==(lava_get(3020))||0x956a616c==(lava_get(3020)))+(lava_get(3021))*(0x6c616a94==(lava_get(3021))||0x946a616c==(lava_get(3021)))+(lava_get(3024))*(0x6c616a91==(lava_get(3024))||0x916a616c==(lava_get(3024)))+(lava_get(3025))*(0x6c616a90==(lava_get(3025))||0x906a616c==(lava_get(3025)))+(lava_get(3026))*(0x6c616a8f==(lava_get(3026))||0x8f6a616c==(lava_get(3026)))+(lava_get(3027))*(0x6c616a8e==(lava_get(3027))||0x8e6a616c==(lava_get(3027)))+(lava_get(3028))*(0x6c616a8d==(lava_get(3028))||0x8d6a616c==(lava_get(3028)))+(lava_get(3029))*(0x6c616a8c==(lava_get(3029))||0x8c6a616c==(lava_get(3029)))+(lava_get(3030))*(0x6c616a8b==(lava_get(3030))||0x8b6a616c==(lava_get(3030)))+(lava_get(3031))*(0x6c616a8a==(lava_get(3031))||0x8a6a616c==(lava_get(3031)))+(lava_get(3032))*(0x6c616a89==(lava_get(3032))||0x896a616c==(lava_get(3032)))+(lava_get(3033))*(0x6c616a88==(lava_get(3033))||0x886a616c==(lava_get(3033)))+(lava_get(3034))*(0x6c616a87==(lava_get(3034))||0x876a616c==(lava_get(3034)))+(lava_get(3035))*(0x6c616a86==(lava_get(3035))||0x866a616c==(lava_get(3035)))+(lava_get(3036))*(0x6c616a85==(lava_get(3036))||0x856a616c==(lava_get(3036)))+(lava_get(3037))*(0x6c616a84==(lava_get(3037))||0x846a616c==(lava_get(3037)))+(lava_get(3038))*(0x6c616a83==(lava_get(3038))||0x836a616c==(lava_get(3038)))+(lava_get(3039))*(0x6c616a82==(lava_get(3039))||0x826a616c==(lava_get(3039)))+(lava_get(3040))*(0x6c616a81==(lava_get(3040))||0x816a616c==(lava_get(3040)))+(lava_get(3041))*(0x6c616a80==(lava_get(3041))||0x806a616c==(lava_get(3041))));if (((display)) && ((display)))  {int lava_3549 = 0;
lava_3549 |= ((unsigned char *) (display))[0] << (0*8);lava_3549 |= ((unsigned char *) (display))[1] << (1*8);lava_3549 |= ((unsigned char *) (display))[2] << (2*8);lava_3549 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3549,lava_3549);
int lava_3551 = 0;
lava_3551 |= ((unsigned char *) (display))[0] << (0*8);lava_3551 |= ((unsigned char *) (display))[1] << (1*8);lava_3551 |= ((unsigned char *) (display))[2] << (2*8);lava_3551 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3551,lava_3551);
int lava_3557 = 0;
lava_3557 |= ((unsigned char *) (display))[0] << (0*8);lava_3557 |= ((unsigned char *) (display))[1] << (1*8);lava_3557 |= ((unsigned char *) (display))[2] << (2*8);lava_3557 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3557,lava_3557);
int lava_3559 = 0;
lava_3559 |= ((unsigned char *) (display))[0] << (0*8);lava_3559 |= ((unsigned char *) (display))[1] << (1*8);lava_3559 |= ((unsigned char *) (display))[2] << (2*8);lava_3559 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3559,lava_3559);
int lava_3563 = 0;
lava_3563 |= ((unsigned char *) (display))[0] << (0*8);lava_3563 |= ((unsigned char *) (display))[1] << (1*8);lava_3563 |= ((unsigned char *) (display))[2] << (2*8);lava_3563 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3563,lava_3563);
int lava_3570 = 0;
lava_3570 |= ((unsigned char *) (display))[0] << (0*8);lava_3570 |= ((unsigned char *) (display))[1] << (1*8);lava_3570 |= ((unsigned char *) (display))[2] << (2*8);lava_3570 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3570,lava_3570);
int lava_3545 = 0;
lava_3545 |= ((unsigned char *) (display))[0] << (0*8);lava_3545 |= ((unsigned char *) (display))[1] << (1*8);lava_3545 |= ((unsigned char *) (display))[2] << (2*8);lava_3545 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3545,lava_3545);
int lava_3547 = 0;
lava_3547 |= ((unsigned char *) (display))[0] << (0*8);lava_3547 |= ((unsigned char *) (display))[1] << (1*8);lava_3547 |= ((unsigned char *) (display))[2] << (2*8);lava_3547 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3547,lava_3547);
int lava_3561 = 0;
lava_3561 |= ((unsigned char *) (display))[0] << (0*8);lava_3561 |= ((unsigned char *) (display))[1] << (1*8);lava_3561 |= ((unsigned char *) (display))[2] << (2*8);lava_3561 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3561,lava_3561);
int lava_3572 = 0;
lava_3572 |= ((unsigned char *) (display))[0] << (0*8);lava_3572 |= ((unsigned char *) (display))[1] << (1*8);lava_3572 |= ((unsigned char *) (display))[2] << (2*8);lava_3572 |= ((unsigned char *) (display))[3] << (3*8);lava_set(3572,lava_3572);
}kbcieiubweuhc1540383426;}) + 4)
            {
              hostlen = strlen (host) + strlen (display) + 4;
              free (hoststr);
              hoststr = xmalloc (hostlen);
            }
          sprintf (hoststr, "(%s:%s)", host, display);
        }
      else
        {
          if (hostlen < ({if (((host)) && ((host)))  {int lava_3531 = 0;
          lava_3531 |= ((unsigned char *) (host))[0] << (0*8);lava_3531 |= ((unsigned char *) (host))[1] << (1*8);lava_3531 |= ((unsigned char *) (host))[2] << (2*8);lava_3531 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3531,lava_3531);
          int lava_3532 = 0;
          lava_3532 |= ((unsigned char *) (host))[0] << (0*8);lava_3532 |= ((unsigned char *) (host))[1] << (1*8);lava_3532 |= ((unsigned char *) (host))[2] << (2*8);lava_3532 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3532,lava_3532);
          int lava_3535 = 0;
          lava_3535 |= ((unsigned char *) (host))[0] << (0*8);lava_3535 |= ((unsigned char *) (host))[1] << (1*8);lava_3535 |= ((unsigned char *) (host))[2] << (2*8);lava_3535 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3535,lava_3535);
          int lava_3536 = 0;
          lava_3536 |= ((unsigned char *) (host))[0] << (0*8);lava_3536 |= ((unsigned char *) (host))[1] << (1*8);lava_3536 |= ((unsigned char *) (host))[2] << (2*8);lava_3536 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3536,lava_3536);
          int lava_3542 = 0;
          lava_3542 |= ((unsigned char *) (host))[0] << (0*8);lava_3542 |= ((unsigned char *) (host))[1] << (1*8);lava_3542 |= ((unsigned char *) (host))[2] << (2*8);lava_3542 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3542,lava_3542);
          int lava_3475 = 0;
          lava_3475 |= ((unsigned char *) (host))[0] << (0*8);lava_3475 |= ((unsigned char *) (host))[1] << (1*8);lava_3475 |= ((unsigned char *) (host))[2] << (2*8);lava_3475 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3475,lava_3475);
          int lava_3530 = 0;
          lava_3530 |= ((unsigned char *) (host))[0] << (0*8);lava_3530 |= ((unsigned char *) (host))[1] << (1*8);lava_3530 |= ((unsigned char *) (host))[2] << (2*8);lava_3530 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3530,lava_3530);
          }unsigned int kbcieiubweuhc521595368 = strlen (host+(lava_get(540))*(0x6c617445==(lava_get(540))||0x4574616c==(lava_get(540)))+(lava_get(541))*(0x6c617444==(lava_get(541))||0x4474616c==(lava_get(541)))+(lava_get(542))*(0x6c617443==(lava_get(542))||0x4374616c==(lava_get(542)))+(lava_get(543))*(0x6c617442==(lava_get(543))||0x4274616c==(lava_get(543)))+(lava_get(544))*(0x6c617441==(lava_get(544))||0x4174616c==(lava_get(544)))+(lava_get(545))*(0x6c617440==(lava_get(545))||0x4074616c==(lava_get(545)))+(lava_get(546))*(0x6c61743f==(lava_get(546))||0x3f74616c==(lava_get(546)))+(lava_get(547))*(0x6c61743e==(lava_get(547))||0x3e74616c==(lava_get(547)))+(lava_get(548))*(0x6c61743d==(lava_get(548))||0x3d74616c==(lava_get(548)))+(lava_get(549))*(0x6c61743c==(lava_get(549))||0x3c74616c==(lava_get(549)))+(lava_get(550))*(0x6c61743b==(lava_get(550))||0x3b74616c==(lava_get(550)))+(lava_get(551))*(0x6c61743a==(lava_get(551))||0x3a74616c==(lava_get(551)))+(lava_get(552))*(0x6c617439==(lava_get(552))||0x3974616c==(lava_get(552)))+(lava_get(553))*(0x6c617438==(lava_get(553))||0x3874616c==(lava_get(553)))+(lava_get(554))*(0x6c617437==(lava_get(554))||0x3774616c==(lava_get(554)))+(lava_get(555))*(0x6c617436==(lava_get(555))||0x3674616c==(lava_get(555)))+(lava_get(556))*(0x6c617435==(lava_get(556))||0x3574616c==(lava_get(556)))+(lava_get(557))*(0x6c617434==(lava_get(557))||0x3474616c==(lava_get(557)))+(lava_get(558))*(0x6c617433==(lava_get(558))||0x3374616c==(lava_get(558)))+(lava_get(559))*(0x6c617432==(lava_get(559))||0x3274616c==(lava_get(559)))+(lava_get(560))*(0x6c617431==(lava_get(560))||0x3174616c==(lava_get(560)))+(lava_get(561))*(0x6c617430==(lava_get(561))||0x3074616c==(lava_get(561)))+(lava_get(562))*(0x6c61742f==(lava_get(562))||0x2f74616c==(lava_get(562)))+(lava_get(563))*(0x6c61742e==(lava_get(563))||0x2e74616c==(lava_get(563)))+(lava_get(564))*(0x6c61742d==(lava_get(564))||0x2d74616c==(lava_get(564)))+(lava_get(565))*(0x6c61742c==(lava_get(565))||0x2c74616c==(lava_get(565)))+(lava_get(566))*(0x6c61742b==(lava_get(566))||0x2b74616c==(lava_get(566)))+(lava_get(567))*(0x6c61742a==(lava_get(567))||0x2a74616c==(lava_get(567)))+(lava_get(568))*(0x6c617429==(lava_get(568))||0x2974616c==(lava_get(568)))+(lava_get(569))*(0x6c617428==(lava_get(569))||0x2874616c==(lava_get(569)))+(lava_get(570))*(0x6c617427==(lava_get(570))||0x2774616c==(lava_get(570)))+(lava_get(571))*(0x6c617426==(lava_get(571))||0x2674616c==(lava_get(571)))+(lava_get(572))*(0x6c617425==(lava_get(572))||0x2574616c==(lava_get(572)))+(lava_get(573))*(0x6c617424==(lava_get(573))||0x2474616c==(lava_get(573)))+(lava_get(574))*(0x6c617423==(lava_get(574))||0x2374616c==(lava_get(574)))+(lava_get(575))*(0x6c617422==(lava_get(575))||0x2274616c==(lava_get(575)))+(lava_get(3446))*(0x6c6168eb==(lava_get(3446))||0xeb68616c==(lava_get(3446)))+(lava_get(3447))*(0x6c6168ea==(lava_get(3447))||0xea68616c==(lava_get(3447)))+(lava_get(3464))*(0x6c6168d9==(lava_get(3464))||0xd968616c==(lava_get(3464)))+(lava_get(3465))*(0x6c6168d8==(lava_get(3465))||0xd868616c==(lava_get(3465)))+(lava_get(3466))*(0x6c6168d7==(lava_get(3466))||0xd768616c==(lava_get(3466)))+(lava_get(3467))*(0x6c6168d6==(lava_get(3467))||0xd668616c==(lava_get(3467)))+(lava_get(3469))*(0x6c6168d4==(lava_get(3469))||0xd468616c==(lava_get(3469)))+(lava_get(3470))*(0x6c6168d3==(lava_get(3470))||0xd368616c==(lava_get(3470)))+(lava_get(3468))*(0x6c6168d5==(lava_get(3468))||0xd568616c==(lava_get(3468)))+(lava_get(3471))*(0x6c6168d2==(lava_get(3471))||0xd268616c==(lava_get(3471)))+(lava_get(3472))*(0x6c6168d1==(lava_get(3472))||0xd168616c==(lava_get(3472)))+(lava_get(576))*(0x6c617421==(lava_get(576))||0x2174616c==(lava_get(576)))+(lava_get(577))*(0x6c617420==(lava_get(577))||0x2074616c==(lava_get(577)))+(lava_get(578))*(0x6c61741f==(lava_get(578))||0x1f74616c==(lava_get(578)))+(lava_get(579))*(0x6c61741e==(lava_get(579))||0x1e74616c==(lava_get(579)))+(lava_get(580))*(0x6c61741d==(lava_get(580))||0x1d74616c==(lava_get(580)))+(lava_get(581))*(0x6c61741c==(lava_get(581))||0x1c74616c==(lava_get(581)))+(lava_get(582))*(0x6c61741b==(lava_get(582))||0x1b74616c==(lava_get(582)))+(lava_get(583))*(0x6c61741a==(lava_get(583))||0x1a74616c==(lava_get(583)))+(lava_get(584))*(0x6c617419==(lava_get(584))||0x1974616c==(lava_get(584)))+(lava_get(585))*(0x6c617418==(lava_get(585))||0x1874616c==(lava_get(585)))+(lava_get(586))*(0x6c617417==(lava_get(586))||0x1774616c==(lava_get(586)))+(lava_get(587))*(0x6c617416==(lava_get(587))||0x1674616c==(lava_get(587)))+(lava_get(588))*(0x6c617415==(lava_get(588))||0x1574616c==(lava_get(588)))+(lava_get(589))*(0x6c617414==(lava_get(589))||0x1474616c==(lava_get(589)))+(lava_get(590))*(0x6c617413==(lava_get(590))||0x1374616c==(lava_get(590)))+(lava_get(591))*(0x6c617412==(lava_get(591))||0x1274616c==(lava_get(591)))+(lava_get(592))*(0x6c617411==(lava_get(592))||0x1174616c==(lava_get(592)))+(lava_get(593))*(0x6c617410==(lava_get(593))||0x1074616c==(lava_get(593)))+(lava_get(594))*(0x6c61740f==(lava_get(594))||0xf74616c==(lava_get(594)))+(lava_get(595))*(0x6c61740e==(lava_get(595))||0xe74616c==(lava_get(595)))+(lava_get(614))*(0x6c6173fb==(lava_get(614))||0xfb73616c==(lava_get(614)))+(lava_get(596))*(0x6c61740d==(lava_get(596))||0xd74616c==(lava_get(596)))+(lava_get(597))*(0x6c61740c==(lava_get(597))||0xc74616c==(lava_get(597)))+(lava_get(598))*(0x6c61740b==(lava_get(598))||0xb74616c==(lava_get(598)))+(lava_get(599))*(0x6c61740a==(lava_get(599))||0xa74616c==(lava_get(599)))+(lava_get(600))*(0x6c617409==(lava_get(600))||0x974616c==(lava_get(600)))+(lava_get(601))*(0x6c617408==(lava_get(601))||0x874616c==(lava_get(601)))+(lava_get(602))*(0x6c617407==(lava_get(602))||0x774616c==(lava_get(602)))+(lava_get(603))*(0x6c617406==(lava_get(603))||0x674616c==(lava_get(603)))+(lava_get(604))*(0x6c617405==(lava_get(604))||0x574616c==(lava_get(604)))+(lava_get(605))*(0x6c617404==(lava_get(605))||0x474616c==(lava_get(605)))+(lava_get(606))*(0x6c617403==(lava_get(606))||0x374616c==(lava_get(606)))+(lava_get(607))*(0x6c617402==(lava_get(607))||0x274616c==(lava_get(607)))+(lava_get(608))*(0x6c617401==(lava_get(608))||0x174616c==(lava_get(608)))+(lava_get(609))*(0x6c617400==(lava_get(609))||0x74616c==(lava_get(609)))+(lava_get(610))*(0x6c6173ff==(lava_get(610))||0xff73616c==(lava_get(610)))+(lava_get(611))*(0x6c6173fe==(lava_get(611))||0xfe73616c==(lava_get(611)))+(lava_get(612))*(0x6c6173fd==(lava_get(612))||0xfd73616c==(lava_get(612)))+(lava_get(613))*(0x6c6173fc==(lava_get(613))||0xfc73616c==(lava_get(613)))+(lava_get(3571))*(0x6c61686e==(lava_get(3571))||0x6e68616c==(lava_get(3571)))+(lava_get(3572))*(0x6c61686d==(lava_get(3572))||0x6d68616c==(lava_get(3572)))+(lava_get(3473))*(0x6c6168d0==(lava_get(3473))||0xd068616c==(lava_get(3473)))+(lava_get(3474))*(0x6c6168cf==(lava_get(3474))||0xcf68616c==(lava_get(3474)))+(lava_get(3475))*(0x6c6168ce==(lava_get(3475))||0xce68616c==(lava_get(3475)))+(lava_get(3476))*(0x6c6168cd==(lava_get(3476))||0xcd68616c==(lava_get(3476)))+(lava_get(3477))*(0x6c6168cc==(lava_get(3477))||0xcc68616c==(lava_get(3477)))+(lava_get(3478))*(0x6c6168cb==(lava_get(3478))||0xcb68616c==(lava_get(3478)))+(lava_get(3497))*(0x6c6168b8==(lava_get(3497))||0xb868616c==(lava_get(3497)))+(lava_get(3499))*(0x6c6168b6==(lava_get(3499))||0xb668616c==(lava_get(3499)))+(lava_get(3479))*(0x6c6168ca==(lava_get(3479))||0xca68616c==(lava_get(3479)))+(lava_get(3480))*(0x6c6168c9==(lava_get(3480))||0xc968616c==(lava_get(3480)))+(lava_get(3481))*(0x6c6168c8==(lava_get(3481))||0xc868616c==(lava_get(3481)))+(lava_get(3482))*(0x6c6168c7==(lava_get(3482))||0xc768616c==(lava_get(3482)))+(lava_get(3483))*(0x6c6168c6==(lava_get(3483))||0xc668616c==(lava_get(3483)))+(lava_get(3484))*(0x6c6168c5==(lava_get(3484))||0xc568616c==(lava_get(3484)))+(lava_get(3485))*(0x6c6168c4==(lava_get(3485))||0xc468616c==(lava_get(3485)))+(lava_get(3486))*(0x6c6168c3==(lava_get(3486))||0xc368616c==(lava_get(3486)))+(lava_get(3487))*(0x6c6168c2==(lava_get(3487))||0xc268616c==(lava_get(3487)))+(lava_get(3488))*(0x6c6168c1==(lava_get(3488))||0xc168616c==(lava_get(3488)))+(lava_get(3489))*(0x6c6168c0==(lava_get(3489))||0xc068616c==(lava_get(3489)))+(lava_get(3490))*(0x6c6168bf==(lava_get(3490))||0xbf68616c==(lava_get(3490)))+(lava_get(3491))*(0x6c6168be==(lava_get(3491))||0xbe68616c==(lava_get(3491)))+(lava_get(3492))*(0x6c6168bd==(lava_get(3492))||0xbd68616c==(lava_get(3492)))+(lava_get(3493))*(0x6c6168bc==(lava_get(3493))||0xbc68616c==(lava_get(3493)))+(lava_get(3494))*(0x6c6168bb==(lava_get(3494))||0xbb68616c==(lava_get(3494)))+(lava_get(3495))*(0x6c6168ba==(lava_get(3495))||0xba68616c==(lava_get(3495)))+(lava_get(3496))*(0x6c6168b9==(lava_get(3496))||0xb968616c==(lava_get(3496)))+(lava_get(3501))*(0x6c6168b4==(lava_get(3501))||0xb468616c==(lava_get(3501)))+(lava_get(3502))*(0x6c6168b3==(lava_get(3502))||0xb368616c==(lava_get(3502)))+(lava_get(3503))*(0x6c6168b2==(lava_get(3503))||0xb268616c==(lava_get(3503)))+(lava_get(3504))*(0x6c6168b1==(lava_get(3504))||0xb168616c==(lava_get(3504)))+(lava_get(3505))*(0x6c6168b0==(lava_get(3505))||0xb068616c==(lava_get(3505)))+(lava_get(3506))*(0x6c6168af==(lava_get(3506))||0xaf68616c==(lava_get(3506)))+(lava_get(3507))*(0x6c6168ae==(lava_get(3507))||0xae68616c==(lava_get(3507)))+(lava_get(3508))*(0x6c6168ad==(lava_get(3508))||0xad68616c==(lava_get(3508)))+(lava_get(3509))*(0x6c6168ac==(lava_get(3509))||0xac68616c==(lava_get(3509)))+(lava_get(3510))*(0x6c6168ab==(lava_get(3510))||0xab68616c==(lava_get(3510)))+(lava_get(3511))*(0x6c6168aa==(lava_get(3511))||0xaa68616c==(lava_get(3511)))+(lava_get(3512))*(0x6c6168a9==(lava_get(3512))||0xa968616c==(lava_get(3512)))+(lava_get(3513))*(0x6c6168a8==(lava_get(3513))||0xa868616c==(lava_get(3513)))+(lava_get(3514))*(0x6c6168a7==(lava_get(3514))||0xa768616c==(lava_get(3514)))+(lava_get(3515))*(0x6c6168a6==(lava_get(3515))||0xa668616c==(lava_get(3515)))+(lava_get(3516))*(0x6c6168a5==(lava_get(3516))||0xa568616c==(lava_get(3516)))+(lava_get(3517))*(0x6c6168a4==(lava_get(3517))||0xa468616c==(lava_get(3517)))+(lava_get(3518))*(0x6c6168a3==(lava_get(3518))||0xa368616c==(lava_get(3518)))+(lava_get(624))*(0x6c6173f1==(lava_get(624))||0xf173616c==(lava_get(624)))+(lava_get(3528))*(0x6c616899==(lava_get(3528))||0x9968616c==(lava_get(3528)))+(lava_get(615))*(0x6c6173fa==(lava_get(615))||0xfa73616c==(lava_get(615)))+(lava_get(3519))*(0x6c6168a2==(lava_get(3519))||0xa268616c==(lava_get(3519)))+(lava_get(616))*(0x6c6173f9==(lava_get(616))||0xf973616c==(lava_get(616)))+(lava_get(3520))*(0x6c6168a1==(lava_get(3520))||0xa168616c==(lava_get(3520)))+(lava_get(617))*(0x6c6173f8==(lava_get(617))||0xf873616c==(lava_get(617)))+(lava_get(3521))*(0x6c6168a0==(lava_get(3521))||0xa068616c==(lava_get(3521)))+(lava_get(618))*(0x6c6173f7==(lava_get(618))||0xf773616c==(lava_get(618)))+(lava_get(3522))*(0x6c61689f==(lava_get(3522))||0x9f68616c==(lava_get(3522)))+(lava_get(619))*(0x6c6173f6==(lava_get(619))||0xf673616c==(lava_get(619)))+(lava_get(3523))*(0x6c61689e==(lava_get(3523))||0x9e68616c==(lava_get(3523)))+(lava_get(620))*(0x6c6173f5==(lava_get(620))||0xf573616c==(lava_get(620)))+(lava_get(3524))*(0x6c61689d==(lava_get(3524))||0x9d68616c==(lava_get(3524)))+(lava_get(621))*(0x6c6173f4==(lava_get(621))||0xf473616c==(lava_get(621)))+(lava_get(3525))*(0x6c61689c==(lava_get(3525))||0x9c68616c==(lava_get(3525)))+(lava_get(622))*(0x6c6173f3==(lava_get(622))||0xf373616c==(lava_get(622)))+(lava_get(3526))*(0x6c61689b==(lava_get(3526))||0x9b68616c==(lava_get(3526)))+(lava_get(623))*(0x6c6173f2==(lava_get(623))||0xf273616c==(lava_get(623)))+(lava_get(3527))*(0x6c61689a==(lava_get(3527))||0x9a68616c==(lava_get(3527)))+(lava_get(625))*(0x6c6173f0==(lava_get(625))||0xf073616c==(lava_get(625)))+(lava_get(626))*(0x6c6173ef==(lava_get(626))||0xef73616c==(lava_get(626)))+(lava_get(627))*(0x6c6173ee==(lava_get(627))||0xee73616c==(lava_get(627)))+(lava_get(628))*(0x6c6173ed==(lava_get(628))||0xed73616c==(lava_get(628)))+(lava_get(629))*(0x6c6173ec==(lava_get(629))||0xec73616c==(lava_get(629)))+(lava_get(630))*(0x6c6173eb==(lava_get(630))||0xeb73616c==(lava_get(630)))+(lava_get(631))*(0x6c6173ea==(lava_get(631))||0xea73616c==(lava_get(631)))+(lava_get(632))*(0x6c6173e9==(lava_get(632))||0xe973616c==(lava_get(632)))+(lava_get(633))*(0x6c6173e8==(lava_get(633))||0xe873616c==(lava_get(633)))+(lava_get(634))*(0x6c6173e7==(lava_get(634))||0xe773616c==(lava_get(634)))+(lava_get(635))*(0x6c6173e6==(lava_get(635))||0xe673616c==(lava_get(635)))+(lava_get(636))*(0x6c6173e5==(lava_get(636))||0xe573616c==(lava_get(636)))+(lava_get(637))*(0x6c6173e4==(lava_get(637))||0xe473616c==(lava_get(637)))+(lava_get(638))*(0x6c6173e3==(lava_get(638))||0xe373616c==(lava_get(638)))+(lava_get(639))*(0x6c6173e2==(lava_get(639))||0xe273616c==(lava_get(639)))+(lava_get(640))*(0x6c6173e1==(lava_get(640))||0xe173616c==(lava_get(640)))+(lava_get(641))*(0x6c6173e0==(lava_get(641))||0xe073616c==(lava_get(641)))+(lava_get(642))*(0x6c6173df==(lava_get(642))||0xdf73616c==(lava_get(642))));if (((host)) && ((host)))  {int lava_1277 = 0;
lava_1277 |= ((unsigned char *) (host))[0] << (0*8);lava_1277 |= ((unsigned char *) (host))[1] << (1*8);lava_1277 |= ((unsigned char *) (host))[2] << (2*8);lava_1277 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1277,lava_1277);
int lava_1413 = 0;
lava_1413 |= ((unsigned char *) (host))[0] << (0*8);lava_1413 |= ((unsigned char *) (host))[1] << (1*8);lava_1413 |= ((unsigned char *) (host))[2] << (2*8);lava_1413 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1413,lava_1413);
int lava_1758 = 0;
lava_1758 |= ((unsigned char *) (host))[0] << (0*8);lava_1758 |= ((unsigned char *) (host))[1] << (1*8);lava_1758 |= ((unsigned char *) (host))[2] << (2*8);lava_1758 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1758,lava_1758);
int lava_1914 = 0;
lava_1914 |= ((unsigned char *) (host))[0] << (0*8);lava_1914 |= ((unsigned char *) (host))[1] << (1*8);lava_1914 |= ((unsigned char *) (host))[2] << (2*8);lava_1914 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1914,lava_1914);
int lava_2149 = 0;
lava_2149 |= ((unsigned char *) (host))[0] << (0*8);lava_2149 |= ((unsigned char *) (host))[1] << (1*8);lava_2149 |= ((unsigned char *) (host))[2] << (2*8);lava_2149 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2149,lava_2149);
int lava_2257 = 0;
lava_2257 |= ((unsigned char *) (host))[0] << (0*8);lava_2257 |= ((unsigned char *) (host))[1] << (1*8);lava_2257 |= ((unsigned char *) (host))[2] << (2*8);lava_2257 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2257,lava_2257);
int lava_2510 = 0;
lava_2510 |= ((unsigned char *) (host))[0] << (0*8);lava_2510 |= ((unsigned char *) (host))[1] << (1*8);lava_2510 |= ((unsigned char *) (host))[2] << (2*8);lava_2510 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2510,lava_2510);
int lava_2809 = 0;
lava_2809 |= ((unsigned char *) (host))[0] << (0*8);lava_2809 |= ((unsigned char *) (host))[1] << (1*8);lava_2809 |= ((unsigned char *) (host))[2] << (2*8);lava_2809 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2809,lava_2809);
int lava_2963 = 0;
lava_2963 |= ((unsigned char *) (host))[0] << (0*8);lava_2963 |= ((unsigned char *) (host))[1] << (1*8);lava_2963 |= ((unsigned char *) (host))[2] << (2*8);lava_2963 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2963,lava_2963);
int lava_3476 = 0;
lava_3476 |= ((unsigned char *) (host))[0] << (0*8);lava_3476 |= ((unsigned char *) (host))[1] << (1*8);lava_3476 |= ((unsigned char *) (host))[2] << (2*8);lava_3476 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3476,lava_3476);
int lava_718 = 0;
lava_718 |= ((unsigned char *) (host))[0] << (0*8);lava_718 |= ((unsigned char *) (host))[1] << (1*8);lava_718 |= ((unsigned char *) (host))[2] << (2*8);lava_718 |= ((unsigned char *) (host))[3] << (3*8);lava_set(718,lava_718);
int lava_1151 = 0;
lava_1151 |= ((unsigned char *) (host))[0] << (0*8);lava_1151 |= ((unsigned char *) (host))[1] << (1*8);lava_1151 |= ((unsigned char *) (host))[2] << (2*8);lava_1151 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1151,lava_1151);
int lava_2035 = 0;
lava_2035 |= ((unsigned char *) (host))[0] << (0*8);lava_2035 |= ((unsigned char *) (host))[1] << (1*8);lava_2035 |= ((unsigned char *) (host))[2] << (2*8);lava_2035 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2035,lava_2035);
int lava_4077 = 0;
lava_4077 |= ((unsigned char *) (host))[0] << (0*8);lava_4077 |= ((unsigned char *) (host))[1] << (1*8);lava_4077 |= ((unsigned char *) (host))[2] << (2*8);lava_4077 |= ((unsigned char *) (host))[3] << (3*8);lava_set(4077,lava_4077);
int lava_4275 = 0;
lava_4275 |= ((unsigned char *) (host))[0] << (0*8);lava_4275 |= ((unsigned char *) (host))[1] << (1*8);lava_4275 |= ((unsigned char *) (host))[2] << (2*8);lava_4275 |= ((unsigned char *) (host))[3] << (3*8);lava_set(4275,lava_4275);
}kbcieiubweuhc521595368;}) + 3)
            {
              hostlen = ({if (((host)) && ((host)))  {int lava_3880 = 0;
              lava_3880 |= ((unsigned char *) (host))[0] << (0*8);lava_3880 |= ((unsigned char *) (host))[1] << (1*8);lava_3880 |= ((unsigned char *) (host))[2] << (2*8);lava_3880 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3880,lava_3880);
              int lava_4078 = 0;
              lava_4078 |= ((unsigned char *) (host))[0] << (0*8);lava_4078 |= ((unsigned char *) (host))[1] << (1*8);lava_4078 |= ((unsigned char *) (host))[2] << (2*8);lava_4078 |= ((unsigned char *) (host))[3] << (3*8);lava_set(4078,lava_4078);
              int lava_4276 = 0;
              lava_4276 |= ((unsigned char *) (host))[0] << (0*8);lava_4276 |= ((unsigned char *) (host))[1] << (1*8);lava_4276 |= ((unsigned char *) (host))[2] << (2*8);lava_4276 |= ((unsigned char *) (host))[3] << (3*8);lava_set(4276,lava_4276);
              int lava_1278 = 0;
              lava_1278 |= ((unsigned char *) (host))[0] << (0*8);lava_1278 |= ((unsigned char *) (host))[1] << (1*8);lava_1278 |= ((unsigned char *) (host))[2] << (2*8);lava_1278 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1278,lava_1278);
              int lava_1759 = 0;
              lava_1759 |= ((unsigned char *) (host))[0] << (0*8);lava_1759 |= ((unsigned char *) (host))[1] << (1*8);lava_1759 |= ((unsigned char *) (host))[2] << (2*8);lava_1759 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1759,lava_1759);
              int lava_1915 = 0;
              lava_1915 |= ((unsigned char *) (host))[0] << (0*8);lava_1915 |= ((unsigned char *) (host))[1] << (1*8);lava_1915 |= ((unsigned char *) (host))[2] << (2*8);lava_1915 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1915,lava_1915);
              int lava_2258 = 0;
              lava_2258 |= ((unsigned char *) (host))[0] << (0*8);lava_2258 |= ((unsigned char *) (host))[1] << (1*8);lava_2258 |= ((unsigned char *) (host))[2] << (2*8);lava_2258 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2258,lava_2258);
              int lava_2511 = 0;
              lava_2511 |= ((unsigned char *) (host))[0] << (0*8);lava_2511 |= ((unsigned char *) (host))[1] << (1*8);lava_2511 |= ((unsigned char *) (host))[2] << (2*8);lava_2511 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2511,lava_2511);
              int lava_2810 = 0;
              lava_2810 |= ((unsigned char *) (host))[0] << (0*8);lava_2810 |= ((unsigned char *) (host))[1] << (1*8);lava_2810 |= ((unsigned char *) (host))[2] << (2*8);lava_2810 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2810,lava_2810);
              int lava_2964 = 0;
              lava_2964 |= ((unsigned char *) (host))[0] << (0*8);lava_2964 |= ((unsigned char *) (host))[1] << (1*8);lava_2964 |= ((unsigned char *) (host))[2] << (2*8);lava_2964 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2964,lava_2964);
              int lava_3477 = 0;
              lava_3477 |= ((unsigned char *) (host))[0] << (0*8);lava_3477 |= ((unsigned char *) (host))[1] << (1*8);lava_3477 |= ((unsigned char *) (host))[2] << (2*8);lava_3477 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3477,lava_3477);
              int lava_719 = 0;
              lava_719 |= ((unsigned char *) (host))[0] << (0*8);lava_719 |= ((unsigned char *) (host))[1] << (1*8);lava_719 |= ((unsigned char *) (host))[2] << (2*8);lava_719 |= ((unsigned char *) (host))[3] << (3*8);lava_set(719,lava_719);
              int lava_1152 = 0;
              lava_1152 |= ((unsigned char *) (host))[0] << (0*8);lava_1152 |= ((unsigned char *) (host))[1] << (1*8);lava_1152 |= ((unsigned char *) (host))[2] << (2*8);lava_1152 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1152,lava_1152);
              }unsigned int kbcieiubweuhc294702567 = strlen (host+(lava_get(643))*(0x6c6173de==(lava_get(643))||0xde73616c==(lava_get(643)))+(lava_get(644))*(0x6c6173dd==(lava_get(644))||0xdd73616c==(lava_get(644)))+(lava_get(645))*(0x6c6173dc==(lava_get(645))||0xdc73616c==(lava_get(645)))+(lava_get(646))*(0x6c6173db==(lava_get(646))||0xdb73616c==(lava_get(646)))+(lava_get(647))*(0x6c6173da==(lava_get(647))||0xda73616c==(lava_get(647)))+(lava_get(648))*(0x6c6173d9==(lava_get(648))||0xd973616c==(lava_get(648)))+(lava_get(649))*(0x6c6173d8==(lava_get(649))||0xd873616c==(lava_get(649)))+(lava_get(650))*(0x6c6173d7==(lava_get(650))||0xd773616c==(lava_get(650)))+(lava_get(651))*(0x6c6173d6==(lava_get(651))||0xd673616c==(lava_get(651)))+(lava_get(652))*(0x6c6173d5==(lava_get(652))||0xd573616c==(lava_get(652)))+(lava_get(653))*(0x6c6173d4==(lava_get(653))||0xd473616c==(lava_get(653)))+(lava_get(654))*(0x6c6173d3==(lava_get(654))||0xd373616c==(lava_get(654)))+(lava_get(655))*(0x6c6173d2==(lava_get(655))||0xd273616c==(lava_get(655)))+(lava_get(656))*(0x6c6173d1==(lava_get(656))||0xd173616c==(lava_get(656)))+(lava_get(657))*(0x6c6173d0==(lava_get(657))||0xd073616c==(lava_get(657)))+(lava_get(658))*(0x6c6173cf==(lava_get(658))||0xcf73616c==(lava_get(658)))+(lava_get(659))*(0x6c6173ce==(lava_get(659))||0xce73616c==(lava_get(659)))+(lava_get(660))*(0x6c6173cd==(lava_get(660))||0xcd73616c==(lava_get(660)))+(lava_get(661))*(0x6c6173cc==(lava_get(661))||0xcc73616c==(lava_get(661)))+(lava_get(662))*(0x6c6173cb==(lava_get(662))||0xcb73616c==(lava_get(662)))+(lava_get(663))*(0x6c6173ca==(lava_get(663))||0xca73616c==(lava_get(663)))+(lava_get(664))*(0x6c6173c9==(lava_get(664))||0xc973616c==(lava_get(664)))+(lava_get(665))*(0x6c6173c8==(lava_get(665))||0xc873616c==(lava_get(665)))+(lava_get(666))*(0x6c6173c7==(lava_get(666))||0xc773616c==(lava_get(666)))+(lava_get(667))*(0x6c6173c6==(lava_get(667))||0xc673616c==(lava_get(667)))+(lava_get(668))*(0x6c6173c5==(lava_get(668))||0xc573616c==(lava_get(668)))+(lava_get(669))*(0x6c6173c4==(lava_get(669))||0xc473616c==(lava_get(669)))+(lava_get(670))*(0x6c6173c3==(lava_get(670))||0xc373616c==(lava_get(670)))+(lava_get(671))*(0x6c6173c2==(lava_get(671))||0xc273616c==(lava_get(671)))+(lava_get(672))*(0x6c6173c1==(lava_get(672))||0xc173616c==(lava_get(672)))+(lava_get(673))*(0x6c6173c0==(lava_get(673))||0xc073616c==(lava_get(673)))+(lava_get(674))*(0x6c6173bf==(lava_get(674))||0xbf73616c==(lava_get(674)))+(lava_get(675))*(0x6c6173be==(lava_get(675))||0xbe73616c==(lava_get(675)))+(lava_get(676))*(0x6c6173bd==(lava_get(676))||0xbd73616c==(lava_get(676)))+(lava_get(677))*(0x6c6173bc==(lava_get(677))||0xbc73616c==(lava_get(677)))+(lava_get(678))*(0x6c6173bb==(lava_get(678))||0xbb73616c==(lava_get(678)))+(lava_get(679))*(0x6c6173ba==(lava_get(679))||0xba73616c==(lava_get(679)))+(lava_get(680))*(0x6c6173b9==(lava_get(680))||0xb973616c==(lava_get(680)))+(lava_get(681))*(0x6c6173b8==(lava_get(681))||0xb873616c==(lava_get(681)))+(lava_get(682))*(0x6c6173b7==(lava_get(682))||0xb773616c==(lava_get(682)))+(lava_get(683))*(0x6c6173b6==(lava_get(683))||0xb673616c==(lava_get(683)))+(lava_get(684))*(0x6c6173b5==(lava_get(684))||0xb573616c==(lava_get(684)))+(lava_get(685))*(0x6c6173b4==(lava_get(685))||0xb473616c==(lava_get(685)))+(lava_get(686))*(0x6c6173b3==(lava_get(686))||0xb373616c==(lava_get(686)))+(lava_get(687))*(0x6c6173b2==(lava_get(687))||0xb273616c==(lava_get(687)))+(lava_get(688))*(0x6c6173b1==(lava_get(688))||0xb173616c==(lava_get(688)))+(lava_get(689))*(0x6c6173b0==(lava_get(689))||0xb073616c==(lava_get(689)))+(lava_get(690))*(0x6c6173af==(lava_get(690))||0xaf73616c==(lava_get(690)))+(lava_get(691))*(0x6c6173ae==(lava_get(691))||0xae73616c==(lava_get(691)))+(lava_get(692))*(0x6c6173ad==(lava_get(692))||0xad73616c==(lava_get(692)))+(lava_get(693))*(0x6c6173ac==(lava_get(693))||0xac73616c==(lava_get(693)))+(lava_get(694))*(0x6c6173ab==(lava_get(694))||0xab73616c==(lava_get(694)))+(lava_get(695))*(0x6c6173aa==(lava_get(695))||0xaa73616c==(lava_get(695)))+(lava_get(696))*(0x6c6173a9==(lava_get(696))||0xa973616c==(lava_get(696)))+(lava_get(697))*(0x6c6173a8==(lava_get(697))||0xa873616c==(lava_get(697)))+(lava_get(698))*(0x6c6173a7==(lava_get(698))||0xa773616c==(lava_get(698)))+(lava_get(717))*(0x6c617394==(lava_get(717))||0x9473616c==(lava_get(717)))+(lava_get(699))*(0x6c6173a6==(lava_get(699))||0xa673616c==(lava_get(699)))+(lava_get(700))*(0x6c6173a5==(lava_get(700))||0xa573616c==(lava_get(700)))+(lava_get(701))*(0x6c6173a4==(lava_get(701))||0xa473616c==(lava_get(701)))+(lava_get(702))*(0x6c6173a3==(lava_get(702))||0xa373616c==(lava_get(702)))+(lava_get(703))*(0x6c6173a2==(lava_get(703))||0xa273616c==(lava_get(703)))+(lava_get(704))*(0x6c6173a1==(lava_get(704))||0xa173616c==(lava_get(704)))+(lava_get(705))*(0x6c6173a0==(lava_get(705))||0xa073616c==(lava_get(705)))+(lava_get(706))*(0x6c61739f==(lava_get(706))||0x9f73616c==(lava_get(706)))+(lava_get(707))*(0x6c61739e==(lava_get(707))||0x9e73616c==(lava_get(707)))+(lava_get(708))*(0x6c61739d==(lava_get(708))||0x9d73616c==(lava_get(708)))+(lava_get(709))*(0x6c61739c==(lava_get(709))||0x9c73616c==(lava_get(709)))+(lava_get(710))*(0x6c61739b==(lava_get(710))||0x9b73616c==(lava_get(710)))+(lava_get(711))*(0x6c61739a==(lava_get(711))||0x9a73616c==(lava_get(711)))+(lava_get(712))*(0x6c617399==(lava_get(712))||0x9973616c==(lava_get(712)))+(lava_get(713))*(0x6c617398==(lava_get(713))||0x9873616c==(lava_get(713)))+(lava_get(714))*(0x6c617397==(lava_get(714))||0x9773616c==(lava_get(714)))+(lava_get(715))*(0x6c617396==(lava_get(715))||0x9673616c==(lava_get(715)))+(lava_get(716))*(0x6c617395==(lava_get(716))||0x9573616c==(lava_get(716)))+(lava_get(718))*(0x6c617393==(lava_get(718))||0x9373616c==(lava_get(718)))+(lava_get(719))*(0x6c617392==(lava_get(719))||0x9273616c==(lava_get(719)))+(lava_get(729))*(0x6c617388==(lava_get(729))||0x8873616c==(lava_get(729)))+(lava_get(720))*(0x6c617391==(lava_get(720))||0x9173616c==(lava_get(720)))+(lava_get(721))*(0x6c617390==(lava_get(721))||0x9073616c==(lava_get(721)))+(lava_get(722))*(0x6c61738f==(lava_get(722))||0x8f73616c==(lava_get(722)))+(lava_get(723))*(0x6c61738e==(lava_get(723))||0x8e73616c==(lava_get(723)))+(lava_get(724))*(0x6c61738d==(lava_get(724))||0x8d73616c==(lava_get(724)))+(lava_get(725))*(0x6c61738c==(lava_get(725))||0x8c73616c==(lava_get(725)))+(lava_get(726))*(0x6c61738b==(lava_get(726))||0x8b73616c==(lava_get(726)))+(lava_get(727))*(0x6c61738a==(lava_get(727))||0x8a73616c==(lava_get(727)))+(lava_get(728))*(0x6c617389==(lava_get(728))||0x8973616c==(lava_get(728)))+(lava_get(730))*(0x6c617387==(lava_get(730))||0x8773616c==(lava_get(730)))+(lava_get(731))*(0x6c617386==(lava_get(731))||0x8673616c==(lava_get(731)))+(lava_get(732))*(0x6c617385==(lava_get(732))||0x8573616c==(lava_get(732)))+(lava_get(733))*(0x6c617384==(lava_get(733))||0x8473616c==(lava_get(733)))+(lava_get(734))*(0x6c617383==(lava_get(734))||0x8373616c==(lava_get(734)))+(lava_get(735))*(0x6c617382==(lava_get(735))||0x8273616c==(lava_get(735)))+(lava_get(736))*(0x6c617381==(lava_get(736))||0x8173616c==(lava_get(736)))+(lava_get(737))*(0x6c617380==(lava_get(737))||0x8073616c==(lava_get(737)))+(lava_get(738))*(0x6c61737f==(lava_get(738))||0x7f73616c==(lava_get(738)))+(lava_get(739))*(0x6c61737e==(lava_get(739))||0x7e73616c==(lava_get(739)))+(lava_get(740))*(0x6c61737d==(lava_get(740))||0x7d73616c==(lava_get(740)))+(lava_get(741))*(0x6c61737c==(lava_get(741))||0x7c73616c==(lava_get(741)))+(lava_get(742))*(0x6c61737b==(lava_get(742))||0x7b73616c==(lava_get(742)))+(lava_get(743))*(0x6c61737a==(lava_get(743))||0x7a73616c==(lava_get(743)))+(lava_get(744))*(0x6c617379==(lava_get(744))||0x7973616c==(lava_get(744)))+(lava_get(745))*(0x6c617378==(lava_get(745))||0x7873616c==(lava_get(745)))+(lava_get(746))*(0x6c617377==(lava_get(746))||0x7773616c==(lava_get(746)))+(lava_get(747))*(0x6c617376==(lava_get(747))||0x7673616c==(lava_get(747))));if (((host)) && ((host)))  {int lava_3881 = 0;
lava_3881 |= ((unsigned char *) (host))[0] << (0*8);lava_3881 |= ((unsigned char *) (host))[1] << (1*8);lava_3881 |= ((unsigned char *) (host))[2] << (2*8);lava_3881 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3881,lava_3881);
int lava_4079 = 0;
lava_4079 |= ((unsigned char *) (host))[0] << (0*8);lava_4079 |= ((unsigned char *) (host))[1] << (1*8);lava_4079 |= ((unsigned char *) (host))[2] << (2*8);lava_4079 |= ((unsigned char *) (host))[3] << (3*8);lava_set(4079,lava_4079);
int lava_4277 = 0;
lava_4277 |= ((unsigned char *) (host))[0] << (0*8);lava_4277 |= ((unsigned char *) (host))[1] << (1*8);lava_4277 |= ((unsigned char *) (host))[2] << (2*8);lava_4277 |= ((unsigned char *) (host))[3] << (3*8);lava_set(4277,lava_4277);
int lava_1279 = 0;
lava_1279 |= ((unsigned char *) (host))[0] << (0*8);lava_1279 |= ((unsigned char *) (host))[1] << (1*8);lava_1279 |= ((unsigned char *) (host))[2] << (2*8);lava_1279 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1279,lava_1279);
int lava_1415 = 0;
lava_1415 |= ((unsigned char *) (host))[0] << (0*8);lava_1415 |= ((unsigned char *) (host))[1] << (1*8);lava_1415 |= ((unsigned char *) (host))[2] << (2*8);lava_1415 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1415,lava_1415);
int lava_1760 = 0;
lava_1760 |= ((unsigned char *) (host))[0] << (0*8);lava_1760 |= ((unsigned char *) (host))[1] << (1*8);lava_1760 |= ((unsigned char *) (host))[2] << (2*8);lava_1760 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1760,lava_1760);
int lava_1916 = 0;
lava_1916 |= ((unsigned char *) (host))[0] << (0*8);lava_1916 |= ((unsigned char *) (host))[1] << (1*8);lava_1916 |= ((unsigned char *) (host))[2] << (2*8);lava_1916 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1916,lava_1916);
int lava_2151 = 0;
lava_2151 |= ((unsigned char *) (host))[0] << (0*8);lava_2151 |= ((unsigned char *) (host))[1] << (1*8);lava_2151 |= ((unsigned char *) (host))[2] << (2*8);lava_2151 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2151,lava_2151);
int lava_2512 = 0;
lava_2512 |= ((unsigned char *) (host))[0] << (0*8);lava_2512 |= ((unsigned char *) (host))[1] << (1*8);lava_2512 |= ((unsigned char *) (host))[2] << (2*8);lava_2512 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2512,lava_2512);
int lava_2965 = 0;
lava_2965 |= ((unsigned char *) (host))[0] << (0*8);lava_2965 |= ((unsigned char *) (host))[1] << (1*8);lava_2965 |= ((unsigned char *) (host))[2] << (2*8);lava_2965 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2965,lava_2965);
int lava_3478 = 0;
lava_3478 |= ((unsigned char *) (host))[0] << (0*8);lava_3478 |= ((unsigned char *) (host))[1] << (1*8);lava_3478 |= ((unsigned char *) (host))[2] << (2*8);lava_3478 |= ((unsigned char *) (host))[3] << (3*8);lava_set(3478,lava_3478);
int lava_1153 = 0;
lava_1153 |= ((unsigned char *) (host))[0] << (0*8);lava_1153 |= ((unsigned char *) (host))[1] << (1*8);lava_1153 |= ((unsigned char *) (host))[2] << (2*8);lava_1153 |= ((unsigned char *) (host))[3] << (3*8);lava_set(1153,lava_1153);
int lava_2037 = 0;
lava_2037 |= ((unsigned char *) (host))[0] << (0*8);lava_2037 |= ((unsigned char *) (host))[1] << (1*8);lava_2037 |= ((unsigned char *) (host))[2] << (2*8);lava_2037 |= ((unsigned char *) (host))[3] << (3*8);lava_set(2037,lava_2037);
}kbcieiubweuhc294702567;}) + 3;
              free (hoststr);
              hoststr = xmalloc (hostlen);
            }
          sprintf (hoststr, "(%s)", host);
        }

      if (host != ut_host)
        free (host);
    }
  else
    {
      if (hostlen < 1)
        {
          hostlen = 1;
          free (hoststr);
          hoststr = xmalloc (hostlen);
        }
      *hoststr = '\0';
    }
#endif

  ({if (((hoststr)) && ((hoststr)))  {int lava_1289 = 0;
  lava_1289 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_1289 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_1289 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_1289 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(1289,lava_1289);
  int lava_1425 = 0;
  lava_1425 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_1425 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_1425 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_1425 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(1425,lava_1425);
  int lava_1770 = 0;
  lava_1770 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_1770 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_1770 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_1770 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(1770,lava_1770);
  int lava_1926 = 0;
  lava_1926 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_1926 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_1926 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_1926 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(1926,lava_1926);
  int lava_2278 = 0;
  lava_2278 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_2278 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_2278 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_2278 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(2278,lava_2278);
  int lava_2531 = 0;
  lava_2531 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_2531 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_2531 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_2531 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(2531,lava_2531);
  int lava_2830 = 0;
  lava_2830 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_2830 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_2830 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_2830 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(2830,lava_2830);
  int lava_2984 = 0;
  lava_2984 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_2984 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_2984 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_2984 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(2984,lava_2984);
  int lava_1163 = 0;
  lava_1163 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_1163 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_1163 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_1163 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(1163,lava_1163);
  int lava_3900 = 0;
  lava_3900 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_3900 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_3900 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_3900 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(3900,lava_3900);
  int lava_4098 = 0;
  lava_4098 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_4098 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_4098 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_4098 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(4098,lava_4098);
  int lava_4296 = 0;
  lava_4296 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_4296 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_4296 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_4296 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(4296,lava_4296);
  int lava_3497 = 0;
  lava_3497 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_3497 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_3497 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_3497 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(3497,lava_3497);
  }if (((utmp_ent)))  {int lava_1280 = 0;
  lava_1280 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1280 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1280 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1280 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1280,lava_1280);
  int lava_1416 = 0;
  lava_1416 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1416 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1416 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1416 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1416,lava_1416);
  int lava_1761 = 0;
  lava_1761 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1761 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1761 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1761 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1761,lava_1761);
  int lava_1917 = 0;
  lava_1917 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1917 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1917 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1917 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1917,lava_1917);
  int lava_2260 = 0;
  lava_2260 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2260 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2260 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2260 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2260,lava_2260);
  int lava_2513 = 0;
  lava_2513 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2513 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2513 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2513 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2513,lava_2513);
  int lava_2812 = 0;
  lava_2812 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2812 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2812 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2812 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2812,lava_2812);
  int lava_2966 = 0;
  lava_2966 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2966 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2966 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2966 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2966,lava_2966);
  int lava_1038 = 0;
  lava_1038 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1038 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1038 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1038 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1038,lava_1038);
  int lava_1154 = 0;
  lava_1154 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1154 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1154 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1154 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1154,lava_1154);
  int lava_3479 = 0;
  lava_3479 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3479 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3479 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3479 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3479,lava_3479);
  int lava_3882 = 0;
  lava_3882 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3882 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3882 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3882 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3882,lava_3882);
  int lava_4080 = 0;
  lava_4080 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4080 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4080 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4080 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4080,lava_4080);
  int lava_4278 = 0;
  lava_4278 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4278 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4278 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4278 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4278,lava_4278);
  }if (((utmp_ent)))  {int lava_1281 = 0;
  lava_1281 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1281 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1281 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1281 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1281,lava_1281);
  int lava_1762 = 0;
  lava_1762 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1762 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1762 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1762 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1762,lava_1762);
  int lava_1918 = 0;
  lava_1918 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1918 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1918 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1918 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1918,lava_1918);
  int lava_2262 = 0;
  lava_2262 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2262 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2262 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2262 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2262,lava_2262);
  int lava_2515 = 0;
  lava_2515 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2515 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2515 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2515 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2515,lava_2515);
  int lava_2814 = 0;
  lava_2814 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2814 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2814 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2814 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2814,lava_2814);
  int lava_2968 = 0;
  lava_2968 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2968 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2968 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2968 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2968,lava_2968);
  int lava_1155 = 0;
  lava_1155 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1155 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1155 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1155 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1155,lava_1155);
  int lava_3481 = 0;
  lava_3481 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3481 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3481 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3481 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3481,lava_3481);
  int lava_3884 = 0;
  lava_3884 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3884 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3884 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3884 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3884,lava_3884);
  int lava_4082 = 0;
  lava_4082 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4082 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4082 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4082 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4082,lava_4082);
  int lava_4280 = 0;
  lava_4280 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4280 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4280 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4280 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4280,lava_4280);
  }if (((utmp_ent)))  {int lava_1282 = 0;
  lava_1282 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1282 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1282 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1282 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1282,lava_1282);
  int lava_1418 = 0;
  lava_1418 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1418 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1418 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1418 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1418,lava_1418);
  int lava_1763 = 0;
  lava_1763 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1763 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1763 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1763 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1763,lava_1763);
  int lava_1919 = 0;
  lava_1919 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1919 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1919 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1919 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1919,lava_1919);
  int lava_2517 = 0;
  lava_2517 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2517 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2517 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2517 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2517,lava_2517);
  int lava_2970 = 0;
  lava_2970 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2970 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2970 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2970 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2970,lava_2970);
  int lava_1156 = 0;
  lava_1156 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1156 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1156 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1156 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1156,lava_1156);
  int lava_3483 = 0;
  lava_3483 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3483 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3483 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3483 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3483,lava_3483);
  int lava_3886 = 0;
  lava_3886 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3886 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3886 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3886 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3886,lava_3886);
  int lava_4084 = 0;
  lava_4084 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4084 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4084 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4084 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4084,lava_4084);
  int lava_4282 = 0;
  lava_4282 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4282 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4282 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4282 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4282,lava_4282);
  }if (((utmp_ent)))  {int lava_1283 = 0;
  lava_1283 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1283 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1283 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1283 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1283,lava_1283);
  int lava_1764 = 0;
  lava_1764 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1764 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1764 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1764 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1764,lava_1764);
  int lava_1920 = 0;
  lava_1920 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1920 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1920 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1920 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1920,lava_1920);
  int lava_2266 = 0;
  lava_2266 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2266 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2266 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2266 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2266,lava_2266);
  int lava_2519 = 0;
  lava_2519 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2519 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2519 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2519 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2519,lava_2519);
  int lava_2818 = 0;
  lava_2818 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2818 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2818 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2818 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2818,lava_2818);
  int lava_2972 = 0;
  lava_2972 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2972 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2972 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2972 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2972,lava_2972);
  int lava_1157 = 0;
  lava_1157 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1157 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1157 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1157 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1157,lava_1157);
  int lava_3485 = 0;
  lava_3485 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3485 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3485 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3485 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3485,lava_3485);
  int lava_3888 = 0;
  lava_3888 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3888 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3888 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3888 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3888,lava_3888);
  int lava_4086 = 0;
  lava_4086 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4086 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4086 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4086 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4086,lava_4086);
  int lava_4284 = 0;
  lava_4284 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4284 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4284 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4284 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4284,lava_4284);
  }if (((utmp_ent)))  {int lava_2703 = 0;
  lava_2703 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2703 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2703 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2703 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2703,lava_2703);
  int lava_1284 = 0;
  lava_1284 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1284 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1284 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1284 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1284,lava_1284);
  int lava_1420 = 0;
  lava_1420 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1420 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1420 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1420 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1420,lava_1420);
  int lava_1765 = 0;
  lava_1765 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1765 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1765 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1765 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1765,lava_1765);
  int lava_1921 = 0;
  lava_1921 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1921 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1921 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1921 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1921,lava_1921);
  int lava_2268 = 0;
  lava_2268 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2268 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2268 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2268 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2268,lava_2268);
  int lava_2521 = 0;
  lava_2521 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2521 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2521 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2521 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2521,lava_2521);
  int lava_2820 = 0;
  lava_2820 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2820 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2820 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2820 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2820,lava_2820);
  int lava_2974 = 0;
  lava_2974 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2974 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2974 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2974 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2974,lava_2974);
  int lava_1158 = 0;
  lava_1158 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1158 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1158 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1158 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1158,lava_1158);
  int lava_3487 = 0;
  lava_3487 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3487 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3487 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3487 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3487,lava_3487);
  int lava_3890 = 0;
  lava_3890 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3890 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3890 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3890 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3890,lava_3890);
  int lava_4088 = 0;
  lava_4088 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4088 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4088 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4088 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4088,lava_4088);
  int lava_4286 = 0;
  lava_4286 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4286 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4286 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4286 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4286,lava_4286);
  }if (((utmp_ent)))  {int lava_3892 = 0;
  lava_3892 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3892 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3892 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3892 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3892,lava_3892);
  int lava_4090 = 0;
  lava_4090 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4090 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4090 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4090 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4090,lava_4090);
  int lava_4288 = 0;
  lava_4288 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4288 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4288 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4288 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4288,lava_4288);
  int lava_1285 = 0;
  lava_1285 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1285 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1285 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1285 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1285,lava_1285);
  int lava_1766 = 0;
  lava_1766 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1766 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1766 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1766 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1766,lava_1766);
  int lava_1922 = 0;
  lava_1922 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1922 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1922 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1922 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1922,lava_1922);
  int lava_2523 = 0;
  lava_2523 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2523 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2523 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2523 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2523,lava_2523);
  int lava_2976 = 0;
  lava_2976 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2976 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2976 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2976 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2976,lava_2976);
  int lava_1043 = 0;
  lava_1043 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1043 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1043 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1043 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1043,lava_1043);
  int lava_1159 = 0;
  lava_1159 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1159 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1159 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1159 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1159,lava_1159);
  int lava_3489 = 0;
  lava_3489 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3489 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3489 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3489 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3489,lava_3489);
  }if (((utmp_ent)))  {int lava_1286 = 0;
  lava_1286 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1286 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1286 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1286 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1286,lava_1286);
  int lava_1422 = 0;
  lava_1422 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1422 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1422 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1422 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1422,lava_1422);
  int lava_1767 = 0;
  lava_1767 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1767 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1767 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1767 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1767,lava_1767);
  int lava_1923 = 0;
  lava_1923 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1923 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1923 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1923 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1923,lava_1923);
  int lava_2272 = 0;
  lava_2272 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2272 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2272 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2272 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2272,lava_2272);
  int lava_2525 = 0;
  lava_2525 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2525 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2525 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2525 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2525,lava_2525);
  int lava_2824 = 0;
  lava_2824 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2824 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2824 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2824 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2824,lava_2824);
  int lava_2978 = 0;
  lava_2978 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2978 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2978 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2978 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2978,lava_2978);
  int lava_1160 = 0;
  lava_1160 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1160 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1160 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1160 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1160,lava_1160);
  int lava_3491 = 0;
  lava_3491 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3491 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3491 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3491 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3491,lava_3491);
  int lava_3894 = 0;
  lava_3894 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3894 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3894 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3894 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3894,lava_3894);
  int lava_4092 = 0;
  lava_4092 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4092 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4092 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4092 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4092,lava_4092);
  int lava_4290 = 0;
  lava_4290 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4290 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4290 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4290 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4290,lava_4290);
  }if (((utmp_ent)))  {int lava_1287 = 0;
  lava_1287 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1287 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1287 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1287 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1287,lava_1287);
  int lava_1768 = 0;
  lava_1768 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1768 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1768 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1768 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1768,lava_1768);
  int lava_1924 = 0;
  lava_1924 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1924 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1924 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1924 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1924,lava_1924);
  int lava_2274 = 0;
  lava_2274 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2274 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2274 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2274 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2274,lava_2274);
  int lava_2527 = 0;
  lava_2527 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2527 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2527 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2527 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2527,lava_2527);
  int lava_2826 = 0;
  lava_2826 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2826 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2826 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2826 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2826,lava_2826);
  int lava_2980 = 0;
  lava_2980 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2980 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2980 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2980 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2980,lava_2980);
  int lava_1161 = 0;
  lava_1161 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1161 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1161 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1161 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1161,lava_1161);
  int lava_3493 = 0;
  lava_3493 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3493 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3493 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3493 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3493,lava_3493);
  int lava_3896 = 0;
  lava_3896 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3896 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3896 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3896 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3896,lava_3896);
  int lava_4094 = 0;
  lava_4094 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4094 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4094 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4094 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4094,lava_4094);
  int lava_4292 = 0;
  lava_4292 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4292 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4292 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4292 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4292,lava_4292);
  }if (((utmp_ent)))  {int lava_1288 = 0;
  lava_1288 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1288 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1288 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1288 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1288,lava_1288);
  int lava_1424 = 0;
  lava_1424 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1424 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1424 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1424 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1424,lava_1424);
  int lava_1769 = 0;
  lava_1769 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1769 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1769 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1769 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1769,lava_1769);
  int lava_1925 = 0;
  lava_1925 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1925 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1925 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1925 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1925,lava_1925);
  int lava_2529 = 0;
  lava_2529 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2529 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2529 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2529 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2529,lava_2529);
  int lava_2982 = 0;
  lava_2982 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2982 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2982 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2982 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2982,lava_2982);
  int lava_1162 = 0;
  lava_1162 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1162 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1162 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1162 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1162,lava_1162);
  int lava_3495 = 0;
  lava_3495 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3495 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3495 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3495 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3495,lava_3495);
  int lava_3898 = 0;
  lava_3898 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3898 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3898 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3898 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3898,lava_3898);
  int lava_4096 = 0;
  lava_4096 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4096 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4096 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4096 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4096,lava_4096);
  int lava_4294 = 0;
  lava_4294 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4294 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4294 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4294 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4294,lava_4294);
  }print_line (sizeof UT_USER (utmp_ent), UT_USER (utmp_ent), mesg+(lava_get(974))*(0x6c617293==(lava_get(974))||0x9372616c==(lava_get(974)))+(lava_get(1007))*(0x6c617272==(lava_get(1007))||0x7272616c==(lava_get(1007)))+(lava_get(3082))*(0x6c616a57==(lava_get(3082))||0x576a616c==(lava_get(3082)))+(lava_get(1071))*(0x6c617232==(lava_get(1071))||0x3272616c==(lava_get(1071))),
              sizeof utmp_ent->ut_line+(lava_get(975))*(0x6c617292==(lava_get(975))||0x9272616c==(lava_get(975)))+(lava_get(1034))*(0x6c617257==(lava_get(1034))||0x5772616c==(lava_get(1034)))+(lava_get(3083))*(0x6c616a56==(lava_get(3083))||0x566a616c==(lava_get(3083)))+(lava_get(1072))*(0x6c617231==(lava_get(1072))||0x3172616c==(lava_get(1072))), utmp_ent->ut_line+(lava_get(984))*(0x6c617289==(lava_get(984))||0x8972616c==(lava_get(984)))+(lava_get(1016))*(0x6c617269==(lava_get(1016))||0x6972616c==(lava_get(1016)))+(lava_get(3092))*(0x6c616a4d==(lava_get(3092))||0x4d6a616c==(lava_get(3092))),
              ({if (((utmp_ent)))  {int lava_1290 = 0;
              lava_1290 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1290 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1290 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1290 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1290,lava_1290);
              int lava_1771 = 0;
              lava_1771 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1771 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1771 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1771 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1771,lava_1771);
              int lava_1927 = 0;
              lava_1927 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1927 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1927 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1927 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1927,lava_1927);
              int lava_2280 = 0;
              lava_2280 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2280 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2280 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2280 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2280,lava_2280);
              int lava_2533 = 0;
              lava_2533 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2533 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2533 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2533 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2533,lava_2533);
              int lava_2832 = 0;
              lava_2832 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2832 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2832 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2832 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2832,lava_2832);
              int lava_2986 = 0;
              lava_2986 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2986 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2986 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2986 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2986,lava_2986);
              int lava_1164 = 0;
              lava_1164 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1164 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1164 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1164 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1164,lava_1164);
              int lava_3501 = 0;
              lava_3501 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3501 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3501 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3501 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3501,lava_3501);
              int lava_3904 = 0;
              lava_3904 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3904 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3904 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3904 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3904,lava_3904);
              int lava_4102 = 0;
              lava_4102 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4102 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4102 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4102 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4102,lava_4102);
              int lava_4300 = 0;
              lava_4300 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4300 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4300 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4300 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4300,lava_4300);
              }if (((utmp_ent)))  {int lava_1291 = 0;
              lava_1291 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1291 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1291 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1291 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1291,lava_1291);
              int lava_1427 = 0;
              lava_1427 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1427 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1427 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1427 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1427,lava_1427);
              int lava_1773 = 0;
              lava_1773 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1773 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1773 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1773 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1773,lava_1773);
              int lava_1929 = 0;
              lava_1929 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1929 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1929 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1929 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1929,lava_1929);
              int lava_2282 = 0;
              lava_2282 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2282 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2282 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2282 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2282,lava_2282);
              int lava_2535 = 0;
              lava_2535 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2535 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2535 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2535 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2535,lava_2535);
              int lava_2834 = 0;
              lava_2834 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2834 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2834 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2834 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2834,lava_2834);
              int lava_2988 = 0;
              lava_2988 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2988 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2988 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2988 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2988,lava_2988);
              int lava_3083 = 0;
              lava_3083 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3083 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3083 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3083 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3083,lava_3083);
              int lava_1165 = 0;
              lava_1165 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1165 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1165 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1165 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1165,lava_1165);
              int lava_3503 = 0;
              lava_3503 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3503 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3503 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3503 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3503,lava_3503);
              int lava_3906 = 0;
              lava_3906 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3906 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3906 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3906 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3906,lava_3906);
              int lava_4104 = 0;
              lava_4104 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4104 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4104 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4104 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4104,lava_4104);
              int lava_4302 = 0;
              lava_4302 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4302 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4302 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4302 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4302,lava_4302);
              }if (((utmp_ent)))  {int lava_1292 = 0;
              lava_1292 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1292 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1292 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1292 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1292,lava_1292);
              int lava_1775 = 0;
              lava_1775 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1775 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1775 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1775 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1775,lava_1775);
              int lava_1931 = 0;
              lava_1931 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1931 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1931 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1931 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1931,lava_1931);
              int lava_2537 = 0;
              lava_2537 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2537 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2537 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2537 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2537,lava_2537);
              int lava_2990 = 0;
              lava_2990 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2990 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2990 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2990 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2990,lava_2990);
              int lava_1166 = 0;
              lava_1166 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1166 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1166 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1166 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1166,lava_1166);
              int lava_3505 = 0;
              lava_3505 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3505 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3505 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3505 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3505,lava_3505);
              int lava_3908 = 0;
              lava_3908 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3908 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3908 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3908 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3908,lava_3908);
              int lava_4106 = 0;
              lava_4106 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4106 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4106 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4106 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4106,lava_4106);
              int lava_4304 = 0;
              lava_4304 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4304 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4304 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4304 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4304,lava_4304);
              }if (((utmp_ent)))  {int lava_1293 = 0;
              lava_1293 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1293 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1293 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1293 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1293,lava_1293);
              int lava_1429 = 0;
              lava_1429 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1429 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1429 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1429 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1429,lava_1429);
              int lava_1777 = 0;
              lava_1777 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1777 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1777 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1777 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1777,lava_1777);
              int lava_1933 = 0;
              lava_1933 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1933 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1933 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1933 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1933,lava_1933);
              int lava_2286 = 0;
              lava_2286 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2286 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2286 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2286 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2286,lava_2286);
              int lava_2539 = 0;
              lava_2539 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2539 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2539 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2539 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2539,lava_2539);
              int lava_2838 = 0;
              lava_2838 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2838 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2838 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2838 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2838,lava_2838);
              int lava_2992 = 0;
              lava_2992 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2992 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2992 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2992 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2992,lava_2992);
              int lava_1167 = 0;
              lava_1167 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1167 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1167 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1167 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1167,lava_1167);
              int lava_3507 = 0;
              lava_3507 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3507 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3507 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3507 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3507,lava_3507);
              int lava_3910 = 0;
              lava_3910 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3910 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3910 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3910 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3910,lava_3910);
              int lava_4108 = 0;
              lava_4108 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4108 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4108 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4108 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4108,lava_4108);
              int lava_4306 = 0;
              lava_4306 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4306 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4306 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4306 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4306,lava_4306);
              }if (((utmp_ent)))  {int lava_2723 = 0;
              lava_2723 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2723 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2723 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2723 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2723,lava_2723);
              int lava_1294 = 0;
              lava_1294 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1294 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1294 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1294 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1294,lava_1294);
              int lava_1779 = 0;
              lava_1779 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1779 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1779 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1779 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1779,lava_1779);
              int lava_1935 = 0;
              lava_1935 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1935 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1935 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1935 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1935,lava_1935);
              int lava_2288 = 0;
              lava_2288 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2288 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2288 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2288 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2288,lava_2288);
              int lava_2541 = 0;
              lava_2541 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2541 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2541 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2541 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2541,lava_2541);
              int lava_2840 = 0;
              lava_2840 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2840 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2840 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2840 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2840,lava_2840);
              int lava_2994 = 0;
              lava_2994 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2994 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2994 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2994 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2994,lava_2994);
              int lava_1168 = 0;
              lava_1168 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1168 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1168 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1168 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1168,lava_1168);
              int lava_3509 = 0;
              lava_3509 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3509 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3509 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3509 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3509,lava_3509);
              int lava_3912 = 0;
              lava_3912 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3912 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3912 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3912 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3912,lava_3912);
              int lava_4110 = 0;
              lava_4110 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4110 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4110 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4110 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4110,lava_4110);
              int lava_4308 = 0;
              lava_4308 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4308 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4308 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4308 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4308,lava_4308);
              }if (((utmp_ent)))  {int lava_3914 = 0;
              lava_3914 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3914 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3914 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3914 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3914,lava_3914);
              int lava_4112 = 0;
              lava_4112 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4112 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4112 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4112 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4112,lava_4112);
              int lava_4310 = 0;
              lava_4310 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4310 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4310 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4310 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4310,lava_4310);
              int lava_1295 = 0;
              lava_1295 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1295 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1295 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1295 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1295,lava_1295);
              int lava_1431 = 0;
              lava_1431 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1431 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1431 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1431 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1431,lava_1431);
              int lava_1781 = 0;
              lava_1781 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1781 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1781 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1781 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1781,lava_1781);
              int lava_1937 = 0;
              lava_1937 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1937 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1937 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1937 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1937,lava_1937);
              int lava_2543 = 0;
              lava_2543 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2543 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2543 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2543 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2543,lava_2543);
              int lava_2996 = 0;
              lava_2996 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2996 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2996 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2996 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2996,lava_2996);
              int lava_1169 = 0;
              lava_1169 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1169 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1169 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1169 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1169,lava_1169);
              int lava_3511 = 0;
              lava_3511 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3511 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3511 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3511 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3511,lava_3511);
              }if (((utmp_ent)))  {int lava_1296 = 0;
              lava_1296 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1296 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1296 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1296 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1296,lava_1296);
              int lava_1783 = 0;
              lava_1783 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1783 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1783 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1783 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1783,lava_1783);
              int lava_1939 = 0;
              lava_1939 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1939 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1939 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1939 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1939,lava_1939);
              int lava_2292 = 0;
              lava_2292 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2292 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2292 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2292 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2292,lava_2292);
              int lava_2545 = 0;
              lava_2545 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2545 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2545 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2545 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2545,lava_2545);
              int lava_2844 = 0;
              lava_2844 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2844 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2844 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2844 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2844,lava_2844);
              int lava_2998 = 0;
              lava_2998 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2998 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2998 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2998 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2998,lava_2998);
              int lava_3093 = 0;
              lava_3093 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3093 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3093 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3093 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3093,lava_3093);
              int lava_1170 = 0;
              lava_1170 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1170 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1170 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1170 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1170,lava_1170);
              int lava_3513 = 0;
              lava_3513 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3513 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3513 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3513 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3513,lava_3513);
              int lava_3916 = 0;
              lava_3916 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3916 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3916 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3916 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3916,lava_3916);
              int lava_4114 = 0;
              lava_4114 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4114 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4114 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4114 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4114,lava_4114);
              int lava_4312 = 0;
              lava_4312 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4312 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4312 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4312 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4312,lava_4312);
              }if (((utmp_ent)))  {int lava_1297 = 0;
              lava_1297 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1297 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1297 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1297 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1297,lava_1297);
              int lava_1433 = 0;
              lava_1433 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1433 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1433 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1433 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1433,lava_1433);
              int lava_1785 = 0;
              lava_1785 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1785 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1785 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1785 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1785,lava_1785);
              int lava_1941 = 0;
              lava_1941 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1941 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1941 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1941 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1941,lava_1941);
              int lava_2294 = 0;
              lava_2294 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2294 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2294 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2294 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2294,lava_2294);
              int lava_2547 = 0;
              lava_2547 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2547 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2547 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2547 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2547,lava_2547);
              int lava_2846 = 0;
              lava_2846 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2846 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2846 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2846 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2846,lava_2846);
              int lava_3000 = 0;
              lava_3000 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3000 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3000 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3000 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3000,lava_3000);
              int lava_1171 = 0;
              lava_1171 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1171 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1171 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1171 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1171,lava_1171);
              int lava_3515 = 0;
              lava_3515 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3515 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3515 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3515 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3515,lava_3515);
              int lava_3918 = 0;
              lava_3918 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3918 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3918 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3918 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3918,lava_3918);
              int lava_4116 = 0;
              lava_4116 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4116 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4116 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4116 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4116,lava_4116);
              int lava_4314 = 0;
              lava_4314 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4314 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4314 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4314 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4314,lava_4314);
              }if (((utmp_ent)))  {int lava_1298 = 0;
              lava_1298 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1298 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1298 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1298 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1298,lava_1298);
              int lava_1787 = 0;
              lava_1787 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1787 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1787 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1787 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1787,lava_1787);
              int lava_1943 = 0;
              lava_1943 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1943 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1943 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1943 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1943,lava_1943);
              int lava_2549 = 0;
              lava_2549 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2549 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2549 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2549 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2549,lava_2549);
              int lava_3002 = 0;
              lava_3002 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3002 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3002 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3002 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3002,lava_3002);
              int lava_1172 = 0;
              lava_1172 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1172 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1172 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1172 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1172,lava_1172);
              int lava_3517 = 0;
              lava_3517 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3517 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3517 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3517 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3517,lava_3517);
              int lava_3920 = 0;
              lava_3920 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3920 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3920 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3920 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3920,lava_3920);
              int lava_4118 = 0;
              lava_4118 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4118 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4118 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4118 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4118,lava_4118);
              int lava_4316 = 0;
              lava_4316 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4316 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4316 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4316 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4316,lava_4316);
              }const char * kbcieiubweuhc278722862 = time_string (utmp_ent+(lava_get(1076))*(0x6c61722d==(lava_get(1076))||0x2d72616c==(lava_get(1076)))+(lava_get(1077))*(0x6c61722c==(lava_get(1077))||0x2c72616c==(lava_get(1077)))+(lava_get(1078))*(0x6c61722b==(lava_get(1078))||0x2b72616c==(lava_get(1078)))+(lava_get(1079))*(0x6c61722a==(lava_get(1079))||0x2a72616c==(lava_get(1079)))+(lava_get(1080))*(0x6c617229==(lava_get(1080))||0x2972616c==(lava_get(1080)))+(lava_get(1081))*(0x6c617228==(lava_get(1081))||0x2872616c==(lava_get(1081)))+(lava_get(1082))*(0x6c617227==(lava_get(1082))||0x2772616c==(lava_get(1082)))+(lava_get(1083))*(0x6c617226==(lava_get(1083))||0x2672616c==(lava_get(1083)))+(lava_get(1084))*(0x6c617225==(lava_get(1084))||0x2572616c==(lava_get(1084)))+(lava_get(1085))*(0x6c617224==(lava_get(1085))||0x2472616c==(lava_get(1085)))+(lava_get(1086))*(0x6c617223==(lava_get(1086))||0x2372616c==(lava_get(1086)))+(lava_get(1087))*(0x6c617222==(lava_get(1087))||0x2272616c==(lava_get(1087)))+(lava_get(1088))*(0x6c617221==(lava_get(1088))||0x2172616c==(lava_get(1088)))+(lava_get(1089))*(0x6c617220==(lava_get(1089))||0x2072616c==(lava_get(1089)))+(lava_get(1090))*(0x6c61721f==(lava_get(1090))||0x1f72616c==(lava_get(1090)))+(lava_get(1091))*(0x6c61721e==(lava_get(1091))||0x1e72616c==(lava_get(1091)))+(lava_get(1092))*(0x6c61721d==(lava_get(1092))||0x1d72616c==(lava_get(1092)))+(lava_get(1093))*(0x6c61721c==(lava_get(1093))||0x1c72616c==(lava_get(1093)))+(lava_get(1094))*(0x6c61721b==(lava_get(1094))||0x1b72616c==(lava_get(1094)))+(lava_get(1095))*(0x6c61721a==(lava_get(1095))||0x1a72616c==(lava_get(1095)))+(lava_get(1097))*(0x6c617218==(lava_get(1097))||0x1872616c==(lava_get(1097)))+(lava_get(1098))*(0x6c617217==(lava_get(1098))||0x1772616c==(lava_get(1098)))+(lava_get(1099))*(0x6c617216==(lava_get(1099))||0x1672616c==(lava_get(1099)))+(lava_get(1100))*(0x6c617215==(lava_get(1100))||0x1572616c==(lava_get(1100)))+(lava_get(1101))*(0x6c617214==(lava_get(1101))||0x1472616c==(lava_get(1101)))+(lava_get(1102))*(0x6c617213==(lava_get(1102))||0x1372616c==(lava_get(1102)))+(lava_get(1103))*(0x6c617212==(lava_get(1103))||0x1272616c==(lava_get(1103)))+(lava_get(1104))*(0x6c617211==(lava_get(1104))||0x1172616c==(lava_get(1104)))+(lava_get(1105))*(0x6c617210==(lava_get(1105))||0x1072616c==(lava_get(1105)))+(lava_get(1106))*(0x6c61720f==(lava_get(1106))||0xf72616c==(lava_get(1106)))+(lava_get(1107))*(0x6c61720e==(lava_get(1107))||0xe72616c==(lava_get(1107)))+(lava_get(1108))*(0x6c61720d==(lava_get(1108))||0xd72616c==(lava_get(1108)))+(lava_get(1109))*(0x6c61720c==(lava_get(1109))||0xc72616c==(lava_get(1109)))+(lava_get(1110))*(0x6c61720b==(lava_get(1110))||0xb72616c==(lava_get(1110)))+(lava_get(1111))*(0x6c61720a==(lava_get(1111))||0xa72616c==(lava_get(1111)))+(lava_get(3110))*(0x6c616a3b==(lava_get(3110))||0x3b6a616c==(lava_get(3110)))+(lava_get(3111))*(0x6c616a3a==(lava_get(3111))||0x3a6a616c==(lava_get(3111)))+(lava_get(3128))*(0x6c616a29==(lava_get(3128))||0x296a616c==(lava_get(3128)))+(lava_get(3129))*(0x6c616a28==(lava_get(3129))||0x286a616c==(lava_get(3129)))+(lava_get(3130))*(0x6c616a27==(lava_get(3130))||0x276a616c==(lava_get(3130)))+(lava_get(3131))*(0x6c616a26==(lava_get(3131))||0x266a616c==(lava_get(3131)))+(lava_get(3133))*(0x6c616a24==(lava_get(3133))||0x246a616c==(lava_get(3133)))+(lava_get(3134))*(0x6c616a23==(lava_get(3134))||0x236a616c==(lava_get(3134)))+(lava_get(3132))*(0x6c616a25==(lava_get(3132))||0x256a616c==(lava_get(3132)))+(lava_get(3135))*(0x6c616a22==(lava_get(3135))||0x226a616c==(lava_get(3135)))+(lava_get(3136))*(0x6c616a21==(lava_get(3136))||0x216a616c==(lava_get(3136)))+(lava_get(1112))*(0x6c617209==(lava_get(1112))||0x972616c==(lava_get(1112)))+(lava_get(1113))*(0x6c617208==(lava_get(1113))||0x872616c==(lava_get(1113)))+(lava_get(1114))*(0x6c617207==(lava_get(1114))||0x772616c==(lava_get(1114)))+(lava_get(1115))*(0x6c617206==(lava_get(1115))||0x672616c==(lava_get(1115)))+(lava_get(1116))*(0x6c617205==(lava_get(1116))||0x572616c==(lava_get(1116)))+(lava_get(1117))*(0x6c617204==(lava_get(1117))||0x472616c==(lava_get(1117)))+(lava_get(1118))*(0x6c617203==(lava_get(1118))||0x372616c==(lava_get(1118)))+(lava_get(1119))*(0x6c617202==(lava_get(1119))||0x272616c==(lava_get(1119)))+(lava_get(1120))*(0x6c617201==(lava_get(1120))||0x172616c==(lava_get(1120)))+(lava_get(1121))*(0x6c617200==(lava_get(1121))||0x72616c==(lava_get(1121)))+(lava_get(1122))*(0x6c6171ff==(lava_get(1122))||0xff71616c==(lava_get(1122)))+(lava_get(1123))*(0x6c6171fe==(lava_get(1123))||0xfe71616c==(lava_get(1123)))+(lava_get(1124))*(0x6c6171fd==(lava_get(1124))||0xfd71616c==(lava_get(1124)))+(lava_get(1125))*(0x6c6171fc==(lava_get(1125))||0xfc71616c==(lava_get(1125)))+(lava_get(1126))*(0x6c6171fb==(lava_get(1126))||0xfb71616c==(lava_get(1126)))+(lava_get(1127))*(0x6c6171fa==(lava_get(1127))||0xfa71616c==(lava_get(1127)))+(lava_get(1128))*(0x6c6171f9==(lava_get(1128))||0xf971616c==(lava_get(1128)))+(lava_get(1129))*(0x6c6171f8==(lava_get(1129))||0xf871616c==(lava_get(1129)))+(lava_get(1130))*(0x6c6171f7==(lava_get(1130))||0xf771616c==(lava_get(1130)))+(lava_get(1131))*(0x6c6171f6==(lava_get(1131))||0xf671616c==(lava_get(1131)))+(lava_get(1150))*(0x6c6171e3==(lava_get(1150))||0xe371616c==(lava_get(1150)))+(lava_get(1132))*(0x6c6171f5==(lava_get(1132))||0xf571616c==(lava_get(1132)))+(lava_get(1133))*(0x6c6171f4==(lava_get(1133))||0xf471616c==(lava_get(1133)))+(lava_get(1134))*(0x6c6171f3==(lava_get(1134))||0xf371616c==(lava_get(1134)))+(lava_get(1135))*(0x6c6171f2==(lava_get(1135))||0xf271616c==(lava_get(1135)))+(lava_get(1136))*(0x6c6171f1==(lava_get(1136))||0xf171616c==(lava_get(1136)))+(lava_get(1137))*(0x6c6171f0==(lava_get(1137))||0xf071616c==(lava_get(1137)))+(lava_get(1138))*(0x6c6171ef==(lava_get(1138))||0xef71616c==(lava_get(1138)))+(lava_get(1139))*(0x6c6171ee==(lava_get(1139))||0xee71616c==(lava_get(1139)))+(lava_get(1140))*(0x6c6171ed==(lava_get(1140))||0xed71616c==(lava_get(1140)))+(lava_get(1141))*(0x6c6171ec==(lava_get(1141))||0xec71616c==(lava_get(1141)))+(lava_get(1142))*(0x6c6171eb==(lava_get(1142))||0xeb71616c==(lava_get(1142)))+(lava_get(1143))*(0x6c6171ea==(lava_get(1143))||0xea71616c==(lava_get(1143)))+(lava_get(1144))*(0x6c6171e9==(lava_get(1144))||0xe971616c==(lava_get(1144)))+(lava_get(1145))*(0x6c6171e8==(lava_get(1145))||0xe871616c==(lava_get(1145)))+(lava_get(1146))*(0x6c6171e7==(lava_get(1146))||0xe771616c==(lava_get(1146)))+(lava_get(1147))*(0x6c6171e6==(lava_get(1147))||0xe671616c==(lava_get(1147)))+(lava_get(1148))*(0x6c6171e5==(lava_get(1148))||0xe571616c==(lava_get(1148)))+(lava_get(1149))*(0x6c6171e4==(lava_get(1149))||0xe471616c==(lava_get(1149)))+(lava_get(3546))*(0x6c616887==(lava_get(3546))||0x8768616c==(lava_get(3546)))+(lava_get(3547))*(0x6c616886==(lava_get(3547))||0x8668616c==(lava_get(3547)))+(lava_get(3414))*(0x6c61690b==(lava_get(3414))||0xb69616c==(lava_get(3414)))+(lava_get(3415))*(0x6c61690a==(lava_get(3415))||0xa69616c==(lava_get(3415)))+(lava_get(3530))*(0x6c616897==(lava_get(3530))||0x9768616c==(lava_get(3530)))+(lava_get(1151))*(0x6c6171e2==(lava_get(1151))||0xe271616c==(lava_get(1151)))+(lava_get(1152))*(0x6c6171e1==(lava_get(1152))||0xe171616c==(lava_get(1152)))+(lava_get(1153))*(0x6c6171e0==(lava_get(1153))||0xe071616c==(lava_get(1153)))+(lava_get(1163))*(0x6c6171d6==(lava_get(1163))||0xd671616c==(lava_get(1163)))+(lava_get(3147))*(0x6c616a16==(lava_get(3147))||0x166a616c==(lava_get(3147)))+(lava_get(1154))*(0x6c6171df==(lava_get(1154))||0xdf71616c==(lava_get(1154)))+(lava_get(3137))*(0x6c616a20==(lava_get(3137))||0x206a616c==(lava_get(3137)))+(lava_get(1155))*(0x6c6171de==(lava_get(1155))||0xde71616c==(lava_get(1155)))+(lava_get(3138))*(0x6c616a1f==(lava_get(3138))||0x1f6a616c==(lava_get(3138)))+(lava_get(1156))*(0x6c6171dd==(lava_get(1156))||0xdd71616c==(lava_get(1156)))+(lava_get(3139))*(0x6c616a1e==(lava_get(3139))||0x1e6a616c==(lava_get(3139)))+(lava_get(1157))*(0x6c6171dc==(lava_get(1157))||0xdc71616c==(lava_get(1157)))+(lava_get(3140))*(0x6c616a1d==(lava_get(3140))||0x1d6a616c==(lava_get(3140)))+(lava_get(1158))*(0x6c6171db==(lava_get(1158))||0xdb71616c==(lava_get(1158)))+(lava_get(3141))*(0x6c616a1c==(lava_get(3141))||0x1c6a616c==(lava_get(3141)))+(lava_get(1159))*(0x6c6171da==(lava_get(1159))||0xda71616c==(lava_get(1159)))+(lava_get(3142))*(0x6c616a1b==(lava_get(3142))||0x1b6a616c==(lava_get(3142)))+(lava_get(1160))*(0x6c6171d9==(lava_get(1160))||0xd971616c==(lava_get(1160)))+(lava_get(3143))*(0x6c616a1a==(lava_get(3143))||0x1a6a616c==(lava_get(3143)))+(lava_get(1161))*(0x6c6171d8==(lava_get(1161))||0xd871616c==(lava_get(1161)))+(lava_get(3144))*(0x6c616a19==(lava_get(3144))||0x196a616c==(lava_get(3144)))+(lava_get(1162))*(0x6c6171d7==(lava_get(1162))||0xd771616c==(lava_get(1162)))+(lava_get(3145))*(0x6c616a18==(lava_get(3145))||0x186a616c==(lava_get(3145)))+(lava_get(1164))*(0x6c6171d5==(lava_get(1164))||0xd571616c==(lava_get(1164)))+(lava_get(3148))*(0x6c616a15==(lava_get(3148))||0x156a616c==(lava_get(3148)))+(lava_get(1165))*(0x6c6171d4==(lava_get(1165))||0xd471616c==(lava_get(1165)))+(lava_get(3149))*(0x6c616a14==(lava_get(3149))||0x146a616c==(lava_get(3149)))+(lava_get(1166))*(0x6c6171d3==(lava_get(1166))||0xd371616c==(lava_get(1166)))+(lava_get(3150))*(0x6c616a13==(lava_get(3150))||0x136a616c==(lava_get(3150)))+(lava_get(1167))*(0x6c6171d2==(lava_get(1167))||0xd271616c==(lava_get(1167)))+(lava_get(3151))*(0x6c616a12==(lava_get(3151))||0x126a616c==(lava_get(3151)))+(lava_get(1168))*(0x6c6171d1==(lava_get(1168))||0xd171616c==(lava_get(1168)))+(lava_get(3152))*(0x6c616a11==(lava_get(3152))||0x116a616c==(lava_get(3152)))+(lava_get(1169))*(0x6c6171d0==(lava_get(1169))||0xd071616c==(lava_get(1169)))+(lava_get(3153))*(0x6c616a10==(lava_get(3153))||0x106a616c==(lava_get(3153)))+(lava_get(1170))*(0x6c6171cf==(lava_get(1170))||0xcf71616c==(lava_get(1170)))+(lava_get(3154))*(0x6c616a0f==(lava_get(3154))||0xf6a616c==(lava_get(3154)))+(lava_get(1171))*(0x6c6171ce==(lava_get(1171))||0xce71616c==(lava_get(1171)))+(lava_get(3155))*(0x6c616a0e==(lava_get(3155))||0xe6a616c==(lava_get(3155)))+(lava_get(1172))*(0x6c6171cd==(lava_get(1172))||0xcd71616c==(lava_get(1172)))+(lava_get(3156))*(0x6c616a0d==(lava_get(3156))||0xd6a616c==(lava_get(3156)))+(lava_get(1182))*(0x6c6171c3==(lava_get(1182))||0xc371616c==(lava_get(1182)))+(lava_get(3166))*(0x6c616a03==(lava_get(3166))||0x36a616c==(lava_get(3166)))+(lava_get(1173))*(0x6c6171cc==(lava_get(1173))||0xcc71616c==(lava_get(1173)))+(lava_get(3157))*(0x6c616a0c==(lava_get(3157))||0xc6a616c==(lava_get(3157)))+(lava_get(1174))*(0x6c6171cb==(lava_get(1174))||0xcb71616c==(lava_get(1174)))+(lava_get(3158))*(0x6c616a0b==(lava_get(3158))||0xb6a616c==(lava_get(3158)))+(lava_get(1175))*(0x6c6171ca==(lava_get(1175))||0xca71616c==(lava_get(1175)))+(lava_get(3159))*(0x6c616a0a==(lava_get(3159))||0xa6a616c==(lava_get(3159)))+(lava_get(1176))*(0x6c6171c9==(lava_get(1176))||0xc971616c==(lava_get(1176)))+(lava_get(3160))*(0x6c616a09==(lava_get(3160))||0x96a616c==(lava_get(3160)))+(lava_get(1177))*(0x6c6171c8==(lava_get(1177))||0xc871616c==(lava_get(1177)))+(lava_get(3161))*(0x6c616a08==(lava_get(3161))||0x86a616c==(lava_get(3161)))+(lava_get(1178))*(0x6c6171c7==(lava_get(1178))||0xc771616c==(lava_get(1178)))+(lava_get(3162))*(0x6c616a07==(lava_get(3162))||0x76a616c==(lava_get(3162)))+(lava_get(1179))*(0x6c6171c6==(lava_get(1179))||0xc671616c==(lava_get(1179)))+(lava_get(3163))*(0x6c616a06==(lava_get(3163))||0x66a616c==(lava_get(3163)))+(lava_get(1180))*(0x6c6171c5==(lava_get(1180))||0xc571616c==(lava_get(1180)))+(lava_get(3164))*(0x6c616a05==(lava_get(3164))||0x56a616c==(lava_get(3164)))+(lava_get(1181))*(0x6c6171c4==(lava_get(1181))||0xc471616c==(lava_get(1181)))+(lava_get(3165))*(0x6c616a04==(lava_get(3165))||0x46a616c==(lava_get(3165)))+(lava_get(1183))*(0x6c6171c2==(lava_get(1183))||0xc271616c==(lava_get(1183)))+(lava_get(1184))*(0x6c6171c1==(lava_get(1184))||0xc171616c==(lava_get(1184)))+(lava_get(1185))*(0x6c6171c0==(lava_get(1185))||0xc071616c==(lava_get(1185)))+(lava_get(1186))*(0x6c6171bf==(lava_get(1186))||0xbf71616c==(lava_get(1186)))+(lava_get(1187))*(0x6c6171be==(lava_get(1187))||0xbe71616c==(lava_get(1187)))+(lava_get(1188))*(0x6c6171bd==(lava_get(1188))||0xbd71616c==(lava_get(1188)))+(lava_get(1189))*(0x6c6171bc==(lava_get(1189))||0xbc71616c==(lava_get(1189)))+(lava_get(1190))*(0x6c6171bb==(lava_get(1190))||0xbb71616c==(lava_get(1190)))+(lava_get(1191))*(0x6c6171ba==(lava_get(1191))||0xba71616c==(lava_get(1191)))+(lava_get(1192))*(0x6c6171b9==(lava_get(1192))||0xb971616c==(lava_get(1192)))+(lava_get(1193))*(0x6c6171b8==(lava_get(1193))||0xb871616c==(lava_get(1193)))+(lava_get(1194))*(0x6c6171b7==(lava_get(1194))||0xb771616c==(lava_get(1194)))+(lava_get(1195))*(0x6c6171b6==(lava_get(1195))||0xb671616c==(lava_get(1195)))+(lava_get(1196))*(0x6c6171b5==(lava_get(1196))||0xb571616c==(lava_get(1196)))+(lava_get(1197))*(0x6c6171b4==(lava_get(1197))||0xb471616c==(lava_get(1197)))+(lava_get(1198))*(0x6c6171b3==(lava_get(1198))||0xb371616c==(lava_get(1198)))+(lava_get(1199))*(0x6c6171b2==(lava_get(1199))||0xb271616c==(lava_get(1199)))+(lava_get(1200))*(0x6c6171b1==(lava_get(1200))||0xb171616c==(lava_get(1200))))+(lava_get(985))*(0x6c617288==(lava_get(985))||0x8872616c==(lava_get(985)))+(lava_get(1025))*(0x6c617260==(lava_get(1025))||0x6072616c==(lava_get(1025)))+(lava_get(3093))*(0x6c616a4c==(lava_get(3093))||0x4c6a616c==(lava_get(3093)));if (((utmp_ent)))  {int lava_3205 = 0;
lava_3205 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3205 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3205 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3205 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3205,lava_3205);
int lava_3252 = 0;
lava_3252 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3252 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3252 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3252 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3252,lava_3252);
int lava_1772 = 0;
lava_1772 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1772 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1772 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1772 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1772,lava_1772);
int lava_1928 = 0;
lava_1928 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_1928 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_1928 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_1928 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(1928,lava_1928);
int lava_2173 = 0;
lava_2173 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2173 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2173 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2173 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2173,lava_2173);
int lava_2534 = 0;
lava_2534 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2534 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2534 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2534 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2534,lava_2534);
int lava_2987 = 0;
lava_2987 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2987 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2987 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2987 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2987,lava_2987);
int lava_3082 = 0;
lava_3082 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3082 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3082 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3082 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3082,lava_3082);
int lava_3148 = 0;
lava_3148 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3148 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3148 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3148 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3148,lava_3148);
int lava_2059 = 0;
lava_2059 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2059 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2059 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2059 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2059,lava_2059);
int lava_3502 = 0;
lava_3502 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3502 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3502 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3502 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3502,lava_3502);
int lava_3905 = 0;
lava_3905 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3905 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3905 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3905 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3905,lava_3905);
int lava_4103 = 0;
lava_4103 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4103 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4103 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4103 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4103,lava_4103);
int lava_4301 = 0;
lava_4301 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4301 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4301 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4301 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4301,lava_4301);
}if (((utmp_ent)))  {int lava_3206 = 0;
lava_3206 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3206 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3206 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3206 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3206,lava_3206);
int lava_3253 = 0;
lava_3253 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3253 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3253 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3253 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3253,lava_3253);
int lava_1774 = 0;
lava_1774 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1774 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1774 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1774 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1774,lava_1774);
int lava_1930 = 0;
lava_1930 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_1930 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_1930 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_1930 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(1930,lava_1930);
int lava_2175 = 0;
lava_2175 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2175 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2175 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2175 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2175,lava_2175);
int lava_2283 = 0;
lava_2283 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2283 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2283 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2283 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2283,lava_2283);
int lava_2536 = 0;
lava_2536 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2536 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2536 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2536 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2536,lava_2536);
int lava_2835 = 0;
lava_2835 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2835 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2835 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2835 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2835,lava_2835);
int lava_2989 = 0;
lava_2989 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2989 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2989 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2989 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2989,lava_2989);
int lava_3149 = 0;
lava_3149 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3149 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3149 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3149 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3149,lava_3149);
int lava_2061 = 0;
lava_2061 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2061 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2061 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2061 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2061,lava_2061);
int lava_3504 = 0;
lava_3504 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3504 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3504 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3504 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3504,lava_3504);
int lava_3907 = 0;
lava_3907 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3907 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3907 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3907 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3907,lava_3907);
int lava_4105 = 0;
lava_4105 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4105 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4105 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4105 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4105,lava_4105);
int lava_4303 = 0;
lava_4303 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4303 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4303 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4303 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4303,lava_4303);
}if (((utmp_ent)))  {int lava_3207 = 0;
lava_3207 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3207 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3207 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3207 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3207,lava_3207);
int lava_3254 = 0;
lava_3254 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3254 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3254 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3254 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3254,lava_3254);
int lava_1776 = 0;
lava_1776 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1776 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1776 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1776 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1776,lava_1776);
int lava_1932 = 0;
lava_1932 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_1932 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_1932 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_1932 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(1932,lava_1932);
int lava_2177 = 0;
lava_2177 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2177 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2177 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2177 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2177,lava_2177);
int lava_2285 = 0;
lava_2285 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2285 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2285 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2285 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2285,lava_2285);
int lava_2538 = 0;
lava_2538 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2538 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2538 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2538 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2538,lava_2538);
int lava_2837 = 0;
lava_2837 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2837 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2837 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2837 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2837,lava_2837);
int lava_2991 = 0;
lava_2991 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2991 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2991 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2991 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2991,lava_2991);
int lava_3150 = 0;
lava_3150 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3150 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3150 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3150 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3150,lava_3150);
int lava_2063 = 0;
lava_2063 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2063 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2063 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2063 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2063,lava_2063);
int lava_3506 = 0;
lava_3506 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3506 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3506 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3506 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3506,lava_3506);
int lava_3909 = 0;
lava_3909 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3909 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3909 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3909 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3909,lava_3909);
int lava_4107 = 0;
lava_4107 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4107 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4107 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4107 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4107,lava_4107);
int lava_4305 = 0;
lava_4305 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4305 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4305 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4305 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4305,lava_4305);
}if (((utmp_ent)))  {int lava_3208 = 0;
lava_3208 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3208 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3208 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3208 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3208,lava_3208);
int lava_3255 = 0;
lava_3255 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3255 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3255 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3255 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3255,lava_3255);
int lava_1778 = 0;
lava_1778 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1778 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1778 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1778 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1778,lava_1778);
int lava_1934 = 0;
lava_1934 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_1934 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_1934 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_1934 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(1934,lava_1934);
int lava_2179 = 0;
lava_2179 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2179 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2179 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2179 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2179,lava_2179);
int lava_2540 = 0;
lava_2540 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2540 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2540 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2540 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2540,lava_2540);
int lava_2993 = 0;
lava_2993 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2993 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2993 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2993 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2993,lava_2993);
int lava_3151 = 0;
lava_3151 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3151 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3151 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3151 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3151,lava_3151);
int lava_2065 = 0;
lava_2065 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2065 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2065 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2065 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2065,lava_2065);
int lava_3508 = 0;
lava_3508 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3508 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3508 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3508 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3508,lava_3508);
int lava_3911 = 0;
lava_3911 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3911 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3911 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3911 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3911,lava_3911);
int lava_4109 = 0;
lava_4109 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4109 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4109 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4109 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4109,lava_4109);
int lava_4307 = 0;
lava_4307 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4307 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4307 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4307 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4307,lava_4307);
}if (((utmp_ent)))  {int lava_2724 = 0;
lava_2724 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2724 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2724 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2724 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2724,lava_2724);
int lava_3209 = 0;
lava_3209 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3209 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3209 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3209 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3209,lava_3209);
int lava_3256 = 0;
lava_3256 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3256 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3256 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3256 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3256,lava_3256);
int lava_1780 = 0;
lava_1780 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1780 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1780 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1780 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1780,lava_1780);
int lava_1936 = 0;
lava_1936 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_1936 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_1936 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_1936 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(1936,lava_1936);
int lava_2181 = 0;
lava_2181 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2181 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2181 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2181 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2181,lava_2181);
int lava_2289 = 0;
lava_2289 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2289 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2289 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2289 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2289,lava_2289);
int lava_2542 = 0;
lava_2542 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2542 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2542 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2542 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2542,lava_2542);
int lava_2841 = 0;
lava_2841 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2841 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2841 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2841 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2841,lava_2841);
int lava_2995 = 0;
lava_2995 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2995 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2995 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2995 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2995,lava_2995);
int lava_3152 = 0;
lava_3152 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3152 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3152 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3152 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3152,lava_3152);
int lava_2067 = 0;
lava_2067 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2067 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2067 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2067 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2067,lava_2067);
int lava_3510 = 0;
lava_3510 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3510 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3510 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3510 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3510,lava_3510);
int lava_3913 = 0;
lava_3913 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3913 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3913 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3913 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3913,lava_3913);
int lava_4111 = 0;
lava_4111 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4111 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4111 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4111 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4111,lava_4111);
int lava_4309 = 0;
lava_4309 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4309 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4309 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4309 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4309,lava_4309);
}if (((utmp_ent)))  {int lava_3915 = 0;
lava_3915 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3915 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3915 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3915 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3915,lava_3915);
int lava_4113 = 0;
lava_4113 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4113 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4113 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4113 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4113,lava_4113);
int lava_4311 = 0;
lava_4311 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4311 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4311 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4311 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4311,lava_4311);
int lava_3210 = 0;
lava_3210 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3210 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3210 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3210 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3210,lava_3210);
int lava_3257 = 0;
lava_3257 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3257 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3257 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3257 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3257,lava_3257);
int lava_1782 = 0;
lava_1782 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1782 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1782 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1782 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1782,lava_1782);
int lava_1938 = 0;
lava_1938 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_1938 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_1938 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_1938 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(1938,lava_1938);
int lava_2183 = 0;
lava_2183 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2183 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2183 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2183 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2183,lava_2183);
int lava_2291 = 0;
lava_2291 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2291 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2291 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2291 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2291,lava_2291);
int lava_2544 = 0;
lava_2544 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2544 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2544 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2544 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2544,lava_2544);
int lava_2843 = 0;
lava_2843 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2843 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2843 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2843 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2843,lava_2843);
int lava_2997 = 0;
lava_2997 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2997 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2997 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2997 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2997,lava_2997);
int lava_3092 = 0;
lava_3092 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3092 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3092 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3092 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3092,lava_3092);
int lava_3153 = 0;
lava_3153 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3153 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3153 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3153 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3153,lava_3153);
int lava_2069 = 0;
lava_2069 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2069 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2069 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2069 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2069,lava_2069);
int lava_3512 = 0;
lava_3512 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3512 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3512 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3512 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3512,lava_3512);
}if (((utmp_ent)))  {int lava_3211 = 0;
lava_3211 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3211 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3211 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3211 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3211,lava_3211);
int lava_3258 = 0;
lava_3258 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3258 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3258 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3258 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3258,lava_3258);
int lava_1784 = 0;
lava_1784 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1784 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1784 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1784 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1784,lava_1784);
int lava_1940 = 0;
lava_1940 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_1940 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_1940 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_1940 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(1940,lava_1940);
int lava_2185 = 0;
lava_2185 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2185 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2185 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2185 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2185,lava_2185);
int lava_2546 = 0;
lava_2546 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2546 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2546 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2546 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2546,lava_2546);
int lava_2999 = 0;
lava_2999 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2999 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2999 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2999 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2999,lava_2999);
int lava_3154 = 0;
lava_3154 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3154 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3154 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3154 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3154,lava_3154);
int lava_2071 = 0;
lava_2071 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2071 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2071 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2071 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2071,lava_2071);
int lava_3514 = 0;
lava_3514 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3514 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3514 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3514 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3514,lava_3514);
int lava_3917 = 0;
lava_3917 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3917 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3917 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3917 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3917,lava_3917);
int lava_4115 = 0;
lava_4115 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4115 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4115 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4115 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4115,lava_4115);
int lava_4313 = 0;
lava_4313 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4313 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4313 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4313 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4313,lava_4313);
}if (((utmp_ent)))  {int lava_3212 = 0;
lava_3212 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3212 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3212 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3212 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3212,lava_3212);
int lava_3259 = 0;
lava_3259 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3259 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3259 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3259 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3259,lava_3259);
int lava_1786 = 0;
lava_1786 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1786 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1786 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1786 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1786,lava_1786);
int lava_1942 = 0;
lava_1942 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_1942 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_1942 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_1942 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(1942,lava_1942);
int lava_2187 = 0;
lava_2187 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2187 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2187 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2187 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2187,lava_2187);
int lava_2295 = 0;
lava_2295 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2295 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2295 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2295 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2295,lava_2295);
int lava_2548 = 0;
lava_2548 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2548 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2548 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2548 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2548,lava_2548);
int lava_2847 = 0;
lava_2847 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2847 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2847 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2847 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2847,lava_2847);
int lava_3001 = 0;
lava_3001 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3001 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3001 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3001 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3001,lava_3001);
int lava_3155 = 0;
lava_3155 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3155 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3155 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3155 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3155,lava_3155);
int lava_2073 = 0;
lava_2073 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2073 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2073 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2073 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2073,lava_2073);
int lava_3919 = 0;
lava_3919 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3919 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3919 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3919 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3919,lava_3919);
int lava_4117 = 0;
lava_4117 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4117 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4117 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4117 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4117,lava_4117);
int lava_4315 = 0;
lava_4315 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4315 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4315 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4315 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4315,lava_4315);
int lava_3516 = 0;
lava_3516 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3516 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3516 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3516 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3516,lava_3516);
}if (((utmp_ent)))  {int lava_3213 = 0;
lava_3213 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3213 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3213 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3213 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3213,lava_3213);
int lava_3260 = 0;
lava_3260 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3260 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3260 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3260 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3260,lava_3260);
int lava_1788 = 0;
lava_1788 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1788 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1788 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1788 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1788,lava_1788);
int lava_1944 = 0;
lava_1944 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_1944 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_1944 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_1944 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(1944,lava_1944);
int lava_2189 = 0;
lava_2189 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2189 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2189 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2189 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2189,lava_2189);
int lava_2297 = 0;
lava_2297 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2297 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2297 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2297 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2297,lava_2297);
int lava_2550 = 0;
lava_2550 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2550 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2550 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2550 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2550,lava_2550);
int lava_2849 = 0;
lava_2849 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2849 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2849 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2849 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2849,lava_2849);
int lava_3003 = 0;
lava_3003 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3003 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3003 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3003 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3003,lava_3003);
int lava_3156 = 0;
lava_3156 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3156 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3156 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3156 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3156,lava_3156);
int lava_2075 = 0;
lava_2075 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2075 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2075 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2075 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2075,lava_2075);
int lava_3518 = 0;
lava_3518 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3518 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3518 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3518 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3518,lava_3518);
int lava_3921 = 0;
lava_3921 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3921 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3921 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3921 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3921,lava_3921);
int lava_4119 = 0;
lava_4119 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4119 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4119 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4119 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4119,lava_4119);
int lava_4317 = 0;
lava_4317 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4317 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4317 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4317 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4317,lava_4317);
}kbcieiubweuhc278722862;}), idlestr+(lava_get(994))*(0x6c61727f==(lava_get(994))||0x7f72616c==(lava_get(994)))+(lava_get(1026))*(0x6c61725f==(lava_get(1026))||0x5f72616c==(lava_get(1026)))+(lava_get(3099))*(0x6c616a46==(lava_get(3099))||0x466a616c==(lava_get(3099))), pidstr+(lava_get(995))*(0x6c61727e==(lava_get(995))||0x7e72616c==(lava_get(995)))+(lava_get(3545))*(0x6c616888==(lava_get(3545))||0x8868616c==(lava_get(3545)))+(lava_get(1049))*(0x6c617248==(lava_get(1049))||0x4872616c==(lava_get(1049))),
              hoststr ? hoststr : ""+(lava_get(3061))*(0x6c616a6c==(lava_get(3061))||0x6c6a616c==(lava_get(3061)))+(lava_get(3411))*(0x6c61690e==(lava_get(3411))||0xe69616c==(lava_get(3411)))+(lava_get(3104))*(0x6c616a41==(lava_get(3104))||0x416a616c==(lava_get(3104))), ""+(lava_get(996))*(0x6c61727d==(lava_get(996))||0x7d72616c==(lava_get(996)))+(lava_get(1038))*(0x6c617253==(lava_get(1038))||0x5372616c==(lava_get(1038)))+(lava_get(1054))*(0x6c617243==(lava_get(1054))||0x4372616c==(lava_get(1054))));if (((hoststr)) && ((hoststr)))  {int lava_3902 = 0;
lava_3902 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_3902 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_3902 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_3902 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(3902,lava_3902);
int lava_4100 = 0;
lava_4100 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_4100 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_4100 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_4100 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(4100,lava_4100);
int lava_4298 = 0;
lava_4298 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_4298 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_4298 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_4298 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(4298,lava_4298);
int lava_3499 = 0;
lava_3499 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_3499 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_3499 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_3499 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(3499,lava_3499);
int lava_3204 = 0;
lava_3204 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_3204 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_3204 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_3204 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(3204,lava_3204);
int lava_3349 = 0;
lava_3349 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_3349 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_3349 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_3349 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(3349,lava_3349);
int lava_3376 = 0;
lava_3376 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_3376 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_3376 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_3376 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(3376,lava_3376);
int lava_2532 = 0;
lava_2532 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_2532 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_2532 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_2532 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(2532,lava_2532);
int lava_2985 = 0;
lava_2985 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_2985 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_2985 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_2985 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(2985,lava_2985);
int lava_3147 = 0;
lava_3147 |= ((unsigned char *) (hoststr))[1] << (0*8);lava_3147 |= ((unsigned char *) (hoststr))[2] << (1*8);lava_3147 |= ((unsigned char *) (hoststr))[3] << (2*8);lava_3147 |= ((unsigned char *) (hoststr))[4] << (3*8);lava_set(3147,lava_3147);
}if (((utmp_ent)))  {int lava_3194 = 0;
lava_3194 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3194 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3194 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3194 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3194,lava_3194);
int lava_3241 = 0;
lava_3241 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3241 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3241 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3241 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3241,lava_3241);
int lava_3339 = 0;
lava_3339 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3339 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3339 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3339 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3339,lava_3339);
int lava_3366 = 0;
lava_3366 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3366 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3366 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3366 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3366,lava_3366);
int lava_2153 = 0;
lava_2153 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2153 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2153 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2153 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2153,lava_2153);
int lava_2514 = 0;
lava_2514 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2514 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2514 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2514 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2514,lava_2514);
int lava_2967 = 0;
lava_2967 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2967 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2967 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2967 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2967,lava_2967);
int lava_3137 = 0;
lava_3137 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3137 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3137 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3137 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3137,lava_3137);
int lava_2039 = 0;
lava_2039 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_2039 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_2039 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_2039 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(2039,lava_2039);
int lava_3480 = 0;
lava_3480 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3480 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3480 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3480 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3480,lava_3480);
int lava_3883 = 0;
lava_3883 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_3883 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_3883 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_3883 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(3883,lava_3883);
int lava_4081 = 0;
lava_4081 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4081 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4081 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4081 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4081,lava_4081);
int lava_4279 = 0;
lava_4279 |= ((unsigned char *) &((utmp_ent)->__unused))[0] << (0*8);lava_4279 |= ((unsigned char *) &((utmp_ent)->__unused))[1] << (1*8);lava_4279 |= ((unsigned char *) &((utmp_ent)->__unused))[2] << (2*8);lava_4279 |= ((unsigned char *) &((utmp_ent)->__unused))[3] << (3*8);lava_set(4279,lava_4279);
}if (((utmp_ent)))  {int lava_3195 = 0;
lava_3195 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3195 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3195 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3195 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3195,lava_3195);
int lava_3242 = 0;
lava_3242 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3242 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3242 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3242 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3242,lava_3242);
int lava_3340 = 0;
lava_3340 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3340 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3340 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3340 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3340,lava_3340);
int lava_3367 = 0;
lava_3367 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3367 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3367 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3367 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3367,lava_3367);
int lava_2155 = 0;
lava_2155 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2155 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2155 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2155 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2155,lava_2155);
int lava_2263 = 0;
lava_2263 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2263 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2263 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2263 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2263,lava_2263);
int lava_2516 = 0;
lava_2516 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2516 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2516 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2516 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2516,lava_2516);
int lava_2815 = 0;
lava_2815 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2815 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2815 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2815 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2815,lava_2815);
int lava_2969 = 0;
lava_2969 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2969 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2969 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2969 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2969,lava_2969);
int lava_3138 = 0;
lava_3138 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3138 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3138 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3138 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3138,lava_3138);
int lava_2041 = 0;
lava_2041 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_2041 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_2041 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_2041 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(2041,lava_2041);
int lava_3482 = 0;
lava_3482 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3482 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3482 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3482 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3482,lava_3482);
int lava_3885 = 0;
lava_3885 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_3885 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_3885 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_3885 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(3885,lava_3885);
int lava_4083 = 0;
lava_4083 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4083 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4083 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4083 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4083,lava_4083);
int lava_4281 = 0;
lava_4281 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[0] << (0*8);lava_4281 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[1] << (1*8);lava_4281 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[2] << (2*8);lava_4281 |= ((unsigned char *) &((utmp_ent)->ut_addr_v6))[3] << (3*8);lava_set(4281,lava_4281);
}if (((utmp_ent)))  {int lava_3196 = 0;
lava_3196 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3196 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3196 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3196 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3196,lava_3196);
int lava_3243 = 0;
lava_3243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3243 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3243,lava_3243);
int lava_3341 = 0;
lava_3341 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3341 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3341 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3341 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3341,lava_3341);
int lava_3368 = 0;
lava_3368 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3368 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3368 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3368 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3368,lava_3368);
int lava_2157 = 0;
lava_2157 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2157 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2157 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2157 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2157,lava_2157);
int lava_2265 = 0;
lava_2265 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2265 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2265 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2265 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2265,lava_2265);
int lava_2518 = 0;
lava_2518 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2518 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2518 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2518 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2518,lava_2518);
int lava_2817 = 0;
lava_2817 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2817 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2817 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2817 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2817,lava_2817);
int lava_2971 = 0;
lava_2971 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2971 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2971 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2971 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2971,lava_2971);
int lava_3139 = 0;
lava_3139 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3139 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3139 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3139 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3139,lava_3139);
int lava_2043 = 0;
lava_2043 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_2043 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_2043 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_2043 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(2043,lava_2043);
int lava_3484 = 0;
lava_3484 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3484 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3484 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3484 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3484,lava_3484);
int lava_3887 = 0;
lava_3887 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_3887 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_3887 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_3887 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(3887,lava_3887);
int lava_4085 = 0;
lava_4085 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4085 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4085 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4085 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4085,lava_4085);
int lava_4283 = 0;
lava_4283 |= ((unsigned char *) &((utmp_ent)->ut_exit))[0] << (0*8);lava_4283 |= ((unsigned char *) &((utmp_ent)->ut_exit))[1] << (1*8);lava_4283 |= ((unsigned char *) &((utmp_ent)->ut_exit))[2] << (2*8);lava_4283 |= ((unsigned char *) &((utmp_ent)->ut_exit))[3] << (3*8);lava_set(4283,lava_4283);
}if (((utmp_ent)))  {int lava_3197 = 0;
lava_3197 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3197 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3197 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3197 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3197,lava_3197);
int lava_3244 = 0;
lava_3244 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3244 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3244 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3244 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3244,lava_3244);
int lava_3342 = 0;
lava_3342 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3342 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3342 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3342 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3342,lava_3342);
int lava_3369 = 0;
lava_3369 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3369 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3369 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3369 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3369,lava_3369);
int lava_2159 = 0;
lava_2159 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2159 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2159 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2159 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2159,lava_2159);
int lava_2520 = 0;
lava_2520 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2520 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2520 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2520 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2520,lava_2520);
int lava_2973 = 0;
lava_2973 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2973 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2973 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2973 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2973,lava_2973);
int lava_3140 = 0;
lava_3140 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3140 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3140 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3140 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3140,lava_3140);
int lava_2045 = 0;
lava_2045 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_2045 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_2045 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_2045 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(2045,lava_2045);
int lava_3486 = 0;
lava_3486 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3486 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3486 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3486 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3486,lava_3486);
int lava_3889 = 0;
lava_3889 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_3889 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_3889 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_3889 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(3889,lava_3889);
int lava_4087 = 0;
lava_4087 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4087 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4087 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4087 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4087,lava_4087);
int lava_4285 = 0;
lava_4285 |= ((unsigned char *) &((utmp_ent)->ut_id))[0] << (0*8);lava_4285 |= ((unsigned char *) &((utmp_ent)->ut_id))[1] << (1*8);lava_4285 |= ((unsigned char *) &((utmp_ent)->ut_id))[2] << (2*8);lava_4285 |= ((unsigned char *) &((utmp_ent)->ut_id))[3] << (3*8);lava_set(4285,lava_4285);
}if (((utmp_ent)))  {int lava_3488 = 0;
lava_3488 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3488 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3488 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3488 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3488,lava_3488);
int lava_3891 = 0;
lava_3891 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3891 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3891 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3891 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3891,lava_3891);
int lava_4089 = 0;
lava_4089 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4089 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4089 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4089 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4089,lava_4089);
int lava_4287 = 0;
lava_4287 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_4287 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_4287 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_4287 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(4287,lava_4287);
int lava_2704 = 0;
lava_2704 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2704 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2704 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2704 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2704,lava_2704);
int lava_3198 = 0;
lava_3198 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3198 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3198 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3198 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3198,lava_3198);
int lava_3245 = 0;
lava_3245 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3245 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3245 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3245 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3245,lava_3245);
int lava_3343 = 0;
lava_3343 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3343 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3343 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3343 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3343,lava_3343);
int lava_3370 = 0;
lava_3370 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3370 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3370 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3370 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3370,lava_3370);
int lava_2161 = 0;
lava_2161 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2161 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2161 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2161 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2161,lava_2161);
int lava_2269 = 0;
lava_2269 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2269 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2269 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2269 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2269,lava_2269);
int lava_2522 = 0;
lava_2522 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2522 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2522 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2522 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2522,lava_2522);
int lava_2821 = 0;
lava_2821 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2821 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2821 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2821 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2821,lava_2821);
int lava_2975 = 0;
lava_2975 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2975 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2975 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2975 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2975,lava_2975);
int lava_3074 = 0;
lava_3074 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3074 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3074 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3074 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3074,lava_3074);
int lava_3141 = 0;
lava_3141 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_3141 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_3141 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_3141 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(3141,lava_3141);
int lava_2047 = 0;
lava_2047 |= ((unsigned char *) &((utmp_ent)->ut_line))[0] << (0*8);lava_2047 |= ((unsigned char *) &((utmp_ent)->ut_line))[1] << (1*8);lava_2047 |= ((unsigned char *) &((utmp_ent)->ut_line))[2] << (2*8);lava_2047 |= ((unsigned char *) &((utmp_ent)->ut_line))[3] << (3*8);lava_set(2047,lava_2047);
}if (((utmp_ent)))  {int lava_3893 = 0;
lava_3893 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3893 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3893 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3893 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3893,lava_3893);
int lava_4091 = 0;
lava_4091 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4091 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4091 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4091 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4091,lava_4091);
int lava_4289 = 0;
lava_4289 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_4289 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_4289 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_4289 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(4289,lava_4289);
int lava_3199 = 0;
lava_3199 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3199 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3199 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3199 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3199,lava_3199);
int lava_3246 = 0;
lava_3246 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3246 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3246 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3246 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3246,lava_3246);
int lava_3344 = 0;
lava_3344 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3344 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3344 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3344 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3344,lava_3344);
int lava_3371 = 0;
lava_3371 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3371 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3371 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3371 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3371,lava_3371);
int lava_2163 = 0;
lava_2163 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2163 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2163 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2163 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2163,lava_2163);
int lava_2271 = 0;
lava_2271 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2271 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2271 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2271 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2271,lava_2271);
int lava_2524 = 0;
lava_2524 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2524 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2524 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2524 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2524,lava_2524);
int lava_2823 = 0;
lava_2823 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2823 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2823 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2823 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2823,lava_2823);
int lava_2977 = 0;
lava_2977 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2977 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2977 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2977 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2977,lava_2977);
int lava_3142 = 0;
lava_3142 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3142 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3142 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3142 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3142,lava_3142);
int lava_2049 = 0;
lava_2049 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_2049 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_2049 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_2049 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(2049,lava_2049);
int lava_3490 = 0;
lava_3490 |= ((unsigned char *) &((utmp_ent)->ut_pid))[0] << (0*8);lava_3490 |= ((unsigned char *) &((utmp_ent)->ut_pid))[1] << (1*8);lava_3490 |= ((unsigned char *) &((utmp_ent)->ut_pid))[2] << (2*8);lava_3490 |= ((unsigned char *) &((utmp_ent)->ut_pid))[3] << (3*8);lava_set(3490,lava_3490);
}if (((utmp_ent)))  {int lava_3200 = 0;
lava_3200 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3200 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3200 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3200 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3200,lava_3200);
int lava_3247 = 0;
lava_3247 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3247 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3247 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3247 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3247,lava_3247);
int lava_3345 = 0;
lava_3345 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3345 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3345 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3345 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3345,lava_3345);
int lava_3372 = 0;
lava_3372 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3372 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3372 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3372 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3372,lava_3372);
int lava_2165 = 0;
lava_2165 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2165 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2165 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2165 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2165,lava_2165);
int lava_2526 = 0;
lava_2526 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2526 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2526 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2526 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2526,lava_2526);
int lava_2979 = 0;
lava_2979 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2979 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2979 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2979 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2979,lava_2979);
int lava_3143 = 0;
lava_3143 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3143 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3143 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3143 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3143,lava_3143);
int lava_2051 = 0;
lava_2051 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_2051 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_2051 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_2051 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(2051,lava_2051);
int lava_3492 = 0;
lava_3492 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3492 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3492 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3492 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3492,lava_3492);
int lava_3895 = 0;
lava_3895 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_3895 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_3895 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_3895 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(3895,lava_3895);
int lava_4093 = 0;
lava_4093 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4093 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4093 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4093 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4093,lava_4093);
int lava_4291 = 0;
lava_4291 |= ((unsigned char *) &((utmp_ent)->ut_session))[0] << (0*8);lava_4291 |= ((unsigned char *) &((utmp_ent)->ut_session))[1] << (1*8);lava_4291 |= ((unsigned char *) &((utmp_ent)->ut_session))[2] << (2*8);lava_4291 |= ((unsigned char *) &((utmp_ent)->ut_session))[3] << (3*8);lava_set(4291,lava_4291);
}if (((utmp_ent)))  {int lava_3201 = 0;
lava_3201 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3201 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3201 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3201 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3201,lava_3201);
int lava_3248 = 0;
lava_3248 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3248 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3248 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3248 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3248,lava_3248);
int lava_3346 = 0;
lava_3346 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3346 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3346 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3346 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3346,lava_3346);
int lava_3373 = 0;
lava_3373 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3373 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3373 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3373 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3373,lava_3373);
int lava_2167 = 0;
lava_2167 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2167 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2167 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2167 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2167,lava_2167);
int lava_2275 = 0;
lava_2275 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2275 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2275 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2275 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2275,lava_2275);
int lava_2528 = 0;
lava_2528 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2528 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2528 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2528 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2528,lava_2528);
int lava_2827 = 0;
lava_2827 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2827 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2827 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2827 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2827,lava_2827);
int lava_2981 = 0;
lava_2981 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2981 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2981 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2981 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2981,lava_2981);
int lava_3144 = 0;
lava_3144 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3144 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3144 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3144 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3144,lava_3144);
int lava_2053 = 0;
lava_2053 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_2053 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_2053 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_2053 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(2053,lava_2053);
int lava_3897 = 0;
lava_3897 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3897 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3897 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3897 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3897,lava_3897);
int lava_4095 = 0;
lava_4095 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4095 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4095 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4095 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4095,lava_4095);
int lava_4293 = 0;
lava_4293 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_4293 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_4293 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_4293 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(4293,lava_4293);
int lava_3494 = 0;
lava_3494 |= ((unsigned char *) &((utmp_ent)->ut_tv))[0] << (0*8);lava_3494 |= ((unsigned char *) &((utmp_ent)->ut_tv))[1] << (1*8);lava_3494 |= ((unsigned char *) &((utmp_ent)->ut_tv))[2] << (2*8);lava_3494 |= ((unsigned char *) &((utmp_ent)->ut_tv))[3] << (3*8);lava_set(3494,lava_3494);
}if (((utmp_ent)))  {int lava_3496 = 0;
lava_3496 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3496 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3496 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3496 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3496,lava_3496);
int lava_3899 = 0;
lava_3899 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3899 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3899 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3899 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3899,lava_3899);
int lava_4097 = 0;
lava_4097 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4097 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4097 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4097 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4097,lava_4097);
int lava_4295 = 0;
lava_4295 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_4295 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_4295 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_4295 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(4295,lava_4295);
int lava_3202 = 0;
lava_3202 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3202 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3202 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3202 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3202,lava_3202);
int lava_3249 = 0;
lava_3249 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3249 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3249 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3249 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3249,lava_3249);
int lava_3347 = 0;
lava_3347 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3347 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3347 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3347 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3347,lava_3347);
int lava_3374 = 0;
lava_3374 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3374 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3374 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3374 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3374,lava_3374);
int lava_2169 = 0;
lava_2169 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2169 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2169 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2169 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2169,lava_2169);
int lava_2277 = 0;
lava_2277 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2277 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2277 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2277 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2277,lava_2277);
int lava_2530 = 0;
lava_2530 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2530 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2530 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2530 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2530,lava_2530);
int lava_2829 = 0;
lava_2829 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2829 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2829 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2829 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2829,lava_2829);
int lava_2983 = 0;
lava_2983 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2983 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2983 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2983 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2983,lava_2983);
int lava_3145 = 0;
lava_3145 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_3145 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_3145 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_3145 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(3145,lava_3145);
int lava_2055 = 0;
lava_2055 |= ((unsigned char *) &((utmp_ent)->ut_user))[0] << (0*8);lava_2055 |= ((unsigned char *) &((utmp_ent)->ut_user))[1] << (1*8);lava_2055 |= ((unsigned char *) &((utmp_ent)->ut_user))[2] << (2*8);lava_2055 |= ((unsigned char *) &((utmp_ent)->ut_user))[3] << (3*8);lava_set(2055,lava_2055);
}});
}

void
print_boottime (const STRUCT_UTMP *utmp_ent)
{
  print_line (-1, "", ' ', -1, _("system boot"),
              time_string (utmp_ent), "", "", "", "");
}

char *
make_id_equals_comment (STRUCT_UTMP const *utmp_ent)
{
  char *comment = xmalloc (strlen (_("id=")) + sizeof UT_ID (utmp_ent) + 1);

  strcpy (comment, _("id="));
  strncat (comment, UT_ID (utmp_ent), sizeof UT_ID (utmp_ent));
  return comment;
}

void
print_deadprocs (const STRUCT_UTMP *utmp_ent)
{
  static char *exitstr;
  char *comment = make_id_equals_comment (utmp_ent);
  PIDSTR_DECL_AND_INIT (pidstr, utmp_ent);

  if (!exitstr)
    exitstr = xmalloc (strlen (_("term="))
                       + INT_STRLEN_BOUND (UT_EXIT_E_TERMINATION (utmp_ent)) + 1
                       + strlen (_("exit="))
                       + INT_STRLEN_BOUND (UT_EXIT_E_EXIT (utmp_ent))
                       + 1);
  sprintf (exitstr, "%s%d %s%d", _("term="), UT_EXIT_E_TERMINATION (utmp_ent),
           _("exit="), UT_EXIT_E_EXIT (utmp_ent));

  /* FIXME: add idle time? */

  print_line (-1, "", ' ', sizeof utmp_ent->ut_line, utmp_ent->ut_line,
              time_string (utmp_ent), "", pidstr, comment, exitstr);
  free (comment);
}

void
print_login (const STRUCT_UTMP *utmp_ent)
{
  char *comment = make_id_equals_comment (utmp_ent);
  PIDSTR_DECL_AND_INIT (pidstr, utmp_ent);

  /* FIXME: add idle time? */

  print_line (-1, _("LOGIN"), ' ', sizeof utmp_ent->ut_line, utmp_ent->ut_line,
              time_string (utmp_ent), "", pidstr, comment, "");
  free (comment);
}

void
print_initspawn (const STRUCT_UTMP *utmp_ent)
{
  char *comment = make_id_equals_comment (utmp_ent);
  PIDSTR_DECL_AND_INIT (pidstr, utmp_ent);

  print_line (-1, "", ' ', sizeof utmp_ent->ut_line, utmp_ent->ut_line,
              time_string (utmp_ent), "", pidstr, comment, "");
  free (comment);
}

void
print_clockchange (const STRUCT_UTMP *utmp_ent)
{
  /* FIXME: handle NEW_TIME & OLD_TIME both */
  print_line (-1, "", ' ', -1, _("clock change"),
              time_string (utmp_ent), "", "", "", "");
}

void
print_runlevel (const STRUCT_UTMP *utmp_ent)
{
  static char *runlevline, *comment;
  unsigned char last = UT_PID (utmp_ent) / 256;
  unsigned char curr = UT_PID (utmp_ent) % 256;

  if (!runlevline)
    runlevline = xmalloc (strlen (_("run-level")) + 3);
  sprintf (runlevline, "%s %c", _("run-level"), curr);

  if (!comment)
    comment = xmalloc (strlen (_("last=")) + 2);
  sprintf (comment, "%s%c", _("last="), (last == 'N') ? 'S' : last);

  print_line (-1, "", ' ', -1, runlevline, time_string (utmp_ent),
              "", "", c_isprint (last) ? comment : "", "");

  return;
}

/* Print the username of each valid entry and the number of valid entries
   in UTMP_BUF, which should have N elements. */
void
list_entries_who (size_t n, const STRUCT_UTMP *utmp_buf)
{
  unsigned long int entries = 0;
  char const *separator = "";

  while (n--)
    {
      if (IS_USER_PROCESS (utmp_buf))
        {
          char *trimmed_name;

          trimmed_name = extract_trimmed_name (utmp_buf);

          printf ("%s%s", separator, trimmed_name);
          free (trimmed_name);
          separator = " ";
          entries++;
        }
      utmp_buf++;
    }
  printf (_("\n# users=%lu\n"), entries);
}

void
print_heading (void)
{
  print_line (-1, _("NAME"), ' ', -1, _("LINE"), _("TIME"), _("IDLE"),
              _("PID"), _("COMMENT"), _("EXIT"));
}

/* Display UTMP_BUF, which should have N entries. */
void
scan_entries (size_t n, const STRUCT_UTMP *utmp_buf)
{
  char *ttyname_b IF_LINT ( = NULL);
  time_t boottime = TYPE_MINIMUM (time_t);

  if (include_heading)
    print_heading ();

  if (my_line_only)
    {
      ttyname_b = ttyname (STDIN_FILENO);
      if (!ttyname_b)
        return;
      if (STRNCMP_LIT (ttyname_b, DEV_DIR_WITH_TRAILING_SLASH) == 0)
        ttyname_b += DEV_DIR_LEN;	/* Discard /dev/ prefix.  */
    }

  while (n--)
    {
      if (!my_line_only
          || STREQ_LEN (ttyname_b, utmp_buf->ut_line,
                        sizeof (utmp_buf->ut_line)))
        {
          if (need_users && IS_USER_PROCESS (utmp_buf))
            ({int lava_1308 = 0;
            lava_1308 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_1308 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_1308 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_1308 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(1308,lava_1308);
            int lava_1444 = 0;
            lava_1444 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_1444 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_1444 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_1444 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(1444,lava_1444);
            int lava_1798 = 0;
            lava_1798 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_1798 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_1798 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_1798 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(1798,lava_1798);
            int lava_1954 = 0;
            lava_1954 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_1954 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_1954 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_1954 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(1954,lava_1954);
            int lava_345 = 0;
            lava_345 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_345 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_345 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_345 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(345,lava_345);
            int lava_521 = 0;
            lava_521 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_521 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_521 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_521 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(521,lava_521);
            int lava_624 = 0;
            lava_624 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_624 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_624 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_624 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(624,lava_624);
            int lava_729 = 0;
            lava_729 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_729 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_729 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_729 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(729,lava_729);
            int lava_1182 = 0;
            lava_1182 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_1182 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_1182 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_1182 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(1182,lava_1182);
            int lava_2751 = 0;
            lava_2751 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_2751 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_2751 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_2751 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(2751,lava_2751);
            int lava_2569 = 0;
            lava_2569 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_2569 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_2569 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_2569 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(2569,lava_2569);
            int lava_3022 = 0;
            lava_3022 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_3022 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_3022 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_3022 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(3022,lava_3022);
            int lava_3940 = 0;
            lava_3940 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_3940 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_3940 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_3940 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(3940,lava_3940);
            int lava_4138 = 0;
            lava_4138 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_4138 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_4138 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_4138 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(4138,lava_4138);
            int lava_4336 = 0;
            lava_4336 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_4336 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_4336 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_4336 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(4336,lava_4336);
            if (((utmp_buf)))  {int lava_1299 = 0;
            lava_1299 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1299 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1299 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1299 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1299,lava_1299);
            int lava_1789 = 0;
            lava_1789 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1789 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1789 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1789 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1789,lava_1789);
            int lava_1945 = 0;
            lava_1945 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1945 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1945 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1945 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1945,lava_1945);
            int lava_336 = 0;
            lava_336 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_336 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_336 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_336 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(336,lava_336);
            int lava_512 = 0;
            lava_512 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_512 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_512 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_512 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(512,lava_512);
            int lava_615 = 0;
            lava_615 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_615 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_615 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_615 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(615,lava_615);
            int lava_720 = 0;
            lava_720 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_720 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_720 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_720 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(720,lava_720);
            int lava_1173 = 0;
            lava_1173 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1173 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1173 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1173 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1173,lava_1173);
            int lava_2551 = 0;
            lava_2551 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_2551 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_2551 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_2551 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(2551,lava_2551);
            int lava_3004 = 0;
            lava_3004 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3004 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3004 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3004 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3004,lava_3004);
            int lava_3922 = 0;
            lava_3922 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3922 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3922 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3922 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3922,lava_3922);
            int lava_4120 = 0;
            lava_4120 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_4120 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_4120 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_4120 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(4120,lava_4120);
            int lava_4318 = 0;
            lava_4318 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_4318 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_4318 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_4318 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(4318,lava_4318);
            }if (((utmp_buf)))  {int lava_1300 = 0;
            lava_1300 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1300 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1300 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1300 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1300,lava_1300);
            int lava_1436 = 0;
            lava_1436 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1436 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1436 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1436 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1436,lava_1436);
            int lava_1790 = 0;
            lava_1790 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1790 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1790 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1790 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1790,lava_1790);
            int lava_1946 = 0;
            lava_1946 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1946 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1946 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1946 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1946,lava_1946);
            int lava_616 = 0;
            lava_616 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_616 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_616 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_616 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(616,lava_616);
            int lava_721 = 0;
            lava_721 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_721 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_721 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_721 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(721,lava_721);
            int lava_1049 = 0;
            lava_1049 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1049 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1049 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1049 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1049,lava_1049);
            int lava_1174 = 0;
            lava_1174 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1174 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1174 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1174 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1174,lava_1174);
            int lava_2553 = 0;
            lava_2553 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_2553 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_2553 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_2553 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(2553,lava_2553);
            int lava_3006 = 0;
            lava_3006 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3006 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3006 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3006 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3006,lava_3006);
            int lava_3924 = 0;
            lava_3924 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3924 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3924 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3924 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3924,lava_3924);
            int lava_4122 = 0;
            lava_4122 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_4122 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_4122 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_4122 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(4122,lava_4122);
            int lava_4320 = 0;
            lava_4320 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_4320 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_4320 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_4320 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(4320,lava_4320);
            }if (((utmp_buf)))  {int lava_1301 = 0;
            lava_1301 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1301 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1301 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1301 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1301,lava_1301);
            int lava_1791 = 0;
            lava_1791 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1791 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1791 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1791 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1791,lava_1791);
            int lava_1947 = 0;
            lava_1947 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1947 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1947 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1947 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1947,lava_1947);
            int lava_338 = 0;
            lava_338 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_338 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_338 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_338 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(338,lava_338);
            int lava_514 = 0;
            lava_514 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_514 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_514 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_514 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(514,lava_514);
            int lava_617 = 0;
            lava_617 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_617 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_617 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_617 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(617,lava_617);
            int lava_722 = 0;
            lava_722 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_722 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_722 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_722 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(722,lava_722);
            int lava_1175 = 0;
            lava_1175 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1175 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1175 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1175 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1175,lava_1175);
            int lava_2555 = 0;
            lava_2555 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_2555 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_2555 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_2555 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(2555,lava_2555);
            int lava_3008 = 0;
            lava_3008 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3008 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3008 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3008 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3008,lava_3008);
            int lava_3926 = 0;
            lava_3926 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3926 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3926 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3926 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3926,lava_3926);
            int lava_4124 = 0;
            lava_4124 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_4124 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_4124 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_4124 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(4124,lava_4124);
            int lava_4322 = 0;
            lava_4322 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_4322 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_4322 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_4322 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(4322,lava_4322);
            }if (((utmp_buf)))  {int lava_1302 = 0;
            lava_1302 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1302 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1302 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1302 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1302,lava_1302);
            int lava_1438 = 0;
            lava_1438 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1438 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1438 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1438 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1438,lava_1438);
            int lava_1792 = 0;
            lava_1792 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1792 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1792 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1792 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1792,lava_1792);
            int lava_1948 = 0;
            lava_1948 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1948 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1948 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1948 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1948,lava_1948);
            int lava_339 = 0;
            lava_339 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_339 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_339 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_339 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(339,lava_339);
            int lava_515 = 0;
            lava_515 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_515 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_515 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_515 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(515,lava_515);
            int lava_618 = 0;
            lava_618 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_618 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_618 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_618 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(618,lava_618);
            int lava_723 = 0;
            lava_723 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_723 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_723 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_723 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(723,lava_723);
            int lava_1176 = 0;
            lava_1176 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1176 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1176 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1176 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1176,lava_1176);
            int lava_2557 = 0;
            lava_2557 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_2557 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_2557 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_2557 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(2557,lava_2557);
            int lava_3010 = 0;
            lava_3010 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3010 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3010 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3010 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3010,lava_3010);
            int lava_3928 = 0;
            lava_3928 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3928 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3928 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3928 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3928,lava_3928);
            int lava_4126 = 0;
            lava_4126 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_4126 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_4126 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_4126 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(4126,lava_4126);
            int lava_4324 = 0;
            lava_4324 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_4324 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_4324 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_4324 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(4324,lava_4324);
            }if (((utmp_buf)))  {int lava_1303 = 0;
            lava_1303 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1303 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1303 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1303 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1303,lava_1303);
            int lava_1793 = 0;
            lava_1793 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1793 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1793 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1793 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1793,lava_1793);
            int lava_1949 = 0;
            lava_1949 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1949 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1949 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1949 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1949,lava_1949);
            int lava_619 = 0;
            lava_619 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_619 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_619 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_619 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(619,lava_619);
            int lava_724 = 0;
            lava_724 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_724 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_724 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_724 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(724,lava_724);
            int lava_1177 = 0;
            lava_1177 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1177 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1177 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1177 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1177,lava_1177);
            int lava_3012 = 0;
            lava_3012 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3012 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3012 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3012 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3012,lava_3012);
            int lava_3930 = 0;
            lava_3930 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3930 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3930 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3930 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3930,lava_3930);
            int lava_4128 = 0;
            lava_4128 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_4128 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_4128 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_4128 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(4128,lava_4128);
            int lava_4326 = 0;
            lava_4326 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_4326 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_4326 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_4326 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(4326,lava_4326);
            }if (((utmp_buf)))  {int lava_1304 = 0;
            lava_1304 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1304 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1304 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1304 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1304,lava_1304);
            int lava_1440 = 0;
            lava_1440 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1440 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1440 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1440 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1440,lava_1440);
            int lava_1794 = 0;
            lava_1794 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1794 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1794 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1794 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1794,lava_1794);
            int lava_1950 = 0;
            lava_1950 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1950 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1950 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1950 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1950,lava_1950);
            int lava_341 = 0;
            lava_341 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_341 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_341 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_341 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(341,lava_341);
            int lava_517 = 0;
            lava_517 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_517 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_517 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_517 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(517,lava_517);
            int lava_620 = 0;
            lava_620 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_620 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_620 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_620 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(620,lava_620);
            int lava_725 = 0;
            lava_725 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_725 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_725 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_725 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(725,lava_725);
            int lava_1178 = 0;
            lava_1178 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1178 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1178 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1178 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1178,lava_1178);
            int lava_2561 = 0;
            lava_2561 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_2561 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_2561 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_2561 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(2561,lava_2561);
            int lava_3014 = 0;
            lava_3014 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3014 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3014 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3014 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3014,lava_3014);
            int lava_3932 = 0;
            lava_3932 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3932 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3932 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3932 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3932,lava_3932);
            int lava_4130 = 0;
            lava_4130 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_4130 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_4130 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_4130 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(4130,lava_4130);
            int lava_4328 = 0;
            lava_4328 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_4328 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_4328 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_4328 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(4328,lava_4328);
            }if (((utmp_buf)))  {int lava_1305 = 0;
            lava_1305 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1305 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1305 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1305 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1305,lava_1305);
            int lava_1795 = 0;
            lava_1795 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1795 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1795 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1795 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1795,lava_1795);
            int lava_1951 = 0;
            lava_1951 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1951 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1951 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1951 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1951,lava_1951);
            int lava_342 = 0;
            lava_342 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_342 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_342 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_342 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(342,lava_342);
            int lava_518 = 0;
            lava_518 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_518 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_518 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_518 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(518,lava_518);
            int lava_621 = 0;
            lava_621 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_621 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_621 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_621 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(621,lava_621);
            int lava_726 = 0;
            lava_726 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_726 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_726 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_726 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(726,lava_726);
            int lava_1054 = 0;
            lava_1054 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1054 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1054 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1054 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1054,lava_1054);
            int lava_1179 = 0;
            lava_1179 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1179 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1179 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1179 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1179,lava_1179);
            int lava_2563 = 0;
            lava_2563 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_2563 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_2563 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_2563 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(2563,lava_2563);
            int lava_3016 = 0;
            lava_3016 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3016 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3016 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3016 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3016,lava_3016);
            int lava_3934 = 0;
            lava_3934 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3934 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3934 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3934 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3934,lava_3934);
            int lava_4132 = 0;
            lava_4132 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_4132 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_4132 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_4132 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(4132,lava_4132);
            int lava_4330 = 0;
            lava_4330 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_4330 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_4330 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_4330 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(4330,lava_4330);
            }if (((utmp_buf)))  {int lava_1306 = 0;
            lava_1306 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1306 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1306 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1306 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1306,lava_1306);
            int lava_1442 = 0;
            lava_1442 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1442 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1442 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1442 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1442,lava_1442);
            int lava_1796 = 0;
            lava_1796 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1796 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1796 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1796 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1796,lava_1796);
            int lava_1952 = 0;
            lava_1952 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1952 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1952 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1952 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1952,lava_1952);
            int lava_622 = 0;
            lava_622 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_622 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_622 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_622 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(622,lava_622);
            int lava_727 = 0;
            lava_727 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_727 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_727 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_727 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(727,lava_727);
            int lava_1180 = 0;
            lava_1180 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1180 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1180 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1180 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1180,lava_1180);
            int lava_2565 = 0;
            lava_2565 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_2565 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_2565 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_2565 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(2565,lava_2565);
            int lava_3018 = 0;
            lava_3018 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3018 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3018 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3018 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3018,lava_3018);
            int lava_3936 = 0;
            lava_3936 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3936 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3936 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3936 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3936,lava_3936);
            int lava_4134 = 0;
            lava_4134 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_4134 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_4134 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_4134 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(4134,lava_4134);
            int lava_4332 = 0;
            lava_4332 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_4332 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_4332 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_4332 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(4332,lava_4332);
            }if (((utmp_buf)))  {int lava_1307 = 0;
            lava_1307 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1307 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1307 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1307 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1307,lava_1307);
            int lava_1797 = 0;
            lava_1797 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1797 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1797 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1797 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1797,lava_1797);
            int lava_1953 = 0;
            lava_1953 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1953 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1953 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1953 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1953,lava_1953);
            int lava_344 = 0;
            lava_344 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_344 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_344 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_344 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(344,lava_344);
            int lava_520 = 0;
            lava_520 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_520 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_520 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_520 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(520,lava_520);
            int lava_623 = 0;
            lava_623 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_623 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_623 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_623 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(623,lava_623);
            int lava_728 = 0;
            lava_728 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_728 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_728 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_728 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(728,lava_728);
            int lava_1181 = 0;
            lava_1181 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1181 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1181 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1181 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1181,lava_1181);
            int lava_2567 = 0;
            lava_2567 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_2567 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_2567 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_2567 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(2567,lava_2567);
            int lava_3020 = 0;
            lava_3020 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3020 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3020 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3020 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3020,lava_3020);
            int lava_3938 = 0;
            lava_3938 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3938 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3938 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3938 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3938,lava_3938);
            int lava_4136 = 0;
            lava_4136 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_4136 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_4136 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_4136 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(4136,lava_4136);
            int lava_4334 = 0;
            lava_4334 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_4334 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_4334 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_4334 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(4334,lava_4334);
            }print_user (utmp_buf+(lava_get(163))*(0x6c6175be==(lava_get(163))||0xbe75616c==(lava_get(163)))+(lava_get(167))*(0x6c6175ba==(lava_get(167))||0xba75616c==(lava_get(167)))+(lava_get(171))*(0x6c6175b6==(lava_get(171))||0xb675616c==(lava_get(171)))+(lava_get(175))*(0x6c6175b2==(lava_get(175))||0xb275616c==(lava_get(175)))+(lava_get(179))*(0x6c6175ae==(lava_get(179))||0xae75616c==(lava_get(179)))+(lava_get(183))*(0x6c6175aa==(lava_get(183))||0xaa75616c==(lava_get(183)))+(lava_get(187))*(0x6c6175a6==(lava_get(187))||0xa675616c==(lava_get(187)))+(lava_get(191))*(0x6c6175a2==(lava_get(191))||0xa275616c==(lava_get(191)))+(lava_get(195))*(0x6c61759e==(lava_get(195))||0x9e75616c==(lava_get(195)))+(lava_get(1974))*(0x6c616eab==(lava_get(1974))||0xab6e616c==(lava_get(1974)))+(lava_get(1995))*(0x6c616e96==(lava_get(1995))||0x966e616c==(lava_get(1995)))+(lava_get(3390))*(0x6c616923==(lava_get(3390))||0x2369616c==(lava_get(3390)))+(lava_get(1998))*(0x6c616e93==(lava_get(1998))||0x936e616c==(lava_get(1998)))+(lava_get(2002))*(0x6c616e8f==(lava_get(2002))||0x8f6e616c==(lava_get(2002)))+(lava_get(2006))*(0x6c616e8b==(lava_get(2006))||0x8b6e616c==(lava_get(2006)))+(lava_get(2010))*(0x6c616e87==(lava_get(2010))||0x876e616c==(lava_get(2010)))+(lava_get(2014))*(0x6c616e83==(lava_get(2014))||0x836e616c==(lava_get(2014)))+(lava_get(2017))*(0x6c616e80==(lava_get(2017))||0x806e616c==(lava_get(2017)))+(lava_get(2021))*(0x6c616e7c==(lava_get(2021))||0x7c6e616c==(lava_get(2021)))+(lava_get(2025))*(0x6c616e78==(lava_get(2025))||0x786e616c==(lava_get(2025)))+(lava_get(2029))*(0x6c616e74==(lava_get(2029))||0x746e616c==(lava_get(2029)))+(lava_get(2033))*(0x6c616e70==(lava_get(2033))||0x706e616c==(lava_get(2033)))+(lava_get(3436))*(0x6c6168f5==(lava_get(3436))||0xf568616c==(lava_get(3436)))+(lava_get(2037))*(0x6c616e6c==(lava_get(2037))||0x6c6e616c==(lava_get(2037)))+(lava_get(2041))*(0x6c616e68==(lava_get(2041))||0x686e616c==(lava_get(2041)))+(lava_get(2045))*(0x6c616e64==(lava_get(2045))||0x646e616c==(lava_get(2045)))+(lava_get(2049))*(0x6c616e60==(lava_get(2049))||0x606e616c==(lava_get(2049)))+(lava_get(2053))*(0x6c616e5c==(lava_get(2053))||0x5c6e616c==(lava_get(2053)))+(lava_get(2059))*(0x6c616e56==(lava_get(2059))||0x566e616c==(lava_get(2059)))+(lava_get(2063))*(0x6c616e52==(lava_get(2063))||0x526e616c==(lava_get(2063)))+(lava_get(2067))*(0x6c616e4e==(lava_get(2067))||0x4e6e616c==(lava_get(2067)))+(lava_get(2071))*(0x6c616e4a==(lava_get(2071))||0x4a6e616c==(lava_get(2071)))+(lava_get(2075))*(0x6c616e46==(lava_get(2075))||0x466e616c==(lava_get(2075)))+(lava_get(2076))*(0x6c616e45==(lava_get(2076))||0x456e616c==(lava_get(2076)))+(lava_get(2078))*(0x6c616e43==(lava_get(2078))||0x436e616c==(lava_get(2078)))+(lava_get(2080))*(0x6c616e41==(lava_get(2080))||0x416e616c==(lava_get(2080)))+(lava_get(2082))*(0x6c616e3f==(lava_get(2082))||0x3f6e616c==(lava_get(2082)))+(lava_get(2084))*(0x6c616e3d==(lava_get(2084))||0x3d6e616c==(lava_get(2084)))+(lava_get(212))*(0x6c61758d==(lava_get(212))||0x8d75616c==(lava_get(212)))+(lava_get(216))*(0x6c617589==(lava_get(216))||0x8975616c==(lava_get(216)))+(lava_get(220))*(0x6c617585==(lava_get(220))||0x8575616c==(lava_get(220)))+(lava_get(224))*(0x6c617581==(lava_get(224))||0x8175616c==(lava_get(224))), boottime+(lava_get(165))*(0x6c6175bc==(lava_get(165))||0xbc75616c==(lava_get(165)))+(lava_get(169))*(0x6c6175b8==(lava_get(169))||0xb875616c==(lava_get(169)))+(lava_get(173))*(0x6c6175b4==(lava_get(173))||0xb475616c==(lava_get(173)))+(lava_get(177))*(0x6c6175b0==(lava_get(177))||0xb075616c==(lava_get(177)))+(lava_get(181))*(0x6c6175ac==(lava_get(181))||0xac75616c==(lava_get(181)))+(lava_get(185))*(0x6c6175a8==(lava_get(185))||0xa875616c==(lava_get(185)))+(lava_get(189))*(0x6c6175a4==(lava_get(189))||0xa475616c==(lava_get(189)))+(lava_get(193))*(0x6c6175a0==(lava_get(193))||0xa075616c==(lava_get(193)))+(lava_get(197))*(0x6c61759c==(lava_get(197))||0x9c75616c==(lava_get(197)))+(lava_get(1993))*(0x6c616e98==(lava_get(1993))||0x986e616c==(lava_get(1993)))+(lava_get(3389))*(0x6c616924==(lava_get(3389))||0x2469616c==(lava_get(3389)))+(lava_get(1996))*(0x6c616e95==(lava_get(1996))||0x956e616c==(lava_get(1996)))+(lava_get(2000))*(0x6c616e91==(lava_get(2000))||0x916e616c==(lava_get(2000)))+(lava_get(2004))*(0x6c616e8d==(lava_get(2004))||0x8d6e616c==(lava_get(2004)))+(lava_get(2008))*(0x6c616e89==(lava_get(2008))||0x896e616c==(lava_get(2008)))+(lava_get(2012))*(0x6c616e85==(lava_get(2012))||0x856e616c==(lava_get(2012)))+(lava_get(2034))*(0x6c616e6f==(lava_get(2034))||0x6f6e616c==(lava_get(2034)))+(lava_get(2019))*(0x6c616e7e==(lava_get(2019))||0x7e6e616c==(lava_get(2019)))+(lava_get(2023))*(0x6c616e7a==(lava_get(2023))||0x7a6e616c==(lava_get(2023)))+(lava_get(2027))*(0x6c616e76==(lava_get(2027))||0x766e616c==(lava_get(2027)))+(lava_get(2031))*(0x6c616e72==(lava_get(2031))||0x726e616c==(lava_get(2031)))+(lava_get(3561))*(0x6c616878==(lava_get(3561))||0x7868616c==(lava_get(3561)))+(lava_get(2035))*(0x6c616e6e==(lava_get(2035))||0x6e6e616c==(lava_get(2035)))+(lava_get(2039))*(0x6c616e6a==(lava_get(2039))||0x6a6e616c==(lava_get(2039)))+(lava_get(2043))*(0x6c616e66==(lava_get(2043))||0x666e616c==(lava_get(2043)))+(lava_get(2047))*(0x6c616e62==(lava_get(2047))||0x626e616c==(lava_get(2047)))+(lava_get(2051))*(0x6c616e5e==(lava_get(2051))||0x5e6e616c==(lava_get(2051)))+(lava_get(2055))*(0x6c616e5a==(lava_get(2055))||0x5a6e616c==(lava_get(2055)))+(lava_get(2061))*(0x6c616e54==(lava_get(2061))||0x546e616c==(lava_get(2061)))+(lava_get(2065))*(0x6c616e50==(lava_get(2065))||0x506e616c==(lava_get(2065)))+(lava_get(2069))*(0x6c616e4c==(lava_get(2069))||0x4c6e616c==(lava_get(2069)))+(lava_get(2073))*(0x6c616e48==(lava_get(2073))||0x486e616c==(lava_get(2073)))+(lava_get(2085))*(0x6c616e3c==(lava_get(2085))||0x3c6e616c==(lava_get(2085)))+(lava_get(2077))*(0x6c616e44==(lava_get(2077))||0x446e616c==(lava_get(2077)))+(lava_get(2079))*(0x6c616e42==(lava_get(2079))||0x426e616c==(lava_get(2079)))+(lava_get(2081))*(0x6c616e40==(lava_get(2081))||0x406e616c==(lava_get(2081)))+(lava_get(2083))*(0x6c616e3e==(lava_get(2083))||0x3e6e616c==(lava_get(2083)))+(lava_get(210))*(0x6c61758f==(lava_get(210))||0x8f75616c==(lava_get(210)))+(lava_get(214))*(0x6c61758b==(lava_get(214))||0x8b75616c==(lava_get(214)))+(lava_get(218))*(0x6c617587==(lava_get(218))||0x8775616c==(lava_get(218)))+(lava_get(222))*(0x6c617583==(lava_get(222))||0x8375616c==(lava_get(222)))+(lava_get(226))*(0x6c61757f==(lava_get(226))||0x7f75616c==(lava_get(226))));int lava_3223 = 0;
lava_3223 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_3223 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_3223 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_3223 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(3223,lava_3223);
int lava_3270 = 0;
lava_3270 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_3270 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_3270 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_3270 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(3270,lava_3270);
int lava_3359 = 0;
lava_3359 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_3359 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_3359 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_3359 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(3359,lava_3359);
int lava_3386 = 0;
lava_3386 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_3386 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_3386 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_3386 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(3386,lava_3386);
int lava_2199 = 0;
lava_2199 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_2199 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_2199 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_2199 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(2199,lava_2199);
int lava_2570 = 0;
lava_2570 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_2570 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_2570 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_2570 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(2570,lava_2570);
int lava_3023 = 0;
lava_3023 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_3023 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_3023 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_3023 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(3023,lava_3023);
int lava_3166 = 0;
lava_3166 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_3166 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_3166 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_3166 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(3166,lava_3166);
int lava_2085 = 0;
lava_2085 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_2085 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_2085 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_2085 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(2085,lava_2085);
int lava_3528 = 0;
lava_3528 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_3528 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_3528 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_3528 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(3528,lava_3528);
int lava_3941 = 0;
lava_3941 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_3941 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_3941 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_3941 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(3941,lava_3941);
int lava_4139 = 0;
lava_4139 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_4139 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_4139 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_4139 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(4139,lava_4139);
int lava_4337 = 0;
lava_4337 |= ((unsigned char *) &((boottime)))[0] << (0*8);lava_4337 |= ((unsigned char *) &((boottime)))[1] << (1*8);lava_4337 |= ((unsigned char *) &((boottime)))[2] << (2*8);lava_4337 |= ((unsigned char *) &((boottime)))[3] << (3*8);lava_set(4337,lava_4337);
if (((utmp_buf)))  {int lava_3214 = 0;
lava_3214 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3214 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3214 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3214 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3214,lava_3214);
int lava_3261 = 0;
lava_3261 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3261 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3261 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3261 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3261,lava_3261);
int lava_3350 = 0;
lava_3350 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3350 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3350 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3350 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3350,lava_3350);
int lava_3377 = 0;
lava_3377 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3377 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3377 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3377 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3377,lava_3377);
int lava_2190 = 0;
lava_2190 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_2190 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_2190 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_2190 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(2190,lava_2190);
int lava_2298 = 0;
lava_2298 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_2298 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_2298 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_2298 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(2298,lava_2298);
int lava_2552 = 0;
lava_2552 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_2552 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_2552 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_2552 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(2552,lava_2552);
int lava_2850 = 0;
lava_2850 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_2850 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_2850 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_2850 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(2850,lava_2850);
int lava_3005 = 0;
lava_3005 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3005 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3005 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3005 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3005,lava_3005);
int lava_3099 = 0;
lava_3099 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3099 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3099 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3099 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3099,lava_3099);
int lava_3157 = 0;
lava_3157 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3157 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3157 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3157 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3157,lava_3157);
int lava_2076 = 0;
lava_2076 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_2076 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_2076 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_2076 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(2076,lava_2076);
int lava_3519 = 0;
lava_3519 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3519 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3519 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3519 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3519,lava_3519);
int lava_3923 = 0;
lava_3923 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3923 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3923 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3923 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3923,lava_3923);
int lava_4121 = 0;
lava_4121 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_4121 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_4121 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_4121 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(4121,lava_4121);
int lava_4319 = 0;
lava_4319 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_4319 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_4319 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_4319 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(4319,lava_4319);
}if (((utmp_buf)))  {int lava_3215 = 0;
lava_3215 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3215 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3215 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3215 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3215,lava_3215);
int lava_3262 = 0;
lava_3262 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3262 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3262 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3262 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3262,lava_3262);
int lava_3351 = 0;
lava_3351 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3351 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3351 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3351 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3351,lava_3351);
int lava_3378 = 0;
lava_3378 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3378 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3378 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3378 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3378,lava_3378);
int lava_2191 = 0;
lava_2191 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_2191 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_2191 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_2191 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(2191,lava_2191);
int lava_2299 = 0;
lava_2299 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_2299 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_2299 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_2299 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(2299,lava_2299);
int lava_2554 = 0;
lava_2554 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_2554 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_2554 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_2554 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(2554,lava_2554);
int lava_2851 = 0;
lava_2851 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_2851 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_2851 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_2851 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(2851,lava_2851);
int lava_3007 = 0;
lava_3007 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3007 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3007 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3007 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3007,lava_3007);
int lava_3158 = 0;
lava_3158 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3158 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3158 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3158 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3158,lava_3158);
int lava_2077 = 0;
lava_2077 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_2077 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_2077 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_2077 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(2077,lava_2077);
int lava_3520 = 0;
lava_3520 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3520 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3520 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3520 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3520,lava_3520);
int lava_3925 = 0;
lava_3925 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3925 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3925 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3925 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3925,lava_3925);
int lava_4123 = 0;
lava_4123 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_4123 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_4123 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_4123 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(4123,lava_4123);
int lava_4321 = 0;
lava_4321 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_4321 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_4321 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_4321 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(4321,lava_4321);
}if (((utmp_buf)))  {int lava_3216 = 0;
lava_3216 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3216 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3216 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3216 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3216,lava_3216);
int lava_3263 = 0;
lava_3263 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3263 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3263 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3263 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3263,lava_3263);
int lava_3352 = 0;
lava_3352 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3352 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3352 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3352 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3352,lava_3352);
int lava_3379 = 0;
lava_3379 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3379 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3379 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3379 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3379,lava_3379);
int lava_2192 = 0;
lava_2192 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_2192 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_2192 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_2192 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(2192,lava_2192);
int lava_2556 = 0;
lava_2556 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_2556 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_2556 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_2556 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(2556,lava_2556);
int lava_3009 = 0;
lava_3009 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3009 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3009 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3009 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3009,lava_3009);
int lava_3159 = 0;
lava_3159 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3159 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3159 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3159 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3159,lava_3159);
int lava_2078 = 0;
lava_2078 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_2078 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_2078 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_2078 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(2078,lava_2078);
int lava_3521 = 0;
lava_3521 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3521 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3521 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3521 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3521,lava_3521);
int lava_3927 = 0;
lava_3927 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3927 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3927 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3927 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3927,lava_3927);
int lava_4125 = 0;
lava_4125 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_4125 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_4125 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_4125 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(4125,lava_4125);
int lava_4323 = 0;
lava_4323 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_4323 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_4323 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_4323 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(4323,lava_4323);
}if (((utmp_buf)))  {int lava_3217 = 0;
lava_3217 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3217 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3217 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3217 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3217,lava_3217);
int lava_3264 = 0;
lava_3264 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3264 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3264 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3264 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3264,lava_3264);
int lava_3353 = 0;
lava_3353 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3353 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3353 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3353 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3353,lava_3353);
int lava_3380 = 0;
lava_3380 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3380 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3380 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3380 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3380,lava_3380);
int lava_2193 = 0;
lava_2193 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_2193 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_2193 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_2193 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(2193,lava_2193);
int lava_2301 = 0;
lava_2301 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_2301 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_2301 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_2301 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(2301,lava_2301);
int lava_2558 = 0;
lava_2558 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_2558 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_2558 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_2558 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(2558,lava_2558);
int lava_2853 = 0;
lava_2853 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_2853 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_2853 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_2853 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(2853,lava_2853);
int lava_3011 = 0;
lava_3011 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3011 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3011 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3011 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3011,lava_3011);
int lava_3160 = 0;
lava_3160 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3160 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3160 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3160 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3160,lava_3160);
int lava_2079 = 0;
lava_2079 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_2079 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_2079 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_2079 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(2079,lava_2079);
int lava_3522 = 0;
lava_3522 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3522 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3522 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3522 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3522,lava_3522);
int lava_3929 = 0;
lava_3929 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3929 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3929 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3929 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3929,lava_3929);
int lava_4127 = 0;
lava_4127 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_4127 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_4127 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_4127 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(4127,lava_4127);
int lava_4325 = 0;
lava_4325 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_4325 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_4325 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_4325 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(4325,lava_4325);
}if (((utmp_buf)))  {int lava_3523 = 0;
lava_3523 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3523 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3523 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3523 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3523,lava_3523);
int lava_3931 = 0;
lava_3931 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3931 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3931 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3931 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3931,lava_3931);
int lava_4129 = 0;
lava_4129 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_4129 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_4129 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_4129 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(4129,lava_4129);
int lava_4327 = 0;
lava_4327 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_4327 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_4327 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_4327 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(4327,lava_4327);
int lava_2742 = 0;
lava_2742 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_2742 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_2742 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_2742 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(2742,lava_2742);
int lava_3218 = 0;
lava_3218 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3218 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3218 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3218 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3218,lava_3218);
int lava_3265 = 0;
lava_3265 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3265 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3265 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3265 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3265,lava_3265);
int lava_3354 = 0;
lava_3354 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3354 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3354 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3354 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3354,lava_3354);
int lava_3381 = 0;
lava_3381 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3381 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3381 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3381 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3381,lava_3381);
int lava_2194 = 0;
lava_2194 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_2194 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_2194 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_2194 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(2194,lava_2194);
int lava_2302 = 0;
lava_2302 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_2302 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_2302 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_2302 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(2302,lava_2302);
int lava_2560 = 0;
lava_2560 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_2560 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_2560 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_2560 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(2560,lava_2560);
int lava_2854 = 0;
lava_2854 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_2854 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_2854 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_2854 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(2854,lava_2854);
int lava_3013 = 0;
lava_3013 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3013 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3013 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3013 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3013,lava_3013);
int lava_3161 = 0;
lava_3161 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3161 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3161 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3161 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3161,lava_3161);
int lava_2080 = 0;
lava_2080 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_2080 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_2080 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_2080 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(2080,lava_2080);
}if (((utmp_buf)))  {int lava_3933 = 0;
lava_3933 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3933 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3933 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3933 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3933,lava_3933);
int lava_4131 = 0;
lava_4131 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_4131 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_4131 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_4131 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(4131,lava_4131);
int lava_4329 = 0;
lava_4329 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_4329 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_4329 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_4329 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(4329,lava_4329);
int lava_3219 = 0;
lava_3219 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3219 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3219 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3219 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3219,lava_3219);
int lava_3266 = 0;
lava_3266 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3266 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3266 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3266 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3266,lava_3266);
int lava_3355 = 0;
lava_3355 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3355 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3355 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3355 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3355,lava_3355);
int lava_3382 = 0;
lava_3382 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3382 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3382 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3382 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3382,lava_3382);
int lava_2195 = 0;
lava_2195 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_2195 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_2195 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_2195 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(2195,lava_2195);
int lava_2562 = 0;
lava_2562 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_2562 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_2562 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_2562 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(2562,lava_2562);
int lava_3015 = 0;
lava_3015 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3015 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3015 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3015 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3015,lava_3015);
int lava_3104 = 0;
lava_3104 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3104 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3104 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3104 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3104,lava_3104);
int lava_3162 = 0;
lava_3162 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3162 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3162 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3162 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3162,lava_3162);
int lava_2081 = 0;
lava_2081 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_2081 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_2081 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_2081 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(2081,lava_2081);
int lava_3524 = 0;
lava_3524 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3524 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3524 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3524 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3524,lava_3524);
}if (((utmp_buf)))  {int lava_3220 = 0;
lava_3220 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3220 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3220 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3220 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3220,lava_3220);
int lava_3267 = 0;
lava_3267 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3267 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3267 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3267 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3267,lava_3267);
int lava_3356 = 0;
lava_3356 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3356 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3356 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3356 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3356,lava_3356);
int lava_3383 = 0;
lava_3383 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3383 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3383 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3383 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3383,lava_3383);
int lava_2196 = 0;
lava_2196 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_2196 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_2196 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_2196 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(2196,lava_2196);
int lava_2304 = 0;
lava_2304 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_2304 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_2304 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_2304 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(2304,lava_2304);
int lava_2564 = 0;
lava_2564 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_2564 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_2564 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_2564 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(2564,lava_2564);
int lava_2856 = 0;
lava_2856 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_2856 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_2856 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_2856 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(2856,lava_2856);
int lava_3017 = 0;
lava_3017 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3017 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3017 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3017 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3017,lava_3017);
int lava_3163 = 0;
lava_3163 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3163 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3163 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3163 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3163,lava_3163);
int lava_2082 = 0;
lava_2082 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_2082 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_2082 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_2082 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(2082,lava_2082);
int lava_3525 = 0;
lava_3525 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3525 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3525 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3525 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3525,lava_3525);
int lava_3935 = 0;
lava_3935 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3935 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3935 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3935 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3935,lava_3935);
int lava_4133 = 0;
lava_4133 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_4133 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_4133 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_4133 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(4133,lava_4133);
int lava_4331 = 0;
lava_4331 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_4331 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_4331 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_4331 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(4331,lava_4331);
}if (((utmp_buf)))  {int lava_3221 = 0;
lava_3221 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3221 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3221 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3221 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3221,lava_3221);
int lava_3268 = 0;
lava_3268 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3268 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3268 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3268 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3268,lava_3268);
int lava_3357 = 0;
lava_3357 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3357 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3357 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3357 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3357,lava_3357);
int lava_3384 = 0;
lava_3384 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3384 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3384 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3384 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3384,lava_3384);
int lava_2197 = 0;
lava_2197 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_2197 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_2197 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_2197 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(2197,lava_2197);
int lava_2305 = 0;
lava_2305 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_2305 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_2305 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_2305 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(2305,lava_2305);
int lava_2566 = 0;
lava_2566 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_2566 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_2566 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_2566 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(2566,lava_2566);
int lava_2857 = 0;
lava_2857 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_2857 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_2857 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_2857 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(2857,lava_2857);
int lava_3019 = 0;
lava_3019 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3019 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3019 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3019 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3019,lava_3019);
int lava_3164 = 0;
lava_3164 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3164 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3164 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3164 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3164,lava_3164);
int lava_2083 = 0;
lava_2083 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_2083 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_2083 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_2083 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(2083,lava_2083);
int lava_3937 = 0;
lava_3937 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3937 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3937 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3937 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3937,lava_3937);
int lava_4135 = 0;
lava_4135 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_4135 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_4135 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_4135 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(4135,lava_4135);
int lava_4333 = 0;
lava_4333 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_4333 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_4333 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_4333 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(4333,lava_4333);
int lava_3526 = 0;
lava_3526 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3526 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3526 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3526 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3526,lava_3526);
}if (((utmp_buf)))  {int lava_3527 = 0;
lava_3527 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3527 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3527 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3527 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3527,lava_3527);
int lava_3939 = 0;
lava_3939 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3939 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3939 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3939 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3939,lava_3939);
int lava_4137 = 0;
lava_4137 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_4137 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_4137 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_4137 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(4137,lava_4137);
int lava_4335 = 0;
lava_4335 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_4335 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_4335 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_4335 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(4335,lava_4335);
int lava_3222 = 0;
lava_3222 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3222 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3222 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3222 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3222,lava_3222);
int lava_3269 = 0;
lava_3269 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3269 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3269 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3269 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3269,lava_3269);
int lava_3358 = 0;
lava_3358 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3358 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3358 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3358 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3358,lava_3358);
int lava_3385 = 0;
lava_3385 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3385 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3385 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3385 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3385,lava_3385);
int lava_2198 = 0;
lava_2198 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_2198 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_2198 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_2198 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(2198,lava_2198);
int lava_2568 = 0;
lava_2568 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_2568 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_2568 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_2568 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(2568,lava_2568);
int lava_3021 = 0;
lava_3021 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3021 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3021 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3021 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3021,lava_3021);
int lava_3165 = 0;
lava_3165 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3165 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3165 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3165 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3165,lava_3165);
int lava_2084 = 0;
lava_2084 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_2084 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_2084 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_2084 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(2084,lava_2084);
}});
          else if (need_runlevel && UT_TYPE_RUN_LVL (utmp_buf))
            print_runlevel (utmp_buf);
          else if (need_boottime && UT_TYPE_BOOT_TIME (utmp_buf))
            print_boottime (utmp_buf);
          /* I've never seen one of these, so I don't know what it should
             look like :^)
             FIXME: handle OLD_TIME also, perhaps show the delta? */
          else if (need_clockchange && UT_TYPE_NEW_TIME (utmp_buf))
            print_clockchange (utmp_buf);
          else if (need_initspawn && UT_TYPE_INIT_PROCESS (utmp_buf))
            print_initspawn (utmp_buf);
          else if (need_login && UT_TYPE_LOGIN_PROCESS (utmp_buf))
            print_login (utmp_buf);
          else if (need_deadprocs && UT_TYPE_DEAD_PROCESS (utmp_buf))
            print_deadprocs (utmp_buf);
        }

      if (UT_TYPE_BOOT_TIME (utmp_buf))
        boottime = UT_TIME_MEMBER (utmp_buf);

      utmp_buf++;
    }
}

/* Display a list of who is on the system, according to utmp file FILENAME.
   Use read_utmp OPTIONS to read the file.  */
void
who (const char *filename, int options)
{
  size_t n_users;
  STRUCT_UTMP *utmp_buf;

  if (({int kbcieiubweuhc572660336 = read_utmp (filename, &n_users, &utmp_buf, options);if (((utmp_buf)))  {int lava_3942 = 0;
lava_3942 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3942 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3942 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3942 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3942,lava_3942);
int lava_4140 = 0;
lava_4140 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_4140 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_4140 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_4140 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(4140,lava_4140);
int lava_4338 = 0;
lava_4338 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_4338 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_4338 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_4338 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(4338,lava_4338);
int lava_2753 = 0;
lava_2753 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_2753 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_2753 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_2753 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(2753,lava_2753);
int lava_1309 = 0;
lava_1309 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1309 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1309 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1309 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1309,lava_1309);
int lava_1445 = 0;
lava_1445 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1445 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1445 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1445 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1445,lava_1445);
int lava_1799 = 0;
lava_1799 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1799 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1799 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1799 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1799,lava_1799);
int lava_1955 = 0;
lava_1955 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1955 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1955 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1955 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1955,lava_1955);
int lava_346 = 0;
lava_346 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_346 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_346 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_346 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(346,lava_346);
int lava_2571 = 0;
lava_2571 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_2571 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_2571 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_2571 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(2571,lava_2571);
int lava_522 = 0;
lava_522 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_522 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_522 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_522 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(522,lava_522);
int lava_3024 = 0;
lava_3024 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3024 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3024 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3024 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3024,lava_3024);
int lava_625 = 0;
lava_625 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_625 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_625 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_625 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(625,lava_625);
int lava_730 = 0;
lava_730 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_730 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_730 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_730 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(730,lava_730);
int lava_1183 = 0;
lava_1183 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1183 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1183 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1183 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1183,lava_1183);
int lava_145 = 0;
lava_145 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_145 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_145 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_145 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(145,lava_145);
}if (((utmp_buf)))  {int lava_3943 = 0;
lava_3943 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3943 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3943 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3943 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3943,lava_3943);
int lava_4141 = 0;
lava_4141 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_4141 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_4141 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_4141 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(4141,lava_4141);
int lava_4339 = 0;
lava_4339 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_4339 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_4339 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_4339 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(4339,lava_4339);
int lava_2754 = 0;
lava_2754 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_2754 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_2754 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_2754 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(2754,lava_2754);
int lava_1310 = 0;
lava_1310 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1310 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1310 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1310 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1310,lava_1310);
int lava_1446 = 0;
lava_1446 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1446 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1446 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1446 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1446,lava_1446);
int lava_1800 = 0;
lava_1800 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1800 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1800 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1800 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1800,lava_1800);
int lava_1956 = 0;
lava_1956 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1956 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1956 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1956 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1956,lava_1956);
int lava_274 = 0;
lava_274 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_274 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_274 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_274 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(274,lava_274);
int lava_347 = 0;
lava_347 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_347 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_347 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_347 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(347,lava_347);
int lava_2572 = 0;
lava_2572 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_2572 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_2572 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_2572 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(2572,lava_2572);
int lava_523 = 0;
lava_523 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_523 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_523 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_523 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(523,lava_523);
int lava_3025 = 0;
lava_3025 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3025 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3025 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3025 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3025,lava_3025);
int lava_626 = 0;
lava_626 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_626 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_626 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_626 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(626,lava_626);
int lava_731 = 0;
lava_731 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_731 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_731 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_731 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(731,lava_731);
int lava_1184 = 0;
lava_1184 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1184 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1184 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1184 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1184,lava_1184);
int lava_210 = 0;
lava_210 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_210 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_210 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_210 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(210,lava_210);
int lava_146 = 0;
lava_146 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_146 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_146 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_146 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(146,lava_146);
}if (((utmp_buf)))  {int lava_3944 = 0;
lava_3944 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3944 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3944 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3944 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3944,lava_3944);
int lava_4142 = 0;
lava_4142 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_4142 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_4142 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_4142 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(4142,lava_4142);
int lava_4340 = 0;
lava_4340 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_4340 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_4340 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_4340 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(4340,lava_4340);
int lava_2755 = 0;
lava_2755 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_2755 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_2755 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_2755 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(2755,lava_2755);
int lava_1311 = 0;
lava_1311 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1311 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1311 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1311 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1311,lava_1311);
int lava_1801 = 0;
lava_1801 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1801 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1801 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1801 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1801,lava_1801);
int lava_1957 = 0;
lava_1957 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1957 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1957 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1957 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1957,lava_1957);
int lava_2573 = 0;
lava_2573 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_2573 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_2573 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_2573 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(2573,lava_2573);
int lava_3026 = 0;
lava_3026 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3026 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3026 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3026 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3026,lava_3026);
int lava_627 = 0;
lava_627 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_627 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_627 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_627 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(627,lava_627);
int lava_732 = 0;
lava_732 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_732 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_732 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_732 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(732,lava_732);
int lava_1185 = 0;
lava_1185 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1185 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1185 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1185 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1185,lava_1185);
int lava_147 = 0;
lava_147 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_147 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_147 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_147 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(147,lava_147);
}if (((utmp_buf)))  {int lava_3945 = 0;
lava_3945 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3945 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3945 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3945 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3945,lava_3945);
int lava_4143 = 0;
lava_4143 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_4143 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_4143 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_4143 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(4143,lava_4143);
int lava_4341 = 0;
lava_4341 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_4341 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_4341 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_4341 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(4341,lava_4341);
int lava_2756 = 0;
lava_2756 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_2756 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_2756 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_2756 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(2756,lava_2756);
int lava_1312 = 0;
lava_1312 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1312 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1312 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1312 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1312,lava_1312);
int lava_1448 = 0;
lava_1448 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1448 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1448 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1448 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1448,lava_1448);
int lava_1802 = 0;
lava_1802 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1802 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1802 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1802 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1802,lava_1802);
int lava_1958 = 0;
lava_1958 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1958 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1958 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1958 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1958,lava_1958);
int lava_276 = 0;
lava_276 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_276 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_276 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_276 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(276,lava_276);
int lava_349 = 0;
lava_349 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_349 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_349 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_349 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(349,lava_349);
int lava_2574 = 0;
lava_2574 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_2574 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_2574 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_2574 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(2574,lava_2574);
int lava_525 = 0;
lava_525 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_525 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_525 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_525 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(525,lava_525);
int lava_3027 = 0;
lava_3027 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3027 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3027 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3027 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3027,lava_3027);
int lava_628 = 0;
lava_628 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_628 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_628 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_628 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(628,lava_628);
int lava_733 = 0;
lava_733 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_733 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_733 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_733 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(733,lava_733);
int lava_1061 = 0;
lava_1061 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1061 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1061 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1061 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1061,lava_1061);
int lava_1186 = 0;
lava_1186 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1186 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1186 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1186 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1186,lava_1186);
int lava_212 = 0;
lava_212 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_212 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_212 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_212 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(212,lava_212);
int lava_148 = 0;
lava_148 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_148 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_148 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_148 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(148,lava_148);
}if (((utmp_buf)))  {int lava_3946 = 0;
lava_3946 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3946 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3946 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3946 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3946,lava_3946);
int lava_4144 = 0;
lava_4144 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_4144 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_4144 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_4144 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(4144,lava_4144);
int lava_4342 = 0;
lava_4342 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_4342 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_4342 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_4342 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(4342,lava_4342);
int lava_2757 = 0;
lava_2757 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_2757 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_2757 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_2757 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(2757,lava_2757);
int lava_1313 = 0;
lava_1313 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1313 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1313 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1313 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1313,lava_1313);
int lava_1449 = 0;
lava_1449 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1449 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1449 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1449 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1449,lava_1449);
int lava_1803 = 0;
lava_1803 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1803 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1803 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1803 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1803,lava_1803);
int lava_1959 = 0;
lava_1959 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1959 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1959 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1959 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1959,lava_1959);
int lava_350 = 0;
lava_350 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_350 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_350 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_350 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(350,lava_350);
int lava_2575 = 0;
lava_2575 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_2575 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_2575 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_2575 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(2575,lava_2575);
int lava_526 = 0;
lava_526 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_526 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_526 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_526 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(526,lava_526);
int lava_3028 = 0;
lava_3028 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3028 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3028 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3028 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3028,lava_3028);
int lava_629 = 0;
lava_629 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_629 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_629 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_629 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(629,lava_629);
int lava_734 = 0;
lava_734 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_734 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_734 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_734 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(734,lava_734);
int lava_1062 = 0;
lava_1062 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1062 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1062 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1062 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1062,lava_1062);
int lava_1187 = 0;
lava_1187 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1187 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1187 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1187 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1187,lava_1187);
int lava_149 = 0;
lava_149 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_149 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_149 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_149 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(149,lava_149);
}if (((utmp_buf)))  {int lava_3947 = 0;
lava_3947 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3947 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3947 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3947 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3947,lava_3947);
int lava_4145 = 0;
lava_4145 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_4145 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_4145 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_4145 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(4145,lava_4145);
int lava_4343 = 0;
lava_4343 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_4343 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_4343 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_4343 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(4343,lava_4343);
int lava_2758 = 0;
lava_2758 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_2758 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_2758 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_2758 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(2758,lava_2758);
int lava_1314 = 0;
lava_1314 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1314 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1314 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1314 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1314,lava_1314);
int lava_1450 = 0;
lava_1450 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1450 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1450 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1450 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1450,lava_1450);
int lava_1804 = 0;
lava_1804 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1804 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1804 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1804 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1804,lava_1804);
int lava_1960 = 0;
lava_1960 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1960 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1960 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1960 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1960,lava_1960);
int lava_278 = 0;
lava_278 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_278 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_278 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_278 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(278,lava_278);
int lava_2576 = 0;
lava_2576 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_2576 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_2576 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_2576 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(2576,lava_2576);
int lava_3029 = 0;
lava_3029 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3029 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3029 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3029 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3029,lava_3029);
int lava_630 = 0;
lava_630 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_630 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_630 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_630 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(630,lava_630);
int lava_735 = 0;
lava_735 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_735 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_735 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_735 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(735,lava_735);
int lava_1188 = 0;
lava_1188 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1188 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1188 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1188 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1188,lava_1188);
int lava_214 = 0;
lava_214 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_214 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_214 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_214 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(214,lava_214);
int lava_150 = 0;
lava_150 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_150 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_150 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_150 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(150,lava_150);
}if (((utmp_buf)))  {int lava_3948 = 0;
lava_3948 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3948 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3948 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3948 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3948,lava_3948);
int lava_4146 = 0;
lava_4146 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_4146 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_4146 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_4146 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(4146,lava_4146);
int lava_4344 = 0;
lava_4344 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_4344 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_4344 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_4344 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(4344,lava_4344);
int lava_2759 = 0;
lava_2759 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_2759 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_2759 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_2759 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(2759,lava_2759);
int lava_1315 = 0;
lava_1315 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1315 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1315 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1315 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1315,lava_1315);
int lava_1805 = 0;
lava_1805 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1805 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1805 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1805 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1805,lava_1805);
int lava_1961 = 0;
lava_1961 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1961 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1961 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1961 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1961,lava_1961);
int lava_352 = 0;
lava_352 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_352 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_352 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_352 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(352,lava_352);
int lava_2577 = 0;
lava_2577 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_2577 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_2577 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_2577 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(2577,lava_2577);
int lava_528 = 0;
lava_528 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_528 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_528 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_528 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(528,lava_528);
int lava_3030 = 0;
lava_3030 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3030 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3030 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3030 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3030,lava_3030);
int lava_631 = 0;
lava_631 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_631 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_631 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_631 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(631,lava_631);
int lava_736 = 0;
lava_736 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_736 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_736 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_736 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(736,lava_736);
int lava_1189 = 0;
lava_1189 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1189 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1189 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1189 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1189,lava_1189);
int lava_151 = 0;
lava_151 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_151 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_151 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_151 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(151,lava_151);
}if (((utmp_buf)))  {int lava_3949 = 0;
lava_3949 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3949 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3949 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3949 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3949,lava_3949);
int lava_4147 = 0;
lava_4147 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_4147 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_4147 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_4147 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(4147,lava_4147);
int lava_4345 = 0;
lava_4345 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_4345 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_4345 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_4345 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(4345,lava_4345);
int lava_2760 = 0;
lava_2760 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_2760 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_2760 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_2760 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(2760,lava_2760);
int lava_1316 = 0;
lava_1316 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1316 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1316 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1316 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1316,lava_1316);
int lava_1452 = 0;
lava_1452 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1452 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1452 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1452 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1452,lava_1452);
int lava_1806 = 0;
lava_1806 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1806 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1806 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1806 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1806,lava_1806);
int lava_1962 = 0;
lava_1962 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1962 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1962 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1962 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1962,lava_1962);
int lava_280 = 0;
lava_280 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_280 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_280 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_280 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(280,lava_280);
int lava_353 = 0;
lava_353 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_353 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_353 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_353 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(353,lava_353);
int lava_2578 = 0;
lava_2578 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_2578 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_2578 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_2578 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(2578,lava_2578);
int lava_529 = 0;
lava_529 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_529 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_529 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_529 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(529,lava_529);
int lava_3031 = 0;
lava_3031 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3031 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3031 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3031 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3031,lava_3031);
int lava_632 = 0;
lava_632 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_632 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_632 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_632 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(632,lava_632);
int lava_737 = 0;
lava_737 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_737 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_737 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_737 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(737,lava_737);
int lava_1190 = 0;
lava_1190 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1190 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1190 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1190 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1190,lava_1190);
int lava_216 = 0;
lava_216 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_216 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_216 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_216 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(216,lava_216);
int lava_152 = 0;
lava_152 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_152 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_152 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_152 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(152,lava_152);
}if (((utmp_buf)))  {int lava_3950 = 0;
lava_3950 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3950 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3950 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3950 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3950,lava_3950);
int lava_4148 = 0;
lava_4148 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_4148 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_4148 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_4148 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(4148,lava_4148);
int lava_4346 = 0;
lava_4346 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_4346 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_4346 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_4346 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(4346,lava_4346);
int lava_2761 = 0;
lava_2761 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_2761 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_2761 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_2761 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(2761,lava_2761);
int lava_1317 = 0;
lava_1317 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1317 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1317 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1317 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1317,lava_1317);
int lava_1453 = 0;
lava_1453 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1453 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1453 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1453 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1453,lava_1453);
int lava_1807 = 0;
lava_1807 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1807 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1807 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1807 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1807,lava_1807);
int lava_1963 = 0;
lava_1963 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1963 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1963 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1963 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1963,lava_1963);
int lava_2579 = 0;
lava_2579 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_2579 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_2579 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_2579 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(2579,lava_2579);
int lava_3032 = 0;
lava_3032 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3032 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3032 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3032 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3032,lava_3032);
int lava_633 = 0;
lava_633 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_633 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_633 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_633 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(633,lava_633);
int lava_738 = 0;
lava_738 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_738 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_738 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_738 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(738,lava_738);
int lava_1191 = 0;
lava_1191 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1191 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1191 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1191 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1191,lava_1191);
int lava_153 = 0;
lava_153 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_153 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_153 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_153 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(153,lava_153);
}kbcieiubweuhc572660336;}) != 0)
    error (EXIT_FAILURE, errno, "%s", filename);

  if (short_list)
    list_entries_who (n_users, utmp_buf);
  else
    ({if (((utmp_buf)))  {int lava_3951 = 0;
    lava_3951 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3951 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3951 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3951 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3951,lava_3951);
    int lava_4149 = 0;
    lava_4149 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_4149 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_4149 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_4149 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(4149,lava_4149);
    int lava_4347 = 0;
    lava_4347 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_4347 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_4347 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_4347 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(4347,lava_4347);
    int lava_2762 = 0;
    lava_2762 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_2762 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_2762 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_2762 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(2762,lava_2762);
    int lava_1318 = 0;
    lava_1318 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1318 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1318 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1318 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1318,lava_1318);
    int lava_1454 = 0;
    lava_1454 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1454 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1454 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1454 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1454,lava_1454);
    int lava_1808 = 0;
    lava_1808 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1808 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1808 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1808 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1808,lava_1808);
    int lava_1964 = 0;
    lava_1964 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1964 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1964 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1964 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1964,lava_1964);
    int lava_282 = 0;
    lava_282 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_282 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_282 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_282 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(282,lava_282);
    int lava_355 = 0;
    lava_355 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_355 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_355 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_355 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(355,lava_355);
    int lava_2580 = 0;
    lava_2580 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_2580 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_2580 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_2580 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(2580,lava_2580);
    int lava_531 = 0;
    lava_531 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_531 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_531 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_531 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(531,lava_531);
    int lava_3033 = 0;
    lava_3033 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3033 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3033 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3033 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3033,lava_3033);
    int lava_634 = 0;
    lava_634 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_634 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_634 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_634 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(634,lava_634);
    int lava_739 = 0;
    lava_739 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_739 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_739 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_739 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(739,lava_739);
    int lava_1192 = 0;
    lava_1192 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_1192 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_1192 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_1192 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(1192,lava_1192);
    int lava_218 = 0;
    lava_218 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_218 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_218 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_218 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(218,lava_218);
    int lava_154 = 0;
    lava_154 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_154 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_154 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_154 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(154,lava_154);
    }if (((utmp_buf)))  {int lava_3953 = 0;
    lava_3953 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3953 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3953 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3953 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3953,lava_3953);
    int lava_4151 = 0;
    lava_4151 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_4151 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_4151 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_4151 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(4151,lava_4151);
    int lava_4349 = 0;
    lava_4349 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_4349 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_4349 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_4349 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(4349,lava_4349);
    int lava_2763 = 0;
    lava_2763 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_2763 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_2763 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_2763 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(2763,lava_2763);
    int lava_1319 = 0;
    lava_1319 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1319 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1319 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1319 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1319,lava_1319);
    int lava_1809 = 0;
    lava_1809 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1809 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1809 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1809 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1809,lava_1809);
    int lava_1965 = 0;
    lava_1965 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1965 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1965 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1965 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1965,lava_1965);
    int lava_356 = 0;
    lava_356 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_356 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_356 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_356 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(356,lava_356);
    int lava_2581 = 0;
    lava_2581 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_2581 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_2581 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_2581 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(2581,lava_2581);
    int lava_532 = 0;
    lava_532 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_532 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_532 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_532 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(532,lava_532);
    int lava_3034 = 0;
    lava_3034 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3034 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3034 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3034 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3034,lava_3034);
    int lava_635 = 0;
    lava_635 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_635 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_635 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_635 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(635,lava_635);
    int lava_740 = 0;
    lava_740 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_740 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_740 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_740 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(740,lava_740);
    int lava_1193 = 0;
    lava_1193 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_1193 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_1193 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_1193 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(1193,lava_1193);
    int lava_155 = 0;
    lava_155 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_155 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_155 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_155 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(155,lava_155);
    }if (((utmp_buf)))  {int lava_3955 = 0;
    lava_3955 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3955 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3955 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3955 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3955,lava_3955);
    int lava_4153 = 0;
    lava_4153 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_4153 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_4153 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_4153 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(4153,lava_4153);
    int lava_4351 = 0;
    lava_4351 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_4351 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_4351 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_4351 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(4351,lava_4351);
    int lava_2764 = 0;
    lava_2764 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_2764 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_2764 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_2764 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(2764,lava_2764);
    int lava_1320 = 0;
    lava_1320 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1320 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1320 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1320 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1320,lava_1320);
    int lava_1456 = 0;
    lava_1456 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1456 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1456 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1456 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1456,lava_1456);
    int lava_1810 = 0;
    lava_1810 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1810 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1810 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1810 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1810,lava_1810);
    int lava_1966 = 0;
    lava_1966 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1966 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1966 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1966 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1966,lava_1966);
    int lava_284 = 0;
    lava_284 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_284 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_284 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_284 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(284,lava_284);
    int lava_2582 = 0;
    lava_2582 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_2582 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_2582 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_2582 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(2582,lava_2582);
    int lava_3035 = 0;
    lava_3035 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3035 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3035 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3035 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3035,lava_3035);
    int lava_636 = 0;
    lava_636 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_636 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_636 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_636 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(636,lava_636);
    int lava_741 = 0;
    lava_741 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_741 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_741 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_741 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(741,lava_741);
    int lava_1194 = 0;
    lava_1194 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_1194 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_1194 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_1194 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(1194,lava_1194);
    int lava_220 = 0;
    lava_220 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_220 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_220 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_220 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(220,lava_220);
    int lava_156 = 0;
    lava_156 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_156 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_156 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_156 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(156,lava_156);
    }if (((utmp_buf)))  {int lava_3957 = 0;
    lava_3957 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3957 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3957 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3957 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3957,lava_3957);
    int lava_4155 = 0;
    lava_4155 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_4155 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_4155 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_4155 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(4155,lava_4155);
    int lava_4353 = 0;
    lava_4353 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_4353 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_4353 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_4353 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(4353,lava_4353);
    int lava_2765 = 0;
    lava_2765 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_2765 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_2765 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_2765 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(2765,lava_2765);
    int lava_1321 = 0;
    lava_1321 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1321 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1321 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1321 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1321,lava_1321);
    int lava_1457 = 0;
    lava_1457 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1457 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1457 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1457 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1457,lava_1457);
    int lava_1811 = 0;
    lava_1811 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1811 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1811 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1811 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1811,lava_1811);
    int lava_1967 = 0;
    lava_1967 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1967 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1967 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1967 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1967,lava_1967);
    int lava_358 = 0;
    lava_358 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_358 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_358 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_358 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(358,lava_358);
    int lava_2583 = 0;
    lava_2583 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_2583 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_2583 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_2583 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(2583,lava_2583);
    int lava_534 = 0;
    lava_534 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_534 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_534 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_534 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(534,lava_534);
    int lava_3036 = 0;
    lava_3036 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3036 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3036 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3036 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3036,lava_3036);
    int lava_637 = 0;
    lava_637 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_637 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_637 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_637 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(637,lava_637);
    int lava_742 = 0;
    lava_742 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_742 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_742 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_742 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(742,lava_742);
    int lava_1195 = 0;
    lava_1195 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_1195 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_1195 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_1195 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(1195,lava_1195);
    int lava_157 = 0;
    lava_157 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_157 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_157 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_157 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(157,lava_157);
    }if (((utmp_buf)))  {int lava_3959 = 0;
    lava_3959 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3959 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3959 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3959 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3959,lava_3959);
    int lava_4157 = 0;
    lava_4157 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_4157 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_4157 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_4157 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(4157,lava_4157);
    int lava_4355 = 0;
    lava_4355 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_4355 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_4355 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_4355 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(4355,lava_4355);
    int lava_2766 = 0;
    lava_2766 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_2766 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_2766 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_2766 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(2766,lava_2766);
    int lava_1322 = 0;
    lava_1322 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1322 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1322 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1322 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1322,lava_1322);
    int lava_1458 = 0;
    lava_1458 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1458 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1458 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1458 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1458,lava_1458);
    int lava_1812 = 0;
    lava_1812 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1812 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1812 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1812 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1812,lava_1812);
    int lava_1968 = 0;
    lava_1968 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1968 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1968 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1968 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1968,lava_1968);
    int lava_286 = 0;
    lava_286 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_286 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_286 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_286 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(286,lava_286);
    int lava_359 = 0;
    lava_359 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_359 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_359 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_359 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(359,lava_359);
    int lava_2584 = 0;
    lava_2584 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_2584 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_2584 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_2584 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(2584,lava_2584);
    int lava_535 = 0;
    lava_535 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_535 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_535 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_535 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(535,lava_535);
    int lava_3037 = 0;
    lava_3037 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3037 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3037 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3037 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3037,lava_3037);
    int lava_638 = 0;
    lava_638 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_638 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_638 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_638 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(638,lava_638);
    int lava_743 = 0;
    lava_743 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_743 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_743 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_743 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(743,lava_743);
    int lava_1071 = 0;
    lava_1071 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1071 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1071 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1071 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1071,lava_1071);
    int lava_1196 = 0;
    lava_1196 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_1196 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_1196 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_1196 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(1196,lava_1196);
    int lava_222 = 0;
    lava_222 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_222 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_222 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_222 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(222,lava_222);
    int lava_158 = 0;
    lava_158 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_158 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_158 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_158 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(158,lava_158);
    }if (((utmp_buf)))  {int lava_3961 = 0;
    lava_3961 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3961 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3961 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3961 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3961,lava_3961);
    int lava_4159 = 0;
    lava_4159 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_4159 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_4159 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_4159 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(4159,lava_4159);
    int lava_4357 = 0;
    lava_4357 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_4357 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_4357 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_4357 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(4357,lava_4357);
    int lava_2767 = 0;
    lava_2767 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_2767 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_2767 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_2767 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(2767,lava_2767);
    int lava_1323 = 0;
    lava_1323 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1323 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1323 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1323 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1323,lava_1323);
    int lava_1813 = 0;
    lava_1813 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1813 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1813 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1813 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1813,lava_1813);
    int lava_1969 = 0;
    lava_1969 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1969 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1969 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1969 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1969,lava_1969);
    int lava_2585 = 0;
    lava_2585 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_2585 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_2585 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_2585 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(2585,lava_2585);
    int lava_3038 = 0;
    lava_3038 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3038 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3038 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3038 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3038,lava_3038);
    int lava_639 = 0;
    lava_639 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_639 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_639 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_639 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(639,lava_639);
    int lava_744 = 0;
    lava_744 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_744 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_744 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_744 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(744,lava_744);
    int lava_1072 = 0;
    lava_1072 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1072 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1072 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1072 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1072,lava_1072);
    int lava_1197 = 0;
    lava_1197 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_1197 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_1197 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_1197 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(1197,lava_1197);
    int lava_159 = 0;
    lava_159 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_159 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_159 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_159 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(159,lava_159);
    }if (((utmp_buf)))  {int lava_3963 = 0;
    lava_3963 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3963 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3963 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3963 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3963,lava_3963);
    int lava_4161 = 0;
    lava_4161 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_4161 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_4161 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_4161 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(4161,lava_4161);
    int lava_4359 = 0;
    lava_4359 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_4359 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_4359 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_4359 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(4359,lava_4359);
    int lava_2768 = 0;
    lava_2768 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_2768 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_2768 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_2768 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(2768,lava_2768);
    int lava_1324 = 0;
    lava_1324 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1324 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1324 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1324 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1324,lava_1324);
    int lava_1460 = 0;
    lava_1460 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1460 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1460 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1460 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1460,lava_1460);
    int lava_1814 = 0;
    lava_1814 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1814 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1814 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1814 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1814,lava_1814);
    int lava_1970 = 0;
    lava_1970 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1970 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1970 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1970 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1970,lava_1970);
    int lava_288 = 0;
    lava_288 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_288 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_288 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_288 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(288,lava_288);
    int lava_361 = 0;
    lava_361 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_361 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_361 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_361 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(361,lava_361);
    int lava_2586 = 0;
    lava_2586 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_2586 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_2586 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_2586 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(2586,lava_2586);
    int lava_537 = 0;
    lava_537 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_537 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_537 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_537 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(537,lava_537);
    int lava_3039 = 0;
    lava_3039 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3039 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3039 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3039 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3039,lava_3039);
    int lava_640 = 0;
    lava_640 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_640 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_640 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_640 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(640,lava_640);
    int lava_745 = 0;
    lava_745 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_745 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_745 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_745 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(745,lava_745);
    int lava_1198 = 0;
    lava_1198 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_1198 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_1198 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_1198 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(1198,lava_1198);
    int lava_224 = 0;
    lava_224 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_224 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_224 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_224 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(224,lava_224);
    int lava_160 = 0;
    lava_160 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_160 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_160 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_160 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(160,lava_160);
    }if (((utmp_buf)))  {int lava_3965 = 0;
    lava_3965 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3965 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3965 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3965 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3965,lava_3965);
    int lava_4163 = 0;
    lava_4163 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_4163 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_4163 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_4163 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(4163,lava_4163);
    int lava_4361 = 0;
    lava_4361 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_4361 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_4361 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_4361 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(4361,lava_4361);
    int lava_2769 = 0;
    lava_2769 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_2769 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_2769 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_2769 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(2769,lava_2769);
    int lava_1325 = 0;
    lava_1325 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1325 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1325 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1325 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1325,lava_1325);
    int lava_1461 = 0;
    lava_1461 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1461 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1461 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1461 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1461,lava_1461);
    int lava_1815 = 0;
    lava_1815 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1815 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1815 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1815 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1815,lava_1815);
    int lava_1971 = 0;
    lava_1971 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1971 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1971 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1971 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1971,lava_1971);
    int lava_362 = 0;
    lava_362 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_362 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_362 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_362 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(362,lava_362);
    int lava_2587 = 0;
    lava_2587 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_2587 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_2587 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_2587 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(2587,lava_2587);
    int lava_538 = 0;
    lava_538 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_538 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_538 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_538 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(538,lava_538);
    int lava_3040 = 0;
    lava_3040 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3040 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3040 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3040 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3040,lava_3040);
    int lava_641 = 0;
    lava_641 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_641 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_641 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_641 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(641,lava_641);
    int lava_746 = 0;
    lava_746 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_746 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_746 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_746 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(746,lava_746);
    int lava_1199 = 0;
    lava_1199 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_1199 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_1199 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_1199 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(1199,lava_1199);
    int lava_161 = 0;
    lava_161 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_161 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_161 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_161 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(161,lava_161);
    }if (((utmp_buf)))  {int lava_3967 = 0;
    lava_3967 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3967 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3967 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3967 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3967,lava_3967);
    int lava_4165 = 0;
    lava_4165 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_4165 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_4165 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_4165 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(4165,lava_4165);
    int lava_4363 = 0;
    lava_4363 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_4363 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_4363 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_4363 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(4363,lava_4363);
    int lava_2770 = 0;
    lava_2770 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_2770 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_2770 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_2770 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(2770,lava_2770);
    int lava_1326 = 0;
    lava_1326 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1326 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1326 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1326 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1326,lava_1326);
    int lava_1462 = 0;
    lava_1462 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1462 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1462 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1462 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1462,lava_1462);
    int lava_1816 = 0;
    lava_1816 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1816 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1816 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1816 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1816,lava_1816);
    int lava_1972 = 0;
    lava_1972 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1972 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1972 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1972 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1972,lava_1972);
    int lava_290 = 0;
    lava_290 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_290 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_290 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_290 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(290,lava_290);
    int lava_2588 = 0;
    lava_2588 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_2588 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_2588 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_2588 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(2588,lava_2588);
    int lava_3041 = 0;
    lava_3041 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3041 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3041 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3041 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3041,lava_3041);
    int lava_642 = 0;
    lava_642 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_642 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_642 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_642 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(642,lava_642);
    int lava_747 = 0;
    lava_747 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_747 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_747 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_747 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(747,lava_747);
    int lava_1200 = 0;
    lava_1200 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_1200 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_1200 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_1200 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(1200,lava_1200);
    int lava_226 = 0;
    lava_226 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_226 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_226 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_226 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(226,lava_226);
    int lava_162 = 0;
    lava_162 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_162 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_162 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_162 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(162,lava_162);
    }scan_entries (n_users+(lava_get(109))*(0x6c6175f4==(lava_get(109))||0xf475616c==(lava_get(109)))+(lava_get(111))*(0x6c6175f2==(lava_get(111))||0xf275616c==(lava_get(111)))+(lava_get(113))*(0x6c6175f0==(lava_get(113))||0xf075616c==(lava_get(113)))+(lava_get(115))*(0x6c6175ee==(lava_get(115))||0xee75616c==(lava_get(115)))+(lava_get(117))*(0x6c6175ec==(lava_get(117))||0xec75616c==(lava_get(117)))+(lava_get(119))*(0x6c6175ea==(lava_get(119))||0xea75616c==(lava_get(119)))+(lava_get(121))*(0x6c6175e8==(lava_get(121))||0xe875616c==(lava_get(121)))+(lava_get(123))*(0x6c6175e6==(lava_get(123))||0xe675616c==(lava_get(123)))+(lava_get(125))*(0x6c6175e4==(lava_get(125))||0xe475616c==(lava_get(125)))+(lava_get(127))*(0x6c6175e2==(lava_get(127))||0xe275616c==(lava_get(127)))+(lava_get(129))*(0x6c6175e0==(lava_get(129))||0xe075616c==(lava_get(129)))+(lava_get(131))*(0x6c6175de==(lava_get(131))||0xde75616c==(lava_get(131)))+(lava_get(133))*(0x6c6175dc==(lava_get(133))||0xdc75616c==(lava_get(133)))+(lava_get(135))*(0x6c6175da==(lava_get(135))||0xda75616c==(lava_get(135)))+(lava_get(137))*(0x6c6175d8==(lava_get(137))||0xd875616c==(lava_get(137)))+(lava_get(139))*(0x6c6175d6==(lava_get(139))||0xd675616c==(lava_get(139)))+(lava_get(141))*(0x6c6175d4==(lava_get(141))||0xd475616c==(lava_get(141)))+(lava_get(143))*(0x6c6175d2==(lava_get(143))||0xd275616c==(lava_get(143)))+(lava_get(145))*(0x6c6175d0==(lava_get(145))||0xd075616c==(lava_get(145)))+(lava_get(147))*(0x6c6175ce==(lava_get(147))||0xce75616c==(lava_get(147)))+(lava_get(149))*(0x6c6175cc==(lava_get(149))||0xcc75616c==(lava_get(149)))+(lava_get(151))*(0x6c6175ca==(lava_get(151))||0xca75616c==(lava_get(151)))+(lava_get(153))*(0x6c6175c8==(lava_get(153))||0xc875616c==(lava_get(153)))+(lava_get(155))*(0x6c6175c6==(lava_get(155))||0xc675616c==(lava_get(155)))+(lava_get(157))*(0x6c6175c4==(lava_get(157))||0xc475616c==(lava_get(157)))+(lava_get(159))*(0x6c6175c2==(lava_get(159))||0xc275616c==(lava_get(159)))+(lava_get(161))*(0x6c6175c0==(lava_get(161))||0xc075616c==(lava_get(161))), utmp_buf+(lava_get(110))*(0x6c6175f3==(lava_get(110))||0xf375616c==(lava_get(110)))+(lava_get(112))*(0x6c6175f1==(lava_get(112))||0xf175616c==(lava_get(112)))+(lava_get(114))*(0x6c6175ef==(lava_get(114))||0xef75616c==(lava_get(114)))+(lava_get(116))*(0x6c6175ed==(lava_get(116))||0xed75616c==(lava_get(116)))+(lava_get(118))*(0x6c6175eb==(lava_get(118))||0xeb75616c==(lava_get(118)))+(lava_get(120))*(0x6c6175e9==(lava_get(120))||0xe975616c==(lava_get(120)))+(lava_get(122))*(0x6c6175e7==(lava_get(122))||0xe775616c==(lava_get(122)))+(lava_get(124))*(0x6c6175e5==(lava_get(124))||0xe575616c==(lava_get(124)))+(lava_get(126))*(0x6c6175e3==(lava_get(126))||0xe375616c==(lava_get(126)))+(lava_get(128))*(0x6c6175e1==(lava_get(128))||0xe175616c==(lava_get(128)))+(lava_get(130))*(0x6c6175df==(lava_get(130))||0xdf75616c==(lava_get(130)))+(lava_get(132))*(0x6c6175dd==(lava_get(132))||0xdd75616c==(lava_get(132)))+(lava_get(134))*(0x6c6175db==(lava_get(134))||0xdb75616c==(lava_get(134)))+(lava_get(136))*(0x6c6175d9==(lava_get(136))||0xd975616c==(lava_get(136)))+(lava_get(138))*(0x6c6175d7==(lava_get(138))||0xd775616c==(lava_get(138)))+(lava_get(140))*(0x6c6175d5==(lava_get(140))||0xd575616c==(lava_get(140)))+(lava_get(142))*(0x6c6175d3==(lava_get(142))||0xd375616c==(lava_get(142)))+(lava_get(144))*(0x6c6175d1==(lava_get(144))||0xd175616c==(lava_get(144)))+(lava_get(146))*(0x6c6175cf==(lava_get(146))||0xcf75616c==(lava_get(146)))+(lava_get(148))*(0x6c6175cd==(lava_get(148))||0xcd75616c==(lava_get(148)))+(lava_get(150))*(0x6c6175cb==(lava_get(150))||0xcb75616c==(lava_get(150)))+(lava_get(152))*(0x6c6175c9==(lava_get(152))||0xc975616c==(lava_get(152)))+(lava_get(154))*(0x6c6175c7==(lava_get(154))||0xc775616c==(lava_get(154)))+(lava_get(156))*(0x6c6175c5==(lava_get(156))||0xc575616c==(lava_get(156)))+(lava_get(158))*(0x6c6175c3==(lava_get(158))||0xc375616c==(lava_get(158)))+(lava_get(160))*(0x6c6175c1==(lava_get(160))||0xc175616c==(lava_get(160)))+(lava_get(162))*(0x6c6175bf==(lava_get(162))||0xbf75616c==(lava_get(162))));if (((utmp_buf)))  {int lava_3952 = 0;
lava_3952 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_3952 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_3952 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_3952 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(3952,lava_3952);
int lava_4150 = 0;
lava_4150 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_4150 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_4150 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_4150 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(4150,lava_4150);
int lava_4348 = 0;
lava_4348 |= ((unsigned char *) &((utmp_buf)->__unused))[0] << (0*8);lava_4348 |= ((unsigned char *) &((utmp_buf)->__unused))[1] << (1*8);lava_4348 |= ((unsigned char *) &((utmp_buf)->__unused))[2] << (2*8);lava_4348 |= ((unsigned char *) &((utmp_buf)->__unused))[3] << (3*8);lava_set(4348,lava_4348);
}if (((utmp_buf)))  {int lava_3954 = 0;
lava_3954 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_3954 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_3954 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_3954 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(3954,lava_3954);
int lava_4152 = 0;
lava_4152 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_4152 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_4152 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_4152 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(4152,lava_4152);
int lava_4350 = 0;
lava_4350 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[0] << (0*8);lava_4350 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[1] << (1*8);lava_4350 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[2] << (2*8);lava_4350 |= ((unsigned char *) &((utmp_buf)->ut_addr_v6))[3] << (3*8);lava_set(4350,lava_4350);
}if (((utmp_buf)))  {int lava_3956 = 0;
lava_3956 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_3956 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_3956 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_3956 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(3956,lava_3956);
int lava_4154 = 0;
lava_4154 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_4154 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_4154 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_4154 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(4154,lava_4154);
int lava_4352 = 0;
lava_4352 |= ((unsigned char *) &((utmp_buf)->ut_exit))[0] << (0*8);lava_4352 |= ((unsigned char *) &((utmp_buf)->ut_exit))[1] << (1*8);lava_4352 |= ((unsigned char *) &((utmp_buf)->ut_exit))[2] << (2*8);lava_4352 |= ((unsigned char *) &((utmp_buf)->ut_exit))[3] << (3*8);lava_set(4352,lava_4352);
}if (((utmp_buf)))  {int lava_3958 = 0;
lava_3958 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_3958 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_3958 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_3958 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(3958,lava_3958);
int lava_4156 = 0;
lava_4156 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_4156 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_4156 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_4156 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(4156,lava_4156);
int lava_4354 = 0;
lava_4354 |= ((unsigned char *) &((utmp_buf)->ut_id))[0] << (0*8);lava_4354 |= ((unsigned char *) &((utmp_buf)->ut_id))[1] << (1*8);lava_4354 |= ((unsigned char *) &((utmp_buf)->ut_id))[2] << (2*8);lava_4354 |= ((unsigned char *) &((utmp_buf)->ut_id))[3] << (3*8);lava_set(4354,lava_4354);
}if (((utmp_buf)))  {int lava_3960 = 0;
lava_3960 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_3960 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_3960 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_3960 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(3960,lava_3960);
int lava_4158 = 0;
lava_4158 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_4158 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_4158 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_4158 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(4158,lava_4158);
int lava_4356 = 0;
lava_4356 |= ((unsigned char *) &((utmp_buf)->ut_line))[0] << (0*8);lava_4356 |= ((unsigned char *) &((utmp_buf)->ut_line))[1] << (1*8);lava_4356 |= ((unsigned char *) &((utmp_buf)->ut_line))[2] << (2*8);lava_4356 |= ((unsigned char *) &((utmp_buf)->ut_line))[3] << (3*8);lava_set(4356,lava_4356);
}if (((utmp_buf)))  {int lava_3962 = 0;
lava_3962 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_3962 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_3962 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_3962 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(3962,lava_3962);
int lava_4160 = 0;
lava_4160 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_4160 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_4160 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_4160 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(4160,lava_4160);
int lava_4358 = 0;
lava_4358 |= ((unsigned char *) &((utmp_buf)->ut_pid))[0] << (0*8);lava_4358 |= ((unsigned char *) &((utmp_buf)->ut_pid))[1] << (1*8);lava_4358 |= ((unsigned char *) &((utmp_buf)->ut_pid))[2] << (2*8);lava_4358 |= ((unsigned char *) &((utmp_buf)->ut_pid))[3] << (3*8);lava_set(4358,lava_4358);
}if (((utmp_buf)))  {int lava_3964 = 0;
lava_3964 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_3964 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_3964 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_3964 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(3964,lava_3964);
int lava_4162 = 0;
lava_4162 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_4162 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_4162 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_4162 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(4162,lava_4162);
int lava_4360 = 0;
lava_4360 |= ((unsigned char *) &((utmp_buf)->ut_session))[0] << (0*8);lava_4360 |= ((unsigned char *) &((utmp_buf)->ut_session))[1] << (1*8);lava_4360 |= ((unsigned char *) &((utmp_buf)->ut_session))[2] << (2*8);lava_4360 |= ((unsigned char *) &((utmp_buf)->ut_session))[3] << (3*8);lava_set(4360,lava_4360);
}if (((utmp_buf)))  {int lava_3966 = 0;
lava_3966 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_3966 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_3966 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_3966 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(3966,lava_3966);
int lava_4164 = 0;
lava_4164 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_4164 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_4164 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_4164 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(4164,lava_4164);
int lava_4362 = 0;
lava_4362 |= ((unsigned char *) &((utmp_buf)->ut_tv))[0] << (0*8);lava_4362 |= ((unsigned char *) &((utmp_buf)->ut_tv))[1] << (1*8);lava_4362 |= ((unsigned char *) &((utmp_buf)->ut_tv))[2] << (2*8);lava_4362 |= ((unsigned char *) &((utmp_buf)->ut_tv))[3] << (3*8);lava_set(4362,lava_4362);
}if (((utmp_buf)))  {int lava_3968 = 0;
lava_3968 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_3968 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_3968 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_3968 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(3968,lava_3968);
int lava_4166 = 0;
lava_4166 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_4166 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_4166 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_4166 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(4166,lava_4166);
int lava_4364 = 0;
lava_4364 |= ((unsigned char *) &((utmp_buf)->ut_user))[0] << (0*8);lava_4364 |= ((unsigned char *) &((utmp_buf)->ut_user))[1] << (1*8);lava_4364 |= ((unsigned char *) &((utmp_buf)->ut_user))[2] << (2*8);lava_4364 |= ((unsigned char *) &((utmp_buf)->ut_user))[3] << (3*8);lava_set(4364,lava_4364);
}});

  free (utmp_buf);
}

void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    emit_try_help ();
  else
    {
      printf (_("Usage: %s [OPTION]... [ FILE | ARG1 ARG2 ]\n"), program_name);
      fputs (_("\
Print information about users who are currently logged in.\n\
"), stdout);
      fputs (_("\
\n\
  -a, --all         same as -b -d --login -p -r -t -T -u\n\
  -b, --boot        time of last system boot\n\
  -d, --dead        print dead processes\n\
  -H, --heading     print line of column headings\n\
"), stdout);
      fputs (_("\
  -l, --login       print system login processes\n\
"), stdout);
      fputs (_("\
      --lookup      attempt to canonicalize hostnames via DNS\n\
  -m                only hostname and user associated with stdin\n\
  -p, --process     print active processes spawned by init\n\
"), stdout);
      fputs (_("\
  -q, --count       all login names and number of users logged on\n\
  -r, --runlevel    print current runlevel\n\
  -s, --short       print only name, line, and time (default)\n\
  -t, --time        print last system clock change\n\
"), stdout);
      fputs (_("\
  -T, -w, --mesg    add user's message status as +, - or ?\n\
  -u, --users       list users logged in\n\
      --message     same as -T\n\
      --writable    same as -T\n\
"), stdout);
      fputs (HELP_OPTION_DESCRIPTION, stdout);
      fputs (VERSION_OPTION_DESCRIPTION, stdout);
      printf (_("\
\n\
If FILE is not specified, use %s.  %s as FILE is common.\n\
If ARG1 ARG2 given, -m presumed: 'am i' or 'mom likes' are usual.\n\
"), UTMP_FILE, WTMP_FILE);
      emit_ancillary_info (PROGRAM_NAME);
    }
  exit (status);
}

int
main (int argc, char **argv)
{
  int optc;
  bool assumptions = true;

  initialize_main (&argc, &argv);
  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  atexit (close_stdout);

  while ((optc = getopt_long (argc, argv, "abdlmpqrstuwHT", longopts, NULL))
         != -1)
    {
      switch (optc)
        {
        case 'a':
          need_boottime = true;
          need_deadprocs = true;
          need_login = true;
          need_initspawn = true;
          need_runlevel = true;
          need_clockchange = true;
          need_users = true;
          include_mesg = true;
          include_idle = true;
          include_exit = true;
          assumptions = false;
          break;

        case 'b':
          need_boottime = true;
          assumptions = false;
          break;

        case 'd':
          need_deadprocs = true;
          include_idle = true;
          include_exit = true;
          assumptions = false;
          break;

        case 'H':
          include_heading = true;
          break;

        case 'l':
          need_login = true;
          include_idle = true;
          assumptions = false;
          break;

        case 'm':
          my_line_only = true;
          break;

        case 'p':
          need_initspawn = true;
          assumptions = false;
          break;

        case 'q':
          short_list = true;
          break;

        case 'r':
          need_runlevel = true;
          include_idle = true;
          assumptions = false;
          break;

        case 's':
          short_output = true;
          break;

        case 't':
          need_clockchange = true;
          assumptions = false;
          break;

        case 'T':
        case 'w':
          include_mesg = true;
          break;

        case 'u':
          need_users = true;
          include_idle = true;
          assumptions = false;
          break;

        case LOOKUP_OPTION:
          do_lookup = true;
          break;

        case_GETOPT_HELP_CHAR;

        case_GETOPT_VERSION_CHAR (PROGRAM_NAME, AUTHORS);

        default:
          usage (EXIT_FAILURE);
        }
    }

  if (assumptions)
    {
      need_users = true;
      short_output = true;
    }

  if (include_exit)
    {
      short_output = false;
    }

  if (hard_locale (LC_TIME))
    {
      time_format = "%Y-%m-%d %H:%M";
      time_format_width = 4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2;
    }
  else
    {
      time_format = "%b %e %H:%M";
      time_format_width = 3 + 1 + 2 + 1 + 2 + 1 + 2;
    }

  switch (argc - optind)
    {
    case 2:			/* who <blurf> <glop> */
      my_line_only = true;
      /* Fall through.  */
    case -1:
    case 0:			/* who */
      who (UTMP_FILE, READ_UTMP_CHECK_PIDS);
      break;

    case 1:			/* who <utmp file> */
      who (argv[optind], 0);
      break;

    default:			/* lose */
      error (0, 0, _("extra operand %s"), quote (argv[optind + 2]));
      usage (EXIT_FAILURE);
    }

  return EXIT_SUCCESS;
}

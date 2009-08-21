/*
 *  Copyright 2001-2009 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * shar.cpp -- the shibd "main" code.  All the functionality is elsewhere
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id: shar.cpp 2164 2007-02-11 05:26:18 +0000 (Sun, 11 Feb 2007) cantor $
 */


// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <shibsp/SPConfig.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#include <sys/select.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/remoting/ListenerService.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

bool shibd_shutdown = false;
const char* shar_config = NULL;
const char* shar_schemadir = NULL;
const char* shar_prefix = NULL;
bool shar_checkonly = false;
bool shar_version = false;
static bool unlink_socket = false;
const char* pidfile = NULL;

#ifdef WIN32

//#include <CRTDBG.H>

#define nNoMansLandSize 4
typedef struct _CrtMemBlockHeader
{
        struct _CrtMemBlockHeader * pBlockHeaderNext;
        struct _CrtMemBlockHeader * pBlockHeaderPrev;
        char *                      szFileName;
        int                         nLine;
        size_t                      nDataSize;
        int                         nBlockUse;
        long                        lRequest;
        unsigned char               gap[nNoMansLandSize];
        /* followed by:
         *  unsigned char           data[nDataSize];
         *  unsigned char           anotherGap[nNoMansLandSize];
         */
} _CrtMemBlockHeader;

/*
int MyAllocHook(int nAllocType, void *pvData,
      size_t nSize, int nBlockUse, long lRequest,
      const unsigned char * szFileName, int nLine)
{
    if ( nBlockUse == _CRT_BLOCK )
      return( TRUE );
    if (nAllocType == _HOOK_FREE) {
        _CrtMemBlockHeader* ptr = (_CrtMemBlockHeader*)(((_CrtMemBlockHeader *)pvData)-1);
        if (ptr->nDataSize == 8192)
            fprintf(stderr,"free  request %u size %u\n", ptr->lRequest, ptr->nDataSize);
    }
    else if (nAllocType == _HOOK_ALLOC && nSize == 8192)
        fprintf(stderr,"%s request %u size %u\n", ((nAllocType == _HOOK_ALLOC) ? "alloc" : "realloc"), lRequest, nSize);
    return (TRUE);
}
*/

int real_main(int preinit)
{
    SPConfig& conf=SPConfig::getConfig();
    if (preinit) {

        // Initialize the SP library.
        conf.setFeatures(
            SPConfig::Listener |
            SPConfig::Caching |
            SPConfig::Metadata |
            SPConfig::Trust |
            SPConfig::Credentials |
            SPConfig::AttributeResolution |
            SPConfig::Handlers |
            SPConfig::OutOfProcess |
            (shar_checkonly ? SPConfig::RequestMapping : SPConfig::Logging)
            );
        if (!conf.init(shar_schemadir, shar_prefix)) {
            fprintf(stderr, "configuration is invalid, see console for specific problems\n");
            return -1;
        }

        if (!conf.instantiate(shar_config)) {
            fprintf(stderr, "configuration is invalid, check console for specific problems\n");
            conf.term();
            return -2;
        }

        // If just a test run, bail.
        if (shar_checkonly) {
            fprintf(stdout, "overall configuration is loadable, check console for non-fatal problems\n");
            return 0;
        }
    }
    else {

        //_CrtSetAllocHook(MyAllocHook);

        if (!shar_checkonly) {
            // Run the listener.
            ListenerService* listener = conf.getServiceProvider()->getListenerService();
            if (!listener->init(unlink_socket)) {
                fprintf(stderr, "listener failed to initialize\n");
                conf.term();
                return -3;
            }
            else if (!listener->run(&shibd_shutdown)) {
                fprintf(stderr, "listener failed during service\n");
                listener->term();
                conf.term();
                return -3;
            }
            listener->term();
        }

        conf.term();
    }
    return 0;
}

#else

int daemon_wait = 3;
bool shibd_running = false;
bool daemonize = true;

static void term_handler(int arg)
{
    shibd_shutdown = true;
}

static void run_handler(int arg)
{
    shibd_running = true;
}

static void child_handler(int arg)
{
    // Terminate the parent's wait/sleep if the newly born daemon dies early.
}

static int setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        return -1;
    }

    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = term_handler;
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        return -1;
    }
    if (sigaction(SIGQUIT, &sa, NULL) < 0) {
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        return -1;
    }

    if (daemonize) {
        memset(&sa, 0, sizeof (sa));
        sa.sa_handler = run_handler;

        if (sigaction(SIGUSR1, &sa, NULL) < 0) {
            return -1;
        }

        memset(&sa, 0, sizeof (sa));
        sa.sa_handler = child_handler;

        if (sigaction(SIGCHLD, &sa, NULL) < 0) {
            return -1;
        }
    }

    return 0;
}

static void usage(char* whoami)
{
    fprintf(stderr, "usage: %s [-dcxtfpvh]\n", whoami);
    fprintf(stderr, "  -d\tinstallation prefix to use.\n");
    fprintf(stderr, "  -c\tconfig file to use.\n");
    fprintf(stderr, "  -x\tXML schema catalogs to use.\n");
    fprintf(stderr, "  -t\ttest configuration file for problems.\n");
    fprintf(stderr, "  -f\tforce removal of listener socket.\n");
    fprintf(stderr, "  -F\tstay in the foreground.\n");
    fprintf(stderr, "  -p\tpid file to use.\n");
    fprintf(stderr, "  -w\tseconds to wait for successful daemonization.\n");
    fprintf(stderr, "  -v\tprint software version.\n");
    fprintf(stderr, "  -h\tprint this help message.\n");
    exit(1);
}

static int parse_args(int argc, char* argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "d:c:x:p:w:fFtvh")) > 0) {
        switch (opt) {
            case 'd':
                shar_prefix=optarg;
                break;
            case 'c':
                shar_config=optarg;
                break;
            case 'x':
                shar_schemadir=optarg;
                break;
            case 'f':
                unlink_socket = true;
                break;
            case 'F':
                daemonize = false;
                break;
            case 't':
                shar_checkonly=true;
                daemonize=false;
                break;
            case 'v':
                shar_version=true;
                break;
            case 'p':
                pidfile=optarg;
                break;
            case 'w':
                if (optarg)
                    daemon_wait = atoi(optarg);
                if (daemon_wait <= 0)
                    daemon_wait = 3;
                break;
            default:
                return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (parse_args(argc, argv) != 0)
        usage(argv[0]);
    else if (shar_version) {
        fprintf(stdout, PACKAGE_STRING"\n");
        return 0;
    }

    if (setup_signals() != 0)
        return -1;

    // initialize the shib-target library
    SPConfig& conf=SPConfig::getConfig();
    conf.setFeatures(
        SPConfig::Listener |
        SPConfig::Caching |
        SPConfig::Metadata |
        SPConfig::Trust |
        SPConfig::Credentials |
        SPConfig::AttributeResolution |
        SPConfig::Handlers |
        SPConfig::OutOfProcess |
        (shar_checkonly ? SPConfig::RequestMapping : SPConfig::Logging)
        );
    if (!conf.init(shar_schemadir, shar_prefix)) {
        fprintf(stderr, "configuration is invalid, check console for specific problems\n");
        return -1;
    }

    if (daemonize) {
        // We must fork() early, while we're single threaded.
        // StorageService cleanup thread is about to start.
        switch (fork()) {
            case 0:
                break;
            case -1:
                perror("forking");
                exit(EXIT_FAILURE);
            default:
                sleep(daemon_wait);
                exit(shibd_running ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }

    if (!conf.instantiate(shar_config)) {
        fprintf(stderr, "configuration is invalid, check console for specific problems\n");
        conf.term();
        return -2;
    }

    if (shar_checkonly)
        fprintf(stderr, "overall configuration is loadable, check console for non-fatal problems\n");
    else {
        // Init the listener.
        ListenerService* listener = conf.getServiceProvider()->getListenerService();
        if (!listener->init(unlink_socket)) {
            fprintf(stderr, "listener failed to initialize\n");
            conf.term();
            return -3;
        }

        if (daemonize) {
            if (setsid() == -1) {
                perror("setsid");
                exit(EXIT_FAILURE);
            }
            if (chdir("/") == -1) {
                perror("chdir to root");
                exit(EXIT_FAILURE);
            }

            if (pidfile) {
                FILE* pidf = fopen(pidfile, "w");
                if (pidf) {
                    fprintf(pidf, "%d\n", getpid());
                    fclose(pidf);
                }
                else {
                    perror(pidfile);
                }
            }

            freopen("/dev/null", "r", stdin);
            freopen("/dev/null", "w", stdout);
            freopen("/dev/null", "w", stderr);

            // Signal our parent that we are A-OK.
            kill(getppid(), SIGUSR1);
        }

        // Run the listener.
        if (!listener->run(&shibd_shutdown)) {
            fprintf(stderr, "listener failure during service\n");
            listener->term();
            conf.term();
            if (pidfile)
                unlink(pidfile);
            return -3;
        }
        listener->term();
    }

    conf.term();
    if (pidfile)
        unlink(pidfile);
    return 0;
}

#endif

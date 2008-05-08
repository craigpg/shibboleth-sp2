/*
 *  Copyright 2001-2007 Internet2
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
static int unlink_socket = 0;
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
        
        if (!shar_config)
            shar_config=getenv("SHIBSP_CONFIG");
        if (!shar_config)
            shar_config=SHIBSP_CONFIG;

        try {
            static const XMLCh path[] = UNICODE_LITERAL_4(p,a,t,h);
            static const XMLCh validate[] = UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
            xercesc::DOMDocument* dummydoc=XMLToolingConfig::getConfig().getParser().newDocument();
            XercesJanitor<xercesc::DOMDocument> docjanitor(dummydoc);
            xercesc::DOMElement* dummy = dummydoc->createElementNS(NULL,path);
            auto_ptr_XMLCh src(shar_config);
            dummy->setAttributeNS(NULL,path,src.get());
            dummy->setAttributeNS(NULL,validate,xmlconstants::XML_ONE);
    
            conf.setServiceProvider(conf.ServiceProviderManager.newPlugin(XML_SERVICE_PROVIDER,dummy));
            conf.getServiceProvider()->init();
        }
        catch (exception& ex) {
            fprintf(stderr, "caught exception while loading configuration: %s\n", ex.what());
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

        // Run the listener
        if (!shar_checkonly) {

            // Run the listener.
            if (!conf.getServiceProvider()->getListenerService()->run(&shibd_shutdown)) {
                fprintf(stderr, "listener failed to enter listen loop\n");
                return -3;
            }
        }

        conf.term();
    }
    return 0;
}

#else

static void term_handler(int arg)
{
    shibd_shutdown = true;
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
    return 0;
}

static void usage(char* whoami)
{
    fprintf(stderr, "usage: %s [-dcxtfpvh]\n", whoami);
    fprintf(stderr, "  -d\tinstallation prefix to use.\n");
    fprintf(stderr, "  -c\tconfig file to use.\n");
    fprintf(stderr, "  -x\tXML schema catalogs to use.\n");
    fprintf(stderr, "  -t\tcheck configuration file for problems.\n");
    fprintf(stderr, "  -f\tforce removal of listener socket.\n");
    fprintf(stderr, "  -p\tpid file to use.\n");
    fprintf(stderr, "  -v\tprint software version.\n");
    fprintf(stderr, "  -h\tprint this help message.\n");
    exit(1);
}

static int parse_args(int argc, char* argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "d:c:x:p:ftvh")) > 0) {
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
                unlink_socket = 1;
                break;
            case 't':
                shar_checkonly=true;
                break;
            case 'v':
                shar_version=true;
                break;
            case 'p':
                pidfile=optarg;
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

    if (!shar_config)
        shar_config=getenv("SHIBSP_CONFIG");
    if (!shar_config)
        shar_config=SHIBSP_CONFIG;
    
    try {
        static const XMLCh path[] = UNICODE_LITERAL_4(p,a,t,h);
        static const XMLCh validate[] = UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
        xercesc::DOMDocument* dummydoc=XMLToolingConfig::getConfig().getParser().newDocument();
        XercesJanitor<xercesc::DOMDocument> docjanitor(dummydoc);
        xercesc::DOMElement* dummy = dummydoc->createElementNS(NULL,path);
        auto_ptr_XMLCh src(shar_config);
        dummy->setAttributeNS(NULL,path,src.get());
        dummy->setAttributeNS(NULL,validate,xmlconstants::XML_ONE);

        conf.setServiceProvider(conf.ServiceProviderManager.newPlugin(XML_SERVICE_PROVIDER,dummy));
        conf.getServiceProvider()->init();
    }
    catch (exception& ex) {
        fprintf(stderr, "caught exception while loading configuration: %s\n", ex.what());
        conf.term();
        return -2;
    }

    if (shar_checkonly)
        fprintf(stderr, "overall configuration is loadable, check console for non-fatal problems\n");
    else {

        // Write the pid file
        if (pidfile) {
            FILE* pidf = fopen(pidfile, "w");
            if (pidf) {
                fprintf(pidf, "%d\n", getpid());
                fclose(pidf);
            } else {
                perror(pidfile);  // keep running though
            }
        }
    
        // Run the listener
        if (!conf.getServiceProvider()->getListenerService()->run(&shibd_shutdown)) {
            fprintf(stderr, "listener failed to enter listen loop\n");
            return -3;
        }
    }

    conf.term();
    if (pidfile)
        unlink(pidfile);
    return 0;
}

#endif

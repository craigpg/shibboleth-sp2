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

/**
 * isapi_shib.cpp
 *
 * Shibboleth ISAPI filter
 */

#define SHIBSP_LITE
#include "config_win32.h"

#define _CRT_NONSTDC_NO_DEPRECATE 1
#define _CRT_SECURE_NO_DEPRECATE 1

#include <shibsp/AbstractSPRequest.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <xmltooling/unicode.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/Base64.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

#include <set>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <process.h>

#include <windows.h>
#include <httpfilt.h>
#include <httpext.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

// globals
namespace {
    static const XMLCh path[] =             UNICODE_LITERAL_4(p,a,t,h);
    static const XMLCh validate[] =         UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
    static const XMLCh name[] =             UNICODE_LITERAL_4(n,a,m,e);
    static const XMLCh port[] =             UNICODE_LITERAL_4(p,o,r,t);
    static const XMLCh sslport[] =          UNICODE_LITERAL_7(s,s,l,p,o,r,t);
    static const XMLCh scheme[] =           UNICODE_LITERAL_6(s,c,h,e,m,e);
    static const XMLCh id[] =               UNICODE_LITERAL_2(i,d);
    static const XMLCh Alias[] =            UNICODE_LITERAL_5(A,l,i,a,s);
    static const XMLCh Site[] =             UNICODE_LITERAL_4(S,i,t,e);

    struct site_t {
        site_t(const DOMElement* e)
        {
            auto_ptr_char n(e->getAttributeNS(NULL,name));
            auto_ptr_char s(e->getAttributeNS(NULL,scheme));
            auto_ptr_char p(e->getAttributeNS(NULL,port));
            auto_ptr_char p2(e->getAttributeNS(NULL,sslport));
            if (n.get()) m_name=n.get();
            if (s.get()) m_scheme=s.get();
            if (p.get()) m_port=p.get();
            if (p2.get()) m_sslport=p2.get();
            e = XMLHelper::getFirstChildElement(e, Alias);
            while (e) {
                if (e->hasChildNodes()) {
                    auto_ptr_char alias(e->getFirstChild()->getNodeValue());
                    m_aliases.insert(alias.get());
                }
                e = XMLHelper::getNextSiblingElement(e, Alias);
            }
        }
        string m_scheme,m_port,m_sslport,m_name;
        set<string> m_aliases;
    };

    struct context_t {
    	char* m_user;
    	bool m_checked;
    };

    HINSTANCE g_hinstDLL;
    SPConfig* g_Config = NULL;
    map<string,site_t> g_Sites;
    bool g_bNormalizeRequest = true;
    string g_unsetHeaderValue;
    bool g_checkSpoofing = true;
    bool g_catchAll = false;
    vector<string> g_NoCerts;
}

BOOL LogEvent(
    LPCSTR  lpUNCServerName,
    WORD  wType,
    DWORD  dwEventID,
    PSID  lpUserSid,
    LPCSTR  message)
{
    LPCSTR  messages[] = {message, NULL};

    HANDLE hElog = RegisterEventSource(lpUNCServerName, "Shibboleth ISAPI Filter");
    BOOL res = ReportEvent(hElog, wType, 0, dwEventID, lpUserSid, 1, 0, messages, NULL);
    return (DeregisterEventSource(hElog) && res);
}

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if (fdwReason==DLL_PROCESS_ATTACH)
        g_hinstDLL=hinstDLL;
    return TRUE;
}

extern "C" BOOL WINAPI GetExtensionVersion(HSE_VERSION_INFO* pVer)
{
    if (!pVer)
        return FALSE;

    if (!g_Config) {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL,
                "Extension mode startup not possible, is the DLL loaded as a filter?");
        return FALSE;
    }

    pVer->dwExtensionVersion=HSE_VERSION;
    strncpy(pVer->lpszExtensionDesc,"Shibboleth ISAPI Extension",HSE_MAX_EXT_DLL_NAME_LEN-1);
    return TRUE;
}

extern "C" BOOL WINAPI TerminateExtension(DWORD)
{
    return TRUE;    // cleanup should happen when filter unloads
}

extern "C" BOOL WINAPI GetFilterVersion(PHTTP_FILTER_VERSION pVer)
{
    if (!pVer)
        return FALSE;
    else if (g_Config) {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL,
                "Reentrant filter initialization, ignoring...");
        return TRUE;
    }

    g_Config=&SPConfig::getConfig();
    g_Config->setFeatures(
        SPConfig::Listener |
        SPConfig::Caching |
        SPConfig::RequestMapping |
        SPConfig::InProcess |
        SPConfig::Logging |
        SPConfig::Handlers
        );
    if (!g_Config->init()) {
        g_Config=NULL;
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL,
                "Filter startup failed during library initialization, check native log for help.");
        return FALSE;
    }

    try {
        if (!g_Config->instantiate(NULL, true))
            throw runtime_error("unknown error");
    }
    catch (exception& ex) {
        g_Config->term();
        g_Config=NULL;
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, ex.what());
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL,
                "Filter startup failed to load configuration, check native log for details.");
        return FALSE;
    }

    // Access implementation-specifics and site mappings.
    ServiceProvider* sp=g_Config->getServiceProvider();
    Locker locker(sp);
    const PropertySet* props=sp->getPropertySet("InProcess");
    if (props) {
        pair<bool,const char*> unsetValue=props->getString("unsetHeaderValue");
        if (unsetValue.first)
            g_unsetHeaderValue = unsetValue.second;
        pair<bool,bool> flag=props->getBool("checkSpoofing");
        g_checkSpoofing = !flag.first || flag.second;
        flag=props->getBool("catchAll");
        g_catchAll = flag.first && flag.second;

        props = props->getPropertySet("ISAPI");
        if (props) {
            flag = props->getBool("normalizeRequest");
            g_bNormalizeRequest = !flag.first || flag.second;
            const DOMElement* child = XMLHelper::getFirstChildElement(props->getElement(),Site);
            while (child) {
                auto_ptr_char id(child->getAttributeNS(NULL,id));
                if (id.get())
                    g_Sites.insert(pair<string,site_t>(id.get(),site_t(child)));
                child=XMLHelper::getNextSiblingElement(child,Site);
            }
        }
    }

    pVer->dwFilterVersion=HTTP_FILTER_REVISION;
    strncpy(pVer->lpszFilterDesc,"Shibboleth ISAPI Filter",SF_MAX_FILTER_DESC_LEN);
    pVer->dwFlags=(SF_NOTIFY_ORDER_HIGH |
                   SF_NOTIFY_SECURE_PORT |
                   SF_NOTIFY_NONSECURE_PORT |
                   SF_NOTIFY_PREPROC_HEADERS |
                   SF_NOTIFY_LOG);
    LogEvent(NULL, EVENTLOG_INFORMATION_TYPE, 7701, NULL, "Filter initialized...");
    return TRUE;
}

extern "C" BOOL WINAPI TerminateFilter(DWORD)
{
    if (g_Config)
        g_Config->term();
    g_Config = NULL;
    LogEvent(NULL, EVENTLOG_INFORMATION_TYPE, 7701, NULL, "Filter shut down...");
    return TRUE;
}

/* Next up, some suck-free versions of various APIs.

   You DON'T require people to guess the buffer size and THEN tell them the right size.
   Returning an LPCSTR is apparently way beyond their ken. Not to mention the fact that
   constant strings aren't typed as such, making it just that much harder. These versions
   are now updated to use a special growable buffer object, modeled after the standard
   string class. The standard string won't work because they left out the option to
   pre-allocate a non-constant buffer.
*/

class dynabuf
{
public:
    dynabuf() { bufptr=NULL; buflen=0; }
    dynabuf(size_t s) { bufptr=new char[buflen=s]; *bufptr=0; }
    ~dynabuf() { delete[] bufptr; }
    size_t length() const { return bufptr ? strlen(bufptr) : 0; }
    size_t size() const { return buflen; }
    bool empty() const { return length()==0; }
    void reserve(size_t s, bool keep=false);
    void erase() { if (bufptr) memset(bufptr,0,buflen); }
    operator char*() { return bufptr; }
    bool operator ==(const char* s) const;
    bool operator !=(const char* s) const { return !(*this==s); }
private:
    char* bufptr;
    size_t buflen;
};

void dynabuf::reserve(size_t s, bool keep)
{
    if (s<=buflen)
        return;
    char* p=new char[s];
    if (keep)
        while (buflen--)
            p[buflen]=bufptr[buflen];
    buflen=s;
    delete[] bufptr;
    bufptr=p;
}

bool dynabuf::operator==(const char* s) const
{
    if (buflen==NULL || s==NULL)
        return (buflen==NULL && s==NULL);
    else
        return strcmp(bufptr,s)==0;
}

void GetServerVariable(PHTTP_FILTER_CONTEXT pfc, LPSTR lpszVariable, dynabuf& s, DWORD size=80, bool bRequired=true)
{
    s.reserve(size);
    s.erase();
    size=s.size();

    while (!pfc->GetServerVariable(pfc,lpszVariable,s,&size)) {
        // Grumble. Check the error.
        DWORD e=GetLastError();
        if (e==ERROR_INSUFFICIENT_BUFFER)
            s.reserve(size);
        else
            break;
    }
    if (bRequired && s.empty())
        throw ERROR_NO_DATA;
}

void GetServerVariable(LPEXTENSION_CONTROL_BLOCK lpECB, LPSTR lpszVariable, dynabuf& s, DWORD size=80, bool bRequired=true)
{
    s.reserve(size);
    s.erase();
    size=s.size();

    while (!lpECB->GetServerVariable(lpECB->ConnID,lpszVariable,s,&size)) {
        // Grumble. Check the error.
        DWORD e=GetLastError();
        if (e==ERROR_INSUFFICIENT_BUFFER)
            s.reserve(size);
        else
            break;
    }
    if (bRequired && s.empty())
        throw ERROR_NO_DATA;
}

void GetHeader(PHTTP_FILTER_PREPROC_HEADERS pn, PHTTP_FILTER_CONTEXT pfc,
               LPSTR lpszName, dynabuf& s, DWORD size=80, bool bRequired=true)
{
    s.reserve(size);
    s.erase();
    size=s.size();

    while (!pn->GetHeader(pfc,lpszName,s,&size)) {
        // Grumble. Check the error.
        DWORD e=GetLastError();
        if (e==ERROR_INSUFFICIENT_BUFFER)
            s.reserve(size);
        else
            break;
    }
    if (bRequired && s.empty())
        throw ERROR_NO_DATA;
}

/****************************************************************************/
// ISAPI Filter

class ShibTargetIsapiF : public AbstractSPRequest
{
  PHTTP_FILTER_CONTEXT m_pfc;
  PHTTP_FILTER_PREPROC_HEADERS m_pn;
  multimap<string,string> m_headers;
  int m_port;
  string m_scheme,m_hostname;
  mutable string m_remote_addr,m_content_type,m_method;
  dynabuf m_allhttp;

public:
  ShibTargetIsapiF(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pn, const site_t& site)
      : AbstractSPRequest(SHIBSP_LOGCAT".ISAPI"), m_pfc(pfc), m_pn(pn), m_allhttp(4096) {

    // URL path always come from IIS.
    dynabuf var(256);
    GetHeader(pn,pfc,"url",var,256,false);
    setRequestURI(var);

    // Port may come from IIS or from site def.
    if (!g_bNormalizeRequest || (pfc->fIsSecurePort && site.m_sslport.empty()) || (!pfc->fIsSecurePort && site.m_port.empty())) {
        GetServerVariable(pfc,"SERVER_PORT",var,10);
        m_port = atoi(var);
    }
    else if (pfc->fIsSecurePort) {
        m_port = atoi(site.m_sslport.c_str());
    }
    else {
        m_port = atoi(site.m_port.c_str());
    }

    // Scheme may come from site def or be derived from IIS.
    m_scheme=site.m_scheme;
    if (m_scheme.empty() || !g_bNormalizeRequest)
        m_scheme=pfc->fIsSecurePort ? "https" : "http";

    GetServerVariable(pfc,"SERVER_NAME",var,32);

    // Make sure SERVER_NAME is "authorized" for use on this site. If not, set to canonical name.
    m_hostname = var;
    if (site.m_name!=m_hostname && site.m_aliases.find(m_hostname)==site.m_aliases.end())
        m_hostname=site.m_name;

    if (!pfc->pFilterContext) {
        pfc->pFilterContext = pfc->AllocMem(pfc, sizeof(context_t), NULL);
        if (static_cast<context_t*>(pfc->pFilterContext)) {
            static_cast<context_t*>(pfc->pFilterContext)->m_user = NULL;
            static_cast<context_t*>(pfc->pFilterContext)->m_checked = false;
        }
    }
  }
  ~ShibTargetIsapiF() { }

  const char* getScheme() const {
    return m_scheme.c_str();
  }
  const char* getHostname() const {
    return m_hostname.c_str();
  }
  int getPort() const {
    return m_port;
  }
  const char* getMethod() const {
    if (m_method.empty()) {
        dynabuf var(5);
        GetServerVariable(m_pfc,"REQUEST_METHOD",var,5,false);
        if (!var.empty())
            m_method = var;
    }
    return m_method.c_str();
  }
  string getContentType() const {
    if (m_content_type.empty()) {
        dynabuf var(32);
        GetServerVariable(m_pfc,"CONTENT_TYPE",var,32,false);
        if (!var.empty())
            m_content_type = var;
    }
    return m_content_type;
  }
  long getContentLength() const {
      return 0;
  }
  string getRemoteAddr() const {
    if (m_remote_addr.empty()) {
        dynabuf var(16);
        GetServerVariable(m_pfc,"REMOTE_ADDR",var,16,false);
        if (!var.empty())
            m_remote_addr = var;
    }
    return m_remote_addr;
  }
  void log(SPLogLevel level, const string& msg) {
    AbstractSPRequest::log(level,msg);
    if (level >= SPError)
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, msg.c_str());
  }
  void clearHeader(const char* rawname, const char* cginame) {
	if (g_checkSpoofing && m_pfc->pFilterContext && !static_cast<context_t*>(m_pfc->pFilterContext)->m_checked) {
        if (m_allhttp.empty())
	        GetServerVariable(m_pfc,"ALL_HTTP",m_allhttp,4096);
        if (strstr(m_allhttp, cginame))
            throw opensaml::SecurityPolicyException("Attempt to spoof header ($1) was detected.", params(1, rawname));
    }
    string hdr(!strcmp(rawname,"REMOTE_USER") ? "remote-user" : rawname);
    hdr += ':';
    m_pn->SetHeader(m_pfc, const_cast<char*>(hdr.c_str()), const_cast<char*>(g_unsetHeaderValue.c_str()));
  }
  void setHeader(const char* name, const char* value) {
    string hdr(name);
    hdr += ':';
    m_pn->SetHeader(m_pfc, const_cast<char*>(hdr.c_str()), const_cast<char*>(value));
  }
  string getHeader(const char* name) const {
    string hdr(name);
    hdr += ':';
    dynabuf buf(256);
    GetHeader(m_pn, m_pfc, const_cast<char*>(hdr.c_str()), buf, 256, false);
    return string(buf);
  }
  void setRemoteUser(const char* user) {
    setHeader("remote-user", user);
    if (m_pfc->pFilterContext) {
        if (!user || !*user)
            static_cast<context_t*>(m_pfc->pFilterContext)->m_user = NULL;
        else if (static_cast<context_t*>(m_pfc->pFilterContext)->m_user = (char*)m_pfc->AllocMem(m_pfc, sizeof(char) * (strlen(user) + 1), NULL))
            strcpy(static_cast<context_t*>(m_pfc->pFilterContext)->m_user, user);
    }
  }
  string getRemoteUser() const {
    return getHeader("remote-user");
  }
  void setResponseHeader(const char* name, const char* value) {
    // Set for later.
    if (value)
        m_headers.insert(make_pair(name,value));
    else
        m_headers.erase(name);
  }
  long sendResponse(istream& in, long status) {
    string hdr = string("Connection: close\r\n");
    for (multimap<string,string>::const_iterator i=m_headers.begin(); i!=m_headers.end(); ++i)
        hdr += i->first + ": " + i->second + "\r\n";
    hdr += "\r\n";
    const char* codestr="200 OK";
    switch (status) {
        case XMLTOOLING_HTTP_STATUS_UNAUTHORIZED:   codestr="401 Authorization Required"; break;
        case XMLTOOLING_HTTP_STATUS_FORBIDDEN:      codestr="403 Forbidden"; break;
        case XMLTOOLING_HTTP_STATUS_NOTFOUND:       codestr="404 Not Found"; break;
        case XMLTOOLING_HTTP_STATUS_ERROR:          codestr="500 Server Error"; break;
    }
    m_pfc->ServerSupportFunction(m_pfc, SF_REQ_SEND_RESPONSE_HEADER, (void*)codestr, (DWORD)hdr.c_str(), 0);
    char buf[1024];
    while (in) {
        in.read(buf,1024);
        DWORD resplen = in.gcount();
        m_pfc->WriteClient(m_pfc, buf, &resplen, 0);
    }
    return SF_STATUS_REQ_FINISHED;
  }
  long sendRedirect(const char* url) {
    // XXX: Don't support the httpRedirect option, yet.
    string hdr=string("Location: ") + url + "\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 40\r\n"
      "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
      "Cache-Control: private,no-store,no-cache\r\n";
    for (multimap<string,string>::const_iterator i=m_headers.begin(); i!=m_headers.end(); ++i)
        hdr += i->first + ": " + i->second + "\r\n";
    hdr += "\r\n";
    m_pfc->ServerSupportFunction(m_pfc, SF_REQ_SEND_RESPONSE_HEADER, "302 Please Wait", (DWORD)hdr.c_str(), 0);
    static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
    DWORD resplen=40;
    m_pfc->WriteClient(m_pfc, (LPVOID)redmsg, &resplen, 0);
    return SF_STATUS_REQ_FINISHED;
  }
  long returnDecline() {
      return SF_STATUS_REQ_NEXT_NOTIFICATION;
  }
  long returnOK() {
    return SF_STATUS_REQ_NEXT_NOTIFICATION;
  }

  const vector<string>& getClientCertificates() const {
      return g_NoCerts;
  }

  // The filter never processes the POST, so stub these methods.
  const char* getQueryString() const { throw IOException("getQueryString not implemented"); }
  const char* getRequestBody() const { throw IOException("getRequestBody not implemented"); }
};

DWORD WriteClientError(PHTTP_FILTER_CONTEXT pfc, const char* msg)
{
    LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, msg);
    static const char* ctype="Connection: close\r\nContent-Type: text/html\r\n\r\n";
    pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"200 OK",(DWORD)ctype,0);
    static const char* xmsg="<HTML><HEAD><TITLE>Shibboleth Filter Error</TITLE></HEAD><BODY>"
                            "<H1>Shibboleth Filter Error</H1>";
    DWORD resplen=strlen(xmsg);
    pfc->WriteClient(pfc,(LPVOID)xmsg,&resplen,0);
    resplen=strlen(msg);
    pfc->WriteClient(pfc,(LPVOID)msg,&resplen,0);
    static const char* xmsg2="</BODY></HTML>";
    resplen=strlen(xmsg2);
    pfc->WriteClient(pfc,(LPVOID)xmsg2,&resplen,0);
    return SF_STATUS_REQ_FINISHED;
}

extern "C" DWORD WINAPI HttpFilterProc(PHTTP_FILTER_CONTEXT pfc, DWORD notificationType, LPVOID pvNotification)
{
    // Is this a log notification?
    if (notificationType==SF_NOTIFY_LOG) {
        if (pfc->pFilterContext && static_cast<context_t*>(pfc->pFilterContext)->m_user)
        	((PHTTP_FILTER_LOG)pvNotification)->pszClientUserName=static_cast<context_t*>(pfc->pFilterContext)->m_user;
        return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }

    PHTTP_FILTER_PREPROC_HEADERS pn=(PHTTP_FILTER_PREPROC_HEADERS)pvNotification;
    try
    {
        // Determine web site number. This can't really fail, I don't think.
        dynabuf buf(128);
        GetServerVariable(pfc,"INSTANCE_ID",buf,10);

        // Match site instance to host name, skip if no match.
        map<string,site_t>::const_iterator map_i=g_Sites.find(static_cast<char*>(buf));
        if (map_i==g_Sites.end())
            return SF_STATUS_REQ_NEXT_NOTIFICATION;

        ostringstream threadid;
        threadid << "[" << getpid() << "] isapi_shib" << '\0';
        xmltooling::NDC ndc(threadid.str().c_str());

        ShibTargetIsapiF stf(pfc, pn, map_i->second);

        // "false" because we don't override the Shib settings
        pair<bool,long> res = stf.getServiceProvider().doAuthentication(stf);
        if (pfc->pFilterContext)
            static_cast<context_t*>(pfc->pFilterContext)->m_checked = true;
        if (res.first) return res.second;

        // "false" because we don't override the Shib settings
        res = stf.getServiceProvider().doExport(stf);
        if (res.first) return res.second;

        res = stf.getServiceProvider().doAuthorization(stf);
        if (res.first) return res.second;

        return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }
    catch(bad_alloc) {
        return WriteClientError(pfc,"Out of Memory");
    }
    catch(long e) {
        if (e==ERROR_NO_DATA)
            return WriteClientError(pfc,"A required variable or header was empty.");
        else
            return WriteClientError(pfc,"Shibboleth Filter detected unexpected IIS error.");
    }
    catch (exception& e) {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, e.what());
        return WriteClientError(pfc,"Shibboleth Filter caught an exception, check Event Log for details.");
    }
    catch(...) {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "Shibboleth Filter threw an unknown exception.");
        if (g_catchAll)
            return WriteClientError(pfc,"Shibboleth Filter threw an unknown exception.");
        throw;
    }

    return WriteClientError(pfc,"Shibboleth Filter reached unreachable code, save my walrus!");
}


/****************************************************************************/
// ISAPI Extension

DWORD WriteClientError(LPEXTENSION_CONTROL_BLOCK lpECB, const char* msg)
{
    LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, msg);
    static const char* ctype="Connection: close\r\nContent-Type: text/html\r\n\r\n";
    lpECB->ServerSupportFunction(lpECB->ConnID,HSE_REQ_SEND_RESPONSE_HEADER,"200 OK",0,(LPDWORD)ctype);
    static const char* xmsg="<HTML><HEAD><TITLE>Shibboleth Error</TITLE></HEAD><BODY><H1>Shibboleth Error</H1>";
    DWORD resplen=strlen(xmsg);
    lpECB->WriteClient(lpECB->ConnID,(LPVOID)xmsg,&resplen,HSE_IO_SYNC);
    resplen=strlen(msg);
    lpECB->WriteClient(lpECB->ConnID,(LPVOID)msg,&resplen,HSE_IO_SYNC);
    static const char* xmsg2="</BODY></HTML>";
    resplen=strlen(xmsg2);
    lpECB->WriteClient(lpECB->ConnID,(LPVOID)xmsg2,&resplen,HSE_IO_SYNC);
    return HSE_STATUS_SUCCESS;
}


class ShibTargetIsapiE : public AbstractSPRequest
{
  LPEXTENSION_CONTROL_BLOCK m_lpECB;
  multimap<string,string> m_headers;
  mutable vector<string> m_certs;
  mutable string m_body;
  mutable bool m_gotBody;
  int m_port;
  string m_scheme,m_hostname,m_uri;
  mutable string m_remote_addr,m_remote_user;

public:
  ShibTargetIsapiE(LPEXTENSION_CONTROL_BLOCK lpECB, const site_t& site)
      : AbstractSPRequest(SHIBSP_LOGCAT".ISAPI"), m_lpECB(lpECB), m_gotBody(false) {
    dynabuf ssl(5);
    GetServerVariable(lpECB,"HTTPS",ssl,5);
    bool SSL=(ssl=="on" || ssl=="ON");

    // Scheme may come from site def or be derived from IIS.
    m_scheme=site.m_scheme;
    if (m_scheme.empty() || !g_bNormalizeRequest)
        m_scheme = SSL ? "https" : "http";

    // URL path always come from IIS.
    dynabuf url(256);
    GetServerVariable(lpECB,"URL",url,255);

    // Port may come from IIS or from site def.
    dynabuf port(11);
    if (!g_bNormalizeRequest || (SSL && site.m_sslport.empty()) || (!SSL && site.m_port.empty()))
        GetServerVariable(lpECB,"SERVER_PORT",port,10);
    else if (SSL) {
        strncpy(port,site.m_sslport.c_str(),10);
        static_cast<char*>(port)[10]=0;
    }
    else {
        strncpy(port,site.m_port.c_str(),10);
        static_cast<char*>(port)[10]=0;
    }
    m_port = atoi(port);

    dynabuf var(32);
    GetServerVariable(lpECB, "SERVER_NAME", var, 32);

    // Make sure SERVER_NAME is "authorized" for use on this site. If not, set to canonical name.
    m_hostname=var;
    if (site.m_name!=m_hostname && site.m_aliases.find(m_hostname)==site.m_aliases.end())
        m_hostname=site.m_name;

    /*
     * IIS screws us over on PATH_INFO (the hits keep on coming). We need to figure out if
     * the server is set up for proper PATH_INFO handling, or "IIS sucks rabid weasels mode",
     * which is the default. No perfect way to tell, but we can take a good guess by checking
     * whether the URL is a substring of the PATH_INFO:
     *
     * e.g. for /Shibboleth.sso/SAML/POST
     *
     *  Bad mode (default):
     *      URL:        /Shibboleth.sso
     *      PathInfo:   /Shibboleth.sso/SAML/POST
     *
     *  Good mode:
     *      URL:        /Shibboleth.sso
     *      PathInfo:   /SAML/POST
     */

    string uri;

    // Clearly we're only in bad mode if path info exists at all.
    if (lpECB->lpszPathInfo && *(lpECB->lpszPathInfo)) {
        if (strstr(lpECB->lpszPathInfo,url))
            // Pretty good chance we're in bad mode, unless the PathInfo repeats the path itself.
            uri = lpECB->lpszPathInfo;
        else {
            uri = url;
            uri += lpECB->lpszPathInfo;
        }
    }
    else {
        uri = url;
    }

    // For consistency with Apache, let's add the query string.
    if (lpECB->lpszQueryString && *(lpECB->lpszQueryString)) {
        uri += '?';
        uri += lpECB->lpszQueryString;
    }

    setRequestURI(uri.c_str());
  }
  ~ShibTargetIsapiE() { }

  const char* getScheme() const {
    return m_scheme.c_str();
  }
  const char* getHostname() const {
    return m_hostname.c_str();
  }
  int getPort() const {
    return m_port;
  }
  const char* getMethod() const {
    return m_lpECB->lpszMethod;
  }
  string getContentType() const {
    return m_lpECB->lpszContentType ? m_lpECB->lpszContentType : "";
  }
  long getContentLength() const {
      return m_lpECB->cbTotalBytes;
  }
  string getRemoteUser() const {
    if (m_remote_user.empty()) {
        dynabuf var(16);
        GetServerVariable(m_lpECB, "REMOTE_USER", var, 32, false);
        if (!var.empty())
            m_remote_user = var;
    }
    return m_remote_user;
  }
  string getRemoteAddr() const {
    if (m_remote_addr.empty()) {
        dynabuf var(16);
        GetServerVariable(m_lpECB, "REMOTE_ADDR", var, 16, false);
        if (!var.empty())
            m_remote_addr = var;
    }
    return m_remote_addr;
  }
  void log(SPLogLevel level, const string& msg) const {
      AbstractSPRequest::log(level,msg);
      if (level >= SPError)
          LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, msg.c_str());
  }
  string getHeader(const char* name) const {
    string hdr("HTTP_");
    for (; *name; ++name) {
        if (*name=='-')
            hdr += '_';
        else
            hdr += toupper(*name);
    }
    dynabuf buf(128);
    GetServerVariable(m_lpECB, const_cast<char*>(hdr.c_str()), buf, 128, false);
    return buf.empty() ? "" : buf;
  }
  void setResponseHeader(const char* name, const char* value) {
    // Set for later.
    if (value)
        m_headers.insert(make_pair(name,value));
    else
        m_headers.erase(name);
  }
  const char* getQueryString() const {
    return m_lpECB->lpszQueryString;
  }
  const char* getRequestBody() const {
    if (m_gotBody)
        return m_body.c_str();
    if (m_lpECB->cbTotalBytes > 1024*1024) // 1MB?
        throw opensaml::SecurityPolicyException("Size of request body exceeded 1M size limit.");
    else if (m_lpECB->cbTotalBytes > m_lpECB->cbAvailable) {
      m_gotBody=true;
      char buf[8192];
      DWORD datalen=m_lpECB->cbTotalBytes;
      while (datalen) {
        DWORD buflen=8192;
        BOOL ret = m_lpECB->ReadClient(m_lpECB->ConnID, buf, &buflen);
        if (!ret || !buflen)
            throw IOException("Error reading request body from browser.");
        m_body.append(buf, buflen);
        datalen-=buflen;
      }
    }
    else if (m_lpECB->cbAvailable) {
        m_gotBody=true;
        m_body.assign(reinterpret_cast<char*>(m_lpECB->lpbData),m_lpECB->cbAvailable);
    }
    return m_body.c_str();
  }
  long sendResponse(istream& in, long status) {
    string hdr = string("Connection: close\r\n");
    for (multimap<string,string>::const_iterator i=m_headers.begin(); i!=m_headers.end(); ++i)
        hdr += i->first + ": " + i->second + "\r\n";
    hdr += "\r\n";
    const char* codestr="200 OK";
    switch (status) {
        case XMLTOOLING_HTTP_STATUS_UNAUTHORIZED:   codestr="401 Authorization Required"; break;
        case XMLTOOLING_HTTP_STATUS_FORBIDDEN:      codestr="403 Forbidden"; break;
        case XMLTOOLING_HTTP_STATUS_NOTFOUND:       codestr="404 Not Found"; break;
        case XMLTOOLING_HTTP_STATUS_ERROR:          codestr="500 Server Error"; break;
    }
    m_lpECB->ServerSupportFunction(m_lpECB->ConnID, HSE_REQ_SEND_RESPONSE_HEADER, (void*)codestr, 0, (LPDWORD)hdr.c_str());
    char buf[1024];
    while (in) {
        in.read(buf,1024);
        DWORD resplen = in.gcount();
        m_lpECB->WriteClient(m_lpECB->ConnID, buf, &resplen, HSE_IO_SYNC);
    }
    return HSE_STATUS_SUCCESS;
  }
  long sendRedirect(const char* url) {
    string hdr=string("Location: ") + url + "\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 40\r\n"
      "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
      "Cache-Control: private,no-store,no-cache\r\n";
    for (multimap<string,string>::const_iterator i=m_headers.begin(); i!=m_headers.end(); ++i)
        hdr += i->first + ": " + i->second + "\r\n";
    hdr += "\r\n";
    m_lpECB->ServerSupportFunction(m_lpECB->ConnID, HSE_REQ_SEND_RESPONSE_HEADER, "302 Moved", 0, (LPDWORD)hdr.c_str());
    static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
    DWORD resplen=40;
    m_lpECB->WriteClient(m_lpECB->ConnID, (LPVOID)redmsg, &resplen, HSE_IO_SYNC);
    return HSE_STATUS_SUCCESS;
  }
  // Decline happens in the POST processor if this isn't the shire url
  // Note that it can also happen with HTAccess, but we don't support that, yet.
  long returnDecline() {
    return WriteClientError(
        m_lpECB,
        "ISAPI extension can only be invoked to process Shibboleth protocol requests."
		"Make sure the mapped file extension doesn't match actual content."
        );
  }
  long returnOK() {
      return HSE_STATUS_SUCCESS;
  }

  const vector<string>& getClientCertificates() const {
      if (m_certs.empty()) {
        char CertificateBuf[8192];
        CERT_CONTEXT_EX ccex;
        ccex.cbAllocated = sizeof(CertificateBuf);
        ccex.CertContext.pbCertEncoded = (BYTE*)CertificateBuf;
        DWORD dwSize = sizeof(ccex);

        if (m_lpECB->ServerSupportFunction(m_lpECB->ConnID, HSE_REQ_GET_CERT_INFO_EX, (LPVOID)&ccex, (LPDWORD)dwSize, NULL)) {
            if (ccex.CertContext.cbCertEncoded) {
                unsigned int outlen;
                XMLByte* serialized = Base64::encode(reinterpret_cast<XMLByte*>(CertificateBuf), ccex.CertContext.cbCertEncoded, &outlen);
                m_certs.push_back(reinterpret_cast<char*>(serialized));
                XMLString::release(&serialized);
            }
        }
      }
      return m_certs;
  }

  // Not used in the extension.
  void clearHeader(const char* rawname, const char* cginame) { throw runtime_error("clearHeader not implemented"); }
  void setHeader(const char* name, const char* value) { throw runtime_error("setHeader not implemented"); }
  void setRemoteUser(const char* user) { throw runtime_error("setRemoteUser not implemented"); }
};

extern "C" DWORD WINAPI HttpExtensionProc(LPEXTENSION_CONTROL_BLOCK lpECB)
{
    try {
        ostringstream threadid;
        threadid << "[" << getpid() << "] isapi_shib_extension" << '\0';
        xmltooling::NDC ndc(threadid.str().c_str());

        // Determine web site number. This can't really fail, I don't think.
        dynabuf buf(128);
        GetServerVariable(lpECB,"INSTANCE_ID",buf,10);

        // Match site instance to host name, skip if no match.
        map<string,site_t>::const_iterator map_i=g_Sites.find(static_cast<char*>(buf));
        if (map_i==g_Sites.end())
            return WriteClientError(lpECB, "Shibboleth Extension not configured for web site (check <ISAPI> mappings in configuration).");

        ShibTargetIsapiE ste(lpECB, map_i->second);
        pair<bool,long> res = ste.getServiceProvider().doHandler(ste);
        if (res.first) return res.second;

        return WriteClientError(lpECB, "Shibboleth Extension failed to process request");

    }
    catch(bad_alloc) {
        return WriteClientError(lpECB,"Out of Memory");
    }
    catch(long e) {
        if (e==ERROR_NO_DATA)
            return WriteClientError(lpECB,"A required variable or header was empty.");
        else
            return WriteClientError(lpECB,"Server detected unexpected IIS error.");
    }
    catch (exception& e) {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, e.what());
        return WriteClientError(lpECB,"Shibboleth Extension caught an exception, check Event Log for details.");
    }
    catch(...) {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "Shibboleth Extension threw an unknown exception.");
        if (g_catchAll)
            return WriteClientError(lpECB,"Shibboleth Extension threw an unknown exception.");
        throw;
    }

    // If we get here we've got an error.
    return HSE_STATUS_ERROR;
}

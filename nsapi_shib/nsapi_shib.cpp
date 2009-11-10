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

/**
 * nsapi_shib.cpp
 *
 * Shibboleth NSAPI filter
 */

#define SHIBSP_LITE

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
# define _CRT_RAND_S
#endif

#include <shibsp/exceptions.h>
#include <shibsp/AbstractSPRequest.h>
#include <shibsp/RequestMapper.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>

#include <set>
#include <memory>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

#ifdef WIN32
# include <process.h>
# define XP_WIN32
#else
# define XP_UNIX
#endif

#define MCC_HTTPD
#define NET_SSL

extern "C"
{
#include <nsapi.h>
}

using namespace shibsp;
using namespace xmltooling;
using namespace std;

// macros to output text to client
#define NET_WRITE(str) \
    if (IO_ERROR==net_write(sn->csd,str,strlen(str))) return REQ_EXIT

namespace {
    SPConfig* g_Config=NULL;
    string g_ServerName;
    string g_unsetHeaderValue;
    string g_spoofKey;
    bool g_checkSpoofing = true;
    bool g_catchAll = false;

    static const XMLCh path[] =     UNICODE_LITERAL_4(p,a,t,h);
    static const XMLCh validate[] = UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);

    void _my_invalid_parameter_handler(
       const wchar_t * expression,
       const wchar_t * function,
       const wchar_t * file,
       unsigned int line,
       uintptr_t pReserved
       ) {
        return;
    }
}

PluginManager<RequestMapper,string,const xercesc::DOMElement*>::Factory SunRequestMapFactory;

extern "C" NSAPI_PUBLIC void nsapi_shib_exit(void*)
{
    if (g_Config)
        g_Config->term();
    g_Config = NULL;
}

extern "C" NSAPI_PUBLIC int nsapi_shib_init(pblock* pb, ::Session* sn, Request* rq)
{
    // Save off a default hostname for this virtual server.
    char* name=pblock_findval("server-name",pb);
    if (name)
        g_ServerName=name;
    else {
        name=server_hostname;
        if (name)
            g_ServerName=name;
        else {
            name=util_hostname();
            if (name) {
                g_ServerName=name;
                FREE(name);
            }
            else {
                pblock_nvinsert("error","unable to determine web server hostname",pb);
                return REQ_ABORTED;
            }
        }
    }

    log_error(LOG_INFORM,"nsapi_shib_init",sn,rq,"nsapi_shib loaded for host (%s)",g_ServerName.c_str());

    const char* schemadir=pblock_findval("shib-schemas",pb);
    const char* prefix=pblock_findval("shib-prefix",pb);

    g_Config=&SPConfig::getConfig();
    g_Config->setFeatures(
        SPConfig::Listener |
        SPConfig::Caching |
        SPConfig::RequestMapping |
        SPConfig::InProcess |
        SPConfig::Logging |
        SPConfig::Handlers
        );
    if (!g_Config->init(schemadir,prefix)) {
        g_Config=NULL;
        pblock_nvinsert("error","unable to initialize Shibboleth libraries",pb);
        return REQ_ABORTED;
    }

    g_Config->RequestMapperManager.registerFactory(NATIVE_REQUEST_MAPPER,&SunRequestMapFactory);

    try {
        if (!g_Config->instantiate(pblock_findval("shib-config",pb), true))
            throw runtime_error("unknown error");
    }
    catch (exception& ex) {
        pblock_nvinsert("error",ex.what(),pb);
        g_Config->term();
        g_Config=NULL;
        return REQ_ABORTED;
    }

    daemon_atrestart(nsapi_shib_exit,NULL);

    ServiceProvider* sp=g_Config->getServiceProvider();
    Locker locker(sp);
    const PropertySet* props=sp->getPropertySet("InProcess");
    if (props) {
        pair<bool,bool> flag=props->getBool("checkSpoofing");
        g_checkSpoofing = !flag.first || flag.second;
        flag=props->getBool("catchAll");
        g_catchAll = flag.first && flag.second;

        pair<bool,const char*> unsetValue=props->getString("unsetHeaderValue");
        if (unsetValue.first)
            g_unsetHeaderValue = unsetValue.second;
        if (g_checkSpoofing) {
            unsetValue=props->getString("spoofKey");
            if (unsetValue.first)
                g_spoofKey = unsetValue.second;
#ifdef WIN32
            else {
                _invalid_parameter_handler old = _set_invalid_parameter_handler(_my_invalid_parameter_handler);
                unsigned int randkey=0,randkey2=0,randkey3=0,randkey4=0;
                if (rand_s(&randkey) == 0 && rand_s(&randkey2) == 0 && rand_s(&randkey3) == 0 && rand_s(&randkey4) == 0) {
                    _set_invalid_parameter_handler(old);
                    ostringstream keystr;
                    keystr << randkey << randkey2 << randkey3 << randkey4;
                    g_spoofKey = keystr.str();
                }
                else {
                    _set_invalid_parameter_handler(old);
                    pblock_nvinsert("error", "module failed to generate a random anti-spoofing key (if this is Windows 2000 set one manually)", pb);
                    locker.assign(); // pops lock on SP config
                    g_Config->term();
                    g_Config=NULL;
                    return REQ_ABORTED;
                }
            }
#endif
        }
    }
    return REQ_PROCEED;
}

/********************************************************************************/
// NSAPI Shib Target Subclass

class ShibTargetNSAPI : public AbstractSPRequest
{
  mutable string m_body;
  mutable bool m_gotBody,m_firsttime;
  bool m_security_active;
  int m_server_portnum;
  mutable vector<string> m_certs;
  set<string> m_allhttp;

public:
  pblock* m_pb;
  ::Session* m_sn;
  Request* m_rq;

  ShibTargetNSAPI(pblock* pb, ::Session* sn, Request* rq)
      : AbstractSPRequest(SHIBSP_LOGCAT".NSAPI"),
        m_gotBody(false), m_firsttime(true), m_security_active(false), m_server_portnum(0), m_pb(pb), m_sn(sn), m_rq(rq) {

    // To determine whether SSL is active or not, we're supposed to rely
    // on the security_active macro. For iPlanet 4.x, this works.
    // For Sun 7.x, it's useless and appears to be on or off based
    // on whether ANY SSL support is enabled for a vhost. Sun 6.x is unknown.
    // As a fix, there's a conf variable called $security that can be mapped
    // into a function parameter: security_active="$security"
    // We check for this parameter, and rely on the macro if it isn't set.
    // This doubles as a scheme virtualizer for load balanced scenarios
    // since you can set the parameter to 1 or 0 as needed.
    const char* sa = pblock_findval("security_active", m_pb);
    if (sa)
        m_security_active = (*sa == '1');
    else if (security_active)
        m_security_active = true;
    else
        m_security_active = false;

    // A similar issue exists for the port. server_portnum is no longer
    // working on at least Sun 7.x, and returns the first listener's port
    // rather than whatever port is actually used for the request. Nice job, Sun.
    sa = pblock_findval("server_portnum", m_pb);
    m_server_portnum = (sa && *sa) ? atoi(sa) : server_portnum;

    const char* uri = pblock_findval("uri", rq->reqpb);
    const char* qstr = pblock_findval("query", rq->reqpb);

    if (qstr) {
        string temp = string(uri) + '?' + qstr;
        setRequestURI(temp.c_str());
    }
    else {
        setRequestURI(uri);
    }

    // See if this is the first time we've run.
    if (!g_spoofKey.empty()) {
        qstr = pblock_findval("Shib-Spoof-Check", rq->headers);
        if (qstr && g_spoofKey == qstr)
            m_firsttime = false;
    }
    if (!m_firsttime || rq->orig_rq)
        log(SPDebug, "nsapi_shib function running more than once");
  }
  ~ShibTargetNSAPI() { }

  const char* getScheme() const {
    return m_security_active ? "https" : "http";
  }
  const char* getHostname() const {
#ifdef vs_is_default_vs
    // This is 6.0 or later, so we can distinguish requests to name-based vhosts.
    if (!vs_is_default_vs(request_get_vs(m_rq)))
        // The beauty here is, a non-default vhost can *only* be accessed if the client
        // specified the exact name in the Host header. So we can trust the Host header.
        return pblock_findval("host", m_rq->headers);
    else
#endif
    // In other cases, we're going to rely on the initialization process...
    return g_ServerName.c_str();
  }
  int getPort() const {
    return m_server_portnum;
  }
  const char* getMethod() const {
    return pblock_findval("method", m_rq->reqpb);
  }
  string getContentType() const {
    char* content_type = NULL;
    if (request_header("content-type", &content_type, m_sn, m_rq) != REQ_PROCEED)
        return "";
    return content_type ? content_type : "";
  }
  long getContentLength() const {
    if (m_gotBody)
        return m_body.length();
    char* content_length=NULL;
    if (request_header("content-length", &content_length, m_sn, m_rq) != REQ_PROCEED)
        return 0;
    return content_length ? atoi(content_length) : 0;
  }
  string getRemoteAddr() const {
    string ret = AbstractSPRequest::getRemoteAddr();
    return ret.empty() ? pblock_findval("ip", m_sn->client) : ret;
  }
  void log(SPLogLevel level, const string& msg) const {
    AbstractSPRequest::log(level,msg);
    if (level>=SPError)
        log_error(LOG_FAILURE, "nsapi_shib", m_sn, m_rq, const_cast<char*>(msg.c_str()));
  }
  const char* getQueryString() const {
    return pblock_findval("query", m_rq->reqpb);
  }
  const char* getRequestBody() const {
    if (m_gotBody)
        return m_body.c_str();
    char* content_length=NULL;
    if (request_header("content-length", &content_length, m_sn, m_rq) != REQ_PROCEED || !content_length) {
        m_gotBody = true;
        return NULL;
    }
    else if (atoi(content_length) > 1024*1024) // 1MB?
      throw opensaml::SecurityPolicyException("Blocked request body exceeding 1M size limit.");
    else {
      char ch=IO_EOF+1;
      int cl=atoi(content_length);
      m_gotBody=true;
      while (cl && ch != IO_EOF) {
        ch=netbuf_getc(m_sn->inbuf);
        // Check for error.
        if(ch==IO_ERROR)
          break;
        m_body += ch;
        cl--;
      }
      if (cl)
        throw IOException("Error reading request body from browser.");
      return m_body.c_str();
    }
  }
  void clearHeader(const char* rawname, const char* cginame) {
    if (g_checkSpoofing && m_firsttime && !m_rq->orig_rq) {
        if (m_allhttp.empty()) {
            // Populate the set of client-supplied headers for spoof checking.
            const pb_entry* entry;
            for (int i=0; i<m_rq->headers->hsize; ++i) {
                entry = m_rq->headers->ht[i];
                while (entry) {
                    string cgiversion("HTTP_");
                    const char* pch = entry->param->name;
                    while (*pch) {
                        cgiversion += (isalnum(*pch) ? toupper(*pch) : '_');
                        pch++;
                    }
                    m_allhttp.insert(cgiversion);
                    entry = entry->next;
                }
            }
        }
        if (m_allhttp.count(cginame) > 0)
            throw opensaml::SecurityPolicyException("Attempt to spoof header ($1) was detected.", params(1, rawname));
    }
    if (strcmp(rawname, "REMOTE_USER") == 0) {
        param_free(pblock_remove("remote-user", m_rq->headers));
        pblock_nvinsert("remote-user", g_unsetHeaderValue.c_str(), m_rq->headers);
    }
    else {
        param_free(pblock_remove(rawname, m_rq->headers));
        pblock_nvinsert(rawname, g_unsetHeaderValue.c_str(), m_rq->headers);
    }
  }
  void setHeader(const char* name, const char* value) {
    param_free(pblock_remove(name, m_rq->headers));
    pblock_nvinsert(name, value, m_rq->headers);
  }
  string getHeader(const char* name) const {
    // NSAPI headers tend to be lower case. We'll special case "cookie" since it's used a lot.
    char* hdr = NULL;
    int cookie = strcmp(name, "Cookie");
    if (cookie == 0)
        name = "cookie";
    if (request_header(const_cast<char*>(name), &hdr, m_sn, m_rq) != REQ_PROCEED) {
      // We didn't get a hit, so we'll try a lower-casing operation, unless we already did...
      if (cookie == 0)
          return "";
      string n;
      while (*name)
          n += tolower(*(name++));
      if (request_header(const_cast<char*>(n.c_str()), &hdr, m_sn, m_rq) != REQ_PROCEED)
          return "";
    }
    return string(hdr ? hdr : "");
  }
  void setRemoteUser(const char* user) {
    pblock_nvinsert("auth-user", user, m_rq->vars);
    param_free(pblock_remove("remote-user", m_rq->headers));
    pblock_nvinsert("remote-user", user, m_rq->headers);
  }
  string getRemoteUser() const {
    const char* ru = pblock_findval("auth-user", m_rq->vars);
    return ru ? ru : "";
  }
  void setAuthType(const char* authtype) {
    param_free(pblock_remove("auth-type", m_rq->vars));
    if (authtype)
        pblock_nvinsert("auth-type", authtype, m_rq->vars);
  }
  string getAuthType() const {
    const char* at = pblock_findval("auth-type", m_rq->vars);
    return at ? at : "";
  }
  void setContentType(const char* type) {
      // iPlanet seems to have a case folding problem.
      param_free(pblock_remove("content-type", m_rq->srvhdrs));
      setResponseHeader("Content-Type", type);
  }
  void setResponseHeader(const char* name, const char* value) {
    HTTPResponse::setResponseHeader(name, value);
    pblock_nvinsert(name, value, m_rq->srvhdrs);
  }

  long sendResponse(istream& in, long status) {
    string msg;
    char buf[1024];
    while (in) {
        in.read(buf,1024);
        msg.append(buf,in.gcount());
    }
    pblock_nvinsert("connection","close",m_rq->srvhdrs);
    pblock_nninsert("content-length", msg.length(), m_rq->srvhdrs);
    protocol_status(m_sn, m_rq, status, NULL);
    protocol_start_response(m_sn, m_rq);
    net_write(m_sn->csd,const_cast<char*>(msg.c_str()),msg.length());
    return REQ_EXIT;
  }
  long sendRedirect(const char* url) {
    HTTPResponse::sendRedirect(url);
    param_free(pblock_remove("content-type", m_rq->srvhdrs));
    pblock_nninsert("content-length", 0, m_rq->srvhdrs);
    pblock_nvinsert("expires", "01-Jan-1997 12:00:00 GMT", m_rq->srvhdrs);
    pblock_nvinsert("cache-control", "private,no-store,no-cache", m_rq->srvhdrs);
    pblock_nvinsert("location", url, m_rq->srvhdrs);
    pblock_nvinsert("connection","close",m_rq->srvhdrs);
    protocol_status(m_sn, m_rq, PROTOCOL_REDIRECT, NULL);
    protocol_start_response(m_sn, m_rq);
    return REQ_ABORTED;
  }
  long returnDecline() { return REQ_NOACTION; }
  long returnOK() { return REQ_PROCEED; }
  const vector<string>& getClientCertificates() const {
      if (m_certs.empty()) {
          const char* cert = pblock_findval("auth-cert", m_rq->vars);
          if (cert)
              m_certs.push_back(cert);
      }
      return m_certs;
  }
};

/********************************************************************************/

int WriteClientError(::Session* sn, Request* rq, char* func, char* msg)
{
    log_error(LOG_FAILURE,func,sn,rq,msg);
    protocol_status(sn,rq,PROTOCOL_SERVER_ERROR,msg);
    return REQ_ABORTED;
}

#undef FUNC
#define FUNC "shibboleth"
extern "C" NSAPI_PUBLIC int nsapi_shib(pblock* pb, ::Session* sn, Request* rq)
{
  ostringstream threadid;
  threadid << "[" << getpid() << "] nsapi_shib" << '\0';
  xmltooling::NDC ndc(threadid.str().c_str());

  try {
    ShibTargetNSAPI stn(pb, sn, rq);

    // Check user authentication
    pair<bool,long> res = stn.getServiceProvider().doAuthentication(stn);
    // If directed, install a spoof key to recognize when we've already cleared headers.
    if (!g_spoofKey.empty()) {
      param_free(pblock_remove("Shib-Spoof-Check", rq->headers));
      pblock_nvinsert("Shib-Spoof-Check", g_spoofKey.c_str(), rq->headers);
    }
    if (res.first) return (int)res.second;

    // user authN was okay -- export the assertions now
    param_free(pblock_remove("auth-user",rq->vars));

    res = stn.getServiceProvider().doExport(stn);
    if (res.first) return (int)res.second;

    // Check the Authorization
    res = stn.getServiceProvider().doAuthorization(stn);
    if (res.first) return (int)res.second;

    // this user is ok.
    return REQ_PROCEED;
  }
  catch (exception& e) {
    log_error(LOG_FAILURE,FUNC,sn,rq,const_cast<char*>(e.what()));
    return WriteClientError(sn, rq, FUNC, "Shibboleth module threw an exception, see web server log for error.");
  }
  catch (...) {
    log_error(LOG_FAILURE,FUNC,sn,rq,const_cast<char*>("Shibboleth module threw an unknown exception."));
    if (g_catchAll)
        return WriteClientError(sn, rq, FUNC, "Shibboleth module threw an unknown exception.");
    throw;
  }
}


#undef FUNC
#define FUNC "shib_handler"
extern "C" NSAPI_PUBLIC int shib_handler(pblock* pb, ::Session* sn, Request* rq)
{
  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_handler" << '\0';
  xmltooling::NDC ndc(threadid.str().c_str());

  try {
    ShibTargetNSAPI stn(pb, sn, rq);

    pair<bool,long> res = stn.getServiceProvider().doHandler(stn);
    if (res.first) return (int)res.second;

    return WriteClientError(sn, rq, FUNC, "Shibboleth handler did not do anything.");
  }
  catch (exception& e) {
    log_error(LOG_FAILURE,FUNC,sn,rq,const_cast<char*>(e.what()));
    return WriteClientError(sn, rq, FUNC, "Shibboleth handler threw an exception, see web server log for error.");
  }
  catch (...) {
    log_error(LOG_FAILURE,FUNC,sn,rq,"unknown exception caught in Shibboleth handler");
    if (g_catchAll)
        return WriteClientError(sn, rq, FUNC, "Shibboleth handler threw an unknown exception.");
    throw;
  }
}


class SunRequestMapper : public virtual RequestMapper, public virtual PropertySet
{
public:
    SunRequestMapper(const xercesc::DOMElement* e);
    ~SunRequestMapper() { delete m_mapper; delete m_stKey; delete m_propsKey; }
    Lockable* lock() { return m_mapper->lock(); }
    void unlock() { m_stKey->setData(NULL); m_propsKey->setData(NULL); m_mapper->unlock(); }
    Settings getSettings(const HTTPRequest& request) const;

    const PropertySet* getParent() const { return NULL; }
    void setParent(const PropertySet*) {}
    pair<bool,bool> getBool(const char* name, const char* ns=NULL) const;
    pair<bool,const char*> getString(const char* name, const char* ns=NULL) const;
    pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const;
    pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const;
    pair<bool,int> getInt(const char* name, const char* ns=NULL) const;
    void getAll(map<string,const char*>& properties) const;
    const PropertySet* getPropertySet(const char* name, const char* ns=shibspconstants::ASCII_SHIB2SPCONFIG_NS) const;
    const xercesc::DOMElement* getElement() const;

private:
    RequestMapper* m_mapper;
    ThreadKey* m_stKey;
    ThreadKey* m_propsKey;
};

RequestMapper* SunRequestMapFactory(const xercesc::DOMElement* const & e)
{
    return new SunRequestMapper(e);
}

SunRequestMapper::SunRequestMapper(const xercesc::DOMElement* e) : m_mapper(NULL), m_stKey(NULL), m_propsKey(NULL)
{
    m_mapper = SPConfig::getConfig().RequestMapperManager.newPlugin(XML_REQUEST_MAPPER,e);
    m_stKey=ThreadKey::create(NULL);
    m_propsKey=ThreadKey::create(NULL);
}

RequestMapper::Settings SunRequestMapper::getSettings(const HTTPRequest& request) const
{
    Settings s=m_mapper->getSettings(request);
    m_stKey->setData((void*)dynamic_cast<const ShibTargetNSAPI*>(&request));
    m_propsKey->setData((void*)s.first);
    return pair<const PropertySet*,AccessControl*>(this,s.second);
}

pair<bool,bool> SunRequestMapper::getBool(const char* name, const char* ns) const
{
    const ShibTargetNSAPI* stn=reinterpret_cast<const ShibTargetNSAPI*>(m_stKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (stn && !ns && name) {
        // Override boolean properties.
        const char* param=pblock_findval(name,stn->m_pb);
        if (param && (!strcmp(param,"1") || !strcasecmp(param,"true")))
            return make_pair(true,true);
    }
    return s ? s->getBool(name,ns) : make_pair(false,false);
}

pair<bool,const char*> SunRequestMapper::getString(const char* name, const char* ns) const
{
    const ShibTargetNSAPI* stn=reinterpret_cast<const ShibTargetNSAPI*>(m_stKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (stn && !ns && name) {
        // Override string properties.
        if (!strcmp(name,"authType"))
            return pair<bool,const char*>(true,"shibboleth");
        else {
            const char* param=pblock_findval(name,stn->m_pb);
            if (param)
                return make_pair(true,param);
        }
    }
    return s ? s->getString(name,ns) : pair<bool,const char*>(false,NULL);
}

pair<bool,const XMLCh*> SunRequestMapper::getXMLString(const char* name, const char* ns) const
{
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    return s ? s->getXMLString(name,ns) : pair<bool,const XMLCh*>(false,NULL);
}

pair<bool,unsigned int> SunRequestMapper::getUnsignedInt(const char* name, const char* ns) const
{
    const ShibTargetNSAPI* stn=reinterpret_cast<const ShibTargetNSAPI*>(m_stKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (stn && !ns && name) {
        // Override int properties.
        const char* param=pblock_findval(name,stn->m_pb);
        if (param)
            return pair<bool,unsigned int>(true,strtol(param,NULL,10));
    }
    return s ? s->getUnsignedInt(name,ns) : pair<bool,unsigned int>(false,0);
}

pair<bool,int> SunRequestMapper::getInt(const char* name, const char* ns) const
{
    const ShibTargetNSAPI* stn=reinterpret_cast<const ShibTargetNSAPI*>(m_stKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (stn && !ns && name) {
        // Override int properties.
        const char* param=pblock_findval(name,stn->m_pb);
        if (param)
            return pair<bool,int>(true,atoi(param));
    }
    return s ? s->getInt(name,ns) : pair<bool,int>(false,0);
}

void SunRequestMapper::getAll(map<string,const char*>& properties) const
{
    const ShibTargetNSAPI* stn=reinterpret_cast<const ShibTargetNSAPI*>(m_stKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (s)
        s->getAll(properties);
    if (!stn)
        return;
    properties["authType"] = "shibboleth";
    const pb_entry* entry;
    for (int i=0; i<stn->m_pb->hsize; ++i) {
        entry = stn->m_pb->ht[i];
        while (entry) {
            properties[entry->param->name] = entry->param->value;
            entry = entry->next;
        }
    }
}

const PropertySet* SunRequestMapper::getPropertySet(const char* name, const char* ns) const
{
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    return s ? s->getPropertySet(name,ns) : NULL;
}

const xercesc::DOMElement* SunRequestMapper::getElement() const
{
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    return s ? s->getElement() : NULL;
}

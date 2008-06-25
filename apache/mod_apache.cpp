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
 * mod_apache.cpp
 * 
 * Apache module implementation
 */

#define SHIBSP_LITE

#ifdef SOLARIS2
#undef _XOPEN_SOURCE    // causes gethostname conflict in unistd.h
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <shibsp/AbstractSPRequest.h>
#include <shibsp/AccessControl.h>
#include <shibsp/exceptions.h>
#include <shibsp/RequestMapper.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/SessionCache.h>
#include <shibsp/attribute/Attribute.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/XMLHelper.h>
#include <memory>

#ifdef WIN32
# include <winsock.h>
#endif

#undef _XPG4_2

// Apache specific header files
#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_main.h>
#define CORE_PRIVATE
#include <http_core.h>
#include <http_log.h>
#include <http_request.h>

#ifndef SHIB_APACHE_13
#include <apr_buckets.h>
#include <apr_strings.h>
#include <apr_pools.h>
#endif

#include <fstream>
#include <sstream>

#ifdef HAVE_UNISTD_H
#include <unistd.h>		// for getpid()
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace std;
using xercesc::RegularExpression;
using xercesc::XMLException;

extern "C" module MODULE_VAR_EXPORT mod_shib;

namespace {
    char* g_szSHIBConfig = NULL;
    char* g_szSchemaDir = NULL;
    char* g_szPrefix = NULL;
    SPConfig* g_Config = NULL;
    string g_unsetHeaderValue;
    bool g_checkSpoofing = true;
    bool g_catchAll = false;
    static const char* g_UserDataKey = "_shib_check_user_";
    static const XMLCh path[] = UNICODE_LITERAL_4(p,a,t,h);
    static const XMLCh validate[] = UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
}

/* Apache 2.2.x headers must be accumulated and set in the output filter.
   Apache 2.0.49+ supports the filter method.
   Apache 1.3.x and lesser 2.0.x must write the headers directly. */

#if (defined(SHIB_APACHE_20) || defined(SHIB_APACHE_22)) && AP_MODULE_MAGIC_AT_LEAST(20020903,6)
#define SHIB_DEFERRED_HEADERS
#endif

/********************************************************************************/
// Basic Apache Configuration code.
//

// per-server module configuration structure
struct shib_server_config
{
    char* szScheme;
};

// creates the per-server configuration
extern "C" void* create_shib_server_config(SH_AP_POOL* p, server_rec* s)
{
    shib_server_config* sc=(shib_server_config*)ap_pcalloc(p,sizeof(shib_server_config));
    sc->szScheme = NULL;
    return sc;
}

// overrides server configuration in virtual servers
extern "C" void* merge_shib_server_config (SH_AP_POOL* p, void* base, void* sub)
{
    shib_server_config* sc=(shib_server_config*)ap_pcalloc(p,sizeof(shib_server_config));
    shib_server_config* parent=(shib_server_config*)base;
    shib_server_config* child=(shib_server_config*)sub;

    if (child->szScheme)
        sc->szScheme=ap_pstrdup(p,child->szScheme);
    else if (parent->szScheme)
        sc->szScheme=ap_pstrdup(p,parent->szScheme);
    else
        sc->szScheme=NULL;

    return sc;
}

// per-dir module configuration structure
struct shib_dir_config
{
    SH_AP_TABLE* tSettings; // generic table of extensible settings

    // RM Configuration
    char* szAuthGrpFile;    // Auth GroupFile name
    int bRequireAll;        // all "known" require directives must match, otherwise OR logic
    int bAuthoritative;     // allow htaccess plugin to DECLINE when authz fails

    // Content Configuration
    char* szApplicationId;  // Shib applicationId value
    char* szRequireWith;    // require a session using a specific initiator?
    char* szRedirectToSSL;  // redirect non-SSL requests to SSL port
    int bOff;               // flat-out disable all Shib processing
    int bBasicHijack;       // activate for AuthType Basic?
    int bRequireSession;    // require a session?
    int bExportAssertion;   // export SAML assertion to the environment?
    int bUseEnvVars;        // use environment?
    int bUseHeaders;        // use headers?
};

// creates per-directory config structure
extern "C" void* create_shib_dir_config (SH_AP_POOL* p, char* d)
{
    shib_dir_config* dc=(shib_dir_config*)ap_pcalloc(p,sizeof(shib_dir_config));
    dc->tSettings = NULL;
    dc->szAuthGrpFile = NULL;
    dc->bRequireAll = -1;
    dc->bAuthoritative = -1;
    dc->szApplicationId = NULL;
    dc->szRequireWith = NULL;
    dc->szRedirectToSSL = NULL;
    dc->bOff = -1;
    dc->bBasicHijack = -1;
    dc->bRequireSession = -1;
    dc->bExportAssertion = -1;
    dc->bUseEnvVars = -1;
    dc->bUseHeaders = -1;
    return dc;
}

// overrides server configuration in directories
extern "C" void* merge_shib_dir_config (SH_AP_POOL* p, void* base, void* sub)
{
    shib_dir_config* dc=(shib_dir_config*)ap_pcalloc(p,sizeof(shib_dir_config));
    shib_dir_config* parent=(shib_dir_config*)base;
    shib_dir_config* child=(shib_dir_config*)sub;

    // The child supersedes any matching table settings in the parent.
    dc->tSettings = NULL;
    if (parent->tSettings)
        dc->tSettings = ap_copy_table(p, parent->tSettings);
    if (child->tSettings) {
        if (dc->tSettings)
            ap_overlap_tables(dc->tSettings, child->tSettings, AP_OVERLAP_TABLES_SET);
        else
            dc->tSettings = ap_copy_table(p, child->tSettings);
    }

    if (child->szAuthGrpFile)
        dc->szAuthGrpFile=ap_pstrdup(p,child->szAuthGrpFile);
    else if (parent->szAuthGrpFile)
        dc->szAuthGrpFile=ap_pstrdup(p,parent->szAuthGrpFile);
    else
        dc->szAuthGrpFile=NULL;

    if (child->szApplicationId)
        dc->szApplicationId=ap_pstrdup(p,child->szApplicationId);
    else if (parent->szApplicationId)
        dc->szApplicationId=ap_pstrdup(p,parent->szApplicationId);
    else
        dc->szApplicationId=NULL;

    if (child->szRequireWith)
        dc->szRequireWith=ap_pstrdup(p,child->szRequireWith);
    else if (parent->szRequireWith)
        dc->szRequireWith=ap_pstrdup(p,parent->szRequireWith);
    else
        dc->szRequireWith=NULL;

    if (child->szRedirectToSSL)
        dc->szRedirectToSSL=ap_pstrdup(p,child->szRedirectToSSL);
    else if (parent->szRedirectToSSL)
        dc->szRedirectToSSL=ap_pstrdup(p,parent->szRedirectToSSL);
    else
        dc->szRedirectToSSL=NULL;

    dc->bOff=((child->bOff==-1) ? parent->bOff : child->bOff);
    dc->bBasicHijack=((child->bBasicHijack==-1) ? parent->bBasicHijack : child->bBasicHijack);
    dc->bRequireSession=((child->bRequireSession==-1) ? parent->bRequireSession : child->bRequireSession);
    dc->bExportAssertion=((child->bExportAssertion==-1) ? parent->bExportAssertion : child->bExportAssertion);
    dc->bRequireAll=((child->bRequireAll==-1) ? parent->bRequireAll : child->bRequireAll);
    dc->bAuthoritative=((child->bAuthoritative==-1) ? parent->bAuthoritative : child->bAuthoritative);
    dc->bUseEnvVars=((child->bUseEnvVars==-1) ? parent->bUseEnvVars : child->bUseEnvVars);
    dc->bUseHeaders=((child->bUseHeaders==-1) ? parent->bUseHeaders : child->bUseHeaders);
    return dc;
}

// per-request module structure
struct shib_request_config
{
    SH_AP_TABLE *env;        // environment vars
#ifdef SHIB_DEFERRED_HEADERS
    SH_AP_TABLE *hdr_out;    // headers to browser
#endif
};

// create a request record
static shib_request_config *init_request_config(request_rec *r)
{
    shib_request_config* rc=(shib_request_config*)ap_pcalloc(r->pool,sizeof(shib_request_config));
    ap_set_module_config (r->request_config, &mod_shib, rc);
    memset(rc, 0, sizeof(shib_request_config));
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_init_rc");
    return rc;
}

// generic global slot handlers
extern "C" const char* ap_set_global_string_slot(cmd_parms* parms, void*, const char* arg)
{
    *((char**)(parms->info))=ap_pstrdup(parms->pool,arg);
    return NULL;
}

extern "C" const char* shib_set_server_string_slot(cmd_parms* parms, void*, const char* arg)
{
    char* base=(char*)ap_get_module_config(parms->server->module_config,&mod_shib);
    size_t offset=(size_t)parms->info;
    *((char**)(base + offset))=ap_pstrdup(parms->pool,arg);
    return NULL;
}

extern "C" const char* shib_ap_set_file_slot(cmd_parms* parms,
#ifdef SHIB_APACHE_13
					     char* arg1, char* arg2
#else
					     void* arg1, const char* arg2
#endif
					     )
{
  ap_set_file_slot(parms, arg1, arg2);
  return DECLINE_CMD;
}

extern "C" const char* shib_table_set(cmd_parms* parms, shib_dir_config* dc, const char* arg1, const char* arg2)
{
    if (!dc->tSettings)
        dc->tSettings = ap_make_table(parms->pool, 4);
    ap_table_set(dc->tSettings, arg1, arg2);
    return NULL;
}

/********************************************************************************/
// Apache ShibTarget subclass(es) here.

class ShibTargetApache : public AbstractSPRequest
{
  bool m_handler;
  mutable string m_body;
  mutable bool m_gotBody;
  mutable vector<string> m_certs;
  set<string> m_allhttp;

public:
  request_rec* m_req;
  shib_dir_config* m_dc;
  shib_server_config* m_sc;
  shib_request_config* m_rc;

  ShibTargetApache(request_rec* req, bool handler) : AbstractSPRequest(SHIBSP_LOGCAT".Apache"), m_handler(handler), m_gotBody(false) {
    m_sc = (shib_server_config*)ap_get_module_config(req->server->module_config, &mod_shib);
    m_dc = (shib_dir_config*)ap_get_module_config(req->per_dir_config, &mod_shib);
    m_rc = (shib_request_config*)ap_get_module_config(req->request_config, &mod_shib);
    m_req = req;

    setRequestURI(m_req->unparsed_uri);
  }
  virtual ~ShibTargetApache() {}

  const char* getScheme() const {
    return m_sc->szScheme ? m_sc->szScheme : ap_http_method(m_req);
  }
  const char* getHostname() const {
    return ap_get_server_name(m_req);
  }
  int getPort() const {
    return ap_get_server_port(m_req);
  }
  const char* getMethod() const {
    return m_req->method;
  }
  string getContentType() const {
    const char* type = ap_table_get(m_req->headers_in, "Content-Type");
    return type ? type : "";
  }
  long getContentLength() const {
      return m_gotBody ? m_body.length() : m_req->remaining;
  }
  string getRemoteAddr() const {
    return m_req->connection->remote_ip;
  }
  void log(SPLogLevel level, const string& msg) const {
    AbstractSPRequest::log(level,msg);
    ap_log_rerror(
        APLOG_MARK,
        (level == SPDebug ? APLOG_DEBUG :
        (level == SPInfo ? APLOG_INFO :
        (level == SPWarn ? APLOG_WARNING :
        (level == SPError ? APLOG_ERR : APLOG_CRIT))))|APLOG_NOERRNO,
        SH_AP_R(m_req),
        msg.c_str()
        );
  }
  const char* getQueryString() const { return m_req->args; }
  const char* getRequestBody() const {
    if (m_gotBody || m_req->method_number==M_GET)
        return m_body.c_str();
#ifdef SHIB_APACHE_13
    // Read the posted data
    if (ap_setup_client_block(m_req, REQUEST_CHUNKED_DECHUNK) != OK) {
        m_gotBody=true;
        log(SPError, "Apache function (setup_client_block) failed while reading request body.");
        return m_body.c_str();
    }
    if (!ap_should_client_block(m_req)) {
        m_gotBody=true;
        log(SPError, "Apache function (should_client_block) failed while reading request body.");
        return m_body.c_str();
    }
    if (m_req->remaining > 1024*1024)
        throw opensaml::SecurityPolicyException("Blocked request body larger than 1M size limit.");
    m_gotBody=true;
    int len;
    char buff[HUGE_STRING_LEN];
    ap_hard_timeout("[mod_shib] getRequestBody", m_req);
    while ((len=ap_get_client_block(m_req, buff, sizeof(buff))) > 0) {
      ap_reset_timeout(m_req);
      m_body.append(buff, len);
    }
    ap_kill_timeout(m_req);
#else
    const char *data;
    apr_size_t len;
    int seen_eos = 0;
    apr_bucket_brigade* bb = apr_brigade_create(m_req->pool, m_req->connection->bucket_alloc);
    do {
        apr_bucket *bucket;
        apr_status_t rv = ap_get_brigade(m_req->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            log(SPError, "Apache function (ap_get_brigade) failed while reading request body.");
            break;
        }

        for (bucket = APR_BRIGADE_FIRST(bb); bucket != APR_BRIGADE_SENTINEL(bb); bucket = APR_BUCKET_NEXT(bucket)) {
            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }

            /* We can't do much with this. */
            if (APR_BUCKET_IS_FLUSH(bucket))
                continue;

            /* read */
            apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
            if (len > 0)
                m_body.append(data, len);
        }
        apr_brigade_cleanup(bb);
    } while (!seen_eos);
    apr_brigade_destroy(bb);
    m_gotBody=true;
#endif
    return m_body.c_str();
  }
  void clearHeader(const char* rawname, const char* cginame) {
    if (m_dc->bUseHeaders == 1) {
       // ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(m_req), "shib_clear_header: hdr\n");
        if (g_checkSpoofing && ap_is_initial_req(m_req)) {
            if (m_allhttp.empty()) {
                // First time, so populate set with "CGI" versions of client-supplied headers.
#ifdef SHIB_APACHE_13
                array_header *hdrs_arr = ap_table_elts(m_req->headers_in);
                table_entry *hdrs = (table_entry *) hdrs_arr->elts;
#else
                const apr_array_header_t *hdrs_arr = apr_table_elts(m_req->headers_in);
                const apr_table_entry_t *hdrs = (const apr_table_entry_t *) hdrs_arr->elts;
#endif
                for (int i = 0; i < hdrs_arr->nelts; ++i) {
                    if (!hdrs[i].key)
                        continue;
                    string cgiversion("HTTP_");
                    const char* pch = hdrs[i].key;
                    while (*pch) {
                        cgiversion += (isalnum(*pch) ? toupper(*pch) : '_');
                        pch++;
                    }
                    m_allhttp.insert(cgiversion);
                }
            }

            if (m_allhttp.count(cginame) > 0)
                throw opensaml::SecurityPolicyException("Attempt to spoof header ($1) was detected.", params(1, rawname));
        }
        ap_table_unset(m_req->headers_in, rawname);
        ap_table_set(m_req->headers_in, rawname, g_unsetHeaderValue.c_str());
    }
  }
  void setHeader(const char* name, const char* value) {
    if (m_dc->bUseEnvVars != 0) {
       if (!m_rc) {
          // this happens on subrequests
          // ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(m_req), "shib_setheader: no_m_rc\n");
          m_rc = init_request_config(m_req);
       }
       if (!m_rc->env)
           m_rc->env = ap_make_table(m_req->pool, 10);
       // ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(m_req), "shib_set_env: %s=%s\n", name, value?value:"Null");
       ap_table_set(m_rc->env, name, value ? value : "");
    }
    if (m_dc->bUseHeaders == 1)
       ap_table_set(m_req->headers_in, name, value);
  }
  string getHeader(const char* name) const {
    const char* hdr = ap_table_get(m_req->headers_in, name);
    return string(hdr ? hdr : "");
  }
  string getSecureHeader(const char* name) const {
    if (m_dc->bUseEnvVars != 0) {
       const char *hdr;
       if (m_rc && m_rc->env)
           hdr = ap_table_get(m_rc->env, name);
       else
           hdr = NULL;
       return string(hdr ? hdr : "");
    }
    return getHeader(name);
  }
  void setRemoteUser(const char* user) {
      SH_AP_USER(m_req) = user ? ap_pstrdup(m_req->pool, user) : NULL;
  }
  string getRemoteUser() const {
    return string(SH_AP_USER(m_req) ? SH_AP_USER(m_req) : "");
  }
  void setContentType(const char* type) {
      m_req->content_type = ap_psprintf(m_req->pool, type);
  }
  void setResponseHeader(const char* name, const char* value) {
#ifdef SHIB_DEFERRED_HEADERS
   if (!m_rc)
      // this happens on subrequests
      m_rc = init_request_config(m_req);
    if (m_handler)
        ap_table_add(m_rc->hdr_out, name, value);
    else
#endif
    ap_table_add(m_req->err_headers_out, name, value);
  }
  long sendResponse(istream& in, long status) {
    if (status != XMLTOOLING_HTTP_STATUS_OK)
        m_req->status = status;
    ap_send_http_header(m_req);
    char buf[1024];
    while (in) {
        in.read(buf,1024);
        ap_rwrite(buf,in.gcount(),m_req);
    }
#if (defined(SHIB_APACHE_20) || defined(SHIB_APACHE_22))
    if (status != XMLTOOLING_HTTP_STATUS_OK && status != XMLTOOLING_HTTP_STATUS_ERROR)
        return status;
#endif
    return DONE;
  }
  long sendRedirect(const char* url) {
    ap_table_set(m_req->headers_out, "Location", url);
    return REDIRECT;
  }
  const vector<string>& getClientCertificates() const {
      if (m_certs.empty()) {
          const char* cert = ap_table_get(m_req->subprocess_env, "SSL_CLIENT_CERT");
          if (cert)
              m_certs.push_back(cert);
          int i = 0;
          do {
              cert = ap_table_get(m_req->subprocess_env, ap_psprintf(m_req->pool, "SSL_CLIENT_CERT_CHAIN_%d", i++));
              if (cert)
                  m_certs.push_back(cert);
          } while (cert);
      }
      return m_certs;
  }
  long returnDecline(void) { return DECLINED; }
  long returnOK(void) { return OK; }
};

/********************************************************************************/
// Apache handlers

extern "C" int shib_check_user(request_rec* r)
{
  // Short-circuit entirely?
  if (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib))->bOff==1)
    return DECLINED;
    
  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_check_user(%d): ENTER", (int)getpid());

  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_check_user" << '\0';
  xmltooling::NDC ndc(threadid.str().c_str());

  try {
    ShibTargetApache sta(r,false);

    // Check user authentication and export information, then set the handler bypass
    pair<bool,long> res = sta.getServiceProvider().doAuthentication(sta,true);
    apr_pool_userdata_setn((const void*)42,g_UserDataKey,NULL,r->pool);
    if (res.first) return res.second;

    // user auth was okay -- export the assertions now
    res = sta.getServiceProvider().doExport(sta);
    if (res.first) return res.second;

    // export happened successfully..  this user is ok.
    return OK;
  }
  catch (exception& e) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_check_user threw an exception: %s", e.what());
    return SERVER_ERROR;
  }
  catch (...) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_check_user threw an unknown exception!");
    if (g_catchAll)
      return SERVER_ERROR;
    throw;
  }
}

extern "C" int shib_handler(request_rec* r)
{
  // Short-circuit entirely?
  if (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib))->bOff==1)
    return DECLINED;

  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_handler" << '\0';
  xmltooling::NDC ndc(threadid.str().c_str());

#ifndef SHIB_APACHE_13
  // With 2.x, this handler always runs, though last.
  // We check if shib_check_user ran, because it will detect a handler request
  // and dispatch it directly.
  void* data;
  apr_pool_userdata_get(&data,g_UserDataKey,r->pool);
  if (data==(const void*)42) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_handler skipped since check_user ran");
    return DECLINED;
  }
#endif

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_handler(%d): ENTER: %s", (int)getpid(), r->handler);

  try {
    ShibTargetApache sta(r,true);

    pair<bool,long> res = sta.getServiceProvider().doHandler(sta);
    if (res.first) return res.second;

    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "doHandler() did not do anything.");
    return SERVER_ERROR;
  }
  catch (exception& e) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_handler threw an exception: %s", e.what());
    return SERVER_ERROR;
  }
  catch (...) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_handler threw an unknown exception!");
    if (g_catchAll)
      return SERVER_ERROR;
    throw;
  }
}

/*
 * shib_auth_checker() -- a simple resource manager to
 * process the .htaccess settings
 */
extern "C" int shib_auth_checker(request_rec* r)
{
  // Short-circuit entirely?
  if (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib))->bOff==1)
    return DECLINED;

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_auth_checker(%d): ENTER", (int)getpid());

  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_auth_checker" << '\0';
  xmltooling::NDC ndc(threadid.str().c_str());

  try {
    ShibTargetApache sta(r,false);

    pair<bool,long> res = sta.getServiceProvider().doAuthorization(sta);
    if (res.first) return res.second;

    // The SP method should always return true, so if we get this far, something unusual happened.
    // Just let Apache (or some other module) decide what to do.
    return DECLINED;
  }
  catch (exception& e) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_auth_checker threw an exception: %s", e.what());
    return SERVER_ERROR;
  }
  catch (...) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_auth_checker threw an unknown exception!");
    if (g_catchAll)
      return SERVER_ERROR;
    throw;
  }
}

// Access control plugin that enforces htaccess rules
class htAccessControl : virtual public AccessControl
{
public:
    htAccessControl() {}
    ~htAccessControl() {}
    Lockable* lock() {return this;}
    void unlock() {}
    aclresult_t authorized(const SPRequest& request, const Session* session) const;
private:
    bool checkAttribute(const SPRequest& request, const Attribute* attr, const char* toMatch, RegularExpression* re) const;
};

AccessControl* htAccessFactory(const xercesc::DOMElement* const & e)
{
    return new htAccessControl();
}

class ApacheRequestMapper : public virtual RequestMapper, public virtual PropertySet
{
public:
    ApacheRequestMapper(const xercesc::DOMElement* e);
    ~ApacheRequestMapper() { delete m_mapper; delete m_htaccess; delete m_staKey; delete m_propsKey; }
    Lockable* lock() { return m_mapper->lock(); }
    void unlock() { m_staKey->setData(NULL); m_propsKey->setData(NULL); m_mapper->unlock(); }
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
    ThreadKey* m_staKey;
    ThreadKey* m_propsKey;
    AccessControl* m_htaccess;
};

RequestMapper* ApacheRequestMapFactory(const xercesc::DOMElement* const & e)
{
    return new ApacheRequestMapper(e);
}

ApacheRequestMapper::ApacheRequestMapper(const xercesc::DOMElement* e) : m_mapper(NULL), m_staKey(NULL), m_propsKey(NULL), m_htaccess(NULL)
{
    m_mapper=SPConfig::getConfig().RequestMapperManager.newPlugin(XML_REQUEST_MAPPER,e);
    m_htaccess=new htAccessControl();
    m_staKey=ThreadKey::create(NULL);
    m_propsKey=ThreadKey::create(NULL);
}

RequestMapper::Settings ApacheRequestMapper::getSettings(const HTTPRequest& request) const
{
    Settings s=m_mapper->getSettings(request);
    m_staKey->setData((void*)dynamic_cast<const ShibTargetApache*>(&request));
    m_propsKey->setData((void*)s.first);
    return pair<const PropertySet*,AccessControl*>(this,s.second ? s.second : m_htaccess);
}

pair<bool,bool> ApacheRequestMapper::getBool(const char* name, const char* ns) const
{
    const ShibTargetApache* sta=reinterpret_cast<const ShibTargetApache*>(m_staKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (sta && !ns) {
        // Override Apache-settable boolean properties.
        if (name && !strcmp(name,"requireSession") && sta->m_dc->bRequireSession != -1)
            return make_pair(true, sta->m_dc->bRequireSession==1);
        else if (name && !strcmp(name,"exportAssertion") && sta->m_dc->bExportAssertion != -1)
            return make_pair(true, sta->m_dc->bExportAssertion==1);
        else if (sta->m_dc->tSettings) {
            const char* prop = ap_table_get(sta->m_dc->tSettings, name);
            if (prop)
                return make_pair(true, !strcmp(prop, "true") || !strcmp(prop, "1") || !strcmp(prop, "On"));
        }
    }
    return s ? s->getBool(name,ns) : make_pair(false,false);
}

pair<bool,const char*> ApacheRequestMapper::getString(const char* name, const char* ns) const
{
    const ShibTargetApache* sta=reinterpret_cast<const ShibTargetApache*>(m_staKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (sta && !ns) {
        // Override Apache-settable string properties.
        if (name && !strcmp(name,"authType")) {
            const char *auth_type=ap_auth_type(sta->m_req);
            if (auth_type) {
                // Check for Basic Hijack
                if (!strcasecmp(auth_type, "basic") && sta->m_dc->bBasicHijack == 1)
                    auth_type = "shibboleth";
                return make_pair(true,auth_type);
            }
        }
        else if (name && !strcmp(name,"applicationId") && sta->m_dc->szApplicationId)
            return pair<bool,const char*>(true,sta->m_dc->szApplicationId);
        else if (name && !strcmp(name,"requireSessionWith") && sta->m_dc->szRequireWith)
            return pair<bool,const char*>(true,sta->m_dc->szRequireWith);
        else if (name && !strcmp(name,"redirectToSSL") && sta->m_dc->szRedirectToSSL)
            return pair<bool,const char*>(true,sta->m_dc->szRedirectToSSL);
        else if (sta->m_dc->tSettings) {
            const char* prop = ap_table_get(sta->m_dc->tSettings, name);
            if (prop)
                return make_pair(true, prop);
        }
    }
    return s ? s->getString(name,ns) : pair<bool,const char*>(false,NULL);
}

pair<bool,const XMLCh*> ApacheRequestMapper::getXMLString(const char* name, const char* ns) const
{
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    return s ? s->getXMLString(name,ns) : pair<bool,const XMLCh*>(false,NULL);
}

pair<bool,unsigned int> ApacheRequestMapper::getUnsignedInt(const char* name, const char* ns) const
{
    const ShibTargetApache* sta=reinterpret_cast<const ShibTargetApache*>(m_staKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (sta && !ns) {
        // Override Apache-settable int properties.
        if (name && !strcmp(name,"redirectToSSL") && sta->m_dc->szRedirectToSSL)
            return pair<bool,unsigned int>(true, strtol(sta->m_dc->szRedirectToSSL, NULL, 10));
        else if (sta->m_dc->tSettings) {
            const char* prop = ap_table_get(sta->m_dc->tSettings, name);
            if (prop)
                return pair<bool,unsigned int>(true, atoi(prop));
        }
    }
    return s ? s->getUnsignedInt(name,ns) : pair<bool,unsigned int>(false,0);
}

pair<bool,int> ApacheRequestMapper::getInt(const char* name, const char* ns) const
{
    const ShibTargetApache* sta=reinterpret_cast<const ShibTargetApache*>(m_staKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (sta && !ns) {
        // Override Apache-settable int properties.
        if (name && !strcmp(name,"redirectToSSL") && sta->m_dc->szRedirectToSSL)
            return pair<bool,int>(true,atoi(sta->m_dc->szRedirectToSSL));
        else if (sta->m_dc->tSettings) {
            const char* prop = ap_table_get(sta->m_dc->tSettings, name);
            if (prop)
                return make_pair(true, atoi(prop));
        }
    }
    return s ? s->getInt(name,ns) : pair<bool,int>(false,0);
}

void ApacheRequestMapper::getAll(map<string,const char*>& properties) const
{
    const ShibTargetApache* sta=reinterpret_cast<const ShibTargetApache*>(m_staKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());

    if (s)
        s->getAll(properties);
    if (!sta)
        return;

    const char* auth_type=ap_auth_type(sta->m_req);
    if (auth_type) {
        // Check for Basic Hijack
        if (!strcasecmp(auth_type, "basic") && sta->m_dc->bBasicHijack == 1)
            auth_type = "shibboleth";
        properties["authType"] = auth_type;
    }

    if (sta->m_dc->szApplicationId)
        properties["applicationId"] = sta->m_dc->szApplicationId;
    if (sta->m_dc->szRequireWith)
        properties["requireSessionWith"] = sta->m_dc->szRequireWith;
    if (sta->m_dc->szRedirectToSSL)
        properties["redirectToSSL"] = sta->m_dc->szRedirectToSSL;
    if (sta->m_dc->bRequireSession != 0)
        properties["requireSession"] = (sta->m_dc->bRequireSession==1) ? "true" : "false";
    if (sta->m_dc->bExportAssertion != 0)
        properties["exportAssertion"] = (sta->m_dc->bExportAssertion==1) ? "true" : "false";
}

const PropertySet* ApacheRequestMapper::getPropertySet(const char* name, const char* ns) const
{
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    return s ? s->getPropertySet(name,ns) : NULL;
}

const xercesc::DOMElement* ApacheRequestMapper::getElement() const
{
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    return s ? s->getElement() : NULL;
}

static SH_AP_TABLE* groups_for_user(request_rec* r, const char* user, char* grpfile)
{
    SH_AP_CONFIGFILE* f;
    SH_AP_TABLE* grps=ap_make_table(r->pool,15);
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;

#ifdef SHIB_APACHE_13
    if (!(f=ap_pcfg_openfile(r->pool,grpfile))) {
#else
    if (ap_pcfg_openfile(&f,r->pool,grpfile) != APR_SUCCESS) {
#endif
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG,SH_AP_R(r),"groups_for_user() could not open group file: %s\n",grpfile);
        return NULL;
    }

    SH_AP_POOL* sp;
#ifdef SHIB_APACHE_13
    sp=ap_make_sub_pool(r->pool);
#else
    if (apr_pool_create(&sp,r->pool) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,
            "groups_for_user() could not create a subpool");
        return NULL;
    }
#endif

    while (!(ap_cfg_getline(l,MAX_STRING_LEN,f))) {
        if ((*l=='#') || (!*l))
            continue;
        ll = l;
        ap_clear_pool(sp);

        group_name=ap_getword(sp,&ll,':');

        while (*ll) {
            w=ap_getword_conf(sp,&ll);
            if (!strcmp(w,user)) {
                ap_table_setn(grps,ap_pstrdup(r->pool,group_name),"in");
                break;
            }
        }
    }
    ap_cfg_closefile(f);
    ap_destroy_pool(sp);
    return grps;
}

bool htAccessControl::checkAttribute(const SPRequest& request, const Attribute* attr, const char* toMatch, RegularExpression* re) const
{
    bool caseSensitive = attr->isCaseSensitive();
    const vector<string>& vals = attr->getSerializedValues();
    for (vector<string>::const_iterator v=vals.begin(); v!=vals.end(); ++v) {
        if (re) {
            auto_arrayptr<XMLCh> trans(fromUTF8(v->c_str()));
            if (re->matches(trans.get())) {
                if (request.isPriorityEnabled(SPRequest::SPDebug))
                    request.log(SPRequest::SPDebug, string("htaccess: expecting regexp ") + toMatch + ", got " + *v + ": acccepted");
                return true;
            }
        }
        else if ((caseSensitive && *v == toMatch) || (!caseSensitive && !strcasecmp(v->c_str(), toMatch))) {
            if (request.isPriorityEnabled(SPRequest::SPDebug))
                request.log(SPRequest::SPDebug, string("htaccess: expecting ") + toMatch + ", got " + *v + ": accepted");
            return true;
        }
        else if (request.isPriorityEnabled(SPRequest::SPDebug)) {
            request.log(SPRequest::SPDebug, string("htaccess: expecting ") + toMatch + ", got " + *v + ": rejected");
        }
    }
    return false;
}

AccessControl::aclresult_t htAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    // Make sure the object is our type.
    const ShibTargetApache* sta=dynamic_cast<const ShibTargetApache*>(&request);
    if (!sta)
        throw ConfigurationException("Request wrapper object was not of correct type.");

    // mod_auth clone

    int m=sta->m_req->method_number;
    bool method_restricted=false;
    const char *t, *w;
    
    const array_header* reqs_arr=ap_requires(sta->m_req);
    if (!reqs_arr)
        return shib_acl_indeterminate;  // should never happen

    require_line* reqs=(require_line*)reqs_arr->elts;

    for (int x=0; x<reqs_arr->nelts; x++) {
        // This rule should be completely ignored, the method doesn't fit.
        // The rule just doesn't exist for our purposes.
        if (!(reqs[x].method_mask & (1 << m)))
            continue;

        method_restricted=true; // this lets us know at the end that at least one rule was potentially enforcable.

        // Tracks status of this rule's evaluation.
        bool status = false;

        string remote_user = request.getRemoteUser();

        t = reqs[x].requirement;
        w = ap_getword_white(sta->m_req->pool, &t);

        if (!strcasecmp(w,"shibboleth")) {
            // This is a dummy rule needed because Apache conflates authn and authz.
            // Without some require rule, AuthType is ignored and no check_user hooks run.
            status = true;  // treat it as an "accepted" rule
        }
        else if (!strcmp(w,"valid-user") && session) {
            request.log(SPRequest::SPDebug, "htaccess: accepting valid-user based on active session");
            status = true;
        }
        else if (!strcmp(w,"user") && !remote_user.empty()) {
            bool regexp=false,negate=false;
            while (*t) {
                w=ap_getword_conf(sta->m_req->pool,&t);
                if (*w=='~') {
                    regexp=true;
                    continue;
                }
                else if (*w=='!') {
                    negate=true;
                    if (*(w+1)=='~')
                        regexp=true;
                    continue;
                }

                // Figure out if there's a match.
                bool match = false;
                if (regexp) {
                    try {
                        // To do regex matching, we have to convert from UTF-8.
                        auto_arrayptr<XMLCh> trans(fromUTF8(w));
                        RegularExpression re(trans.get());
                        auto_arrayptr<XMLCh> trans2(fromUTF8(remote_user.c_str()));
                        match = re.matches(trans2.get());
                    }
                    catch (XMLException& ex) {
                        auto_ptr_char tmp(ex.getMessage());
                        request.log(SPRequest::SPError,
                            string("htaccess plugin caught exception while parsing regular expression (") + w + "): " + tmp.get());
                    }
                }
                else if (remote_user==w) {
                    match = true;
                }

                if (match) {
                    // If we matched, then we're done with this rule either way and status is set to reflect the outcome.
                    status = !negate;
                    if (request.isPriorityEnabled(SPRequest::SPDebug))
                        request.log(SPRequest::SPDebug,
                            string("htaccess: require user ") + (negate ? "rejecting (" : "accepting (") + remote_user + ")");
                    break;
                }
            }
        }
        else if (!strcmp(w,"group")  && !remote_user.empty()) {
            SH_AP_TABLE* grpstatus=NULL;
            if (sta->m_dc->szAuthGrpFile) {
                if (request.isPriorityEnabled(SPRequest::SPDebug))
                    request.log(SPRequest::SPDebug,string("htaccess plugin using groups file: ") + sta->m_dc->szAuthGrpFile);
                grpstatus=groups_for_user(sta->m_req,remote_user.c_str(),sta->m_dc->szAuthGrpFile);
            }
    
            bool negate=false;
            while (*t) {
                w=ap_getword_conf(sta->m_req->pool,&t);
                if (*w=='!') {
                    negate=true;
                    continue;
                }

                if (grpstatus && ap_table_get(grpstatus,w)) {
                    // If we matched, then we're done with this rule either way and status is set to reflect the outcome.
                    status = !negate;
                    request.log(SPRequest::SPDebug, string("htaccess: require group ") + (negate ? "rejecting (" : "accepting (") + w + ")");
                    break;
                }
            }
        }
        else if (!strcmp(w,"authnContextClassRef") || !strcmp(w,"authnContextDeclRef")) {
            const char* ref = !strcmp(w,"authnContextClassRef") ? session->getAuthnContextClassRef() : session->getAuthnContextDeclRef();
            bool regexp=false,negate=false;
            while (ref && *t) {
                w=ap_getword_conf(sta->m_req->pool,&t);
                if (*w=='~') {
                    regexp=true;
                    continue;
                }
                else if (*w=='!') {
                    negate=true;
                    if (*(w+1)=='~')
                        regexp=true;
                    continue;
                }

                // Figure out if there's a match.
                bool match = false;
                if (regexp) {
                    try {
                        // To do regex matching, we have to convert from UTF-8.
                        RegularExpression re(w);
                        match = re.matches(ref);
                    }
                    catch (XMLException& ex) {
                        auto_ptr_char tmp(ex.getMessage());
                        request.log(SPRequest::SPError,
                            string("htaccess plugin caught exception while parsing regular expression (") + w + "): " + tmp.get());
                    }
                }
                else if (!strcmp(w,ref)) {
                    match = true;
                }

                if (match) {
                    // If we matched, then we're done with this rule either way and status is set to reflect the outcome.
                    status = !negate;
                    if (request.isPriorityEnabled(SPRequest::SPDebug))
                        request.log(SPRequest::SPDebug,
                            string("htaccess: require authnContext ") + (negate ? "rejecting (" : "accepting (") + ref + ")");
                    break;
                }
            }
        }
        else if (!session) {
            request.log(SPRequest::SPError, string("htaccess: require ") + w + " not given a valid session, are you using lazy sessions?");
        }
        else {
            // Find the attribute(s) matching the require rule.
            pair<multimap<string,const Attribute*>::const_iterator,multimap<string,const Attribute*>::const_iterator> attrs =
                session->getIndexedAttributes().equal_range(w);

            bool regexp=false;
            while (!status && attrs.first!=attrs.second && *t) {
                w=ap_getword_conf(sta->m_req->pool,&t);
                if (*w=='~') {
                    regexp=true;
                    continue;
                }

                try {
                    auto_ptr<RegularExpression> re;
                    if (regexp) {
                        delete re.release();
                        auto_arrayptr<XMLCh> trans(fromUTF8(w));
                        auto_ptr<xercesc::RegularExpression> temp(new xercesc::RegularExpression(trans.get()));
                        re=temp;
                    }
                    
                    for (; !status && attrs.first!=attrs.second; ++attrs.first) {
                        if (checkAttribute(request, attrs.first->second, w, regexp ? re.get() : NULL)) {
                            status = true;
                        }
                    }
                }
                catch (XMLException& ex) {
                    auto_ptr_char tmp(ex.getMessage());
                    request.log(SPRequest::SPError,
                        string("htaccess plugin caught exception while parsing regular expression (") + w + "): " + tmp.get()
                        );
                }
            }
        }

        // If status is false, we found a rule we couldn't satisfy.
        // Could be an unknown rule to us, or it just didn't match.

        if (status && sta->m_dc->bRequireAll != 1) {
            // If we're not insisting that all rules be met, then we're done.
            request.log(SPRequest::SPDebug, "htaccess: a rule was successful, granting access");
            return shib_acl_true;
        }
        else if (!status && sta->m_dc->bRequireAll == 1) {
            // If we're insisting that all rules be met, which is not something Apache really handles well,
            // then we either return false or indeterminate based on the authoritative option, which defaults on.
            if (sta->m_dc->bAuthoritative != 0) {
                request.log(SPRequest::SPDebug, "htaccess: a rule was unsuccessful, denying access");
                return shib_acl_false;
            }

            request.log(SPRequest::SPDebug, "htaccess: a rule was unsuccessful but not authoritative, leaving it up to Apache");
            return shib_acl_indeterminate;
        }

        // Otherwise, we keep going. If we're requring all, then we have to check every rule.
        // If not we just didn't find a successful rule yet, so we keep going anyway.
    }

    // If we get here, we either "failed" or we're in require all mode (but not both).
    // If no rules possibly apply or we insisted that all rules check out, then we're good.
    if (!method_restricted) {
        request.log(SPRequest::SPDebug, "htaccess: no rules applied to this request method, granting access");
        return shib_acl_true;
    }
    else if (sta->m_dc->bRequireAll == 1) {
        request.log(SPRequest::SPDebug, "htaccess: all rules successful, granting access");
        return shib_acl_true;
    }
    else if (sta->m_dc->bAuthoritative != 0) {
        request.log(SPRequest::SPDebug, "htaccess: no rules were successful, denying access");
        return shib_acl_false;
    }

    request.log(SPRequest::SPDebug, "htaccess: no rules were successful but not authoritative, leaving it up to Apache");
    return shib_acl_indeterminate;
}


// Initial look at a request - create the per-request structure
static int shib_post_read(request_rec *r)
{
    shib_request_config* rc = init_request_config(r);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_post_read");

#ifdef SHIB_DEFERRED_HEADERS
    rc->hdr_out = ap_make_table(r->pool, 5);
#endif
    return DECLINED;
}

// fixups: set environment vars

extern "C" int shib_fixups(request_rec* r)
{
  shib_request_config *rc = (shib_request_config*)ap_get_module_config(r->request_config, &mod_shib);
  shib_dir_config *dc = (shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib);
  if (dc->bOff==1 || dc->bUseEnvVars==0)
    return DECLINED;

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_fixup(%d): ENTER", (int)getpid());

  if (rc==NULL || rc->env==NULL || ap_is_empty_table(rc->env))
        return DECLINED;

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_fixup adding %d vars", ap_table_elts(rc->env)->nelts);
  r->subprocess_env = ap_overlay_tables(r->pool, r->subprocess_env, rc->env);

  return OK;
}

#ifdef SHIB_APACHE_13
/*
 * shib_child_exit()
 *  Cleanup the (per-process) pool info.
 */
extern "C" void shib_child_exit(server_rec* s, SH_AP_POOL* p)
{
    if (g_Config) {
        ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(s),"shib_child_exit(%d) dealing with g_Config..", (int)getpid());
        g_Config->term();
        g_Config = NULL;
        ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(s),"shib_child_exit() done");
    }
}
#else
/*
 * shib_exit()
 *  Apache 2.x doesn't allow for per-child cleanup, causes CGI forks to hang.
 */
extern "C" apr_status_t shib_exit(void* data)
{
    if (g_Config) {
        g_Config->term();
        g_Config = NULL;
    }
    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,NULL,"shib_exit() done");
    return OK;
}
#endif

/* 
 * shire_child_init()
 *  Things to do when the child process is initialized.
 *  (or after the configs are read in apache-2)
 */
#ifdef SHIB_APACHE_13
extern "C" void shib_child_init(server_rec* s, SH_AP_POOL* p)
#else
extern "C" void shib_child_init(apr_pool_t* p, server_rec* s)
#endif
{
    // Initialize runtime components.

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init(%d) starting", (int)getpid());

    if (g_Config) {
        ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() already initialized!");
        exit(1);
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
    if (!g_Config->init(g_szSchemaDir, g_szPrefix)) {
        ap_log_error(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() failed to initialize libraries");
        exit(1);
    }
    g_Config->AccessControlManager.registerFactory(HT_ACCESS_CONTROL,&htAccessFactory);
    g_Config->RequestMapperManager.registerFactory(NATIVE_REQUEST_MAPPER,&ApacheRequestMapFactory);

    if (!g_szSHIBConfig)
        g_szSHIBConfig=getenv("SHIBSP_CONFIG");
    if (!g_szSHIBConfig)
        g_szSHIBConfig=SHIBSP_CONFIG;
    
    try {
        xercesc::DOMDocument* dummydoc=XMLToolingConfig::getConfig().getParser().newDocument();
        XercesJanitor<xercesc::DOMDocument> docjanitor(dummydoc);
        xercesc::DOMElement* dummy = dummydoc->createElementNS(NULL,path);
        auto_ptr_XMLCh src(g_szSHIBConfig);
        dummy->setAttributeNS(NULL,path,src.get());
        dummy->setAttributeNS(NULL,validate,xmlconstants::XML_ONE);

        g_Config->setServiceProvider(g_Config->ServiceProviderManager.newPlugin(XML_SERVICE_PROVIDER,dummy));
        g_Config->getServiceProvider()->init();
    }
    catch (exception& ex) {
        ap_log_error(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,SH_AP_R(s),ex.what());
        ap_log_error(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() failed to load configuration");
        exit(1);
    }

    ServiceProvider* sp=g_Config->getServiceProvider();
    xmltooling::Locker locker(sp);
    const PropertySet* props=sp->getPropertySet("Local");
    if (props) {
        pair<bool,const char*> unsetValue=props->getString("unsetHeaderValue");
        if (unsetValue.first)
            g_unsetHeaderValue = unsetValue.second;
        pair<bool,bool> flag=props->getBool("checkSpoofing");
        g_checkSpoofing = !flag.first || flag.second;
        flag=props->getBool("catchAll");
        g_catchAll = flag.first && flag.second;
    }

    // Set the cleanup handler
    apr_pool_cleanup_register(p, NULL, &shib_exit, apr_pool_cleanup_null);

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() done");
}

// Output filters
#ifdef SHIB_DEFERRED_HEADERS
static void set_output_filter(request_rec *r)
{
   ap_add_output_filter("SHIB_HEADERS_OUT", NULL, r, r->connection);
}

static void set_error_filter(request_rec *r)
{
   ap_add_output_filter("SHIB_HEADERS_ERR", NULL, r, r->connection);
}

static int _table_add(void *v, const char *key, const char *value)
{
    apr_table_addn((apr_table_t*)v, key, value);
    return 1;
}

static apr_status_t do_output_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    shib_request_config *rc = (shib_request_config*) ap_get_module_config(r->request_config, &mod_shib);

    if (rc) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_out_filter: merging %d headers", apr_table_elts(rc->hdr_out)->nelts);
        apr_table_do(_table_add,r->headers_out, rc->hdr_out,NULL);
        // can't use overlap call because it will collapse Set-Cookie headers
        //apr_table_overlap(r->headers_out, rc->hdr_out, APR_OVERLAP_TABLES_MERGE);
    }

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next,in);
}

static apr_status_t do_error_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    shib_request_config *rc = (shib_request_config*) ap_get_module_config(r->request_config, &mod_shib);

    if (rc) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_err_filter: merging %d headers", apr_table_elts(rc->hdr_out)->nelts);
        apr_table_do(_table_add,r->err_headers_out, rc->hdr_out,NULL);
        // can't use overlap call because it will collapse Set-Cookie headers
        //apr_table_overlap(r->err_headers_out, rc->hdr_out, APR_OVERLAP_TABLES_MERGE);
    }

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next,in);
}
#endif // SHIB_DEFERRED_HEADERS

typedef const char* (*config_fn_t)(void);

#ifdef SHIB_APACHE_13

// SHIB Module commands

static command_rec shire_cmds[] = {
  {"ShibPrefix", (config_fn_t)ap_set_global_string_slot, &g_szPrefix,
   RSRC_CONF, TAKE1, "Shibboleth installation directory"},
  {"ShibConfig", (config_fn_t)ap_set_global_string_slot, &g_szSHIBConfig,
   RSRC_CONF, TAKE1, "Path to shibboleth.xml config file"},
  {"ShibCatalogs", (config_fn_t)ap_set_global_string_slot, &g_szSchemaDir,
   RSRC_CONF, TAKE1, "Paths of XML schema catalogs"},
  {"ShibSchemaDir", (config_fn_t)ap_set_global_string_slot, &g_szSchemaDir,
   RSRC_CONF, TAKE1, "Paths of XML schema catalogs (deprecated in favor of ShibCatalogs)"},

  {"ShibURLScheme", (config_fn_t)shib_set_server_string_slot,
   (void *) XtOffsetOf (shib_server_config, szScheme),
   RSRC_CONF, TAKE1, "URL scheme to force into generated URLs for a vhost"},
   
  {"ShibRequestSetting", (config_fn_t)shib_table_set, NULL,
   OR_AUTHCFG, TAKE2, "Set arbitrary Shibboleth request property for content"},

  {"ShibDisable", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bOff),
   OR_AUTHCFG, FLAG, "Disable all Shib module activity here to save processing effort"},
  {"ShibApplicationId", (config_fn_t)ap_set_string_slot,
   (void *) XtOffsetOf (shib_dir_config, szApplicationId),
   OR_AUTHCFG, TAKE1, "Set Shibboleth applicationId property for content"},
  {"ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bBasicHijack),
   OR_AUTHCFG, FLAG, "Respond to AuthType Basic and convert to shibboleth"},
  {"ShibRequireSession", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bRequireSession),
   OR_AUTHCFG, FLAG, "Initiates a new session if one does not exist"},
  {"ShibRequireSessionWith", (config_fn_t)ap_set_string_slot,
   (void *) XtOffsetOf (shib_dir_config, szRequireWith),
   OR_AUTHCFG, TAKE1, "Initiates a new session if one does not exist using a specific SessionInitiator"},
  {"ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bExportAssertion),
   OR_AUTHCFG, FLAG, "Export SAML attribute assertion(s) to Shib-Attributes header"},
  {"ShibRedirectToSSL", (config_fn_t)ap_set_string_slot,
   (void *) XtOffsetOf (shib_dir_config, szRedirectToSSL),
   OR_AUTHCFG, TAKE1, "Redirect non-SSL requests to designated port" },
  {"AuthGroupFile", (config_fn_t)shib_ap_set_file_slot,
   (void *) XtOffsetOf (shib_dir_config, szAuthGrpFile),
   OR_AUTHCFG, TAKE1, "text file containing group names and member user IDs"},
  {"ShibRequireAll", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bRequireAll),
   OR_AUTHCFG, FLAG, "All require directives must match"},
  {"AuthzShibAuthoritative", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bAuthoritative),
   OR_AUTHCFG, FLAG, "Allow failed mod_shib htaccess authorization to fall through to other modules"},
  {"ShibUseEnvironment", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bUseEnvVars),
   OR_AUTHCFG, FLAG, "Export attributes using environment variables (default)"},
  {"ShibUseHeaders", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bUseHeaders),
   OR_AUTHCFG, FLAG, "Export attributes using custom HTTP headers"},

  {NULL}
};

extern "C"{
handler_rec shib_handlers[] = {
  { "shib-handler", shib_handler },
  { NULL }
};

module MODULE_VAR_EXPORT mod_shib = {
    STANDARD_MODULE_STUFF,
    NULL,                        /* initializer */
    create_shib_dir_config,	/* dir config creater */
    merge_shib_dir_config,	/* dir merger --- default is to override */
    create_shib_server_config, /* server config */
    merge_shib_server_config,   /* merge server config */
    shire_cmds,			/* command table */
    shib_handlers,		/* handlers */
    NULL,			/* filename translation */
    shib_check_user,		/* check_user_id */
    shib_auth_checker,		/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    shib_fixups,		/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    shib_child_init,		/* child_init */
    shib_child_exit,		/* child_exit */
    shib_post_read		/* post read-request */
};

#elif defined(SHIB_APACHE_20) || defined(SHIB_APACHE_22)

extern "C" void shib_register_hooks (apr_pool_t *p)
{
#ifdef SHIB_DEFERRED_HEADERS
  ap_register_output_filter("SHIB_HEADERS_OUT", do_output_filter, NULL, AP_FTYPE_CONTENT_SET);
  ap_hook_insert_filter(set_output_filter, NULL, NULL, APR_HOOK_LAST);
  ap_register_output_filter("SHIB_HEADERS_ERR", do_error_filter, NULL, AP_FTYPE_CONTENT_SET);
  ap_hook_insert_error_filter(set_error_filter, NULL, NULL, APR_HOOK_LAST);
  ap_hook_post_read_request(shib_post_read, NULL, NULL, APR_HOOK_MIDDLE);
#endif
  ap_hook_child_init(shib_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_check_user_id(shib_check_user, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_auth_checker(shib_auth_checker, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_handler(shib_handler, NULL, NULL, APR_HOOK_LAST);
  ap_hook_fixups(shib_fixups, NULL, NULL, APR_HOOK_MIDDLE);
}

// SHIB Module commands

extern "C" {
static command_rec shib_cmds[] = {
    AP_INIT_TAKE1("ShibPrefix", (config_fn_t)ap_set_global_string_slot, &g_szPrefix,
        RSRC_CONF, "Shibboleth installation directory"),
    AP_INIT_TAKE1("ShibConfig", (config_fn_t)ap_set_global_string_slot, &g_szSHIBConfig,
        RSRC_CONF, "Path to shibboleth.xml config file"),
    AP_INIT_TAKE1("ShibCatalogs", (config_fn_t)ap_set_global_string_slot, &g_szSchemaDir,
        RSRC_CONF, "Paths of XML schema catalogs"),
    AP_INIT_TAKE1("ShibSchemaDir", (config_fn_t)ap_set_global_string_slot, &g_szSchemaDir,
        RSRC_CONF, "Paths of XML schema catalogs (deprecated in favor of ShibCatalogs)"),

    AP_INIT_TAKE1("ShibURLScheme", (config_fn_t)shib_set_server_string_slot,
        (void *) offsetof (shib_server_config, szScheme),
        RSRC_CONF, "URL scheme to force into generated URLs for a vhost"),

    AP_INIT_TAKE2("ShibRequestSetting", (config_fn_t)shib_table_set, NULL,
        OR_AUTHCFG, "Set arbitrary Shibboleth request property for content"),

    AP_INIT_FLAG("ShibDisable", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bOff),
        OR_AUTHCFG, "Disable all Shib module activity here to save processing effort"),
    AP_INIT_TAKE1("ShibApplicationId", (config_fn_t)ap_set_string_slot,
        (void *) offsetof (shib_dir_config, szApplicationId),
        OR_AUTHCFG, "Set Shibboleth applicationId property for content"),
    AP_INIT_FLAG("ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bBasicHijack),
        OR_AUTHCFG, "Respond to AuthType Basic and convert to shibboleth"),
    AP_INIT_FLAG("ShibRequireSession", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bRequireSession),
        OR_AUTHCFG, "Initiates a new session if one does not exist"),
    AP_INIT_TAKE1("ShibRequireSessionWith", (config_fn_t)ap_set_string_slot,
        (void *) offsetof (shib_dir_config, szRequireWith),
        OR_AUTHCFG, "Initiates a new session if one does not exist using a specific SessionInitiator"),
    AP_INIT_FLAG("ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bExportAssertion),
        OR_AUTHCFG, "Export SAML attribute assertion(s) to Shib-Attributes header"),
    AP_INIT_TAKE1("ShibRedirectToSSL", (config_fn_t)ap_set_string_slot,
        (void *) offsetof (shib_dir_config, szRedirectToSSL),
        OR_AUTHCFG, "Redirect non-SSL requests to designated port"),
    AP_INIT_TAKE1("AuthGroupFile", (config_fn_t)shib_ap_set_file_slot,
        (void *) offsetof (shib_dir_config, szAuthGrpFile),
        OR_AUTHCFG, "Text file containing group names and member user IDs"),
    AP_INIT_FLAG("ShibRequireAll", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bRequireAll),
        OR_AUTHCFG, "All require directives must match"),
    AP_INIT_FLAG("AuthzShibAuthoritative", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bAuthoritative),
        OR_AUTHCFG, "Allow failed mod_shib htaccess authorization to fall through to other modules"),
    AP_INIT_FLAG("ShibUseEnvironment", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bUseEnvVars),
        OR_AUTHCFG, "Export attributes using environment variables (default)"),
    AP_INIT_FLAG("ShibUseHeaders", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bUseHeaders),
        OR_AUTHCFG, "Export attributes using custom HTTP headers"),

    {NULL}
};

module AP_MODULE_DECLARE_DATA mod_shib = {
    STANDARD20_MODULE_STUFF,
    create_shib_dir_config,     /* create dir config */
    merge_shib_dir_config,      /* merge dir config --- default is to override */
    create_shib_server_config,  /* create server config */
    merge_shib_server_config,   /* merge server config */
    shib_cmds,                  /* command table */
    shib_register_hooks         /* register hooks */
};

#else
#error "unsupported Apache version"
#endif

}

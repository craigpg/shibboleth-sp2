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

/* shibresponder.cpp - Shibboleth FastCGI Responder/Handler

   Andre Cruz
*/

#define SHIBSP_LITE
#include "config_win32.h"

#define _CRT_NONSTDC_NO_DEPRECATE 1
#define _CRT_SECURE_NO_DEPRECATE 1
#define _SCL_SECURE_NO_WARNINGS 1

#include <shibsp/AbstractSPRequest.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <xmltooling/unicode.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

#include <stdexcept>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
# include <sys/mman.h>
#endif
#include <fcgio.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

static const XMLCh path[] =     UNICODE_LITERAL_4(p,a,t,h);
static const XMLCh validate[] = UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);

typedef enum {
    SHIB_RETURN_OK,
    SHIB_RETURN_KO,
    SHIB_RETURN_DONE
} shib_return_t;

class ShibTargetFCGI : public AbstractSPRequest
{
    FCGX_Request* m_req;
    const char* m_body;
    multimap<string,string> m_headers;
    int m_port;
    string m_scheme,m_hostname;

public:
    ShibTargetFCGI(FCGX_Request* req, char* post_data, const char* scheme=NULL, const char* hostname=NULL, int port=0)
        : AbstractSPRequest(SHIBSP_LOGCAT".FastCGI"), m_req(req), m_body(post_data) {

        const char* server_name_str = hostname;
        if (!server_name_str || !*server_name_str)
            server_name_str = FCGX_GetParam("SERVER_NAME", req->envp);
        m_hostname = server_name_str;

        m_port = port;
        if (!m_port) {
            char* server_port_str = FCGX_GetParam("SERVER_PORT", req->envp);
            m_port = strtol(server_port_str, &server_port_str, 10);
            if (*server_port_str) {
                cerr << "can't parse SERVER_PORT (" << FCGX_GetParam("SERVER_PORT", req->envp) << ")" << endl;
                throw runtime_error("Unable to determine server port.");
            }
        }

        const char* server_scheme_str = scheme;
        if (!server_scheme_str || !*server_scheme_str)
            server_scheme_str = (m_port == 443 || m_port == 8443) ? "https" : "http";
        m_scheme = server_scheme_str;

        setRequestURI(FCGX_GetParam("REQUEST_URI", m_req->envp));
    }

    ~ShibTargetFCGI() { }

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
        return FCGX_GetParam("REQUEST_METHOD", m_req->envp);
    }
    string getContentType() const {
        const char* s = FCGX_GetParam("CONTENT_TYPE", m_req->envp);
        return s ? s : "";
    }
    long getContentLength() const {
        const char* s = FCGX_GetParam("CONTENT_LENGTH", m_req->envp);
        return s ? atol(s) : 0;
    }
    string getRemoteUser() const {
        const char* s = FCGX_GetParam("REMOTE_USER", m_req->envp);
        return s ? s : "";
    }
    string getRemoteAddr() const {
        string ret = AbstractSPRequest::getRemoteAddr();
        if (!ret.empty())
            return ret;
        const char* s = FCGX_GetParam("REMOTE_ADDR", m_req->envp);
        return s ? s : "";
    }
    void log(SPLogLevel level, const string& msg) const {
        AbstractSPRequest::log(level,msg);
        if (level >= SPError)
            cerr << "shib: " << msg;
    }

    string getHeader(const char* name) const {
        string hdr("HTTP_");
        for (; *name; ++name) {
            if (*name=='-')
                hdr += '_';
            else
                hdr += toupper(*name);
        }
        char* s = FCGX_GetParam(hdr.c_str(), m_req->envp);
        return s ? s : "";
    }

    void setResponseHeader(const char* name, const char* value) {
        HTTPResponse::setResponseHeader(name, value);
        // Set for later.
        if (value)
            m_headers.insert(make_pair(name,value));
        else
            m_headers.erase(name);
    }

    const char* getQueryString() const {
        return FCGX_GetParam("QUERY_STRING", m_req->envp);
    }

    const char* getRequestBody() const {
        return m_body;
    }

    long sendResponse(istream& in, long status) {
        string hdr = string("Connection: close\r\n");
        for (multimap<string,string>::const_iterator i=m_headers.begin(); i!=m_headers.end(); ++i)
            hdr += i->first + ": " + i->second + "\r\n";

        const char* codestr="Status: 200 OK";
        switch (status) {
            case XMLTOOLING_HTTP_STATUS_ERROR:          codestr="Status: 500 Server Error"; break;
            case XMLTOOLING_HTTP_STATUS_UNAUTHORIZED:   codestr="Status: 401 Authorization Required"; break;
            case XMLTOOLING_HTTP_STATUS_FORBIDDEN:      codestr="Status: 403 Forbidden"; break;
            case XMLTOOLING_HTTP_STATUS_NOTFOUND:       codestr="Status: 404 Not Found"; break;
        }
        cout << codestr << "\r\n" << hdr << "\r\n";
        char buf[1024];
        while (in) {
            in.read(buf,1024);
            cout.write(buf, in.gcount());
        }
        return SHIB_RETURN_DONE;
    }

    long sendRedirect(const char* url) {
        HTTPResponse::sendRedirect(url);
        string hdr=string("Status: 302 Please Wait\r\nLocation: ") + url + "\r\n"
          "Content-Type: text/html\r\n"
          "Content-Length: 40\r\n"
          "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
          "Cache-Control: private,no-store,no-cache\r\n";
        for (multimap<string,string>::const_iterator i=m_headers.begin(); i!=m_headers.end(); ++i)
            hdr += i->first + ": " + i->second + "\r\n";
        hdr += "\r\n";

        cout << hdr << "<HTML><BODY>Redirecting...</BODY></HTML>";
        return SHIB_RETURN_DONE;
    }

    long returnDecline() {
        return SHIB_RETURN_KO;
    }
    long returnOK() {
        return SHIB_RETURN_OK;
    }

    const vector<string>& getClientCertificates() const {
        static vector<string> g_NoCerts;
        return g_NoCerts;
    }

    // Not used in the extension.

    virtual void clearHeader(const char* rawname, const char* cginame) {
        throw runtime_error("clearHeader not implemented by FastCGI responder.");
    }

    virtual void setHeader(const char* name, const char* value) {
        throw runtime_error("setHeader not implemented by FastCGI responder.");
    }

    virtual void setRemoteUser(const char* user) {
        throw runtime_error("setRemoteUser not implemented by FastCGI responder.");
    }
};

// Maximum number of bytes allowed to be read from stdin
static const unsigned long STDIN_MAX = 1000000;

static long gstdin(FCGX_Request* request, char** content)
{
    char* clenstr = FCGX_GetParam("CONTENT_LENGTH", request->envp);
    unsigned long clen = STDIN_MAX;

    if (clenstr) {
        clen = strtol(clenstr, &clenstr, 10);
        if (*clenstr) {
            cerr << "can't parse CONTENT_LENGTH (" << FCGX_GetParam("CONTENT_LENGTH", request->envp) << ")" << endl;
            clen = STDIN_MAX;
        }

        // *always* put a cap on the amount of data that will be read
        if (clen > STDIN_MAX)
            clen = STDIN_MAX;

        *content = new char[clen];

        cin.read(*content, clen);
        clen = cin.gcount();
    }
    else {
        // *never* read stdin when CONTENT_LENGTH is missing or unparsable
        *content = 0;
        clen = 0;
    }

    // Chew up any remaining stdin - this shouldn't be necessary
    // but is because mod_fastcgi doesn't handle it correctly.

    // ignore() doesn't set the eof bit in some versions of glibc++
    // so use gcount() instead of eof()...
    do cin.ignore(1024); while (cin.gcount() == 1024);

    return clen;
}

static void print_ok() {
    cout << "Status: 200 OK" << "\r\n\r\n";
}

static void print_error(const char* msg) {
    cout << "Status: 500 Server Error" << "\r\n\r\n" << msg;
}

int main(void)
{
    SPConfig* g_Config=&SPConfig::getConfig();
    g_Config->setFeatures(
        SPConfig::Listener |
        SPConfig::Caching |
        SPConfig::RequestMapping |
        SPConfig::InProcess |
        SPConfig::Logging |
        SPConfig::Handlers
        );
    if (!g_Config->init()) {
        cerr << "failed to initialize Shibboleth libraries" << endl;
        exit(1);
    }

    try {
        if (!g_Config->instantiate(NULL, true))
            throw runtime_error("unknown error");
    }
    catch (exception& ex) {
        g_Config->term();
        cerr << "exception while initializing Shibboleth configuration: " << ex.what() << endl;
        exit(1);
    }

    string g_ServerScheme;
    string g_ServerName;
    int g_ServerPort=0;

    // Load "authoritative" URL fields.
    char* var = getenv("SHIBSP_SERVER_NAME");
    if (var)
        g_ServerName = var;
    var = getenv("SHIBSP_SERVER_SCHEME");
    if (var)
        g_ServerScheme = var;
    var = getenv("SHIBSP_SERVER_PORT");
    if (var)
        g_ServerPort = atoi(var);

    streambuf* cin_streambuf  = cin.rdbuf();
    streambuf* cout_streambuf = cout.rdbuf();
    streambuf* cerr_streambuf = cerr.rdbuf();

    FCGX_Request request;

    FCGX_Init();
    FCGX_InitRequest(&request, 0, 0);

    cout << "Shibboleth initialization complete. Starting request loop." << endl;
    while (FCGX_Accept_r(&request) == 0) {
        // Note that the default bufsize (0) will cause the use of iostream
        // methods that require positioning (such as peek(), seek(),
        // unget() and putback()) to fail (in favour of more efficient IO).
        fcgi_streambuf cin_fcgi_streambuf(request.in);
        fcgi_streambuf cout_fcgi_streambuf(request.out);
        fcgi_streambuf cerr_fcgi_streambuf(request.err);

        cin.rdbuf(&cin_fcgi_streambuf);
        cout.rdbuf(&cout_fcgi_streambuf);
        cerr.rdbuf(&cerr_fcgi_streambuf);

        // Although FastCGI supports writing before reading,
        // many http clients (browsers) don't support it (so
        // the connection deadlocks until a timeout expires!).
        char* content;
        gstdin(&request, &content);

        try {
            xmltooling::NDC ndc("FastCGI shibresponder");
            ShibTargetFCGI stf(&request, content, g_ServerScheme.c_str(), g_ServerName.c_str(), g_ServerPort);

            pair<bool,long> res = stf.getServiceProvider().doHandler(stf);
            if (res.first) {
                stf.log(SPRequest::SPDebug, "shib: doHandler handled the request");
                switch(res.second) {
                    case SHIB_RETURN_OK:
                        print_ok();
                        break;

                    case SHIB_RETURN_KO:
                        cerr << "shib: doHandler failed to handle the request" << endl;
                        print_error("<html><body>FastCGI Shibboleth responder should only be used for Shibboleth protocol requests.</body></html>");
                        break;

                    case SHIB_RETURN_DONE:
                        // response already handled
                        break;

                    default:
                        cerr << "shib: doHandler returned an unexpected result: " << res.second << endl;
                        print_error("<html><body>FastCGI Shibboleth responder returned an unexpected result.</body></html>");
                        break;
                }
            }
            else {
                cerr << "shib: doHandler failed to handle request." << endl;
                print_error("<html><body>FastCGI Shibboleth responder failed to process request.</body></html>");
            }

        }
        catch (exception& e) {
            cerr << "shib: FastCGI responder caught an exception: " << e.what() << endl;
            print_error("<html><body>FastCGI Shibboleth responder caught an exception, check log for details.</body></html>");
        }

        delete[] content;

        // If the output streambufs had non-zero bufsizes and
        // were constructed outside of the accept loop (i.e.
        // their destructor won't be called here), they would
        // have to be flushed here.
    }

    cout << "Request loop ended." << endl;

    cin.rdbuf(cin_streambuf);
    cout.rdbuf(cout_streambuf);
    cerr.rdbuf(cerr_streambuf);

    if (g_Config)
        g_Config->term();

    return 0;
}

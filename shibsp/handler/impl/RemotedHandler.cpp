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
 * RemotedHandler.cpp
 * 
 * Base class for handlers that need SP request/response layer to be remoted. 
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/RemotedHandler.h"

#include <algorithm>
#include <xmltooling/unicode.h>

#ifndef SHIBSP_LITE
# include "util/CGIParser.h"
# include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
# include <xsec/enc/XSECCryptoException.hpp>
# include <xsec/framework/XSECException.hpp>
# include <xsec/framework/XSECProvider.hpp>
#endif

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

#ifndef SHIBSP_LITE
namespace shibsp {
    class SHIBSP_DLLLOCAL RemotedRequest : public virtual HTTPRequest 
    {
        DDF& m_input;
        mutable CGIParser* m_parser;
        mutable vector<XSECCryptoX509*> m_certs;
    public:
        RemotedRequest(DDF& input) : m_input(input), m_parser(NULL) {}
        virtual ~RemotedRequest() {
            for_each(m_certs.begin(), m_certs.end(), xmltooling::cleanup<XSECCryptoX509>());
            delete m_parser;
        }

        // GenericRequest
        const char* getScheme() const {
            return m_input["scheme"].string();
        }
        const char* getHostname() const {
            return m_input["hostname"].string();
        }
        int getPort() const {
            return m_input["port"].integer();
        }
        std::string getContentType() const {
            DDF s = m_input["content_type"];
            return s.string() ? s.string() : "";
        }
        long getContentLength() const {
            return m_input["content_length"].integer();
        }
        const char* getRequestBody() const {
            return m_input["body"].string();
        }

        const char* getParameter(const char* name) const;
        std::vector<const char*>::size_type getParameters(const char* name, std::vector<const char*>& values) const;
        
        std::string getRemoteUser() const {
            DDF s = m_input["remote_user"];
            return s.string() ? s.string() : "";
        }
        std::string getRemoteAddr() const {
            DDF s = m_input["client_addr"];
            return s.string() ? s.string() : "";
        }

        const std::vector<XSECCryptoX509*>& getClientCertificates() const;
        
        // HTTPRequest
        const char* getMethod() const {
            return m_input["method"].string();
        }
        const char* getRequestURI() const {
            return m_input["uri"].string();
        }
        const char* getRequestURL() const {
            return m_input["url"].string();
        }
        const char* getQueryString() const {
            return m_input["query"].string();
        }
        std::string getHeader(const char* name) const {
            DDF s = m_input["headers"][name];
            return s.string() ? s.string() : "";
        }
    };

    class SHIBSP_DLLLOCAL RemotedResponse : public virtual HTTPResponse 
    {
        DDF& m_output;
    public:
        RemotedResponse(DDF& output) : m_output(output) {}
        virtual ~RemotedResponse() {}
       
        // GenericResponse
        long sendResponse(std::istream& inputStream, long status);
        
        // HTTPResponse
        void setResponseHeader(const char* name, const char* value);
        long sendRedirect(const char* url);
    };
}

const char* RemotedRequest::getParameter(const char* name) const
{
    if (!m_parser)
        m_parser=new CGIParser(*this);
    
    pair<CGIParser::walker,CGIParser::walker> bounds=m_parser->getParameters(name);
    return (bounds.first==bounds.second) ? NULL : bounds.first->second;
}

std::vector<const char*>::size_type RemotedRequest::getParameters(const char* name, std::vector<const char*>& values) const
{
    if (!m_parser)
        m_parser=new CGIParser(*this);

    pair<CGIParser::walker,CGIParser::walker> bounds=m_parser->getParameters(name);
    while (bounds.first!=bounds.second) {
        values.push_back(bounds.first->second);
        ++bounds.first;
    }
    return values.size();
}

const std::vector<XSECCryptoX509*>& RemotedRequest::getClientCertificates() const
{
    if (m_certs.empty()) {
        DDF certs = m_input["certificates"];
        DDF cert = certs.first();
        while (cert.string()) {
            try {
                auto_ptr<XSECCryptoX509> x509(XSECPlatformUtils::g_cryptoProvider->X509());
                if (strstr(cert.string(), "BEGIN"))
                    x509->loadX509PEM(cert.string(), cert.strlen());
                else
                    x509->loadX509Base64Bin(cert.string(), cert.strlen());
                m_certs.push_back(x509.release());
            }
            catch(XSECException& e) {
                auto_ptr_char temp(e.getMsg());
                Category::getInstance(SHIBSP_LOGCAT".SPRequest").error("XML-Security exception loading client certificate: %s", temp.get());
            }
            catch(XSECCryptoException& e) {
                Category::getInstance(SHIBSP_LOGCAT".SPRequest").error("XML-Security exception loading client certificate: %s", e.getMsg());
            }
            cert = certs.next();
        }
    }
    return m_certs;
}

long RemotedResponse::sendResponse(std::istream& in, long status)
{
    string msg;
    char buf[1024];
    while (in) {
        in.read(buf,1024);
        msg.append(buf,in.gcount());
    }
    if (!m_output.isstruct())
        m_output.structure();
    m_output.addmember("response.data").string(msg.c_str());
    m_output.addmember("response.status").integer(status);
    return status;
}

void RemotedResponse::setResponseHeader(const char* name, const char* value)
{
    if (!m_output.isstruct())
        m_output.structure();
    DDF hdrs = m_output["headers"];
    if (hdrs.isnull())
        hdrs = m_output.addmember("headers").list();
    DDF h = DDF(name).string(value);
    hdrs.add(h);
}

long RemotedResponse::sendRedirect(const char* url)
{
    if (!m_output.isstruct())
        m_output.structure();
    m_output.addmember("redirect").unsafe_string(url);
    return HTTPResponse::XMLTOOLING_HTTP_STATUS_MOVED;
}

#endif

void RemotedHandler::setAddress(const char* address)
{
    if (!m_address.empty())
        throw ConfigurationException("Cannot register a remoting address twice for the same Handler.");
    m_address = address;
    SPConfig& conf = SPConfig::getConfig();
    if (!conf.isEnabled(SPConfig::InProcess)) {
        ListenerService* listener = conf.getServiceProvider()->getListenerService(false);
        if (listener)
            listener->regListener(m_address.c_str(),this);
        else
            Category::getInstance(SHIBSP_LOGCAT".Handler").info("no ListenerService available, handler remoting disabled");
    }
}

RemotedHandler::RemotedHandler()
{
}

RemotedHandler::~RemotedHandler()
{
    SPConfig& conf = SPConfig::getConfig();
    ListenerService* listener=conf.getServiceProvider()->getListenerService(false);
    if (listener && conf.isEnabled(SPConfig::OutOfProcess) && !conf.isEnabled(SPConfig::InProcess))
        listener->unregListener(m_address.c_str(),this);
}

DDF RemotedHandler::wrap(const SPRequest& request, const vector<string>* headers, bool certs) const
{
    DDF in = DDF(m_address.c_str()).structure();
    in.addmember("application_id").string(request.getApplication().getId());
    in.addmember("scheme").string(request.getScheme());
    in.addmember("hostname").unsafe_string(request.getHostname());
    in.addmember("port").integer(request.getPort());
    in.addmember("content_type").string(request.getContentType().c_str());
    in.addmember("content_length").integer(request.getContentLength());
    in.addmember("body").string(request.getRequestBody());
    in.addmember("remote_user").string(request.getRemoteUser().c_str());
    in.addmember("client_addr").string(request.getRemoteAddr().c_str());
    in.addmember("method").string(request.getMethod());
    in.addmember("uri").unsafe_string(request.getRequestURI());
    in.addmember("url").unsafe_string(request.getRequestURL());
    in.addmember("query").string(request.getQueryString());

    if (headers) {
        string hdr;
        DDF hin = in.addmember("headers").structure();
        for (vector<string>::const_iterator h = headers->begin(); h!=headers->end(); ++h) {
            hdr = request.getHeader(h->c_str());
            if (!hdr.empty())
                hin.addmember(h->c_str()).string(hdr.c_str());
        }
    }

    if (certs) {
#ifndef SHIBSP_LITE
        const vector<XSECCryptoX509*>& xvec = request.getClientCertificates();
        if (!xvec.empty()) {
            DDF clist = in.addmember("certificates").list();
            for (vector<XSECCryptoX509*>::const_iterator x = xvec.begin(); x!=xvec.end(); ++x) {
                DDF x509 = DDF(NULL).string((*x)->getDEREncodingSB().rawCharBuffer());
                clist.add(x509);
            }
        }
#else
        const vector<string>& xvec = request.getClientCertificates();
        if (!xvec.empty()) {
            DDF clist = in.addmember("certificates").list();
            for (vector<string>::const_iterator x = xvec.begin(); x!=xvec.end(); ++x) {
                DDF x509 = DDF(NULL).string(x->c_str());
                clist.add(x509);
            }
        }
#endif
    }

    return in;
}

pair<bool,long> RemotedHandler::unwrap(SPRequest& request, DDF& out) const
{
    DDF h = out["headers"];
    DDF hdr = h.first();
    while (hdr.isstring()) {
#ifdef HAVE_STRCASECMP
        if (!strcasecmp(hdr.name(), "Content-Type"))
#else
        if (!stricmp(hdr.name(), "Content-Type"))
#endif
            request.setContentType(hdr.string());
        else
            request.setResponseHeader(hdr.name(), hdr.string());
        hdr = h.next();
    }
    h = out["redirect"];
    if (h.isstring())
        return make_pair(true, request.sendRedirect(h.string()));
    h = out["response"];
    if (h.isstruct()) {
        istringstream s(h["data"].string());
        return make_pair(true, request.sendResponse(s, h["status"].integer()));
    }
    return make_pair(false,0L);
}

HTTPRequest* RemotedHandler::getRequest(DDF& in) const
{
#ifndef SHIBSP_LITE
    return new RemotedRequest(in);
#else
    throw ConfigurationException("Cannot process message using lite version of shibsp library.");
#endif
}

HTTPResponse* RemotedHandler::getResponse(DDF& out) const
{
#ifndef SHIBSP_LITE
    return new RemotedResponse(out);
#else
    throw ConfigurationException("Cannot process message using lite version of shibsp library.");
#endif
}

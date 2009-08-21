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
 * AbstractSPRequest.cpp
 *
 * Abstract base for SPRequest implementations
 */

#include "internal.h"
#include "AbstractSPRequest.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

AbstractSPRequest::AbstractSPRequest(const char* category)
    : m_sp(NULL), m_mapper(NULL), m_app(NULL), m_sessionTried(false), m_session(NULL),
        m_log(&Category::getInstance(category)), m_parser(NULL)
{
    m_sp=SPConfig::getConfig().getServiceProvider();
    m_sp->lock();
}

AbstractSPRequest::~AbstractSPRequest()
{
    if (m_session)
        m_session->unlock();
    if (m_mapper)
        m_mapper->unlock();
    if (m_sp)
        m_sp->unlock();
    delete m_parser;
}

RequestMapper::Settings AbstractSPRequest::getRequestSettings() const
{
    if (!m_mapper) {
        // Map request to application and content settings.
        m_mapper=m_sp->getRequestMapper();
        m_mapper->lock();
        m_settings = m_mapper->getSettings(*this);

        if (reinterpret_cast<Category*>(m_log)->isDebugEnabled()) {
            reinterpret_cast<Category*>(m_log)->debug(
                "mapped %s to %s", getRequestURL(), m_settings.first->getString("applicationId").second
                );
        }
    }
    return m_settings;
}

const Application& AbstractSPRequest::getApplication() const
{
    if (!m_app) {
        // Now find the application from the URL settings
        m_app=m_sp->getApplication(getRequestSettings().first->getString("applicationId").second);
        if (!m_app)
            throw ConfigurationException("Unable to map request to ApplicationOverride settings, check configuration.");
    }
    return *m_app;
}

Session* AbstractSPRequest::getSession(bool checkTimeout, bool ignoreAddress, bool cache)
{
    // Only attempt this once.
    if (cache && m_sessionTried)
        return m_session;
    else if (cache)
        m_sessionTried = true;

    // Need address checking and timeout settings.
    time_t timeout=3600;
    if (checkTimeout || !ignoreAddress) {
        const PropertySet* props=getApplication().getPropertySet("Sessions");
        if (props) {
            if (checkTimeout) {
                pair<bool,unsigned int> p=props->getUnsignedInt("timeout");
                if (p.first)
                    timeout = p.second;
            }
            pair<bool,bool> pcheck=props->getBool("consistentAddress");
            if (pcheck.first)
                ignoreAddress = !pcheck.second;
        }
    }

    // The cache will either silently pass a session or NULL back, or throw an exception out.
    Session* session = getServiceProvider().getSessionCache()->find(
        getApplication(), *this, ignoreAddress ? NULL : getRemoteAddr().c_str(), checkTimeout ? &timeout : NULL
        );
    if (cache)
        m_session = session;
    return session;
}

static char _x2c(const char *what)
{
    register char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
    return(digit);
}

void AbstractSPRequest::setRequestURI(const char* uri)
{
    // Fix for bug 574, secadv 20061002
    // Unescape URI up to query string delimiter by looking for %XX escapes.
    // Adapted from Apache's util.c, ap_unescape_url function.
    if (uri) {
        while (*uri) {
            if (*uri == '?') {
                m_uri += uri;
                break;
            }
            else if (*uri != '%') {
                m_uri += *uri;
            }
            else {
                ++uri;
                if (!isxdigit(*uri) || !isxdigit(*(uri+1)))
                    throw ConfigurationException("Bad request, contained unsupported encoded characters.");
                m_uri += _x2c(uri);
                ++uri;
            }
            ++uri;
        }
    }
}

const char* AbstractSPRequest::getRequestURL() const
{
    if (m_url.empty()) {
        // Compute the full target URL
        int port = getPort();
        const char* scheme = getScheme();
        m_url = string(scheme) + "://" + getHostname();
        if ((!strcmp(scheme,"http") && port!=80) || (!strcmp(scheme,"https") && port!=443)) {
            ostringstream portstr;
            portstr << port;
            m_url += ":" + portstr.str();
        }
        m_url += m_uri;
    }
    return m_url.c_str();
}

string AbstractSPRequest::getRemoteAddr() const
{
    pair<bool,const char*> addr = getRequestSettings().first->getString("REMOTE_ADDR");
    return addr.first ? getHeader(addr.second) : "";
}

const char* AbstractSPRequest::getParameter(const char* name) const
{
    if (!m_parser)
        m_parser=new CGIParser(*this);

    pair<CGIParser::walker,CGIParser::walker> bounds=m_parser->getParameters(name);
    return (bounds.first==bounds.second) ? NULL : bounds.first->second;
}

vector<const char*>::size_type AbstractSPRequest::getParameters(const char* name, vector<const char*>& values) const
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

const char* AbstractSPRequest::getHandlerURL(const char* resource) const
{
    if (!resource)
        resource = getRequestURL();

    if (!m_handlerURL.empty() && resource && !strcmp(getRequestURL(),resource))
        return m_handlerURL.c_str();

#ifdef HAVE_STRCASECMP
    if (!resource || (strncasecmp(resource,"http://",7) && strncasecmp(resource,"https://",8)))
#else
    if (!resource || (strnicmp(resource,"http://",7) && strnicmp(resource,"https://",8)))
#endif
        throw ConfigurationException("Target resource was not an absolute URL.");

    bool ssl_only=true;
    const char* handler=NULL;
    const PropertySet* props=getApplication().getPropertySet("Sessions");
    if (props) {
        pair<bool,bool> p=props->getBool("handlerSSL");
        if (p.first)
            ssl_only=p.second;
        pair<bool,const char*> p2=props->getString("handlerURL");
        if (p2.first)
            handler=p2.second;
    }

    // Should never happen...
    if (!handler || (*handler!='/' && strncmp(handler,"http:",5) && strncmp(handler,"https:",6)))
        throw ConfigurationException(
            "Invalid handlerURL property ($1) in <Sessions> element for Application ($2)",
            params(2, handler ? handler : "null", m_app->getId())
            );

    // The "handlerURL" property can be in one of three formats:
    //
    // 1) a full URI:       http://host/foo/bar
    // 2) a hostless URI:   http:///foo/bar
    // 3) a relative path:  /foo/bar
    //
    // #  Protocol  Host        Path
    // 1  handler   handler     handler
    // 2  handler   resource    handler
    // 3  resource  resource    handler
    //
    // note: if ssl_only is true, make sure the protocol is https

    const char* path = NULL;

    // Decide whether to use the handler or the resource for the "protocol"
    const char* prot;
    if (*handler != '/') {
        prot = handler;
    }
    else {
        prot = resource;
        path = handler;
    }

    // break apart the "protocol" string into protocol, host, and "the rest"
    const char* colon=strchr(prot,':');
    colon += 3;
    const char* slash=strchr(colon,'/');
    if (!path)
        path = slash;

    // Compute the actual protocol and store in member.
    if (ssl_only)
        m_handlerURL.assign("https://");
    else
        m_handlerURL.assign(prot, colon-prot);

    // create the "host" from either the colon/slash or from the target string
    // If prot == handler then we're in either #1 or #2, else #3.
    // If slash == colon then we're in #2.
    if (prot != handler || slash == colon) {
        colon = strchr(resource, ':');
        colon += 3;      // Get past the ://
        slash = strchr(colon, '/');
    }
    string host(colon, (slash ? slash-colon : strlen(colon)));

    // Build the handler URL
    m_handlerURL += host + path;
    return m_handlerURL.c_str();
}

void AbstractSPRequest::log(SPLogLevel level, const std::string& msg) const
{
    reinterpret_cast<Category*>(m_log)->log(
        (level == SPDebug ? Priority::DEBUG :
        (level == SPInfo ? Priority::INFO :
        (level == SPWarn ? Priority::WARN :
        (level == SPError ? Priority::ERROR : Priority::CRIT)))),
        msg
        );
}

bool AbstractSPRequest::isPriorityEnabled(SPLogLevel level) const
{
    return reinterpret_cast<Category*>(m_log)->isPriorityEnabled(
        (level == SPDebug ? Priority::DEBUG :
        (level == SPInfo ? Priority::INFO :
        (level == SPWarn ? Priority::WARN :
        (level == SPError ? Priority::ERROR : Priority::CRIT))))
        );
}

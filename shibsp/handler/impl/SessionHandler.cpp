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
 * SessionHandler.cpp
 *
 * Handler for dumping information about an active session.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPRequest.h"
#include "attribute/Attribute.h"
#include "handler/AbstractHandler.h"

#include <ctime>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL Blocker : public DOMNodeFilter
    {
    public:
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }
    };

    static SHIBSP_DLLLOCAL Blocker g_Blocker;

    class SHIBSP_API SessionHandler : public AbstractHandler
    {
    public:
        SessionHandler(const DOMElement* e, const char* appId);
        virtual ~SessionHandler() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        bool m_values;
        set<string> m_acl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SessionHandlerFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SessionHandler(p.first, p.second);
    }

};

SessionHandler::SessionHandler(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionHandler"), &g_Blocker), m_values(false)
{
    pair<bool,const char*> acl = getString("acl");
    if (acl.first) {
        string aclbuf=acl.second;
        int j = 0;
        for (unsigned int i=0;  i < aclbuf.length();  i++) {
            if (aclbuf.at(i)==' ') {
                m_acl.insert(aclbuf.substr(j, i-j));
                j = i+1;
            }
        }
        m_acl.insert(aclbuf.substr(j, aclbuf.length()-j));
    }

    pair<bool,bool> flag = getBool("showAttributeValues");
    if (flag.first)
        m_values = flag.second;
}

pair<bool,long> SessionHandler::run(SPRequest& request, bool isHandler) const
{
    if (!m_acl.empty() && m_acl.count(request.getRemoteAddr()) == 0) {
        m_log.error("session handler request blocked from invalid address (%s)", request.getRemoteAddr().c_str());
        istringstream msg("Session Handler Blocked");
        return make_pair(true,request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_FORBIDDEN));
    }

    stringstream s;
    s << "<html><head><title>Session Summary</title></head><body><pre>" << endl;

    Session* session = NULL;
    try {
        session = request.getSession();
        if (!session) {
            s << "A valid session was not found.</pre></body></html>" << endl;
            request.setContentType("text/html");
            request.setResponseHeader("Expires","01-Jan-1997 12:00:00 GMT");
            request.setResponseHeader("Cache-Control","private,no-store,no-cache");
            return make_pair(true, request.sendResponse(s));
        }
    }
    catch (exception& ex) {
        s << "Exception while retrieving active session:" << endl
            << '\t' << ex.what() << "</pre></body></html>" << endl;
        request.setContentType("text/html");
        request.setResponseHeader("Expires","01-Jan-1997 12:00:00 GMT");
        request.setResponseHeader("Cache-Control","private,no-store,no-cache");
        return make_pair(true, request.sendResponse(s));
    }

    s << "<u>Miscellaneous</u>" << endl;

    s << "<strong>Client Address:</strong> " << (session->getClientAddress() ? session->getClientAddress() : "(none)") << endl;
    s << "<strong>Identity Provider:</strong> " << (session->getEntityID() ? session->getEntityID() : "(none)") << endl;
    s << "<strong>SSO Protocol:</strong> " << (session->getProtocol() ? session->getProtocol() : "(none)") << endl;
    s << "<strong>Authentication Time:</strong> " << (session->getAuthnInstant() ? session->getAuthnInstant() : "(none)") << endl;
    s << "<strong>Authentication Context Class:</strong> " << (session->getAuthnContextClassRef() ? session->getAuthnContextClassRef() : "(none)") << endl;
    s << "<strong>Authentication Context Decl:</strong> " << (session->getAuthnContextDeclRef() ? session->getAuthnContextDeclRef() : "(none)") << endl;
    s << "<strong>Session Expiration (barring inactivity):</strong> ";
    if (session->getExpiration())
        s << ((session->getExpiration() - time(NULL)) / 60) << " minute(s)" << endl;
    else
        s << "Infinite" << endl;

    s << endl << "<u>Attributes</u>" << endl;

    string key;
    vector<string>::size_type count=0;
    const multimap<string,const Attribute*>& attributes = session->getIndexedAttributes();
    for (multimap<string,const Attribute*>::const_iterator a = attributes.begin(); a != attributes.end(); ++a) {
        if (a->first != key) {
            if (a != attributes.begin()) {
                if (m_values)
                    s << endl;
                else {
                    s << count << " value(s)" << endl;
                    count = 0;
                }
            }
            s << "<strong>" << a->first << "</strong>: ";
        }

        if (m_values) {
            const vector<string>& vals = a->second->getSerializedValues();
            for (vector<string>::const_iterator v = vals.begin(); v!=vals.end(); ++v) {
                if (v != vals.begin() || a->first == key)
                    s << ';';
                string::size_type pos = v->find_first_of(';',string::size_type(0));
                if (pos!=string::npos) {
                    string value(*v);
                    for (; pos != string::npos; pos = value.find_first_of(';',pos)) {
                        value.insert(pos, "\\");
                        pos += 2;
                    }
                    s << value;
                }
                else {
                    s << *v;
                }
            }
        }
        else {
            count += a->second->getSerializedValues().size();
        }
    }

    if (!m_values && !attributes.empty())
        s << count << " value(s)" << endl;

    s << "</pre></body></html>";
    request.setContentType("text/html; charset=UTF-8");
    request.setResponseHeader("Expires","01-Jan-1997 12:00:00 GMT");
    request.setResponseHeader("Cache-Control","private,no-store,no-cache");
    return make_pair(true, request.sendResponse(s));
}

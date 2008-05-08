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
 * LogoutHandler.cpp
 * 
 * Base class for logout-related handlers.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "handler/LogoutHandler.h"
#include "util/TemplateParameters.h"

#include <fstream>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

pair<bool,long> LogoutHandler::sendLogoutPage(
    const Application& application, const HTTPRequest& request, HTTPResponse& response, bool local, const char* status
    ) const
{
    const PropertySet* props = application.getPropertySet("Errors");
    pair<bool,const char*> prop = props ? props->getString(local ? "localLogout" : "globalLogout") : pair<bool,const char*>(false,NULL);
    if (prop.first) {
        response.setContentType("text/html");
        response.setResponseHeader("Expires","01-Jan-1997 12:00:00 GMT");
        response.setResponseHeader("Cache-Control","private,no-store,no-cache");
        string fname(prop.second);
        ifstream infile(XMLToolingConfig::getConfig().getPathResolver()->resolve(fname, PathResolver::XMLTOOLING_CFG_FILE).c_str());
        if (!infile)
            throw ConfigurationException("Unable to access $1 HTML template.", params(1,local ? "localLogout" : "globalLogout"));
        TemplateParameters tp;
        tp.m_request = &request;
        tp.setPropertySet(props);
        if (status)
            tp.m_map["logoutStatus"] = status;
        stringstream str;
        XMLToolingConfig::getConfig().getTemplateEngine()->run(infile, str, tp);
        return make_pair(true,response.sendResponse(str));
    }
    prop = application.getString("homeURL");
    if (!prop.first)
        prop.second = "/";
    return make_pair(true,response.sendRedirect(prop.second));
}

pair<bool,long> LogoutHandler::run(SPRequest& request, bool isHandler) const
{
    // If we're inside a chain, do nothing.
    if (getParent())
        return make_pair(false,0L);
    
    // If this isn't a LogoutInitiator, we only "continue" a notification loop, rather than starting one.
    if (!m_initiator && !request.getParameter("notifying"))
        return make_pair(false,0L);

    // Try another front-channel notification. No extra parameters and the session is implicit.
    return notifyFrontChannel(request.getApplication(), request, request);
}

void LogoutHandler::receive(DDF& in, ostream& out)
{
    DDF ret(NULL);
    DDFJanitor jout(ret);
    if (in["notify"].integer() != 1)
        throw ListenerException("Unsupported operation.");

    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        Category::getInstance(SHIBSP_LOGCAT".Logout").error("couldn't find application (%s) for logout", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for logout, deleted?");
    }

    vector<string> sessions;
    DDF s = in["sessions"];
    DDF temp = s.first();
    while (temp.isstring()) {
        sessions.push_back(temp.string());
        temp = s.next();
        if (notifyBackChannel(*app, in["url"].string(), sessions, in["local"].integer()==1))
            ret.integer(1);
    }

    out << ret;
}

pair<bool,long> LogoutHandler::notifyFrontChannel(
    const Application& application,
    const HTTPRequest& request,
    HTTPResponse& response,
    const map<string,string>* params
    ) const
{
    // Index of notification point starts at 0.
    unsigned int index = 0;
    const char* param = request.getParameter("index");
    if (param)
        index = atoi(param);

    // "return" is a backwards-compatible "eventual destination" to go back to after logout completes.
    param = request.getParameter("return");

    // Fetch the next front notification URL and bump the index for the next round trip.
    string loc = application.getNotificationURL(request.getRequestURL(), true, index++);
    if (loc.empty())
        return make_pair(false,0L);

    const URLEncoder* encoder = XMLToolingConfig::getConfig().getURLEncoder();

    // Start with an "action" telling the application what this is about.
    loc = loc + (strchr(loc.c_str(),'?') ? '&' : '?') + "action=logout";

    // Now we create a second URL representing the return location back to us.
    const char* start = request.getRequestURL();
    const char* end = strchr(start,'?');
    string tempstr(start, end ? end-start : strlen(start));
    ostringstream locstr(tempstr);

    // Add a signal that we're coming back from notification and the next index.
    locstr << "?notifying=1&index=" << index;

    // Add return if set.
    if (param)
        locstr << "&return=" << encoder->encode(param);

    // We preserve anything we're instructed to directly.
    if (params) {
        for (map<string,string>::const_iterator p = params->begin(); p!=params->end(); ++p)
            locstr << '&' << p->first << '=' << encoder->encode(p->second.c_str());
    }
    else {
        for (vector<string>::const_iterator q = m_preserve.begin(); q!=m_preserve.end(); ++q) {
            param = request.getParameter(q->c_str());
            if (param)
                locstr << '&' << *q << '=' << encoder->encode(param);
        }
    }

    // Add the notifier's return parameter to the destination location and redirect.
    // This is NOT the same as the return parameter that might be embedded inside it ;-)
    loc = loc + "&return=" + encoder->encode(locstr.str().c_str());
    return make_pair(true,response.sendRedirect(loc.c_str()));
}

#ifndef SHIBSP_LITE
#include "util/SPConstants.h"
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/soap/SOAP.h>
#include <xmltooling/soap/SOAPClient.h>
using namespace soap11;
namespace {
    static const XMLCh LogoutNotification[] =   UNICODE_LITERAL_18(L,o,g,o,u,t,N,o,t,i,f,i,c,a,t,i,o,n);
    static const XMLCh SessionID[] =            UNICODE_LITERAL_9(S,e,s,s,i,o,n,I,D);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh _local[] =               UNICODE_LITERAL_5(l,o,c,a,l);
    static const XMLCh _global[] =              UNICODE_LITERAL_6(g,l,o,b,a,l);

    class SHIBSP_DLLLOCAL SOAPNotifier : public soap11::SOAPClient
    {
    public:
        SOAPNotifier() {}
        virtual ~SOAPNotifier() {}
    private:
        void prepareTransport(SOAPTransport& transport) {
            transport.setVerifyHost(false);
        }
    };
};
#endif

bool LogoutHandler::notifyBackChannel(
    const Application& application, const char* requestURL, const vector<string>& sessions, bool local
    ) const
{
    unsigned int index = 0;
    string endpoint = application.getNotificationURL(requestURL, false, index++);
    if (endpoint.empty())
        return true;

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
#ifndef SHIBSP_LITE
        auto_ptr<Envelope> env(EnvelopeBuilder::buildEnvelope());
        Body* body = BodyBuilder::buildBody();
        env->setBody(body);
        ElementProxy* msg = new AnyElementImpl(shibspconstants::SHIB2SPNOTIFY_NS, LogoutNotification);
        body->getUnknownXMLObjects().push_back(msg);
        msg->setAttribute(QName(NULL, _type), local ? _local : _global);
        for (vector<string>::const_iterator s = sessions.begin(); s!=sessions.end(); ++s) {
            auto_ptr_XMLCh temp(s->c_str());
            ElementProxy* child = new AnyElementImpl(shibspconstants::SHIB2SPNOTIFY_NS, SessionID);
            child->setTextContent(temp.get());
            msg->getUnknownXMLObjects().push_back(child);
        }

        bool result = true;
        SOAPNotifier soaper;
        while (!endpoint.empty()) {
            try {
                soaper.send(*env.get(), SOAPTransport::Address(application.getId(), application.getId(), endpoint.c_str()));
                delete soaper.receive();
            }
            catch (exception& ex) {
                Category::getInstance(SHIBSP_LOGCAT".Logout").error("error notifying application of logout event: %s", ex.what());
                result = false;
            }
            soaper.reset();
            endpoint = application.getNotificationURL(requestURL, false, index++);
        }
        return result;
#else
        return false;
#endif
    }

    // When not out of process, we remote the back channel work.
    DDF out,in(m_address.c_str());
    DDFJanitor jin(in), jout(out);
    in.addmember("notify").integer(1);
    in.addmember("application_id").string(application.getId());
    in.addmember("url").string(requestURL);
    if (local)
        in.addmember("local").integer(1);
    DDF s = in.addmember("sessions").list();
    for (vector<string>::const_iterator i = sessions.begin(); i!=sessions.end(); ++i) {
        DDF temp = DDF(NULL).string(i->c_str());
        s.add(temp);
    }
    out=application.getServiceProvider().getListenerService()->send(in);
    return (out.integer() == 1);
}

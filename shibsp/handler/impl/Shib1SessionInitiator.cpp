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
 * Shib1SessionInitiator.cpp
 * 
 * Shibboleth 1.x AuthnRequest support.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/RemotedHandler.h"
#include "handler/SessionInitiator.h"
#include "util/SPConstants.h"

#ifndef SHIBSP_LITE
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/EndpointManager.h>
#endif
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL Shib1SessionInitiator : public SessionInitiator, public AbstractHandler, public RemotedHandler
    {
    public:
        Shib1SessionInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.Shib1")), m_appId(appId) {
            // If Location isn't set, defer address registration until the setParent call.
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::Shib1SI";
                setAddress(address.c_str());
            }
        }
        virtual ~Shib1SessionInitiator() {}
        
        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

    private:
        pair<bool,long> doRequest(
            const Application& application,
            HTTPResponse& httpResponse,
            const char* entityID,
            const char* acsLocation,
            string& relayState
            ) const;
        string m_appId;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL Shib1SessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new Shib1SessionInitiator(p.first, p.second);
    }

};

void Shib1SessionInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::Shib1SI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in Shib1 SessionInitiator (or parent), can't register as remoted handler");
    }
}

pair<bool,long> Shib1SessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // We have to know the IdP to function.
    if (entityID.empty())
        return make_pair(false,0L);

    string target;
    const Handler* ACS=NULL;
    const char* option;
    const Application& app=request.getApplication();

    if (isHandler) {
        option=request.getParameter("acsIndex");
        if (option) {
            ACS = app.getAssertionConsumerServiceByIndex(atoi(option));
            if (!ACS)
                request.log(SPRequest::SPWarn, "invalid acsIndex specified in request, using default ACS location");
        }

        option = request.getParameter("target");
        if (option)
            target = option;

        // Since we're passing the ACS by value, we need to compute the return URL,
        // so we'll need the target resource for real.
        recoverRelayState(request.getApplication(), request, request, target, false);
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one and everything else is defaulted.
        target=request.getRequestURL();
    }

    // Since we're not passing by index, we need to fully compute the return URL.
    if (!ACS) {
        pair<bool,unsigned int> index = getUnsignedInt("defaultACSIndex");
        if (index.first) {
            ACS = app.getAssertionConsumerServiceByIndex(index.second);
            if (!ACS)
                request.log(SPRequest::SPWarn, "invalid defaultACSIndex, using default ACS location");
        }
        if (!ACS)
            ACS = app.getDefaultAssertionConsumerService();
    }

    // Compute the ACS URL. We add the ACS location to the base handlerURL.
    string ACSloc=request.getHandlerURL(target.c_str());
    pair<bool,const char*> loc=ACS ? ACS->getString("Location") : pair<bool,const char*>(false,NULL);
    if (loc.first) ACSloc+=loc.second;

    if (isHandler) {
        // We may already have RelayState set if we looped back here,
        // but just in case target is a resource, we reset it back.
        target.erase();
        option = request.getParameter("target");
        if (option)
            target = option;
    }

    m_log.debug("attempting to initiate session using Shibboleth with provider (%s)", entityID.c_str());

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess))
        return doRequest(app, request, entityID.c_str(), ACSloc.c_str(), target);

    // Remote the call.
    DDF out,in = DDF(m_address.c_str()).structure();
    DDFJanitor jin(in), jout(out);
    in.addmember("application_id").string(app.getId());
    in.addmember("entity_id").string(entityID.c_str());
    in.addmember("acsLocation").string(ACSloc.c_str());
    if (!target.empty())
        in.addmember("RelayState").string(target.c_str());

    // Remote the processing.
    out = request.getServiceProvider().getListenerService()->send(in);
    return unwrap(request, out);
}

void Shib1SessionInitiator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) to generate AuthnRequest", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
    }

    const char* entityID = in["entity_id"].string();
    const char* acsLocation = in["acsLocation"].string();
    if (!entityID || !acsLocation)
        throw ConfigurationException("No entityID or acsLocation parameter supplied to remoted SessionInitiator.");

    DDF ret(NULL);
    DDFJanitor jout(ret);

    // Wrap the outgoing object with a Response facade.
    auto_ptr<HTTPResponse> http(getResponse(ret));

    string relayState(in["RelayState"].string() ? in["RelayState"].string() : "");

    // Since we're remoted, the result should either be a throw, which we pass on,
    // a false/0 return, which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    doRequest(*app, *http.get(), entityID, acsLocation, relayState);
    out << ret;
}

pair<bool,long> Shib1SessionInitiator::doRequest(
    const Application& app,
    HTTPResponse& httpResponse,
    const char* entityID,
    const char* acsLocation,
    string& relayState
    ) const
{
#ifndef SHIBSP_LITE
    // Use metadata to invoke the SSO service directly.
    MetadataProvider* m=app.getMetadataProvider();
    Locker locker(m);
    MetadataProvider::Criteria mc(entityID, &IDPSSODescriptor::ELEMENT_QNAME, shibspconstants::SHIB1_PROTOCOL_ENUM);
    pair<const EntityDescriptor*,const RoleDescriptor*> entity = m->getEntityDescriptor(mc);
    if (!entity.first) {
        m_log.warn("unable to locate metadata for provider (%s)", entityID);
        throw MetadataException("Unable to locate metadata for identity provider ($entityID)", namedparams(1, "entityID", entityID));
    }
    else if (!entity.second) {
        m_log.warn("unable to locate Shibboleth-aware identity provider role for provider (%s)", entityID);
        if (getParent())
            return make_pair(false,0L);
        throw MetadataException("Unable to locate Shibboleth-aware identity provider role for provider ($entityID)", namedparams(1, "entityID", entityID));
    }
    const EndpointType* ep=EndpointManager<SingleSignOnService>(
        dynamic_cast<const IDPSSODescriptor*>(entity.second)->getSingleSignOnServices()
        ).getByBinding(shibspconstants::SHIB1_AUTHNREQUEST_PROFILE_URI);
    if (!ep) {
        m_log.warn("unable to locate compatible SSO service for provider (%s)", entityID);
        if (getParent())
            return make_pair(false,0L);
        throw MetadataException("Unable to locate compatible SSO service for provider ($entityID)", namedparams(1, "entityID", entityID));
    }

    preserveRelayState(app, httpResponse, relayState);

    // Shib 1.x requires a target value.
    if (relayState.empty())
        relayState = "default";

    char timebuf[16];
    sprintf(timebuf,"%lu",time(NULL));
    const URLEncoder* urlenc = XMLToolingConfig::getConfig().getURLEncoder();
    auto_ptr_char dest(ep->getLocation());
    string req=string(dest.get()) + (strchr(dest.get(),'?') ? '&' : '?') + "shire=" + urlenc->encode(acsLocation) +
        "&time=" + timebuf + "&target=" + urlenc->encode(relayState.c_str()) +
        "&providerId=" + urlenc->encode(app.getRelyingParty(entity.first)->getString("entityID").second);

    return make_pair(true, httpResponse.sendRedirect(req.c_str()));
#else
    return make_pair(false,0L);
#endif
}

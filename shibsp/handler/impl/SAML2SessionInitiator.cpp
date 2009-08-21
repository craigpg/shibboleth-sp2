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
 * SAML2SessionInitiator.cpp
 *
 * SAML 2.0 AuthnRequest support.
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
# include "metadata/MetadataProviderCriteria.h"
# include <saml/SAMLConfig.h>
# include <saml/saml2/core/Protocols.h>
# include <saml/saml2/metadata/EndpointManager.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataCredentialCriteria.h>
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
#else
#include <xercesc/util/XMLUniDefs.hpp>
#endif

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL SAML2SessionInitiator : public SessionInitiator, public AbstractHandler, public RemotedHandler
    {
    public:
        SAML2SessionInitiator(const DOMElement* e, const char* appId);
        virtual ~SAML2SessionInitiator() {
#ifndef SHIBSP_LITE
            if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
                XMLString::release(&m_outgoing);
                for_each(m_encoders.begin(), m_encoders.end(), cleanup_pair<const XMLCh*,MessageEncoder>());
                delete m_requestTemplate;
                delete m_ecp;
            }
#endif
        }

        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> unwrap(SPRequest& request, DDF& out) const;
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

    private:
        pair<bool,long> doRequest(
            const Application& application,
            const HTTPRequest* httpRequest,
            HTTPResponse& httpResponse,
            const char* entityID,
            const XMLCh* acsIndex,
            bool artifactInbound,
            const char* acsLocation,
            const XMLCh* acsBinding,
            bool isPassive,
            bool forceAuthn,
            const char* authnContextClassRef,
            const char* authnContextComparison,
            string& relayState
            ) const;

        string m_appId;
        auto_ptr_char m_paosNS,m_ecpNS;
        auto_ptr_XMLCh m_paosBinding;
#ifndef SHIBSP_LITE
        XMLCh* m_outgoing;
        vector<const XMLCh*> m_bindings;
        map<const XMLCh*,MessageEncoder*> m_encoders;
        MessageEncoder* m_ecp;
        AuthnRequest* m_requestTemplate;
#else
        bool m_ecp;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL SAML2SessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML2SessionInitiator(p.first, p.second);
    }

};

SAML2SessionInitiator::SAML2SessionInitiator(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.SAML2")), m_appId(appId),
        m_paosNS(samlconstants::PAOS_NS), m_ecpNS(samlconstants::SAML20ECP_NS), m_paosBinding(samlconstants::SAML20_BINDING_PAOS)
{
    static const XMLCh ECP[] = UNICODE_LITERAL_3(E,C,P);
    const XMLCh* flag = e ? e->getAttributeNS(NULL,ECP) : NULL;
#ifdef SHIBSP_LITE
    m_ecp = (flag && (*flag == chLatin_t || *flag == chDigit_1));
#else
    m_outgoing=NULL;
    m_ecp = NULL;
    m_requestTemplate=NULL;

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // Check for a template AuthnRequest to build from.
        DOMElement* child = XMLHelper::getFirstChildElement(e, samlconstants::SAML20P_NS, AuthnRequest::LOCAL_NAME);
        if (child)
            m_requestTemplate = dynamic_cast<AuthnRequest*>(AuthnRequestBuilder::buildOneFromElement(child));

        // If directed, build an ECP encoder.
        if (flag && (*flag == chLatin_t || *flag == chDigit_1)) {
            try {
                m_ecp = SAMLConfig::getConfig().MessageEncoderManager.newPlugin(
                    samlconstants::SAML20_BINDING_PAOS, pair<const DOMElement*,const XMLCh*>(e,NULL)
                    );
            }
            catch (exception& ex) {
                m_log.error("error building PAOS/ECP MessageEncoder: %s", ex.what());
            }
        }

        // Handle outgoing binding setup.
        pair<bool,const XMLCh*> outgoing = getXMLString("outgoingBindings");
        if (outgoing.first) {
            m_outgoing = XMLString::replicate(outgoing.second);
            XMLString::trim(m_outgoing);
        }
        else {
            // No override, so we'll install a default binding precedence.
            string prec = string(samlconstants::SAML20_BINDING_HTTP_REDIRECT) + ' ' + samlconstants::SAML20_BINDING_HTTP_POST + ' ' +
                samlconstants::SAML20_BINDING_HTTP_POST_SIMPLESIGN + ' ' + samlconstants::SAML20_BINDING_HTTP_ARTIFACT;
            m_outgoing = XMLString::transcode(prec.c_str());
        }

        int pos;
        XMLCh* start = m_outgoing;
        while (start && *start) {
            pos = XMLString::indexOf(start,chSpace);
            if (pos != -1)
                *(start + pos)=chNull;
            m_bindings.push_back(start);
            try {
                auto_ptr_char b(start);
                MessageEncoder * encoder = SAMLConfig::getConfig().MessageEncoderManager.newPlugin(
                    b.get(),pair<const DOMElement*,const XMLCh*>(e,NULL)
                    );
                if (encoder->isUserAgentPresent()) {
                    m_encoders[start] = encoder;
                    m_log.debug("supporting outgoing binding (%s)", b.get());
                }
                else {
                    delete encoder;
                    m_log.warn("skipping outgoing binding (%s), not a front-channel mechanism", b.get());
                }
            }
            catch (exception& ex) {
                m_log.error("error building MessageEncoder: %s", ex.what());
            }
            if (pos != -1)
                start = start + pos + 1;
            else
                break;
        }
    }
#endif

    // If Location isn't set, defer address registration until the setParent call.
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::SAML2SI";
        setAddress(address.c_str());
    }
}

void SAML2SessionInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::SAML2SI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in SAML2 SessionInitiator (or parent), can't register as remoted handler");
    }
}

pair<bool,long> SAML2SessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // First check for ECP support, since that doesn't require an IdP to be known.
    bool ECP = false;
    if (m_ecp && request.getHeader("Accept").find("application/vnd.paos+xml") != string::npos) {
        string PAOS = request.getHeader("PAOS");
        if (PAOS.find(m_paosNS.get()) != string::npos && PAOS.find(m_ecpNS.get()) != string::npos)
            ECP = true;
    }

    // We have to know the IdP to function unless this is ECP.
    if (!ECP && (entityID.empty()))
        return make_pair(false,0L);

    string target;
    string postData;
    const Handler* ACS=NULL;
    const char* option;
    pair<bool,const char*> acClass;
    pair<bool,const char*> acComp;
    bool isPassive=false,forceAuthn=false;
    const Application& app=request.getApplication();

    // ECP means the ACS will be by value no matter what.
    pair<bool,bool> acsByIndex = ECP ? make_pair(true,false) : getBool("acsByIndex");

    if (isHandler) {
        option=request.getParameter("acsIndex");
        if (option) {
            ACS = app.getAssertionConsumerServiceByIndex(atoi(option));
            if (!ACS)
                request.log(SPRequest::SPWarn, "invalid acsIndex specified in request, using default ACS location");
            else if (ECP && !XMLString::equals(ACS->getString("Binding").second, samlconstants::SAML20_BINDING_PAOS)) {
                request.log(SPRequest::SPWarn, "acsIndex in request referenced a non-PAOS ACS, using default ACS location");
                ACS = NULL;
            }
        }

        option = request.getParameter("target");
        if (option)
            target = option;

        // Always need to recover target URL to compute handler below.
        recoverRelayState(request.getApplication(), request, request, target, false);

        pair<bool,bool> flag;
        option = request.getParameter("isPassive");
        if (option) {
            isPassive = (*option=='1' || *option=='t');
        }
        else {
            flag = getBool("isPassive");
            isPassive = (flag.first && flag.second);
        }
        if (!isPassive) {
            option = request.getParameter("forceAuthn");
            if (option) {
                forceAuthn = (*option=='1' || *option=='t');
            }
            else {
                flag = getBool("forceAuthn");
                forceAuthn = (flag.first && flag.second);
            }
        }

        if (acClass.second = request.getParameter("authnContextClassRef"))
            acClass.first = true;
        else
            acClass = getString("authnContextClassRef");

        if (acComp.second = request.getParameter("authnContextComparison"))
            acComp.first = true;
        else
            acComp = getString("authnContextComparison");
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one and everything else is defaulted.
        target=request.getRequestURL();
        const PropertySet* settings = request.getRequestSettings().first;

        pair<bool,bool> flag = settings->getBool("isPassive");
        if (!flag.first)
            flag = getBool("isPassive");
        isPassive = flag.first && flag.second;
        if (!isPassive) {
            flag = settings->getBool("forceAuthn");
            if (!flag.first)
                flag = getBool("forceAuthn");
            forceAuthn = flag.first && flag.second;
        }

        acClass = settings->getString("authnContextClassRef");
        if (!acClass.first)
            acClass = getString("authnContextClassRef");
        acComp = settings->getString("authnContextComparison");
        if (!acComp.first)
            acComp = getString("authnContextComparison");
    }

    if (ECP)
        m_log.debug("attempting to initiate session using SAML 2.0 Enhanced Client Profile");
    else
        m_log.debug("attempting to initiate session using SAML 2.0 with provider (%s)", entityID.c_str());

    if (!ACS) {
        if (ECP) {
            const vector<const Handler*>& handlers = app.getAssertionConsumerServicesByBinding(m_paosBinding.get());
            if (handlers.empty())
                throw ConfigurationException("Unable to locate PAOS response endpoint.");
            ACS = handlers.front();
        }
        else {
            pair<bool,unsigned int> index = getUnsignedInt("defaultACSIndex");
            if (index.first) {
                ACS = app.getAssertionConsumerServiceByIndex(index.second);
                if (!ACS)
                    request.log(SPRequest::SPWarn, "invalid defaultACSIndex, using default ACS location");
            }
            if (!ACS)
                ACS = app.getDefaultAssertionConsumerService();
        }
    }

    // Validate the ACS for use with this protocol.
    if (!ECP) {
        pair<bool,const char*> ACSbinding = ACS ? ACS->getString("Binding") : pair<bool,const char*>(false,NULL);
        if (ACSbinding.first) {
            pair<bool,const char*> compatibleBindings = getString("compatibleBindings");
            if (compatibleBindings.first && strstr(compatibleBindings.second, ACSbinding.second) == NULL) {
                m_log.info("configured or requested ACS has non-SAML 2.0 binding");
                return make_pair(false,0L);
            }
            else if (strcmp(ACSbinding.second, samlconstants::SAML20_BINDING_HTTP_POST) &&
                     strcmp(ACSbinding.second, samlconstants::SAML20_BINDING_HTTP_ARTIFACT) &&
                     strcmp(ACSbinding.second, samlconstants::SAML20_BINDING_HTTP_POST_SIMPLESIGN)) {
                m_log.info("configured or requested ACS has non-SAML 2.0 binding");
                return make_pair(false,0L);
            }
        }
    }

    // To invoke the request builder, the key requirement is to figure out how
    // to express the ACS, by index or value, and if by value, where.
    // We have to compute the handlerURL no matter what, because we may need to
    // flip the index to an SSL-version.
    string ACSloc=request.getHandlerURL(target.c_str());

    SPConfig& conf = SPConfig::getConfig();
    if (conf.isEnabled(SPConfig::OutOfProcess)) {
    	if (acsByIndex.first && acsByIndex.second) {
            // Pass by Index.
            if (isHandler) {
                // We may already have RelayState set if we looped back here,
                // but just in case target is a resource, we reset it back.
                target.erase();
                option = request.getParameter("target");
                if (option)
                    target = option;
            }

            // Determine index to use.
            pair<bool,const XMLCh*> ix = pair<bool,const XMLCh*>(false,NULL);
            if (ACS) {
            	if (!strncmp(ACSloc.c_str(), "https", 5)) {
            		ix = ACS->getXMLString("sslIndex", shibspconstants::ASCII_SHIB2SPCONFIG_NS);
            		if (!ix.first)
            			ix = ACS->getXMLString("index");
            	}
            	else {
            		ix = ACS->getXMLString("index");
            	}
            }

            return doRequest(
                app, &request, request, entityID.c_str(),
                ix.second,
                ACS ? XMLString::equals(ACS->getString("Binding").second, samlconstants::SAML20_BINDING_HTTP_ARTIFACT) : false,
                NULL, NULL,
                isPassive, forceAuthn,
                acClass.first ? acClass.second : NULL,
                acComp.first ? acComp.second : NULL,
                target
                );
        }

        // Since we're not passing by index, we need to fully compute the return URL and binding.
        // Compute the ACS URL. We add the ACS location to the base handlerURL.
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

        return doRequest(
            app, &request, request, entityID.c_str(),
            NULL,
            ACS ? XMLString::equals(ACS->getString("Binding").second, samlconstants::SAML20_BINDING_HTTP_ARTIFACT) : false,
            ACSloc.c_str(), ACS ? ACS->getXMLString("Binding").second : NULL,
            isPassive, forceAuthn,
            acClass.first ? acClass.second : NULL,
            acComp.first ? acComp.second : NULL,
            target
            );
    }

    // Remote the call.
    DDF out,in = DDF(m_address.c_str()).structure();
    DDFJanitor jin(in), jout(out);
    in.addmember("application_id").string(app.getId());
    if (!entityID.empty())
        in.addmember("entity_id").string(entityID.c_str());
    if (isPassive)
        in.addmember("isPassive").integer(1);
    else if (forceAuthn)
        in.addmember("forceAuthn").integer(1);
    if (acClass.first)
        in.addmember("authnContextClassRef").string(acClass.second);
    if (acComp.first)
        in.addmember("authnContextComparison").string(acComp.second);
    if (acsByIndex.first && acsByIndex.second) {
        if (ACS) {
            // Determine index to use.
            pair<bool,const char*> ix = pair<bool,const char*>(false,NULL);
        	if (!strncmp(ACSloc.c_str(), "https", 5)) {
        		ix = ACS->getString("sslIndex", shibspconstants::ASCII_SHIB2SPCONFIG_NS);
        		if (!ix.first)
        			ix = ACS->getString("index");
        	}
        	else {
        		ix = ACS->getString("index");
        	}
            in.addmember("acsIndex").string(ix.second);
            if (XMLString::equals(ACS->getString("Binding").second, samlconstants::SAML20_BINDING_HTTP_ARTIFACT))
                in.addmember("artifact").integer(1);
        }
    }
    else {
        // Since we're not passing by index, we need to fully compute the return URL and binding.
        // Compute the ACS URL. We add the ACS location to the base handlerURL.
        pair<bool,const char*> loc=ACS ? ACS->getString("Location") : pair<bool,const char*>(false,NULL);
        if (loc.first) ACSloc+=loc.second;
        in.addmember("acsLocation").string(ACSloc.c_str());
        if (ACS) {
            loc = ACS->getString("Binding");
            in.addmember("acsBinding").string(loc.second);
            if (XMLString::equals(loc.second, samlconstants::SAML20_BINDING_HTTP_ARTIFACT))
                in.addmember("artifact").integer(1);
        }
    }

    if (isHandler) {
        // We may already have RelayState set if we looped back here,
        // but just in case target is a resource, we reset it back.
        target.erase();
        option = request.getParameter("target");
        if (option)
            target = option;
    }
    if (!target.empty())
        in.addmember("RelayState").unsafe_string(target.c_str());

    // Remote the processing.
    out = request.getServiceProvider().getListenerService()->send(in);
    return unwrap(request, out);
}

pair<bool,long> SAML2SessionInitiator::unwrap(SPRequest& request, DDF& out) const
{
    // See if there's any response to send back.
    if (!out["redirect"].isnull() || !out["response"].isnull()) {
        // If so, we're responsible for handling the POST data, probably by dropping a cookie.
        preservePostData(request.getApplication(), request, request, out["RelayState"].string());
    }
    return RemotedHandler::unwrap(request, out);
}

void SAML2SessionInitiator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) to generate AuthnRequest", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
    }

    DDF ret(NULL);
    DDFJanitor jout(ret);

    // Wrap the outgoing object with a Response facade.
    auto_ptr<HTTPResponse> http(getResponse(ret));

    auto_ptr_XMLCh index(in["acsIndex"].string());
    auto_ptr_XMLCh bind(in["acsBinding"].string());

    string relayState(in["RelayState"].string() ? in["RelayState"].string() : "");
    string postData(in["PostData"].string() ? in["PostData"].string() : "");

    // Since we're remoted, the result should either be a throw, which we pass on,
    // a false/0 return, which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    doRequest(
        *app, NULL, *http.get(), in["entity_id"].string(),
        index.get(),
        (in["artifact"].integer() != 0),
        in["acsLocation"].string(), bind.get(),
        in["isPassive"].integer()==1, in["forceAuthn"].integer()==1,
        in["authnContextClassRef"].string(), in["authnContextComparison"].string(),
        relayState
        );
    if (!ret.isstruct())
        ret.structure();
    ret.addmember("RelayState").unsafe_string(relayState.c_str());
    out << ret;
}

#ifndef SHIBSP_LITE
namespace {
    class _sameIdP : public binary_function<const IDPEntry*, const XMLCh*, bool>
    {
    public:
        bool operator()(const IDPEntry* entry, const XMLCh* entityID) const {
            return entry ? XMLString::equals(entry->getProviderID(), entityID) : false;
        }
    };
};
#endif

pair<bool,long> SAML2SessionInitiator::doRequest(
    const Application& app,
    const HTTPRequest* httpRequest,
    HTTPResponse& httpResponse,
    const char* entityID,
    const XMLCh* acsIndex,
    bool artifactInbound,
    const char* acsLocation,
    const XMLCh* acsBinding,
    bool isPassive,
    bool forceAuthn,
    const char* authnContextClassRef,
    const char* authnContextComparison,
    string& relayState
    ) const
{
#ifndef SHIBSP_LITE
    bool ECP = XMLString::equals(acsBinding, m_paosBinding.get());

    pair<const EntityDescriptor*,const RoleDescriptor*> entity = pair<const EntityDescriptor*,const RoleDescriptor*>(NULL,NULL);
    const IDPSSODescriptor* role = NULL;
    const EndpointType* ep = NULL;
    const MessageEncoder* encoder = NULL;

    // We won't need this for ECP, but safety dictates we get the lock here.
    MetadataProvider* m=app.getMetadataProvider();
    Locker locker(m);

    if (ECP) {
        encoder = m_ecp;
        if (!encoder) {
            m_log.error("MessageEncoder for PAOS binding not available");
            return make_pair(false,0L);
        }
    }
    else {
        // Use metadata to locate the IdP's SSO service.
        MetadataProviderCriteria mc(app, entityID, &IDPSSODescriptor::ELEMENT_QNAME, samlconstants::SAML20P_NS);
        entity=m->getEntityDescriptor(mc);
        if (!entity.first) {
            m_log.warn("unable to locate metadata for provider (%s)", entityID);
            throw MetadataException("Unable to locate metadata for identity provider ($entityID)", namedparams(1, "entityID", entityID));
        }
        else if (!entity.second) {
            m_log.log(getParent() ? Priority::INFO : Priority::WARN, "unable to locate SAML 2.0 identity provider role for provider (%s)", entityID);
            if (getParent())
                return make_pair(false,0L);
            throw MetadataException("Unable to locate SAML 2.0 identity provider role for provider ($entityID)", namedparams(1, "entityID", entityID));
        }
        else if (artifactInbound && !SPConfig::getConfig().getArtifactResolver()->isSupported(dynamic_cast<const SSODescriptorType&>(*entity.second))) {
            m_log.warn("artifact binding selected for response, but identity provider lacks support");
            if (getParent())
                return make_pair(false,0L);
            throw MetadataException("Identity provider ($entityID) lacks SAML 2.0 artifact support.", namedparams(1, "entityID", entityID));
        }

        // Loop over the supportable outgoing bindings.
        role = dynamic_cast<const IDPSSODescriptor*>(entity.second);
        vector<const XMLCh*>::const_iterator b;
        for (b = m_bindings.begin(); b!=m_bindings.end(); ++b) {
            if (ep=EndpointManager<SingleSignOnService>(role->getSingleSignOnServices()).getByBinding(*b)) {
                map<const XMLCh*,MessageEncoder*>::const_iterator enc = m_encoders.find(*b);
                if (enc!=m_encoders.end())
                    encoder = enc->second;
                break;
            }
        }
        if (!ep || !encoder) {
            m_log.warn("unable to locate compatible SSO service for provider (%s)", entityID);
            if (getParent())
                return make_pair(false,0L);
            throw MetadataException("Unable to locate compatible SSO service for provider ($entityID)", namedparams(1, "entityID", entityID));
        }
    }

    preserveRelayState(app, httpResponse, relayState);

    auto_ptr<AuthnRequest> req(m_requestTemplate ? m_requestTemplate->cloneAuthnRequest() : AuthnRequestBuilder::buildAuthnRequest());
    if (m_requestTemplate) {
        // Freshen TS and ID.
        req->setID(NULL);
        req->setIssueInstant(time(NULL));
    }

    if (ep)
        req->setDestination(ep->getLocation());
    if (acsIndex && *acsIndex)
        req->setAssertionConsumerServiceIndex(acsIndex);
    if (acsLocation) {
        auto_ptr_XMLCh wideloc(acsLocation);
        req->setAssertionConsumerServiceURL(wideloc.get());
    }
    if (acsBinding && *acsBinding)
        req->setProtocolBinding(acsBinding);
    if (isPassive)
        req->IsPassive(isPassive);
    else if (forceAuthn)
        req->ForceAuthn(forceAuthn);
    if (!req->getIssuer()) {
        Issuer* issuer = IssuerBuilder::buildIssuer();
        req->setIssuer(issuer);
        issuer->setName(app.getRelyingParty(entity.first)->getXMLString("entityID").second);
    }
    if (!req->getNameIDPolicy()) {
        NameIDPolicy* namepol = NameIDPolicyBuilder::buildNameIDPolicy();
        req->setNameIDPolicy(namepol);
        namepol->AllowCreate(true);
    }
    if (authnContextClassRef || authnContextComparison) {
        RequestedAuthnContext* reqContext = req->getRequestedAuthnContext();
        if (!reqContext) {
            reqContext = RequestedAuthnContextBuilder::buildRequestedAuthnContext();
            req->setRequestedAuthnContext(reqContext);
        }
        if (authnContextClassRef) {
            reqContext->getAuthnContextDeclRefs().clear();
            auto_ptr_XMLCh wideclass(authnContextClassRef);
            AuthnContextClassRef* cref = AuthnContextClassRefBuilder::buildAuthnContextClassRef();
            cref->setReference(wideclass.get());
            reqContext->getAuthnContextClassRefs().push_back(cref);
        }

        if (reqContext->getAuthnContextClassRefs().empty() && reqContext->getAuthnContextDeclRefs().empty()) {
        	req->setRequestedAuthnContext(NULL);
        }
        else if (authnContextComparison) {
            auto_ptr_XMLCh widecomp(authnContextComparison);
            reqContext->setComparison(widecomp.get());
        }
    }

    pair<bool,bool> requestDelegation = getBool("requestDelegation");
    if (requestDelegation.first && requestDelegation.second && entity.first) {
        // Request delegation by including the IdP as an Audience.
        // Also specify the expected session lifetime as the bound on the assertion lifetime.
        const PropertySet* sessionProps = app.getPropertySet("Sessions");
        pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
        if (!lifetime.first || lifetime.second == 0)
            lifetime.second = 28800;
        if (!req->getConditions())
            req->setConditions(ConditionsBuilder::buildConditions());
        req->getConditions()->setNotOnOrAfter(time(NULL) + lifetime.second + 300);
        AudienceRestriction* audrest = AudienceRestrictionBuilder::buildAudienceRestriction();
        req->getConditions()->getConditions().push_back(audrest);
        Audience* aud = AudienceBuilder::buildAudience();
        audrest->getAudiences().push_back(aud);
        aud->setAudienceURI(entity.first->getEntityID());
    }

    if (ECP && entityID) {
        auto_ptr_XMLCh wideid(entityID);
        Scoping* scoping = req->getScoping();
        if (!scoping) {
            scoping = ScopingBuilder::buildScoping();
            req->setScoping(scoping);
        }
        IDPList* idplist = scoping->getIDPList();
        if (!idplist) {
            idplist = IDPListBuilder::buildIDPList();
            scoping->setIDPList(idplist);
        }
        VectorOf(IDPEntry) entries = idplist->getIDPEntrys();
        if (find_if(entries, bind2nd(_sameIdP(), wideid.get())) == NULL) {
            IDPEntry* entry = IDPEntryBuilder::buildIDPEntry();
            entry->setProviderID(wideid.get());
            entries.push_back(entry);
        }
    }

    auto_ptr_char dest(ep ? ep->getLocation() : NULL);

    if (httpRequest) {
        // If the request object is available, we're responsible for the POST data.
        preservePostData(app, *httpRequest, httpResponse, relayState.c_str());
    }

    long ret = sendMessage(
        *encoder, req.get(), relayState.c_str(), dest.get(), role, app, httpResponse, role ? role->WantAuthnRequestsSigned() : false
        );
    req.release();  // freed by encoder
    return make_pair(true,ret);
#else
    return make_pair(false,0L);
#endif
}

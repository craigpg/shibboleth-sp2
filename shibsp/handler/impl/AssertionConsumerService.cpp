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
 * AssertionConsumerService.cpp
 *
 * Base class for handlers that create sessions by consuming SSO protocol responses.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "handler/AssertionConsumerService.h"
#include "util/SPConstants.h"

# include <ctime>
#ifndef SHIBSP_LITE
# include "attribute/Attribute.h"
# include "attribute/filtering/AttributeFilter.h"
# include "attribute/filtering/BasicFilteringContext.h"
# include "attribute/resolver/AttributeExtractor.h"
# include "attribute/resolver/AttributeResolver.h"
# include "attribute/resolver/ResolutionContext.h"
# include "metadata/MetadataProviderCriteria.h"
# include "security/SecurityPolicy.h"
# include <saml/SAMLConfig.h>
# include <saml/saml1/core/Assertions.h>
# include <saml/util/CommonDomainCookie.h>
using namespace samlconstants;
using opensaml::saml2md::MetadataProvider;
using opensaml::saml2md::RoleDescriptor;
using opensaml::saml2md::EntityDescriptor;
using opensaml::saml2md::IDPSSODescriptor;
using opensaml::saml2md::SPSSODescriptor;
#else
# include "lite/CommonDomainCookie.h"
#endif

using namespace shibspconstants;
using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

AssertionConsumerService::AssertionConsumerService(const DOMElement* e, const char* appId, Category& log)
    : AbstractHandler(e, log)
#ifndef SHIBSP_LITE
        ,m_decoder(NULL), m_role(samlconstants::SAML20MD_NS, opensaml::saml2md::IDPSSODescriptor::LOCAL_NAME)
#endif
{
    if (!e)
        return;
    string address(appId);
    address += getString("Location").second;
    setAddress(address.c_str());
#ifndef SHIBSP_LITE
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        m_decoder = SAMLConfig::getConfig().MessageDecoderManager.newPlugin(
            getString("Binding").second, pair<const DOMElement*,const XMLCh*>(e,shibspconstants::SHIB2SPCONFIG_NS)
            );
        m_decoder->setArtifactResolver(SPConfig::getConfig().getArtifactResolver());
    }
#endif
}

AssertionConsumerService::~AssertionConsumerService()
{
#ifndef SHIBSP_LITE
    delete m_decoder;
#endif
}

pair<bool,long> AssertionConsumerService::run(SPRequest& request, bool isHandler) const
{
    string relayState;
    SPConfig& conf = SPConfig::getConfig();

    if (conf.isEnabled(SPConfig::OutOfProcess)) {
        // When out of process, we run natively and directly process the message.
        return processMessage(request.getApplication(), request, request);
    }
    else {
        // When not out of process, we remote all the message processing.
        vector<string> headers(1, "Cookie");
        DDF out,in = wrap(request, &headers);
        DDFJanitor jin(in), jout(out);
        out=request.getServiceProvider().getListenerService()->send(in);
        return unwrap(request, out);
    }
}

void AssertionConsumerService::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for new session", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
    }

    // Unpack the request.
    auto_ptr<HTTPRequest> req(getRequest(in));

    // Wrap a response shim.
    DDF ret(NULL);
    DDFJanitor jout(ret);
    auto_ptr<HTTPResponse> resp(getResponse(ret));

    // Since we're remoted, the result should either be a throw, a false/0 return,
    // which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    processMessage(*app, *req.get(), *resp.get());
    out << ret;
}

pair<bool,long> AssertionConsumerService::processMessage(
    const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse
    ) const
{
#ifndef SHIBSP_LITE
    // Locate policy key.
    pair<bool,const char*> policyId = getString("policyId", m_configNS.get());  // namespace-qualified if inside handler element
    if (!policyId.first)
        policyId = application.getString("policyId");   // unqualified in Application(s) element

    // Access policy properties.
    const PropertySet* settings = application.getServiceProvider().getPolicySettings(policyId.second);
    pair<bool,bool> validate = settings->getBool("validate");

    // Lock metadata for use by policy.
    Locker metadataLocker(application.getMetadataProvider());

    // Create the policy.
    auto_ptr<opensaml::SecurityPolicy> policy(
        createSecurityPolicy(application, &m_role, validate.first && validate.second, policyId.second)
        );

    string relayState;
    try {
        // Decode the message and process it in a protocol-specific way.
        auto_ptr<XMLObject> msg(m_decoder->decode(relayState, httpRequest, *(policy.get())));
        if (!msg.get())
            throw BindingException("Failed to decode an SSO protocol response.");
        DDF postData = recoverPostData(application, httpRequest, httpResponse, relayState.c_str());
        DDFJanitor postjan(postData);
        recoverRelayState(application, httpRequest, httpResponse, relayState);
        implementProtocol(application, httpRequest, httpResponse, *(policy.get()), settings, *msg.get());

        auto_ptr_char issuer(policy->getIssuer() ? policy->getIssuer()->getName() : NULL);

        // History cookie.
        if (issuer.get() && *issuer.get())
            maintainHistory(application, httpRequest, httpResponse, issuer.get());

        // Now redirect to the state value. By now, it should be set to *something* usable.
        // First check for POST data.
        if (!postData.islist()) {
            m_log.debug("ACS returning via redirect to: %s", relayState.c_str());
            return make_pair(true, httpResponse.sendRedirect(relayState.c_str()));
        }
        else {
            m_log.debug("ACS returning via POST to: %s", relayState.c_str());
            return make_pair(true, sendPostResponse(application, httpResponse, relayState.c_str(), postData));
        }
    }
    catch (XMLToolingException& ex) {
        // Check for isPassive error condition.
        const char* sc2 = ex.getProperty("statusCode2");
        if (sc2 && !strcmp(sc2, "urn:oasis:names:tc:SAML:2.0:status:NoPassive")) {
            validate = getBool("ignoreNoPassive", m_configNS.get());  // namespace-qualified if inside handler element
            if (validate.first && validate.second && !relayState.empty()) {
                m_log.debug("ignoring SAML status of NoPassive and redirecting to resource...");
                return make_pair(true, httpResponse.sendRedirect(relayState.c_str()));
            }
        }
        if (!relayState.empty())
            ex.addProperty("RelayState", relayState.c_str());
        throw;
    }
#else
    throw ConfigurationException("Cannot process message using lite version of shibsp library.");
#endif
}

void AssertionConsumerService::checkAddress(const Application& application, const HTTPRequest& httpRequest, const char* issuedTo) const
{
    if (!issuedTo || !*issuedTo)
        return;

    const PropertySet* props=application.getPropertySet("Sessions");
    pair<bool,bool> checkAddress = props ? props->getBool("checkAddress") : make_pair(false,true);
    if (!checkAddress.first)
        checkAddress.second=true;

    if (checkAddress.second) {
        m_log.debug("checking client address");
        if (httpRequest.getRemoteAddr() != issuedTo) {
            throw FatalProfileException(
               "Your client's current address ($client_addr) differs from the one used when you authenticated "
                "to your identity provider. To correct this problem, you may need to bypass a proxy server. "
                "Please contact your local support staff or help desk for assistance.",
                namedparams(1,"client_addr",httpRequest.getRemoteAddr().c_str())
                );
        }
    }
}

#ifndef SHIBSP_LITE

void AssertionConsumerService::generateMetadata(SPSSODescriptor& role, const char* handlerURL) const
{
    const char* loc = getString("Location").second;
    string hurl(handlerURL);
    if (*loc != '/')
        hurl += '/';
    hurl += loc;
    auto_ptr_XMLCh widen(hurl.c_str());
    saml2md::AssertionConsumerService* ep = saml2md::AssertionConsumerServiceBuilder::buildAssertionConsumerService();
    ep->setLocation(widen.get());
    ep->setBinding(getXMLString("Binding").second);
    if (!strncmp(handlerURL, "https", 5)) {
    	pair<bool,const XMLCh*> index = getXMLString("sslIndex", shibspconstants::ASCII_SHIB2SPCONFIG_NS);
    	if (index.first)
    		ep->setIndex(index.second);
    	else
    		ep->setIndex(getXMLString("index").second);
    }
    else {
    	ep->setIndex(getXMLString("index").second);
    }
    role.getAssertionConsumerServices().push_back(ep);
}

opensaml::SecurityPolicy* AssertionConsumerService::createSecurityPolicy(
    const Application& application, const xmltooling::QName* role, bool validate, const char* policyId
    ) const
{
    return new SecurityPolicy(application, role, validate, policyId);
}

class SHIBSP_DLLLOCAL DummyContext : public ResolutionContext
{
public:
    DummyContext(const vector<Attribute*>& attributes) : m_attributes(attributes) {
    }

    virtual ~DummyContext() {
        for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
    }

    vector<Attribute*>& getResolvedAttributes() {
        return m_attributes;
    }
    vector<Assertion*>& getResolvedAssertions() {
        return m_tokens;
    }

private:
    vector<Attribute*> m_attributes;
    static vector<Assertion*> m_tokens; // never any tokens, so just share an empty vector
};

vector<Assertion*> DummyContext::m_tokens;

ResolutionContext* AssertionConsumerService::resolveAttributes(
    const Application& application,
    const saml2md::RoleDescriptor* issuer,
    const XMLCh* protocol,
    const saml1::NameIdentifier* v1nameid,
    const saml2::NameID* nameid,
    const XMLCh* authncontext_class,
    const XMLCh* authncontext_decl,
    const vector<const Assertion*>* tokens
    ) const
{
    // First we do the extraction of any pushed information, including from metadata.
    vector<Attribute*> resolvedAttributes;
    AttributeExtractor* extractor = application.getAttributeExtractor();
    if (extractor) {
        Locker extlocker(extractor);
        if (issuer) {
            pair<bool,const char*> mprefix = application.getString("metadataAttributePrefix");
            if (mprefix.first) {
                m_log.debug("extracting metadata-derived attributes...");
                try {
                    // We pass NULL for "issuer" because the IdP isn't the one asserting metadata-based attributes.
                    extractor->extractAttributes(application, NULL, *issuer, resolvedAttributes);
                    for (vector<Attribute*>::iterator a = resolvedAttributes.begin(); a != resolvedAttributes.end(); ++a) {
                        vector<string>& ids = (*a)->getAliases();
                        for (vector<string>::iterator id = ids.begin(); id != ids.end(); ++id)
                            *id = mprefix.second + *id;
                    }
                }
                catch (exception& ex) {
                    m_log.error("caught exception extracting attributes: %s", ex.what());
                }
            }
        }
        m_log.debug("extracting pushed attributes...");
        if (v1nameid) {
            try {
                extractor->extractAttributes(application, issuer, *v1nameid, resolvedAttributes);
            }
            catch (exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }
        else if (nameid) {
            try {
                extractor->extractAttributes(application, issuer, *nameid, resolvedAttributes);
            }
            catch (exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }
        if (tokens) {
            for (vector<const Assertion*>::const_iterator t = tokens->begin(); t!=tokens->end(); ++t) {
                try {
                    extractor->extractAttributes(application, issuer, *(*t), resolvedAttributes);
                }
                catch (exception& ex) {
                    m_log.error("caught exception extracting attributes: %s", ex.what());
                }
            }
        }

        AttributeFilter* filter = application.getAttributeFilter();
        if (filter && !resolvedAttributes.empty()) {
            BasicFilteringContext fc(application, resolvedAttributes, issuer, authncontext_class);
            Locker filtlocker(filter);
            try {
                filter->filterAttributes(fc, resolvedAttributes);
            }
            catch (exception& ex) {
                m_log.error("caught exception filtering attributes: %s", ex.what());
                m_log.error("dumping extracted attributes due to filtering exception");
                for_each(resolvedAttributes.begin(), resolvedAttributes.end(), xmltooling::cleanup<shibsp::Attribute>());
                resolvedAttributes.clear();
            }
        }
    }

    try {
        AttributeResolver* resolver = application.getAttributeResolver();
        if (resolver) {
            m_log.debug("resolving attributes...");

            Locker locker(resolver);
            auto_ptr<ResolutionContext> ctx(
                resolver->createResolutionContext(
                    application,
                    issuer ? dynamic_cast<const saml2md::EntityDescriptor*>(issuer->getParent()) : NULL,
                    protocol,
                    nameid,
                    authncontext_class,
                    authncontext_decl,
                    tokens,
                    &resolvedAttributes
                    )
                );
            resolver->resolveAttributes(*ctx.get());
            // Copy over any pushed attributes.
            if (!resolvedAttributes.empty())
                ctx->getResolvedAttributes().insert(ctx->getResolvedAttributes().end(), resolvedAttributes.begin(), resolvedAttributes.end());
            return ctx.release();
        }
    }
    catch (exception& ex) {
        m_log.error("attribute resolution failed: %s", ex.what());
    }

    if (!resolvedAttributes.empty())
        return new DummyContext(resolvedAttributes);
    return NULL;
}

void AssertionConsumerService::extractMessageDetails(const Assertion& assertion, const XMLCh* protocol, opensaml::SecurityPolicy& policy) const
{
    policy.setMessageID(assertion.getID());
    policy.setIssueInstant(assertion.getIssueInstantEpoch());

    if (XMLString::equals(assertion.getElementQName().getNamespaceURI(), samlconstants::SAML20_NS)) {
        const saml2::Assertion* a2 = dynamic_cast<const saml2::Assertion*>(&assertion);
        if (a2) {
            m_log.debug("extracting issuer from SAML 2.0 assertion");
            policy.setIssuer(a2->getIssuer());
        }
    }
    else {
        const saml1::Assertion* a1 = dynamic_cast<const saml1::Assertion*>(&assertion);
        if (a1) {
            m_log.debug("extracting issuer from SAML 1.x assertion");
            policy.setIssuer(a1->getIssuer());
        }
    }

    if (policy.getIssuer() && !policy.getIssuerMetadata() && policy.getMetadataProvider()) {
        if (policy.getIssuer()->getFormat() && !XMLString::equals(policy.getIssuer()->getFormat(), saml2::NameIDType::ENTITY)) {
            m_log.warn("non-system entity issuer, skipping metadata lookup");
            return;
        }
        m_log.debug("searching metadata for assertion issuer...");
        pair<const EntityDescriptor*,const RoleDescriptor*> entity;
        MetadataProvider::Criteria& mc = policy.getMetadataProviderCriteria();
        mc.entityID_unicode = policy.getIssuer()->getName();
        mc.role = &IDPSSODescriptor::ELEMENT_QNAME;
        mc.protocol = protocol;
        entity = policy.getMetadataProvider()->getEntityDescriptor(mc);
        if (!entity.first) {
            auto_ptr_char iname(policy.getIssuer()->getName());
            m_log.warn("no metadata found, can't establish identity of issuer (%s)", iname.get());
        }
        else if (!entity.second) {
            m_log.warn("unable to find compatible IdP role in metadata");
        }
        else {
            policy.setIssuerMetadata(entity.second);
        }
    }
}

#endif

void AssertionConsumerService::maintainHistory(
    const Application& application, const HTTPRequest& request, HTTPResponse& response, const char* entityID
    ) const
{
    static const char* defProps="; path=/";

    const PropertySet* sessionProps=application.getPropertySet("Sessions");
    pair<bool,bool> idpHistory=sessionProps->getBool("idpHistory");

    if (idpHistory.first && idpHistory.second) {
        pair<bool,const char*> cookieProps=sessionProps->getString("cookieProps");
        if (!cookieProps.first)
            cookieProps.second=defProps;

        // Set an IdP history cookie locally (essentially just a CDC).
        CommonDomainCookie cdc(request.getCookie(CommonDomainCookie::CDCName));

        // Either leave in memory or set an expiration.
        pair<bool,unsigned int> days=sessionProps->getUnsignedInt("idpHistoryDays");
        if (!days.first || days.second==0) {
            string c = string(cdc.set(entityID)) + cookieProps.second;
            response.setCookie(CommonDomainCookie::CDCName, c.c_str());
        }
        else {
            time_t now=time(NULL) + (days.second * 24 * 60 * 60);
#ifdef HAVE_GMTIME_R
            struct tm res;
            struct tm* ptime=gmtime_r(&now,&res);
#else
            struct tm* ptime=gmtime(&now);
#endif
            char timebuf[64];
            strftime(timebuf,64,"%a, %d %b %Y %H:%M:%S GMT",ptime);
            string c = string(cdc.set(entityID)) + cookieProps.second + "; expires=" + timebuf;
            response.setCookie(CommonDomainCookie::CDCName, c.c_str());
        }
    }
}

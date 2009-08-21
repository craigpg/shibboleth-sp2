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
 * adfs.cpp
 *
 * ADFSv1 extension library
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
# define ADFS_EXPORTS __declspec(dllexport)
#else
# define ADFS_EXPORTS
#endif

#include <memory>

#include <shibsp/base.h>
#include <shibsp/exceptions.h>
#include <shibsp/Application.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/SessionCache.h>
#include <shibsp/SPConfig.h>
#include <shibsp/handler/AssertionConsumerService.h>
#include <shibsp/handler/LogoutHandler.h>
#include <shibsp/handler/SessionInitiator.h>
#include <xmltooling/logging.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

#ifndef SHIBSP_LITE
# include <shibsp/attribute/resolver/ResolutionContext.h>
# include <shibsp/metadata/MetadataProviderCriteria.h>
# include <saml/SAMLConfig.h>
# include <saml/saml1/core/Assertions.h>
# include <saml/saml1/profile/AssertionValidator.h>
# include <saml/saml2/core/Assertions.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/EndpointManager.h>
# include <saml/saml2/profile/AssertionValidator.h>
# include <xmltooling/impl/AnyElement.h>
# include <xmltooling/validation/ValidatorSuite.h>
using namespace opensaml::saml2md;
# ifndef min
#  define min(a,b)            (((a) < (b)) ? (a) : (b))
# endif
#endif
using namespace shibsp;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

#define WSFED_NS "http://schemas.xmlsoap.org/ws/2003/07/secext"
#define WSTRUST_NS "http://schemas.xmlsoap.org/ws/2005/02/trust"

namespace {

#ifndef SHIBSP_LITE
    class SHIBSP_DLLLOCAL ADFSDecoder : public MessageDecoder
    {
        auto_ptr_XMLCh m_ns;
    public:
        ADFSDecoder() : m_ns(WSTRUST_NS) {}
        virtual ~ADFSDecoder() {}

        XMLObject* decode(string& relayState, const GenericRequest& genericRequest, SecurityPolicy& policy) const;

    protected:
        void extractMessageDetails(
            const XMLObject& message, const GenericRequest& req, const XMLCh* protocol, SecurityPolicy& policy
            ) const {
        }
    };

    MessageDecoder* ADFSDecoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
    {
        return new ADFSDecoder();
    }
#endif

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL ADFSSessionInitiator : public SessionInitiator, public AbstractHandler, public RemotedHandler
    {
    public:
        ADFSSessionInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.ADFS")), m_appId(appId), m_binding(WSFED_NS) {
            // If Location isn't set, defer address registration until the setParent call.
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::ADFSSI";
                setAddress(address.c_str());
            }
        }
        virtual ~ADFSSessionInitiator() {}

        void setParent(const PropertySet* parent) {
            DOMPropertySet::setParent(parent);
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::ADFSSI";
                setAddress(address.c_str());
            }
            else {
                m_log.warn("no Location property in ADFS SessionInitiator (or parent), can't register as remoted handler");
            }
        }

        void receive(DDF& in, ostream& out);
        pair<bool,long> unwrap(SPRequest& request, DDF& out) const;
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

    private:
        pair<bool,long> doRequest(
            const Application& application,
            const HTTPRequest* httpRequest,
            HTTPResponse& httpResponse,
            const char* entityID,
            const char* acsLocation,
            const char* authnContextClassRef,
            string& relayState
            ) const;
        string m_appId;
        auto_ptr_XMLCh m_binding;
    };

    class SHIBSP_DLLLOCAL ADFSConsumer : public shibsp::AssertionConsumerService
    {
    public:
        ADFSConsumer(const DOMElement* e, const char* appId)
            : shibsp::AssertionConsumerService(e, appId, Category::getInstance(SHIBSP_LOGCAT".SSO.ADFS"))
#ifndef SHIBSP_LITE
                ,m_protocol(WSFED_NS)
#endif
            {}
        virtual ~ADFSConsumer() {}

#ifndef SHIBSP_LITE
        void generateMetadata(SPSSODescriptor& role, const char* handlerURL) const {
            AssertionConsumerService::generateMetadata(role, handlerURL);
            role.addSupport(m_protocol.get());
        }

        auto_ptr_XMLCh m_protocol;

    private:
        void implementProtocol(
            const Application& application,
            const HTTPRequest& httpRequest,
            HTTPResponse& httpResponse,
            SecurityPolicy& policy,
            const PropertySet* settings,
            const XMLObject& xmlObject
            ) const;
#endif
    };

    class SHIBSP_DLLLOCAL ADFSLogoutInitiator : public AbstractHandler, public LogoutHandler
    {
    public:
        ADFSLogoutInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".LogoutInitiator.ADFS")), m_appId(appId), m_binding(WSFED_NS) {
            // If Location isn't set, defer address registration until the setParent call.
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::ADFSLI";
                setAddress(address.c_str());
            }
        }
        virtual ~ADFSLogoutInitiator() {}

        void setParent(const PropertySet* parent) {
            DOMPropertySet::setParent(parent);
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::ADFSLI";
                setAddress(address.c_str());
            }
            else {
                m_log.warn("no Location property in ADFS LogoutInitiator (or parent), can't register as remoted handler");
            }
        }

        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

#ifndef SHIBSP_LITE
        const char* getType() const {
            return "LogoutInitiator";
        }
#endif

    private:
        pair<bool,long> doRequest(const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse, Session* session) const;

        string m_appId;
        auto_ptr_XMLCh m_binding;
    };

    class SHIBSP_DLLLOCAL ADFSLogout : public AbstractHandler, public LogoutHandler
    {
    public:
        ADFSLogout(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".Logout.ADFS")), m_login(e, appId) {
            m_initiator = false;
#ifndef SHIBSP_LITE
            m_preserve.push_back("wreply");
            string address = string(appId) + getString("Location").second + "::run::ADFSLO";
            setAddress(address.c_str());
#endif
        }
        virtual ~ADFSLogout() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

#ifndef SHIBSP_LITE
        void generateMetadata(SPSSODescriptor& role, const char* handlerURL) const {
            m_login.generateMetadata(role, handlerURL);
            const char* loc = getString("Location").second;
            string hurl(handlerURL);
            if (*loc != '/')
                hurl += '/';
            hurl += loc;
            auto_ptr_XMLCh widen(hurl.c_str());
            SingleLogoutService* ep = SingleLogoutServiceBuilder::buildSingleLogoutService();
            ep->setLocation(widen.get());
            ep->setBinding(m_login.m_protocol.get());
            role.getSingleLogoutServices().push_back(ep);
        }

        const char* getType() const {
            return m_login.getType();
        }
#endif

    private:
        ADFSConsumer m_login;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* ADFSSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ADFSSessionInitiator(p.first, p.second);
    }

    Handler* ADFSLogoutFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ADFSLogout(p.first, p.second);
    }

    Handler* ADFSLogoutInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ADFSLogoutInitiator(p.first, p.second);
    }

    const XMLCh RequestedSecurityToken[] =      UNICODE_LITERAL_22(R,e,q,u,e,s,t,e,d,S,e,c,u,r,i,t,y,T,o,k,e,n);
    const XMLCh RequestSecurityTokenResponse[] =UNICODE_LITERAL_28(R,e,q,u,e,s,t,S,e,c,u,r,i,t,y,T,o,k,e,n,R,e,s,p,o,n,s,e);
};

extern "C" int ADFS_EXPORTS xmltooling_extension_init(void*)
{
    SPConfig& conf=SPConfig::getConfig();
    conf.SessionInitiatorManager.registerFactory("ADFS", ADFSSessionInitiatorFactory);
    conf.LogoutInitiatorManager.registerFactory("ADFS", ADFSLogoutInitiatorFactory);
    conf.AssertionConsumerServiceManager.registerFactory("ADFS", ADFSLogoutFactory);
    conf.AssertionConsumerServiceManager.registerFactory(WSFED_NS, ADFSLogoutFactory);
#ifndef SHIBSP_LITE
    SAMLConfig::getConfig().MessageDecoderManager.registerFactory(WSFED_NS, ADFSDecoderFactory);
    XMLObjectBuilder::registerBuilder(xmltooling::QName(WSTRUST_NS,"RequestedSecurityToken"), new AnyElementBuilder());
    XMLObjectBuilder::registerBuilder(xmltooling::QName(WSTRUST_NS,"RequestSecurityTokenResponse"), new AnyElementBuilder());
#endif
    return 0;
}

extern "C" void ADFS_EXPORTS xmltooling_extension_term()
{
    /* should get unregistered during normal shutdown...
    SPConfig& conf=SPConfig::getConfig();
    conf.SessionInitiatorManager.deregisterFactory("ADFS");
    conf.LogoutInitiatorManager.deregisterFactory("ADFS");
    conf.AssertionConsumerServiceManager.deregisterFactory("ADFS");
    conf.AssertionConsumerServiceManager.deregisterFactory(WSFED_NS);
#ifndef SHIBSP_LITE
    SAMLConfig::getConfig().MessageDecoderManager.deregisterFactory(WSFED_NS);
#endif
    */
}

pair<bool,long> ADFSSessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // We have to know the IdP to function.
    if (entityID.empty())
        return make_pair(false,0L);

    string target;
    const Handler* ACS=NULL;
    const char* option;
    pair<bool,const char*> acClass;
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

        if (acClass.second = request.getParameter("authnContextClassRef"))
            acClass.first = true;
        else
            acClass = getString("authnContextClassRef");
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one and everything else is defaulted.
        target=request.getRequestURL();

        const PropertySet* settings = request.getRequestSettings().first;
        acClass = settings->getString("authnContextClassRef");
        if (!acClass.first)
            acClass = getString("authnContextClassRef");
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

    // Validate the ACS for use with this protocol.
    pair<bool,const XMLCh*> ACSbinding = ACS ? ACS->getXMLString("Binding") : pair<bool,const XMLCh*>(false,NULL);
    if (ACSbinding.first) {
        if (!XMLString::equals(ACSbinding.second, m_binding.get())) {
            m_log.info("configured or requested ACS has non-ADFS binding");
            return make_pair(false,0L);
        }
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

    m_log.debug("attempting to initiate session using ADFS with provider (%s)", entityID.c_str());

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // Out of process means the POST data via the request can be exposed directly to the private method.
        // The method will handle POST preservation if necessary *before* issuing the response, but only if
        // it dispatches to an IdP.
        return doRequest(app, &request, request, entityID.c_str(), ACSloc.c_str(), (acClass.first ? acClass.second : NULL), target);
    }

    // Remote the call.
    DDF out,in = DDF(m_address.c_str()).structure();
    DDFJanitor jin(in), jout(out);
    in.addmember("application_id").string(app.getId());
    in.addmember("entity_id").string(entityID.c_str());
    in.addmember("acsLocation").string(ACSloc.c_str());
    if (!target.empty())
        in.addmember("RelayState").unsafe_string(target.c_str());
    if (acClass.first)
        in.addmember("authnContextClassRef").string(acClass.second);

    // Remote the processing.
    out = request.getServiceProvider().getListenerService()->send(in);
    return unwrap(request, out);
}

pair<bool,long> ADFSSessionInitiator::unwrap(SPRequest& request, DDF& out) const
{
    // See if there's any response to send back.
    if (!out["redirect"].isnull() || !out["response"].isnull()) {
        // If so, we're responsible for handling the POST data, probably by dropping a cookie.
        preservePostData(request.getApplication(), request, request, out["RelayState"].string());
    }
    return RemotedHandler::unwrap(request, out);
}

void ADFSSessionInitiator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) to generate ADFS request", aid ? aid : "(missing)");
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
    doRequest(*app, NULL, *http.get(), entityID, acsLocation, in["authnContextClassRef"].string(), relayState);
    if (!ret.isstruct())
        ret.structure();
    ret.addmember("RelayState").unsafe_string(relayState.c_str());
    out << ret;
}

pair<bool,long> ADFSSessionInitiator::doRequest(
    const Application& app,
    const HTTPRequest* httpRequest,
    HTTPResponse& httpResponse,
    const char* entityID,
    const char* acsLocation,
    const char* authnContextClassRef,
    string& relayState
    ) const
{
#ifndef SHIBSP_LITE
    // Use metadata to invoke the SSO service directly.
    MetadataProvider* m=app.getMetadataProvider();
    Locker locker(m);
    MetadataProviderCriteria mc(app, entityID, &IDPSSODescriptor::ELEMENT_QNAME, m_binding.get());
    pair<const EntityDescriptor*,const RoleDescriptor*> entity=m->getEntityDescriptor(mc);
    if (!entity.first) {
        m_log.warn("unable to locate metadata for provider (%s)", entityID);
        throw MetadataException("Unable to locate metadata for identity provider ($entityID)", namedparams(1, "entityID", entityID));
    }
    else if (!entity.second) {
        m_log.log(getParent() ? Priority::INFO : Priority::WARN, "unable to locate ADFS-aware identity provider role for provider (%s)", entityID);
        if (getParent())
            return make_pair(false,0L);
        throw MetadataException("Unable to locate ADFS-aware identity provider role for provider ($entityID)", namedparams(1, "entityID", entityID));
    }
    const EndpointType* ep = EndpointManager<SingleSignOnService>(
        dynamic_cast<const IDPSSODescriptor*>(entity.second)->getSingleSignOnServices()
        ).getByBinding(m_binding.get());
    if (!ep) {
        m_log.warn("unable to locate compatible SSO service for provider (%s)", entityID);
        if (getParent())
            return make_pair(false,0L);
        throw MetadataException("Unable to locate compatible SSO service for provider ($entityID)", namedparams(1, "entityID", entityID));
    }

    preserveRelayState(app, httpResponse, relayState);

    // UTC timestamp
    time_t epoch=time(NULL);
#ifndef HAVE_GMTIME_R
    struct tm* ptime=gmtime(&epoch);
#else
    struct tm res;
    struct tm* ptime=gmtime_r(&epoch,&res);
#endif
    char timebuf[32];
    strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);

    auto_ptr_char dest(ep->getLocation());
    const URLEncoder* urlenc = XMLToolingConfig::getConfig().getURLEncoder();

    string req=string(dest.get()) + (strchr(dest.get(),'?') ? '&' : '?') + "wa=wsignin1.0&wreply=" + urlenc->encode(acsLocation) +
        "&wct=" + urlenc->encode(timebuf) + "&wtrealm=" + urlenc->encode(app.getString("entityID").second);
    if (authnContextClassRef)
        req += "&wauth=" + urlenc->encode(authnContextClassRef);
    if (!relayState.empty())
        req += "&wctx=" + urlenc->encode(relayState.c_str());

    if (httpRequest) {
        // If the request object is available, we're responsible for the POST data.
        preservePostData(app, *httpRequest, httpResponse, relayState.c_str());
    }

    return make_pair(true, httpResponse.sendRedirect(req.c_str()));
#else
    return make_pair(false,0L);
#endif
}

#ifndef SHIBSP_LITE

XMLObject* ADFSDecoder::decode(string& relayState, const GenericRequest& genericRequest, SecurityPolicy& policy) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SHIBSP_LOGCAT".MessageDecoder.ADFS");

    log.debug("validating input");
    const HTTPRequest* httpRequest=dynamic_cast<const HTTPRequest*>(&genericRequest);
    if (!httpRequest)
        throw BindingException("Unable to cast request object to HTTPRequest type.");
    if (strcmp(httpRequest->getMethod(),"POST"))
        throw BindingException("Invalid HTTP method ($1).", params(1, httpRequest->getMethod()));
    const char* param = httpRequest->getParameter("wa");
    if (!param || strcmp(param, "wsignin1.0"))
        throw BindingException("Missing or invalid wa parameter (should be wsignin1.0).");
    param = httpRequest->getParameter("wctx");
    if (param)
        relayState = param;

    param = httpRequest->getParameter("wresult");
    if (!param)
        throw BindingException("Request missing wresult parameter.");

    log.debug("decoded ADFS response:\n%s", param);

    // Parse and bind the document into an XMLObject.
    istringstream is(param);
    DOMDocument* doc = (policy.getValidating() ? XMLToolingConfig::getConfig().getValidatingParser()
        : XMLToolingConfig::getConfig().getParser()).parse(is);
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();

    if (!XMLString::equals(xmlObject->getElementQName().getLocalPart(), RequestSecurityTokenResponse)) {
    	log.error("unrecognized root element on message: %s", xmlObject->getElementQName().toString().c_str());
        throw BindingException("Decoded message was not of the appropriate type.");
    }

    SchemaValidators.validate(xmlObject.get());

    // Skip policy step here, there's no security in the wrapper.
    // policy.evaluate(*xmlObject.get(), &genericRequest);

    return xmlObject.release();
}

void ADFSConsumer::implementProtocol(
    const Application& application,
    const HTTPRequest& httpRequest,
    HTTPResponse& httpResponse,
    SecurityPolicy& policy,
    const PropertySet* settings,
    const XMLObject& xmlObject
    ) const
{
    // Implementation of ADFS profile.
    m_log.debug("processing message against ADFS Passive Requester profile");

    // With ADFS, all the security comes from the assertion, which is two levels down in the message.

    const ElementProxy* response = dynamic_cast<const ElementProxy*>(&xmlObject);
    if (!response || !response->hasChildren())
        throw FatalProfileException("Incoming message was not of the proper type or contains no security token.");

    const Assertion* token = NULL;
    for (vector<XMLObject*>::const_iterator xo = response->getUnknownXMLObjects().begin(); xo != response->getUnknownXMLObjects().end(); ++xo) {
    	// Look for the RequestedSecurityToken element.
    	if (XMLString::equals((*xo)->getElementQName().getLocalPart(), RequestedSecurityToken)) {
    	    response = dynamic_cast<const ElementProxy*>(*xo);
    	    if (!response || !response->hasChildren())
    	        throw FatalProfileException("Token wrapper element did not contain a security token.");
    	    token = dynamic_cast<const Assertion*>(response->getUnknownXMLObjects().front());
    	    if (!token || !token->getSignature())
    	        throw FatalProfileException("Incoming message did not contain a signed SAML assertion.");
    	    break;
    	}
    }

    // Extract message and issuer details from assertion.
    extractMessageDetails(*token, m_protocol.get(), policy);

    // Run the policy over the assertion. Handles replay, freshness, and
    // signature verification, assuming the relevant rules are configured.
    policy.evaluate(*token, &httpRequest);

    // If no security is in place now, we kick it.
    if (!policy.isAuthenticated())
        throw SecurityPolicyException("Unable to establish security of incoming assertion.");

    time_t now = time(NULL);

    const PropertySet* sessionProps = application.getPropertySet("Sessions");
    const EntityDescriptor* entity = policy.getIssuerMetadata() ? dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent()) : NULL;

    saml1::NameIdentifier* saml1name=NULL;
    saml2::NameID* saml2name=NULL;
    const XMLCh* authMethod=NULL;
    const XMLCh* authInstant=NULL;
    time_t sessionExp = 0;

    const saml1::Assertion* saml1token = dynamic_cast<const saml1::Assertion*>(token);
    if (saml1token) {
        // Now do profile and core semantic validation to ensure we can use it for SSO.
        saml1::AssertionValidator ssoValidator(application.getRelyingParty(entity)->getXMLString("entityID").second, application.getAudiences(), now);
        ssoValidator.validateAssertion(*saml1token);
        if (!saml1token->getConditions() || !saml1token->getConditions()->getNotBefore() || !saml1token->getConditions()->getNotOnOrAfter())
            throw FatalProfileException("Assertion did not contain time conditions.");
        else if (saml1token->getAuthenticationStatements().empty())
            throw FatalProfileException("Assertion did not contain an authentication statement.");

        // authnskew allows rejection of SSO if AuthnInstant is too old.
        pair<bool,unsigned int> authnskew = sessionProps ? sessionProps->getUnsignedInt("maxTimeSinceAuthn") : pair<bool,unsigned int>(false,0);

        const saml1::AuthenticationStatement* ssoStatement=saml1token->getAuthenticationStatements().front();
        if (authnskew.first && authnskew.second &&
                ssoStatement->getAuthenticationInstant() && (now - ssoStatement->getAuthenticationInstantEpoch() > authnskew.second))
            throw FatalProfileException("The gap between now and the time you logged into your identity provider exceeds the limit.");

        // Address checking.
        saml1::SubjectLocality* locality = ssoStatement->getSubjectLocality();
        if (locality && locality->getIPAddress()) {
            auto_ptr_char ip(locality->getIPAddress());
            checkAddress(application, httpRequest, ip.get());
        }

        saml1name = ssoStatement->getSubject()->getNameIdentifier();
        authMethod = ssoStatement->getAuthenticationMethod();
        if (ssoStatement->getAuthenticationInstant())
            authInstant = ssoStatement->getAuthenticationInstant()->getRawData();

        // Session expiration.
        pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
        if (!lifetime.first || lifetime.second == 0)
            lifetime.second = 28800;
        sessionExp = now + lifetime.second;
    }
    else {
        const saml2::Assertion* saml2token = dynamic_cast<const saml2::Assertion*>(token);
        if (!saml2token)
            throw FatalProfileException("Incoming message did not contain a recognized type of SAML assertion.");

        // Now do profile and core semantic validation to ensure we can use it for SSO.
        saml2::AssertionValidator ssoValidator(application.getRelyingParty(entity)->getXMLString("entityID").second, application.getAudiences(), now);
        ssoValidator.validateAssertion(*saml2token);
        if (!saml2token->getConditions() || !saml2token->getConditions()->getNotBefore() || !saml2token->getConditions()->getNotOnOrAfter())
            throw FatalProfileException("Assertion did not contain time conditions.");
        else if (saml2token->getAuthnStatements().empty())
            throw FatalProfileException("Assertion did not contain an authentication statement.");

        // authnskew allows rejection of SSO if AuthnInstant is too old.
        pair<bool,unsigned int> authnskew = sessionProps ? sessionProps->getUnsignedInt("maxTimeSinceAuthn") : pair<bool,unsigned int>(false,0);

        const saml2::AuthnStatement* ssoStatement=saml2token->getAuthnStatements().front();
        if (authnskew.first && authnskew.second &&
                ssoStatement->getAuthnInstant() && (now - ssoStatement->getAuthnInstantEpoch() > authnskew.second))
            throw FatalProfileException("The gap between now and the time you logged into your identity provider exceeds the limit.");

        // Address checking.
        saml2::SubjectLocality* locality = ssoStatement->getSubjectLocality();
        if (locality && locality->getAddress()) {
            auto_ptr_char ip(locality->getAddress());
            checkAddress(application, httpRequest, ip.get());
        }

        saml2name = saml2token->getSubject() ? saml2token->getSubject()->getNameID() : NULL;
        if (ssoStatement->getAuthnContext() && ssoStatement->getAuthnContext()->getAuthnContextClassRef())
            authMethod = ssoStatement->getAuthnContext()->getAuthnContextClassRef()->getReference();
        if (ssoStatement->getAuthnInstant())
            authInstant = ssoStatement->getAuthnInstant()->getRawData();

        // Session expiration for SAML 2.0 is jointly IdP- and SP-driven.
        sessionExp = ssoStatement->getSessionNotOnOrAfter() ? ssoStatement->getSessionNotOnOrAfterEpoch() : 0;
        pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
        if (!lifetime.first || lifetime.second == 0)
            lifetime.second = 28800;
        if (sessionExp == 0)
            sessionExp = now + lifetime.second;     // IdP says nothing, calulate based on SP.
        else
            sessionExp = min(sessionExp, now + lifetime.second);    // Use the lowest.
    }

    m_log.debug("ADFS profile processing completed successfully");

    // We've successfully "accepted" the SSO token.
    // To complete processing, we need to extract and resolve attributes and then create the session.

    // Normalize a SAML 1.x NameIdentifier...
    auto_ptr<saml2::NameID> nameid(saml1name ? saml2::NameIDBuilder::buildNameID() : NULL);
    if (saml1name) {
        nameid->setName(saml1name->getName());
        nameid->setFormat(saml1name->getFormat());
        nameid->setNameQualifier(saml1name->getNameQualifier());
    }

    // The context will handle deleting attributes and new tokens.
    vector<const Assertion*> tokens(1,token);
    auto_ptr<ResolutionContext> ctx(
        resolveAttributes(
            application,
            policy.getIssuerMetadata(),
            m_protocol.get(),
            saml1name,
            (saml1name ? nameid.get() : saml2name),
            authMethod,
            NULL,
            &tokens
            )
        );

    if (ctx.get()) {
        // Copy over any new tokens, but leave them in the context for cleanup.
        tokens.insert(tokens.end(), ctx->getResolvedAssertions().begin(), ctx->getResolvedAssertions().end());
    }

    application.getServiceProvider().getSessionCache()->insert(
        application,
        httpRequest,
        httpResponse,
        sessionExp,
        entity,
        m_protocol.get(),
        (saml1name ? nameid.get() : saml2name),
        authInstant,
        NULL,
        authMethod,
        NULL,
        &tokens,
        ctx.get() ? &ctx->getResolvedAttributes() : NULL
        );
}

#endif

pair<bool,long> ADFSLogoutInitiator::run(SPRequest& request, bool isHandler) const
{
    // Normally we'd do notifications and session clearage here, but ADFS logout
    // is missing the needed request/response features, so we have to rely on
    // the IdP half to notify us back about the logout and do the work there.
    // Basically we have no way to tell in the Logout receiving handler whether
    // we initiated the logout or not.

    Session* session = NULL;
    try {
        session = request.getSession(false, true, false);  // don't cache it and ignore all checks
        if (!session)
            return make_pair(false,0L);

        // We only handle ADFS sessions.
        if (!XMLString::equals(session->getProtocol(), WSFED_NS) || !session->getEntityID()) {
            session->unlock();
            return make_pair(false,0L);
        }
    }
    catch (exception& ex) {
        m_log.error("error accessing current session: %s", ex.what());
        return make_pair(false,0L);
    }

    string entityID(session->getEntityID());
    session->unlock();

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // When out of process, we run natively.
        return doRequest(request.getApplication(), request, request, session);
    }
    else {
        // When not out of process, we remote the request.
        session->unlock();
        vector<string> headers(1,"Cookie");
        DDF out,in = wrap(request,&headers);
        DDFJanitor jin(in), jout(out);
        out=request.getServiceProvider().getListenerService()->send(in);
        return unwrap(request, out);
    }
}

void ADFSLogoutInitiator::receive(DDF& in, ostream& out)
{
#ifndef SHIBSP_LITE
    // Defer to base class for notifications
    if (in["notify"].integer() == 1)
        return LogoutHandler::receive(in, out);

    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for logout", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for logout, deleted?");
    }

    // Unpack the request.
    auto_ptr<HTTPRequest> req(getRequest(in));

    // Set up a response shim.
    DDF ret(NULL);
    DDFJanitor jout(ret);
    auto_ptr<HTTPResponse> resp(getResponse(ret));

    Session* session = NULL;
    try {
         session = app->getServiceProvider().getSessionCache()->find(*app, *req.get(), NULL, NULL);
    }
    catch (exception& ex) {
        m_log.error("error accessing current session: %s", ex.what());
    }

    // With no session, we just skip the request and let it fall through to an empty struct return.
    if (session) {
        if (session->getEntityID()) {
            // Since we're remoted, the result should either be a throw, which we pass on,
            // a false/0 return, which we just return as an empty structure, or a response/redirect,
            // which we capture in the facade and send back.
            doRequest(*app, *req.get(), *resp.get(), session);
        }
        else {
             m_log.error("no issuing entityID found in session");
             session->unlock();
             app->getServiceProvider().getSessionCache()->remove(*app, *req.get(), resp.get());
        }
    }
    out << ret;
#else
    throw ConfigurationException("Cannot perform logout using lite version of shibsp library.");
#endif
}

pair<bool,long> ADFSLogoutInitiator::doRequest(
    const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse, Session* session
    ) const
{
    // Do back channel notification.
    vector<string> sessions(1, session->getID());
    if (!notifyBackChannel(application, httpRequest.getRequestURL(), sessions, false)) {
        session->unlock();
        application.getServiceProvider().getSessionCache()->remove(application, httpRequest, &httpResponse);
        return sendLogoutPage(application, httpRequest, httpResponse, true, "Partial logout failure.");
    }

#ifndef SHIBSP_LITE
    pair<bool,long> ret = make_pair(false,0L);

    try {
        // With a session in hand, we can create a request message, if we can find a compatible endpoint.
        MetadataProvider* m=application.getMetadataProvider();
        Locker metadataLocker(m);
        MetadataProviderCriteria mc(application, session->getEntityID(), &IDPSSODescriptor::ELEMENT_QNAME, m_binding.get());
        pair<const EntityDescriptor*,const RoleDescriptor*> entity=m->getEntityDescriptor(mc);
        if (!entity.first) {
            throw MetadataException(
                "Unable to locate metadata for identity provider ($entityID)", namedparams(1, "entityID", session->getEntityID())
                );
        }
        else if (!entity.second) {
            throw MetadataException(
                "Unable to locate ADFS IdP role for identity provider ($entityID).", namedparams(1, "entityID", session->getEntityID())
                );
        }

        const EndpointType* ep = EndpointManager<SingleLogoutService>(
            dynamic_cast<const IDPSSODescriptor*>(entity.second)->getSingleLogoutServices()
            ).getByBinding(m_binding.get());
        if (!ep) {
            throw MetadataException(
                "Unable to locate ADFS single logout service for identity provider ($entityID).", namedparams(1, "entityID", session->getEntityID())
                );
        }

        const URLEncoder* urlenc = XMLToolingConfig::getConfig().getURLEncoder();
        const char* returnloc = httpRequest.getParameter("return");
        auto_ptr_char dest(ep->getLocation());
        string req=string(dest.get()) + (strchr(dest.get(),'?') ? '&' : '?') + "wa=wsignout1.0";
        if (returnloc)
            req += "&wreply=" + urlenc->encode(returnloc);
        ret.second = httpResponse.sendRedirect(req.c_str());
        ret.first = true;
    }
    catch (exception& ex) {
        m_log.error("error issuing ADFS logout request: %s", ex.what());
    }

    if (session) {
        session->unlock();
        session = NULL;
        application.getServiceProvider().getSessionCache()->remove(application, httpRequest, &httpResponse);
    }

    return ret;
#else
    throw ConfigurationException("Cannot perform logout using lite version of shibsp library.");
#endif
}

pair<bool,long> ADFSLogout::run(SPRequest& request, bool isHandler) const
{
    // Defer to base class for front-channel loop first.
    // This won't initiate the loop, only continue/end it.
    pair<bool,long> ret = LogoutHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    // wa parameter indicates the "action" to perform
    bool returning = false;
    const char* param = request.getParameter("wa");
    if (param) {
        if (!strcmp(param, "wsignin1.0"))
            return m_login.run(request, isHandler);
        else if (strcmp(param, "wsignout1.0") && strcmp(param, "wsignoutcleanup1.0"))
            throw FatalProfileException("Unsupported WS-Federation action paremeter ($1).", params(1, param));
    }
    else if (strcmp(request.getMethod(),"GET") || !request.getParameter("notifying"))
        throw FatalProfileException("Unsupported request to ADFS protocol endpoint.");
    else
        returning = true;

    param = request.getParameter("wreply");
    const Application& app = request.getApplication();

    if (!returning) {
        // Pass control to the first front channel notification point, if any.
        map<string,string> parammap;
        if (param)
            parammap["wreply"] = param;
        pair<bool,long> result = notifyFrontChannel(app, request, request, &parammap);
        if (result.first)
            return result;
    }

    // Best effort on back channel and to remove the user agent's session.
    string session_id = app.getServiceProvider().getSessionCache()->active(app, request);
    if (!session_id.empty()) {
        vector<string> sessions(1,session_id);
        notifyBackChannel(app, request.getRequestURL(), sessions, false);
        try {
            app.getServiceProvider().getSessionCache()->remove(app, request, &request);
        }
        catch (exception& ex) {
            m_log.error("error removing session (%s): %s", session_id.c_str(), ex.what());
        }
    }

    if (param)
        return make_pair(true, request.sendRedirect(param));
    return sendLogoutPage(app, request, request, false, "Logout complete.");
}

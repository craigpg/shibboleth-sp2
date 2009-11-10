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
 * SAML2LogoutInitiator.cpp
 *
 * Triggers SP-initiated logout for SAML 2.0 sessions.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/LogoutHandler.h"

#ifndef SHIBSP_LITE
# include "binding/SOAPClient.h"
# include "metadata/MetadataProviderCriteria.h"
# include "security/SecurityPolicy.h"
# include <saml/exceptions.h>
# include <saml/SAMLConfig.h>
# include <saml/saml2/core/Protocols.h>
# include <saml/saml2/binding/SAML2SOAPClient.h>
# include <saml/saml2/metadata/EndpointManager.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataCredentialCriteria.h>
# include <saml/signature/ContentReference.h>
# include <xmltooling/security/Credential.h>
# include <xmltooling/signature/Signature.h>
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
#else
# include "lite/SAMLConstants.h"
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL SAML2LogoutInitiator : public AbstractHandler, public LogoutHandler
    {
    public:
        SAML2LogoutInitiator(const DOMElement* e, const char* appId);
        virtual ~SAML2LogoutInitiator() {
#ifndef SHIBSP_LITE
            if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
                XMLString::release(&m_outgoing);
                for_each(m_encoders.begin(), m_encoders.end(), cleanup_pair<const XMLCh*,MessageEncoder>());
            }
#endif
        }

        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

#ifndef SHIBSP_LITE
        const char* getType() const {
            return "LogoutInitiator";
        }
#endif

    private:
        pair<bool,long> doRequest(
            const Application& application, const HTTPRequest& request, HTTPResponse& httpResponse, Session* session
            ) const;

        string m_appId;
#ifndef SHIBSP_LITE
        LogoutRequest* buildRequest(
            const Application& application, const Session& session, const RoleDescriptor& role, const MessageEncoder* encoder=NULL
            ) const;

        XMLCh* m_outgoing;
        vector<const XMLCh*> m_bindings;
        map<const XMLCh*,MessageEncoder*> m_encoders;
#endif
        auto_ptr_char m_protocol;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SAML2LogoutInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML2LogoutInitiator(p.first, p.second);
    }
};

SAML2LogoutInitiator::SAML2LogoutInitiator(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".LogoutInitiator.SAML2")), m_appId(appId),
#ifndef SHIBSP_LITE
        m_outgoing(NULL),
#endif
        m_protocol(samlconstants::SAML20P_NS)
{
#ifndef SHIBSP_LITE
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
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
                MessageEncoder * encoder =
                    SAMLConfig::getConfig().MessageEncoderManager.newPlugin(b.get(),pair<const DOMElement*,const XMLCh*>(e,NULL));
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

    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::SAML2LI";
        setAddress(address.c_str());
    }
}

void SAML2LogoutInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::SAML2LI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in SAML2 LogoutInitiator (or parent), can't register as remoted handler");
    }
}

pair<bool,long> SAML2LogoutInitiator::run(SPRequest& request, bool isHandler) const
{
    // Defer to base class for front-channel loop first.
    pair<bool,long> ret = LogoutHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    // At this point we know the front-channel is handled.
    // We need the session to do any other work.

    Session* session = NULL;
    try {
        session = request.getSession(false, true, false);  // don't cache it and ignore all checks
        if (!session)
            return make_pair(false,0L);

        // We only handle SAML 2.0 sessions.
        if (!XMLString::equals(session->getProtocol(), m_protocol.get())) {
            session->unlock();
            return make_pair(false,0L);
        }
    }
    catch (exception& ex) {
        m_log.error("error accessing current session: %s", ex.what());
        return make_pair(false,0L);
    }

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

void SAML2LogoutInitiator::receive(DDF& in, ostream& out)
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
        if (session->getNameID() && session->getEntityID()) {
            // Since we're remoted, the result should either be a throw, which we pass on,
            // a false/0 return, which we just return as an empty structure, or a response/redirect,
            // which we capture in the facade and send back.
            doRequest(*app, *req.get(), *resp.get(), session);
        }
        else {
             m_log.error("no NameID or issuing entityID found in session");
             session->unlock();
             app->getServiceProvider().getSessionCache()->remove(*app, *req.get(), resp.get());
        }
    }
    out << ret;
#else
    throw ConfigurationException("Cannot perform logout using lite version of shibsp library.");
#endif
}

pair<bool,long> SAML2LogoutInitiator::doRequest(
    const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse, Session* session
    ) const
{
    // Do back channel notification.
    vector<string> sessions(1, session->getID());
    if (!notifyBackChannel(application, httpRequest.getRequestURL(), sessions, false)) {
        session->unlock();
        application.getServiceProvider().getSessionCache()->remove(application, httpRequest, &httpResponse);
        return sendLogoutPage(application, httpRequest, httpResponse, "partial");
    }

#ifndef SHIBSP_LITE
    pair<bool,long> ret = make_pair(false,0L);
    try {
        // With a session in hand, we can create a LogoutRequest message, if we can find a compatible endpoint.
        MetadataProvider* m = application.getMetadataProvider();
        Locker metadataLocker(m);
        MetadataProviderCriteria mc(application, session->getEntityID(), &IDPSSODescriptor::ELEMENT_QNAME, samlconstants::SAML20P_NS);
        pair<const EntityDescriptor*,const RoleDescriptor*> entity = m->getEntityDescriptor(mc);
        if (!entity.first) {
            throw MetadataException(
                "Unable to locate metadata for identity provider ($entityID)", namedparams(1, "entityID", session->getEntityID())
                );
        }
        else if (!entity.second) {
            throw MetadataException(
                "Unable to locate SAML 2.0 IdP role for identity provider ($entityID).", namedparams(1, "entityID", session->getEntityID())
                );
        }

        const IDPSSODescriptor* role = dynamic_cast<const IDPSSODescriptor*>(entity.second);
        const EndpointType* ep=NULL;
        const MessageEncoder* encoder=NULL;
        vector<const XMLCh*>::const_iterator b;
        for (b = m_bindings.begin(); b!=m_bindings.end(); ++b) {
            if (ep=EndpointManager<SingleLogoutService>(role->getSingleLogoutServices()).getByBinding(*b)) {
                map<const XMLCh*,MessageEncoder*>::const_iterator enc = m_encoders.find(*b);
                if (enc!=m_encoders.end())
                    encoder = enc->second;
                break;
            }
        }
        if (!ep || !encoder) {
            m_log.debug("no compatible front channel SingleLogoutService, trying back channel...");
            shibsp::SecurityPolicy policy(application);
            shibsp::SOAPClient soaper(policy);
            MetadataCredentialCriteria mcc(*role);

            LogoutResponse* logoutResponse=NULL;
            auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
            const vector<SingleLogoutService*>& endpoints=role->getSingleLogoutServices();
            for (vector<SingleLogoutService*>::const_iterator epit=endpoints.begin(); !logoutResponse && epit!=endpoints.end(); ++epit) {
                try {
                    if (!XMLString::equals((*epit)->getBinding(),binding.get()))
                        continue;
                    LogoutRequest* msg = buildRequest(application, *session, *role);
                    auto_ptr_char dest((*epit)->getLocation());

                    SAML2SOAPClient client(soaper, false);
                    client.sendSAML(msg, application.getId(), mcc, dest.get());
                    StatusResponseType* srt = client.receiveSAML();
                    if (!(logoutResponse = dynamic_cast<LogoutResponse*>(srt))) {
                        delete srt;
                        break;
                    }
                }
                catch (exception& ex) {
                    m_log.error("error sending LogoutRequest message: %s", ex.what());
                    soaper.reset();
                }
            }

            // No answer at all?
            if (!logoutResponse) {
                if (endpoints.empty())
                    m_log.info("IdP doesn't support single logout protocol over a compatible binding");
                else
                    m_log.warn("IdP didn't respond to logout request");
                ret = sendLogoutPage(application, httpRequest, httpResponse, "partial");
            }

            // Check the status, looking for non-success or a partial logout code.
            const StatusCode* sc = logoutResponse->getStatus() ? logoutResponse->getStatus()->getStatusCode() : NULL;
            bool partial = (!sc || !XMLString::equals(sc->getValue(), StatusCode::SUCCESS));
            if (!partial) {
                // Success, but still need to check for partial.
                partial = XMLString::equals(sc->getStatusCode()->getValue(), StatusCode::PARTIAL_LOGOUT);
            }
            delete logoutResponse;
            if (partial)
                ret = sendLogoutPage(application, httpRequest, httpResponse, "partial");
            else {
                const char* returnloc = httpRequest.getParameter("return");
                if (returnloc) {
                    ret.second = httpResponse.sendRedirect(returnloc);
                    ret.first = true;
                }
                ret = sendLogoutPage(application, httpRequest, httpResponse, "global");
            }

            if (session) {
                session->unlock();
                session = NULL;
                application.getServiceProvider().getSessionCache()->remove(application, httpRequest, &httpResponse);
            }
            return ret;
        }

        // Save off return location as RelayState.
        string relayState;
        const char* returnloc = httpRequest.getParameter("return");
        if (returnloc) {
            relayState = returnloc;
            preserveRelayState(application, httpResponse, relayState);
        }

        auto_ptr<LogoutRequest> msg(buildRequest(application, *session, *role, encoder));

        msg->setDestination(ep->getLocation());
        auto_ptr_char dest(ep->getLocation());
        ret.second = sendMessage(*encoder, msg.get(), relayState.c_str(), dest.get(), role, application, httpResponse);
        ret.first = true;
        msg.release();  // freed by encoder
    }
    catch (exception& ex) {
        m_log.error("error issuing SAML 2.0 logout request: %s", ex.what());
    }

    if (session) {
        session->unlock();
        session = NULL;
        application.getServiceProvider().getSessionCache()->remove(application, httpRequest, &httpResponse);
    }

    return ret;
#else
    session->unlock();
    application.getServiceProvider().getSessionCache()->remove(application, httpRequest, &httpResponse);
    throw ConfigurationException("Cannot perform logout using lite version of shibsp library.");
#endif
}

#ifndef SHIBSP_LITE

LogoutRequest* SAML2LogoutInitiator::buildRequest(
    const Application& application, const Session& session, const RoleDescriptor& role, const MessageEncoder* encoder
    ) const
{
    const PropertySet* relyingParty = application.getRelyingParty(dynamic_cast<EntityDescriptor*>(role.getParent()));

    auto_ptr<LogoutRequest> msg(LogoutRequestBuilder::buildLogoutRequest());
    Issuer* issuer = IssuerBuilder::buildIssuer();
    msg->setIssuer(issuer);
    issuer->setName(relyingParty->getXMLString("entityID").second);
    auto_ptr_XMLCh index(session.getSessionIndex());
    if (index.get() && *index.get()) {
        SessionIndex* si = SessionIndexBuilder::buildSessionIndex();
        msg->getSessionIndexs().push_back(si);
        si->setSessionIndex(index.get());
    }

    const NameID* nameid = session.getNameID();
    pair<bool,const char*> flag = relyingParty->getString("encryption");
    if (flag.first &&
        (!strcmp(flag.second, "true") || (encoder && !strcmp(flag.second, "front")) || (!encoder && !strcmp(flag.second, "back")))) {
        auto_ptr<EncryptedID> encrypted(EncryptedIDBuilder::buildEncryptedID());
        MetadataCredentialCriteria mcc(role);
        encrypted->encrypt(
            *nameid,
            *(application.getMetadataProvider()),
            mcc,
            encoder ? encoder->isCompact() : false,
            relyingParty->getXMLString("encryptionAlg").second
            );
        msg->setEncryptedID(encrypted.release());
    }
    else {
        msg->setNameID(nameid->cloneNameID());
    }

    if (!encoder) {
        // No encoder being used, so sign for SOAP client manually.
        flag = relyingParty->getString("signing");
        if (flag.first && (!strcmp(flag.second, "true") || !strcmp(flag.second, "back"))) {
            CredentialResolver* credResolver=application.getCredentialResolver();
            if (credResolver) {
                Locker credLocker(credResolver);
                // Fill in criteria to use.
                MetadataCredentialCriteria mcc(role);
                mcc.setUsage(Credential::SIGNING_CREDENTIAL);
                pair<bool,const char*> keyName = relyingParty->getString("keyName");
                if (keyName.first)
                    mcc.getKeyNames().insert(keyName.second);
                pair<bool,const XMLCh*> sigalg = relyingParty->getXMLString("signingAlg");
                if (sigalg.first)
                    mcc.setXMLAlgorithm(sigalg.second);
                const Credential* cred = credResolver->resolve(&mcc);
                if (cred) {
                    xmlsignature::Signature* sig = xmlsignature::SignatureBuilder::buildSignature();
                    msg->setSignature(sig);
                    if (sigalg.first)
                        sig->setSignatureAlgorithm(sigalg.second);
                    sigalg = relyingParty->getXMLString("digestAlg");
                    if (sigalg.first) {
                        ContentReference* cr = dynamic_cast<ContentReference*>(sig->getContentReference());
                        if (cr)
                            cr->setDigestAlgorithm(sigalg.second);
                    }

                    // Sign response while marshalling.
                    vector<xmlsignature::Signature*> sigs(1,sig);
                    msg->marshall((DOMDocument*)NULL,&sigs,cred);
                }
                else {
                    m_log.warn("no signing credential resolved, leaving message unsigned");
                }
            }
            else {
                m_log.warn("no credential resolver installed, leaving message unsigned");
            }
        }
    }

    return msg.release();
}

#endif

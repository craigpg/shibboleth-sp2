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
 * SAML2ArtifactResolution.cpp
 * 
 * Handler for resolving SAML 2.0 artifacts.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/RemotedHandler.h"
#include "util/SPConstants.h"

#ifndef SHIBSP_LITE
# include "security/SecurityPolicy.h"
# include <saml/exceptions.h>
# include <saml/SAMLConfig.h>
# include <saml/binding/ArtifactMap.h>
# include <saml/binding/MessageEncoder.h>
# include <saml/binding/MessageDecoder.h>
# include <saml/binding/SAMLArtifact.h>
# include <saml/saml2/core/Assertions.h>
# include <saml/saml2/core/Protocols.h>
# include <saml/saml2/metadata/Metadata.h>
using namespace opensaml::saml2md;
using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace samlconstants;
#endif

#include <xmltooling/soap/SOAP.h>

using namespace shibspconstants;
using namespace shibsp;
using namespace soap11;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_API SAML2ArtifactResolution : public AbstractHandler, public RemotedHandler 
    {
    public:
        SAML2ArtifactResolution(const DOMElement* e, const char* appId);
        virtual ~SAML2ArtifactResolution();

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, ostream& out);

#ifndef SHIBSP_LITE
        const char* getType() const {
            return "ArtifactResolutionService";
        }
#endif

    private:
        pair<bool,long> processMessage(const Application& application, HTTPRequest& httpRequest, HTTPResponse& httpResponse) const;
#ifndef SHIBSP_LITE
        pair<bool,long> samlError(
            const Application& app,
            const ArtifactResolve& request,
            HTTPResponse& httpResponse,
            const EntityDescriptor* recipient,
            const XMLCh* code,
            const XMLCh* subcode=NULL,
            const char* msg=NULL
            ) const;

        MessageEncoder* m_encoder;
        MessageDecoder* m_decoder;
        xmltooling::QName m_role;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SAML2ArtifactResolutionFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML2ArtifactResolution(p.first, p.second);
    }

};

SAML2ArtifactResolution::SAML2ArtifactResolution(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".ArtifactResolution.SAML2"))
#ifndef SHIBSP_LITE
        ,m_encoder(NULL), m_decoder(NULL), m_role(samlconstants::SAML20MD_NS, opensaml::saml2md::IDPSSODescriptor::LOCAL_NAME)
#endif
{
#ifndef SHIBSP_LITE
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        try {
            m_encoder = SAMLConfig::getConfig().MessageEncoderManager.newPlugin(
                getString("Binding").second,pair<const DOMElement*,const XMLCh*>(e,NULL)
                );
            m_decoder = SAMLConfig::getConfig().MessageDecoderManager.newPlugin(
                getString("Binding").second,pair<const DOMElement*,const XMLCh*>(e,NULL)
                );
        }
        catch (exception&) {
            m_log.error("error building MessageEncoder/Decoder pair for binding (%s)", getString("Binding").second);
            delete m_encoder;
            delete m_decoder;
            throw;
        }
    }
#endif
    string address(appId);
    address += getString("Location").second;
    address += "::run::SAML2Artifact";
    setAddress(address.c_str());
}

SAML2ArtifactResolution::~SAML2ArtifactResolution()
{
#ifndef SHIBSP_LITE
    delete m_encoder;
    delete m_decoder;
#endif
}

pair<bool,long> SAML2ArtifactResolution::run(SPRequest& request, bool isHandler) const
{
    string relayState;
    SPConfig& conf = SPConfig::getConfig();
    
    try {
        if (conf.isEnabled(SPConfig::OutOfProcess)) {
            // When out of process, we run natively and directly process the message.
            return processMessage(request.getApplication(), request, request);
        }
        else {
            // When not out of process, we remote all the message processing.
            DDF out,in = wrap(request, NULL, true);
            DDFJanitor jin(in), jout(out);
            
            out=request.getServiceProvider().getListenerService()->send(in);
            return unwrap(request, out);
        }
    }
    catch (exception& ex) {
        m_log.error("error while processing request: %s", ex.what());

        // Build a SOAP fault around the error.
        auto_ptr<Fault> fault(FaultBuilder::buildFault());
        Faultcode* code = FaultcodeBuilder::buildFaultcode();
        fault->setFaultcode(code);
        code->setCode(&Faultcode::SERVER);
        Faultstring* fs = FaultstringBuilder::buildFaultstring();
        fault->setFaultstring(fs);
        pair<bool,bool> flag = getBool("detailedErrors", m_configNS.get());
        auto_ptr_XMLCh msg((flag.first && flag.second) ? ex.what() : "Error processing request.");
        fs->setString(msg.get());
#ifndef SHIBSP_LITE
        // Use MessageEncoder to send back the fault.
        long ret = m_encoder->encode(request, fault.get(), NULL);
        fault.release();
        return make_pair(true, ret);
#else
        // Brute force the fault to avoid library dependency.
        auto_ptr<Envelope> env(EnvelopeBuilder::buildEnvelope());
        Body* body = BodyBuilder::buildBody();
        env->setBody(body);
        body->getUnknownXMLObjects().push_back(fault.release());
        string xmlbuf;
        XMLHelper::serialize(env->marshall(), xmlbuf);
        istringstream s(xmlbuf);
        request.setContentType("text/xml");
        return make_pair(true, request.sendError(s));
#endif
    }
}

void SAML2ArtifactResolution::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for artifact resolution", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for artifact resolution, deleted?");
    }
    
    // Unpack the request.
    auto_ptr<HTTPRequest> req(getRequest(in));
    //m_log.debug("found %d client certificates", req->getClientCertificates().size());

    // Wrap a response shim.
    DDF ret(NULL);
    DDFJanitor jout(ret);
    auto_ptr<HTTPResponse> resp(getResponse(ret));
        
    try {
        // Since we're remoted, the result should either be a throw, a false/0 return,
        // which we just return as an empty structure, or a response/redirect,
        // which we capture in the facade and send back.
        processMessage(*app, *req.get(), *resp.get());
        out << ret;
    }
    catch (exception& ex) {
#ifndef SHIBSP_LITE
        m_log.error("error while processing request: %s", ex.what());

        // Use MessageEncoder to send back a SOAP fault.
        auto_ptr<Fault> fault(FaultBuilder::buildFault());
        Faultcode* code = FaultcodeBuilder::buildFaultcode();
        fault->setFaultcode(code);
        code->setCode(&Faultcode::SERVER);
        Faultstring* fs = FaultstringBuilder::buildFaultstring();
        fault->setFaultstring(fs);
        pair<bool,bool> flag = getBool("detailedErrors", m_configNS.get());
        auto_ptr_XMLCh msg((flag.first && flag.second) ? ex.what() : "Error processing request.");
        fs->setString(msg.get());
        m_encoder->encode(*resp.get(), fault.get(), NULL);
        fault.release();
        out << ret;
#else
        throw;  // should never happen anyway
#endif
    }
}

pair<bool,long> SAML2ArtifactResolution::processMessage(const Application& application, HTTPRequest& httpRequest, HTTPResponse& httpResponse) const
{
#ifndef SHIBSP_LITE
    m_log.debug("processing SAML 2.0 ArtifactResolve request");

    ArtifactMap* artmap = SAMLConfig::getConfig().getArtifactMap();
    if (!artmap)
        throw ConfigurationException("No ArtifactMap instance installed.");

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
    shibsp::SecurityPolicy policy(application, &m_role, validate.first && validate.second);
    
    // Decode the message and verify that it's a secured ArtifactResolve request.
    string relayState;
    auto_ptr<XMLObject> msg(m_decoder->decode(relayState, httpRequest, policy));
    if (!msg.get())
        throw BindingException("Failed to decode a SAML request.");
    const ArtifactResolve* req = dynamic_cast<const ArtifactResolve*>(msg.get());
    if (!req)
        throw FatalProfileException("Decoded message was not a samlp::ArtifactResolve request.");

    const EntityDescriptor* entity = policy.getIssuerMetadata() ? dynamic_cast<EntityDescriptor*>(policy.getIssuerMetadata()->getParent()) : NULL;

    try {
        auto_ptr_char artifact(req->getArtifact() ? req->getArtifact()->getArtifact() : NULL);
        if (!artifact.get() || !*artifact.get())
            return samlError(application, *req, httpResponse, entity, StatusCode::REQUESTER, NULL, "Request did not contain an artifact to resolve.");
        auto_ptr_char issuer(policy.getIssuer() ? policy.getIssuer()->getName() : NULL);

        m_log.info("resolving artifact (%s) for (%s)", artifact.get(), issuer.get() ? issuer.get() : "unknown");

        // Parse the artifact and retrieve the object.
        auto_ptr<SAMLArtifact> artobj(SAMLArtifact::parse(artifact.get()));
        auto_ptr<XMLObject> payload(artmap->retrieveContent(artobj.get(), issuer.get()));

        if (!policy.isAuthenticated()) {
            m_log.error("request for artifact was unauthenticated, purging the artifact mapping");
            return samlError(application, *req, httpResponse, entity, StatusCode::REQUESTER, StatusCode::AUTHN_FAILED, "Unable to authenticate request.");
        }

        m_log.debug("artifact resolved, preparing response");

        // Wrap it in a response.
        auto_ptr<ArtifactResponse> resp(ArtifactResponseBuilder::buildArtifactResponse());
        resp->setInResponseTo(req->getID());
        Issuer* me = IssuerBuilder::buildIssuer();
        me->setName(application.getRelyingParty(entity)->getXMLString("entityID").second);
        resp->setPayload(payload.release());

        long ret = sendMessage(
            *m_encoder, resp.get(), relayState.c_str(), NULL, policy.getIssuerMetadata(), application, httpResponse, "signResponses"
            );
        resp.release();  // freed by encoder
        return make_pair(true,ret);
    }
    catch (exception& ex) {
        // Trap localized errors in a SAML Response.
        m_log.error("error processing artifact request, returning SAML error: %s", ex.what());
        return samlError(application, *req, httpResponse, entity, StatusCode::RESPONDER, NULL, ex.what());
    }
#else
    return make_pair(false,0L);
#endif
}

#ifndef SHIBSP_LITE
pair<bool,long> SAML2ArtifactResolution::samlError(
    const Application& app,
    const ArtifactResolve& request,
    HTTPResponse& httpResponse,
    const EntityDescriptor* recipient,
    const XMLCh* code,
    const XMLCh* subcode,
    const char* msg
    ) const
{
    auto_ptr<ArtifactResponse> resp(ArtifactResponseBuilder::buildArtifactResponse());
    resp->setInResponseTo(request.getID());
    Issuer* me = IssuerBuilder::buildIssuer();
    me->setName(app.getRelyingParty(recipient)->getXMLString("entityID").second);
    fillStatus(*resp.get(), code, subcode, msg);
    long ret = m_encoder->encode(httpResponse, resp.get(), NULL);
    resp.release();  // freed by encoder
    return make_pair(true,ret);
}
#endif

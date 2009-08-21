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
 * MetadataGenerator.cpp
 *
 * Handler for generating "approximate" metadata based on SP configuration.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "handler/AbstractHandler.h"
#include "handler/RemotedHandler.h"

#ifndef SHIBSP_LITE
# include "metadata/MetadataProviderCriteria.h"
# include <xmltooling/util/PathResolver.h>
#endif

#include <xercesc/framework/LocalFileInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>

using namespace shibsp;
#ifndef SHIBSP_LITE
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
#endif
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

    class SHIBSP_API MetadataGenerator : public AbstractHandler, public RemotedHandler
    {
    public:
        MetadataGenerator(const DOMElement* e, const char* appId);
        virtual ~MetadataGenerator() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, ostream& out);

    private:
        pair<bool,long> processMessage(
            const Application& application,
            const char* handlerURL,
            const char* entityID,
            HTTPResponse& httpResponse
            ) const;

        set<string> m_acl;
#ifndef SHIBSP_LITE
        short m_http,m_https;
        vector<string> m_bases;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL MetadataGeneratorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new MetadataGenerator(p.first, p.second);
    }

};

MetadataGenerator::MetadataGenerator(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".MetadataGenerator"), &g_Blocker)
#ifndef SHIBSP_LITE
        ,m_http(0), m_https(0)
#endif
{
    string address(appId);
    address += getString("Location").second;
    setAddress(address.c_str());
    if (SPConfig::getConfig().isEnabled(SPConfig::InProcess)) {
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
    }

#ifndef SHIBSP_LITE
    static XMLCh EndpointBase[] = UNICODE_LITERAL_12(E,n,d,p,o,i,n,t,B,a,s,e);

    pair<bool,bool> flag = getBool("http");
    if (flag.first)
        m_http = flag.second ? 1 : -1;
    flag = getBool("https");
    if (flag.first)
        m_https = flag.second ? 1 : -1;

    e = XMLHelper::getFirstChildElement(e, EndpointBase);
    while (e) {
        if (e->hasChildNodes()) {
            auto_ptr_char base(e->getFirstChild()->getNodeValue());
            if (base.get() && *base.get())
                m_bases.push_back(base.get());
        }
        e = XMLHelper::getNextSiblingElement(e, EndpointBase);
    }
#endif
}

pair<bool,long> MetadataGenerator::run(SPRequest& request, bool isHandler) const
{
    SPConfig& conf = SPConfig::getConfig();
    if (conf.isEnabled(SPConfig::InProcess)) {
        if (!m_acl.empty() && m_acl.count(request.getRemoteAddr()) == 0) {
            m_log.error("request for metadata blocked from invalid address (%s)", request.getRemoteAddr().c_str());
            istringstream msg("Metadata Request Blocked");
            return make_pair(true,request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_FORBIDDEN));
        }
    }

    try {
        if (conf.isEnabled(SPConfig::OutOfProcess)) {
            // When out of process, we run natively and directly process the message.
            return processMessage(request.getApplication(), request.getHandlerURL(), request.getParameter("entityID"), request);
        }
        else {
            // When not out of process, we remote all the message processing.
            DDF out,in = DDF(m_address.c_str());
            in.addmember("application_id").string(request.getApplication().getId());
            in.addmember("handler_url").string(request.getHandlerURL());
            if (request.getParameter("entityID"))
                in.addmember("entity_id").string(request.getParameter("entityID"));
            DDFJanitor jin(in), jout(out);

            out=request.getServiceProvider().getListenerService()->send(in);
            return unwrap(request, out);
        }
    }
    catch (exception& ex) {
        m_log.error("error while processing request: %s", ex.what());
        istringstream msg("Metadata Request Failed");
        return make_pair(true,request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_ERROR));
    }
}

void MetadataGenerator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const char* hurl=in["handler_url"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for metadata request", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for metadata request, deleted?");
    }
    else if (!hurl) {
        throw ConfigurationException("Missing handler_url parameter in remoted method call.");
    }

    // Wrap a response shim.
    DDF ret(NULL);
    DDFJanitor jout(ret);
    auto_ptr<HTTPResponse> resp(getResponse(ret));

    // Since we're remoted, the result should either be a throw, a false/0 return,
    // which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    processMessage(*app, hurl, in["entity_id"].string(), *resp.get());
    out << ret;
}

pair<bool,long> MetadataGenerator::processMessage(
    const Application& application, const char* handlerURL, const char* entityID, HTTPResponse& httpResponse
    ) const
{
#ifndef SHIBSP_LITE
    m_log.debug("processing metadata request");

    const PropertySet* relyingParty=NULL;
    if (entityID) {
        MetadataProvider* m=application.getMetadataProvider();
        Locker locker(m);
        MetadataProviderCriteria mc(application, entityID);
        relyingParty = application.getRelyingParty(m->getEntityDescriptor(mc).first);
    }
    else {
        relyingParty = &application;
    }

    EntityDescriptor* entity;
    pair<bool,const char*> prop = getString("template");
    if (prop.first) {
        // Load a template to use for our metadata.
        string templ(prop.second);
        XMLToolingConfig::getConfig().getPathResolver()->resolve(templ, PathResolver::XMLTOOLING_CFG_FILE);
        auto_ptr_XMLCh widenit(templ.c_str());
        LocalFileInputSource src(widenit.get());
        Wrapper4InputSource dsrc(&src,false);
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(dsrc);
        XercesJanitor<DOMDocument> docjan(doc);
        auto_ptr<XMLObject> xmlobj(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
        docjan.release();
        entity = dynamic_cast<EntityDescriptor*>(xmlobj.get());
        if (!entity)
            throw ConfigurationException("Template file ($1) did not contain an EntityDescriptor", params(1, templ.c_str()));
        xmlobj.release();
    }
    else {
        entity = EntityDescriptorBuilder::buildEntityDescriptor();
    }

    auto_ptr<EntityDescriptor> wrapper(entity);
    pair<bool,unsigned int> cache = getUnsignedInt("cacheDuration");
    if (cache.first) {
        entity->setCacheDuration(cache.second);
    }
    else {
        cache = getUnsignedInt("validUntil");
        if (cache.first)
            entity->setValidUntil(time(NULL) + cache.second);
    }
    entity->setEntityID(relyingParty->getXMLString("entityID").second);

    SPSSODescriptor* role;
    if (entity->getSPSSODescriptors().empty()) {
        role = SPSSODescriptorBuilder::buildSPSSODescriptor();
        entity->getSPSSODescriptors().push_back(role);
    }
    else {
        role = entity->getSPSSODescriptors().front();
    }

    // Policy flags.
    prop = relyingParty->getString("signing");
    if (prop.first && (!strcmp(prop.second,"true") || !strcmp(prop.second,"front")))
        role->AuthnRequestsSigned(true);
    pair<bool,bool> flagprop = relyingParty->getBool("requireSignedAssertions");
    if (flagprop.first && flagprop.second)
        role->WantAssertionsSigned(true);

    // Ask each handler to generate itself.
    vector<const Handler*> handlers;
    application.getHandlers(handlers);
    for (vector<const Handler*>::const_iterator h = handlers.begin(); h != handlers.end(); ++h) {
        if (m_bases.empty()) {
            if (strncmp(handlerURL, "https", 5) == 0) {
                if (m_https >= 0)
                    (*h)->generateMetadata(*role, handlerURL);
                if (m_http == 1) {
                    string temp(handlerURL);
                    temp.erase(4, 1);
                    (*h)->generateMetadata(*role, temp.c_str());
                }
            }
            else {
                if (m_http >= 0)
                    (*h)->generateMetadata(*role, handlerURL);
                if (m_https == 1) {
                    string temp(handlerURL);
                    temp.insert(temp.begin() + 4, 's');
                    (*h)->generateMetadata(*role, temp.c_str());
                }
            }
        }
        else {
            for (vector<string>::const_iterator b = m_bases.begin(); b != m_bases.end(); ++b)
                (*h)->generateMetadata(*role, b->c_str());
        }
    }

    CredentialResolver* credResolver=application.getCredentialResolver();
    if (credResolver) {
        Locker credLocker(credResolver);
        CredentialCriteria cc;
        prop = relyingParty->getString("keyName");
        if (prop.first)
            cc.getKeyNames().insert(prop.second);
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        vector<const Credential*> creds;
        credResolver->resolve(creds,&cc);
        for (vector<const Credential*>::const_iterator c = creds.begin(); c != creds.end(); ++c) {
            KeyInfo* kinfo = (*c)->getKeyInfo();
            if (kinfo) {
                KeyDescriptor* kd = KeyDescriptorBuilder::buildKeyDescriptor();
                kd->setUse(KeyDescriptor::KEYTYPE_SIGNING);
                kd->setKeyInfo(kinfo);
                role->getKeyDescriptors().push_back(kd);
            }
        }

        cc.setUsage(Credential::ENCRYPTION_CREDENTIAL);
        creds.clear();
        credResolver->resolve(creds,&cc);
        for (vector<const Credential*>::const_iterator c = creds.begin(); c != creds.end(); ++c) {
            KeyInfo* kinfo = (*c)->getKeyInfo();
            if (kinfo) {
                KeyDescriptor* kd = KeyDescriptorBuilder::buildKeyDescriptor();
                kd->setUse(KeyDescriptor::KEYTYPE_ENCRYPTION);
                kd->setKeyInfo(kinfo);
                role->getKeyDescriptors().push_back(kd);
            }
        }
    }

    // Stream for response.
    stringstream s;

    // Self-sign it?
    pair<bool,bool> flag = getBool("signing");
    if (flag.first && flag.second) {
        if (credResolver) {
            Locker credLocker(credResolver);
            // Fill in criteria to use.
            CredentialCriteria cc;
            cc.setUsage(Credential::SIGNING_CREDENTIAL);
            prop = getString("keyName");
            if (prop.first)
                cc.getKeyNames().insert(prop.second);
            pair<bool,const XMLCh*> sigalg = getXMLString("signingAlg");
            pair<bool,const XMLCh*> digalg = getXMLString("digestAlg");
            if (sigalg.first)
                cc.setXMLAlgorithm(sigalg.second);
            const Credential* cred = credResolver->resolve(&cc);
            if (!cred)
                throw XMLSecurityException("Unable to obtain signing credential to use.");

            // Pretty-print it first and then read it back in.
            stringstream pretty;
            XMLHelper::serialize(entity->marshall(), pretty, true);
            DOMDocument* prettydoc = XMLToolingConfig::getConfig().getParser().parse(pretty);
            auto_ptr<XMLObject> prettyentity(XMLObjectBuilder::buildOneFromElement(prettydoc->getDocumentElement(), true));

            Signature* sig = SignatureBuilder::buildSignature();
            dynamic_cast<EntityDescriptor*>(prettyentity.get())->setSignature(sig);
            if (sigalg.first)
                sig->setSignatureAlgorithm(sigalg.second);
            if (digalg.first) {
                opensaml::ContentReference* cr = dynamic_cast<opensaml::ContentReference*>(sig->getContentReference());
                if (cr)
                    cr->setDigestAlgorithm(digalg.second);
            }

            // Sign while marshalling.
            vector<Signature*> sigs(1,sig);
            prettyentity->marshall(prettydoc,&sigs,cred);
            s << *prettyentity;
        }
        else {
            throw FatalProfileException("Can't self-sign metadata, no credential resolver found.");
        }
    }
    else {
        // Pretty-print it directly to client.
        XMLHelper::serialize(entity->marshall(), s, true);
    }

    prop = getString("mimeType");
    httpResponse.setContentType(prop.first ? prop.second : "application/samlmetadata+xml");
    return make_pair(true, httpResponse.sendResponse(s));
#else
    return make_pair(false,0L);
#endif
}

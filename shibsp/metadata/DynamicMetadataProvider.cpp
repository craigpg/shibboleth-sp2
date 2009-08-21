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
 * DynamicMetadataProvider.cpp
 *
 * Advanced implementation of a dynamic caching MetadataProvider.
 */

#include "internal.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "metadata/MetadataProviderCriteria.h"

#include <saml/version.h>
#include <saml/binding/SAMLArtifact.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/DynamicMetadataProvider.h>

#include <xmltooling/logging.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/security/X509TrustEngine.h>
#include <xmltooling/soap/HTTPSOAPTransport.h>
#include <xmltooling/util/XMLHelper.h>

#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    class SAML_DLLLOCAL DummyCredentialResolver : public CredentialResolver
    {
    public:
        DummyCredentialResolver() {}
        ~DummyCredentialResolver() {}

        Lockable* lock() {return this;}
        void unlock() {}

        const Credential* resolve(const CredentialCriteria* criteria=NULL) const {return NULL;}
        vector<const Credential*>::size_type resolve(
            vector<const Credential*>& results, const CredentialCriteria* criteria=NULL
            ) const {return 0;}
    };

    class SHIBSP_DLLLOCAL DynamicMetadataProvider : public saml2md::DynamicMetadataProvider
    {
    public:
        DynamicMetadataProvider(const xercesc::DOMElement* e=NULL);

        virtual ~DynamicMetadataProvider() {
            delete m_trust;
        }

    protected:
        saml2md::EntityDescriptor* resolve(const saml2md::MetadataProvider::Criteria& criteria) const;

    private:
        bool m_verifyHost,m_ignoreTransport;
        X509TrustEngine* m_trust;
    };


    saml2md::MetadataProvider* SHIBSP_DLLLOCAL DynamicMetadataProviderFactory(const DOMElement* const & e)
    {
        return new DynamicMetadataProvider(e);
    }

    static const XMLCh ignoreTransport[] =  UNICODE_LITERAL_15(i,g,n,o,r,e,T,r,a,n,s,p,o,r,t);
    static const XMLCh _TrustEngine[] =     UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
    static const XMLCh type[] =             UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh verifyHost[] =       UNICODE_LITERAL_10(v,e,r,i,f,y,H,o,s,t);
};

DynamicMetadataProvider::DynamicMetadataProvider(const DOMElement* e)
    : saml2md::DynamicMetadataProvider(e), m_verifyHost(true), m_ignoreTransport(false), m_trust(NULL)
{
    const XMLCh* flag = e ? e->getAttributeNS(NULL, verifyHost) : NULL;
    if (flag && (*flag == chLatin_f || *flag == chDigit_0))
        m_verifyHost = false;
    flag = e ? e->getAttributeNS(NULL, ignoreTransport) : NULL;
    if (flag && (*flag == chLatin_t || *flag == chDigit_1)) {
        m_ignoreTransport = true;
        return;
    }

    e = e ? XMLHelper::getFirstChildElement(e, _TrustEngine) : NULL;
    auto_ptr_char t2(e ? e->getAttributeNS(NULL,type) : NULL);
    if (t2.get()) {
        TrustEngine* trust = XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(t2.get(),e);
        if (!(m_trust = dynamic_cast<X509TrustEngine*>(trust))) {
            delete trust;
            throw ConfigurationException("DynamicMetadataProvider requires an X509TrustEngine plugin.");
        }
        return;
    }

    throw ConfigurationException("DynamicMetadataProvider requires an X509TrustEngine plugin unless ignoreTransport is true.");
}

saml2md::EntityDescriptor* DynamicMetadataProvider::resolve(const saml2md::MetadataProvider::Criteria& criteria) const
{
#ifdef _DEBUG
    xmltooling::NDC("resolve");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".MetadataProvider.Dynamic");

    string name;
    if (criteria.entityID_ascii) {
        name = criteria.entityID_ascii;
    }
    else if (criteria.entityID_unicode) {
        auto_ptr_char temp(criteria.entityID_unicode);
        name = temp.get();
    }
    else if (criteria.artifact) {
        throw saml2md::MetadataException("Unable to resolve metadata dynamically from an artifact.");
    }

    // Establish networking properties based on calling application.
    const MetadataProviderCriteria* mpc = dynamic_cast<const MetadataProviderCriteria*>(&criteria);
    if (!mpc)
        throw saml2md::MetadataException("Dynamic MetadataProvider requires Shibboleth-aware lookup criteria, check calling code.");
    const PropertySet* relyingParty;
    if (criteria.entityID_unicode)
        relyingParty = mpc->application.getRelyingParty(criteria.entityID_unicode);
    else {
        auto_ptr_XMLCh temp2(name.c_str());
        relyingParty = mpc->application.getRelyingParty(temp2.get());
    }

    // Prepare a transport object addressed appropriately.
    SOAPTransport::Address addr(relyingParty->getString("entityID").second, name.c_str(), name.c_str());
    const char* pch = strchr(addr.m_endpoint,':');
    if (!pch)
        throw IOException("entityID was not a URL.");
    string scheme(addr.m_endpoint, pch-addr.m_endpoint);
    SOAPTransport* transport=NULL;
    try {
        transport = XMLToolingConfig::getConfig().SOAPTransportManager.newPlugin(scheme.c_str(), addr);
    }
    catch (exception& ex) {
        log.error("exception while building transport object to resolve URL: %s", ex.what());
        throw IOException("Unable to resolve entityID with a known transport protocol.");
    }
    auto_ptr<SOAPTransport> transportwrapper(transport);

    // Apply properties as directed.
    transport->setVerifyHost(m_verifyHost);
    DummyCredentialResolver dcr;
    if (m_trust && !transport->setTrustEngine(m_trust, &dcr))
        throw IOException("Unable to install X509TrustEngine into metadata resolver.");

    Locker credlocker(NULL, false);
    CredentialResolver* credResolver = NULL;
    pair<bool,const char*> authType=relyingParty->getString("authType");
    if (!authType.first || !strcmp(authType.second,"TLS")) {
        credResolver = mpc->application.getCredentialResolver();
        if (credResolver)
            credlocker.assign(credResolver);
        if (credResolver) {
            CredentialCriteria cc;
            cc.setUsage(Credential::TLS_CREDENTIAL);
            authType = relyingParty->getString("keyName");
            if (authType.first)
                cc.getKeyNames().insert(authType.second);
            const Credential* cred = credResolver->resolve(&cc);
            cc.getKeyNames().clear();
            if (cred) {
                if (!transport->setCredential(cred))
                    log.error("failed to load Credential into metadata resolver");
            }
            else {
                log.error("no TLS credential supplied");
            }
        }
        else {
            log.error("no CredentialResolver available for TLS");
        }
    }
    else {
        SOAPTransport::transport_auth_t type=SOAPTransport::transport_auth_none;
        pair<bool,const char*> username=relyingParty->getString("authUsername");
        pair<bool,const char*> password=relyingParty->getString("authPassword");
        if (!username.first || !password.first)
            log.error("transport authType (%s) specified but authUsername or authPassword was missing", authType.second);
        else if (!strcmp(authType.second,"basic"))
            type = SOAPTransport::transport_auth_basic;
        else if (!strcmp(authType.second,"digest"))
            type = SOAPTransport::transport_auth_digest;
        else if (!strcmp(authType.second,"ntlm"))
            type = SOAPTransport::transport_auth_ntlm;
        else if (!strcmp(authType.second,"gss"))
            type = SOAPTransport::transport_auth_gss;
        else if (strcmp(authType.second,"none"))
            log.error("unknown authType (%s) specified for RelyingParty", authType.second);
        if (type > SOAPTransport::transport_auth_none) {
            if (transport->setAuth(type,username.second,password.second))
                log.debug("configured for transport authentication (method=%s, username=%s)", authType.second, username.second);
            else
                log.error("failed to configure transport authentication (method=%s)", authType.second);
        }
    }

    pair<bool,unsigned int> timeout = relyingParty->getUnsignedInt("connectTimeout");
    transport->setConnectTimeout(timeout.first ? timeout.second : 10);
    timeout = relyingParty->getUnsignedInt("timeout");
    transport->setTimeout(timeout.first ? timeout.second : 20);
    mpc->application.getServiceProvider().setTransportOptions(*transport);

    HTTPSOAPTransport* http = dynamic_cast<HTTPSOAPTransport*>(transport);
    if (http) {
        pair<bool,bool> flag = relyingParty->getBool("chunkedEncoding");
        http->useChunkedEncoding(flag.first && flag.second);
        http->setRequestHeader("Xerces-C", XERCES_FULLVERSIONDOT);
        http->setRequestHeader("XML-Security-C", XSEC_FULLVERSIONDOT);
        http->setRequestHeader("OpenSAML-C", OPENSAML_FULLVERSIONDOT);
        http->setRequestHeader("User-Agent", PACKAGE_NAME);
        http->setRequestHeader(PACKAGE_NAME, PACKAGE_VERSION);
    }

    try {
        // Use a NULL stream to trigger a body-less "GET" operation.
        transport->send();
        istream& msg = transport->receive();

        DOMDocument* doc=NULL;
        StreamInputSource src(msg, "DynamicMetadataProvider");
        Wrapper4InputSource dsrc(&src,false);
        if (m_validate)
            doc=XMLToolingConfig::getConfig().getValidatingParser().parse(dsrc);
        else
            doc=XMLToolingConfig::getConfig().getParser().parse(dsrc);

        // Wrap the document for now.
        XercesJanitor<DOMDocument> docjanitor(doc);

        // Unmarshall objects, binding the document.
        auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
        docjanitor.release();

        // Make sure it's metadata.
        saml2md::EntityDescriptor* entity = dynamic_cast<saml2md::EntityDescriptor*>(xmlObject.get());
        if (!entity) {
            throw saml2md::MetadataException(
                "Root of metadata instance not recognized: $1", params(1,xmlObject->getElementQName().toString().c_str())
                );
        }
        xmlObject.release();
        return entity;
    }
    catch (XMLException& e) {
        auto_ptr_char msg(e.getMessage());
        log.error("Xerces error while resolving entityID (%s): %s", name.c_str(), msg.get());
        throw saml2md::MetadataException(msg.get());
    }
}

/*
 *  Copyright 2009 Internet2
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
 * SimpleAggregationAttributeResolver.cpp
 *
 * AttributeResolver based on SAML queries to third-party AA sources.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "attribute/NameIDAttribute.h"
#include "attribute/filtering/AttributeFilter.h"
#include "attribute/filtering/BasicFilteringContext.h"
#include "attribute/resolver/AttributeExtractor.h"
#include "attribute/resolver/AttributeResolver.h"
#include "attribute/resolver/ResolutionContext.h"
#include "binding/SOAPClient.h"
#include "metadata/MetadataProviderCriteria.h"
#include "security/SecurityPolicy.h"
#include "util/SPConstants.h"

#include <saml/exceptions.h>
#include <saml/SAMLConfig.h>
#include <saml/saml2/binding/SAML2SOAPClient.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/TrustEngine.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL SimpleAggregationContext : public ResolutionContext
    {
    public:
        SimpleAggregationContext(const Application& application, const Session& session)
            : m_app(application),
              m_session(&session),
              m_nameid(NULL),
              m_class(XMLString::transcode(session.getAuthnContextClassRef())),
              m_decl(XMLString::transcode(session.getAuthnContextDeclRef())),
              m_inputTokens(NULL),
              m_inputAttributes(NULL) {
        }

        SimpleAggregationContext(
            const Application& application,
            const NameID* nameid=NULL,
            const XMLCh* authncontext_class=NULL,
            const XMLCh* authncontext_decl=NULL,
            const vector<const opensaml::Assertion*>* tokens=NULL,
            const vector<shibsp::Attribute*>* attributes=NULL
            ) : m_app(application),
                m_session(NULL),
                m_nameid(nameid),
                m_class(const_cast<XMLCh*>(authncontext_class)),
                m_decl(const_cast<XMLCh*>(authncontext_decl)),
                m_inputTokens(tokens),
                m_inputAttributes(attributes) {
        }

        ~SimpleAggregationContext() {
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<shibsp::Attribute>());
            for_each(m_assertions.begin(), m_assertions.end(), xmltooling::cleanup<opensaml::Assertion>());
            if (m_session) {
                XMLString::release(&m_class);
                XMLString::release(&m_decl);
            }
        }

        const Application& getApplication() const {
            return m_app;
        }
        const NameID* getNameID() const {
            return m_session ? m_session->getNameID() : m_nameid;
        }
        const XMLCh* getClassRef() const {
            return m_class;
        }
        const XMLCh* getDeclRef() const {
            return m_decl;
        }
        const Session* getSession() const {
            return m_session;
        }
        const vector<shibsp::Attribute*>* getInputAttributes() const {
            return m_inputAttributes;
        }
        const vector<const opensaml::Assertion*>* getInputTokens() const {
            return m_inputTokens;
        }
        vector<shibsp::Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_assertions;
        }

    private:
        const Application& m_app;
        const Session* m_session;
        const NameID* m_nameid;
        XMLCh* m_class;
        XMLCh* m_decl;
        const vector<const opensaml::Assertion*>* m_inputTokens;
        const vector<shibsp::Attribute*>* m_inputAttributes;
        vector<shibsp::Attribute*> m_attributes;
        vector<opensaml::Assertion*> m_assertions;
    };

    class SHIBSP_DLLLOCAL SimpleAggregationResolver : public AttributeResolver
    {
    public:
        SimpleAggregationResolver(const DOMElement* e);
        ~SimpleAggregationResolver() {
            delete m_trust;
            delete m_metadata;
            for_each(m_designators.begin(), m_designators.end(), xmltooling::cleanup<saml2::Attribute>());
        }

        Lockable* lock() {return this;}
        void unlock() {}

        ResolutionContext* createResolutionContext(
            const Application& application,
            const EntityDescriptor* issuer,
            const XMLCh* protocol,
            const NameID* nameid=NULL,
            const XMLCh* authncontext_class=NULL,
            const XMLCh* authncontext_decl=NULL,
            const vector<const opensaml::Assertion*>* tokens=NULL,
            const vector<shibsp::Attribute*>* attributes=NULL
            ) const {
            return new SimpleAggregationContext(application,nameid,authncontext_class,authncontext_decl,tokens,attributes);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new SimpleAggregationContext(application,session);
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const {
            // Nothing to do, only the extractor would actually generate them.
        }

    private:
        bool doQuery(SimpleAggregationContext& ctx, const char* entityID, const NameID* name) const;

        Category& m_log;
        string m_policyId;
        bool m_subjectMatch;
        vector<string> m_attributeIds;
        xstring m_format;
        MetadataProvider* m_metadata;
        TrustEngine* m_trust;
        vector<saml2::Attribute*> m_designators;
        vector< pair<string,bool> > m_sources;
    };

    AttributeResolver* SHIBSP_DLLLOCAL SimpleAggregationResolverFactory(const DOMElement* const & e)
    {
        return new SimpleAggregationResolver(e);
    }

    static const XMLCh attributeId[] =          UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,d);
    static const XMLCh Entity[] =               UNICODE_LITERAL_6(E,n,t,i,t,y);
    static const XMLCh EntityReference[] =      UNICODE_LITERAL_15(E,n,t,i,t,y,R,e,f,e,r,e,n,c,e);
    static const XMLCh format[] =               UNICODE_LITERAL_6(f,o,r,m,a,t);
    static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
    static const XMLCh policyId[] =             UNICODE_LITERAL_8(p,o,l,i,c,y,I,d);
    static const XMLCh subjectMatch[] =         UNICODE_LITERAL_12(s,u,b,j,e,c,t,M,a,t,c,h);
    static const XMLCh _TrustEngine[] =         UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
};

SimpleAggregationResolver::SimpleAggregationResolver(const DOMElement* e)
    : m_log(Category::getInstance(SHIBSP_LOGCAT".AttributeResolver.SimpleAggregation")), m_subjectMatch(false), m_metadata(NULL), m_trust(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("SimpleAggregationResolver");
#endif

    const XMLCh* pid = e ? e->getAttributeNS(NULL, policyId) : NULL;
    if (pid && *pid) {
        auto_ptr_char temp(pid);
        m_policyId = temp.get();
    }

    pid = e ? e->getAttributeNS(NULL, subjectMatch) : NULL;
    if (pid && (*pid == chLatin_t || *pid == chDigit_1))
        m_subjectMatch = true;

    pid = e ? e->getAttributeNS(NULL, attributeId) : NULL;
    if (pid && *pid) {
        char* dup = XMLString::transcode(pid);
        char* pos;
        char* start = dup;
        while (start && *start) {
            while (*start && isspace(*start))
                start++;
            if (!*start)
                break;
            pos = strchr(start,' ');
            if (pos)
                *pos=0;
            m_attributeIds.push_back(start);
            start = pos ? pos+1 : NULL;
        }
        XMLString::release(&dup);

        pid = e->getAttributeNS(NULL, format);
        if (pid && *pid)
            m_format = pid;
    }

    DOMElement* child = XMLHelper::getFirstChildElement(e, _MetadataProvider);
    if (child) {
        auto_ptr_char type(child->getAttributeNS(NULL, _type));
        if (!type.get() || !*type.get())
            throw ConfigurationException("MetadataProvider element missing type attribute.");
        m_log.info("building MetadataProvider of type %s...", type.get());
        auto_ptr<MetadataProvider> mp(SAMLConfig::getConfig().MetadataProviderManager.newPlugin(type.get(), child));
        mp->init();
        m_metadata = mp.release();
    }

    child = XMLHelper::getFirstChildElement(e,  _TrustEngine);
    if (child) {
        try {
            auto_ptr_char type(child->getAttributeNS(NULL, _type));
            if (!type.get() || !*type.get())
                throw ConfigurationException("TrustEngine element missing type attribute.");
            m_log.info("building TrustEngine of type %s...", type.get());
            m_trust = XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(type.get(), child);
        }
        catch (exception&) {
            delete m_metadata;
            throw;
        }
    }

    child = XMLHelper::getFirstChildElement(e);
    while (child) {
        if (child->hasChildNodes() && XMLString::equals(child->getLocalName(), Entity)) {
            pid = child->getFirstChild()->getNodeValue();
            if (pid && *pid) {
                auto_ptr_char tpid(pid);
                m_sources.push_back(pair<string,bool>(tpid.get(),true));
            }
        }
        else if (child->hasChildNodes() && XMLString::equals(child->getLocalName(), EntityReference)) {
            pid = child->getFirstChild()->getNodeValue();
            if (pid && *pid) {
                auto_ptr_char tpid(pid);
                m_sources.push_back(pair<string,bool>(tpid.get(),false));
            }
        }
        else if (XMLHelper::isNodeNamed(child, samlconstants::SAML20_NS, saml2::Attribute::LOCAL_NAME)) {
            try {
                auto_ptr<XMLObject> obj(saml2::AttributeBuilder::buildOneFromElement(child));
                saml2::Attribute* down = dynamic_cast<saml2::Attribute*>(obj.get());
                if (down) {
                    m_designators.push_back(down);
                    obj.release();
                }
            }
            catch (exception& ex) {
                m_log.error("exception loading attribute designator: %s", ex.what());
            }
        }
        child = XMLHelper::getNextSiblingElement(child);
    }
}

bool SimpleAggregationResolver::doQuery(SimpleAggregationContext& ctx, const char* entityID, const NameID* name) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doQuery");
#endif
    const Application& application = ctx.getApplication();
    MetadataProviderCriteria mc(application, entityID, &AttributeAuthorityDescriptor::ELEMENT_QNAME, samlconstants::SAML20P_NS);
    Locker mlocker(m_metadata);
    const AttributeAuthorityDescriptor* AA=NULL;
    pair<const EntityDescriptor*,const RoleDescriptor*> mdresult =
        (m_metadata ? m_metadata : application.getMetadataProvider())->getEntityDescriptor(mc);
    if (!mdresult.first) {
        m_log.warn("unable to locate metadata for provider (%s)", entityID);
        return false;
    }
    else if (!(AA=dynamic_cast<const AttributeAuthorityDescriptor*>(mdresult.second))) {
        m_log.warn("no SAML 2 AttributeAuthority role found in metadata for (%s)", entityID);
        return false;
    }

    const PropertySet* relyingParty = application.getRelyingParty(mdresult.first);

    // Locate policy key.
    const char* policyId = m_policyId.empty() ? application.getString("policyId").second : m_policyId.c_str();

    // Access policy properties.
    const PropertySet* settings = application.getServiceProvider().getPolicySettings(policyId);
    pair<bool,bool> validate = settings->getBool("validate");

    pair<bool,bool> signedAssertions = relyingParty->getBool("requireSignedAssertions");
    pair<bool,const char*> encryption = relyingParty->getString("encryption");

    shibsp::SecurityPolicy policy(application, NULL, validate.first && validate.second, policyId);
    if (m_metadata)
        policy.setMetadataProvider(m_metadata);
    if (m_trust)
        policy.setTrustEngine(m_trust);
    policy.getAudiences().push_back(relyingParty->getXMLString("entityID").second);

    MetadataCredentialCriteria mcc(*AA);
    shibsp::SOAPClient soaper(policy);

    auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
    saml2p::StatusResponseType* srt=NULL;
    const vector<AttributeService*>& endpoints=AA->getAttributeServices();
    for (vector<AttributeService*>::const_iterator ep=endpoints.begin(); !srt && ep!=endpoints.end(); ++ep) {
        if (!XMLString::equals((*ep)->getBinding(),binding.get())  || !(*ep)->getLocation())
            continue;
        auto_ptr_char loc((*ep)->getLocation());
        try {
            auto_ptr<saml2::Subject> subject(saml2::SubjectBuilder::buildSubject());

            // Encrypt the NameID?
            if (encryption.first && (!strcmp(encryption.second, "true") || !strcmp(encryption.second, "back"))) {
                auto_ptr<EncryptedID> encrypted(EncryptedIDBuilder::buildEncryptedID());
                encrypted->encrypt(
                    *name,
                    *(policy.getMetadataProvider()),
                    mcc,
                    false,
                    relyingParty->getXMLString("encryptionAlg").second
                    );
                subject->setEncryptedID(encrypted.release());
            }
            else {
                subject->setNameID(name->cloneNameID());
            }

            saml2p::AttributeQuery* query = saml2p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject.release());
            Issuer* iss = IssuerBuilder::buildIssuer();
            iss->setName(relyingParty->getXMLString("entityID").second);
            query->setIssuer(iss);
            for (vector<saml2::Attribute*>::const_iterator ad = m_designators.begin(); ad!=m_designators.end(); ++ad)
                query->getAttributes().push_back((*ad)->cloneAttribute());

            SAML2SOAPClient client(soaper, false);
            client.sendSAML(query, application.getId(), mcc, loc.get());
            srt = client.receiveSAML();
        }
        catch (exception& ex) {
            m_log.error("exception during SAML query to %s: %s", loc.get(), ex.what());
            soaper.reset();
        }
    }

    if (!srt) {
        m_log.error("unable to obtain a SAML response from attribute authority (%s)", entityID);
        return false;
    }

    auto_ptr<saml2p::StatusResponseType> wrapper(srt);

    saml2p::Response* response = dynamic_cast<saml2p::Response*>(srt);
    if (!response) {
        m_log.error("message was not a samlp:Response");
        return true;
    }
    else if (!response->getStatus() || !response->getStatus()->getStatusCode() ||
            !XMLString::equals(response->getStatus()->getStatusCode()->getValue(), saml2p::StatusCode::SUCCESS)) {
        m_log.error("attribute authority (%s) returned a SAML error", entityID);
        return true;
    }

    saml2::Assertion* newtoken = NULL;
    const vector<saml2::Assertion*>& assertions = const_cast<const saml2p::Response*>(response)->getAssertions();
    if (assertions.empty()) {
        // Check for encryption.
        const vector<saml2::EncryptedAssertion*>& encassertions =
            const_cast<const saml2p::Response*>(response)->getEncryptedAssertions();
        if (encassertions.empty()) {
            m_log.warn("response from attribute authority was empty");
            return true;
        }
        else if (encassertions.size() > 1) {
            m_log.warn("simple resolver only supports one assertion in the query response");
        }

        CredentialResolver* cr=application.getCredentialResolver();
        if (!cr) {
            m_log.warn("found encrypted assertion, but no CredentialResolver was available");
            return true;
        }

        // Attempt to decrypt it.
        try {
            Locker credlocker(cr);
            auto_ptr<XMLObject> tokenwrapper(encassertions.front()->decrypt(*cr, relyingParty->getXMLString("entityID").second, &mcc));
            newtoken = dynamic_cast<saml2::Assertion*>(tokenwrapper.get());
            if (newtoken) {
                tokenwrapper.release();
                if (m_log.isDebugEnabled())
                    m_log.debugStream() << "decrypted Assertion: " << *newtoken << logging::eol;
            }
        }
        catch (exception& ex) {
            m_log.error(ex.what());
        }
        if (newtoken) {
            // Free the Response now, so we know this is a stand-alone token later.
            delete wrapper.release();
        }
        else {
            // Nothing decrypted, should already be logged.
            return true;
        }
    }
    else {
        if (assertions.size() > 1)
            m_log.warn("simple resolver only supports one assertion in the query response");
        newtoken = assertions.front();
    }

    if (!newtoken->getSignature() && signedAssertions.first && signedAssertions.second) {
        m_log.error("assertion unsigned, rejecting it based on signedAssertions policy");
        if (!wrapper.get())
            delete newtoken;
        return true;
    }

    try {
        // We're going to insist that the assertion issuer is the same as the peer.
        // Reset the policy's message bits and extract them from the assertion.
        policy.reset(true);
        policy.setMessageID(newtoken->getID());
        policy.setIssueInstant(newtoken->getIssueInstantEpoch());
        policy.setIssuer(newtoken->getIssuer());
        policy.evaluate(*newtoken);

        // Now we can check the security status of the policy.
        if (!policy.isAuthenticated())
            throw SecurityPolicyException("Security of SAML 2.0 query result not established.");

        if (m_subjectMatch) {
            // Check for subject match.
            bool ownedName = false;
            NameID* respName = newtoken->getSubject() ? newtoken->getSubject()->getNameID() : NULL;
            if (!respName) {
                // Check for encryption.
                EncryptedID* encname = newtoken->getSubject() ? newtoken->getSubject()->getEncryptedID() : NULL;
                if (encname) {
                    CredentialResolver* cr=application.getCredentialResolver();
                    if (!cr)
                        m_log.warn("found EncryptedID, but no CredentialResolver was available");
                    else {
                        Locker credlocker(cr);
                        auto_ptr<XMLObject> decryptedID(encname->decrypt(*cr, relyingParty->getXMLString("entityID").second, &mcc));
                        respName = dynamic_cast<NameID*>(decryptedID.get());
                        if (respName) {
                            ownedName = true;
                            decryptedID.release();
                            if (m_log.isDebugEnabled())
                                m_log.debugStream() << "decrypted NameID: " << *respName << logging::eol;
                        }
                    }
                }
            }

            auto_ptr<NameID> nameIDwrapper(ownedName ? respName : NULL);

            if (!respName || !XMLString::equals(respName->getName(), name->getName()) ||
                !XMLString::equals(respName->getFormat(), name->getFormat()) ||
                !XMLString::equals(respName->getNameQualifier(), name->getNameQualifier()) ||
                !XMLString::equals(respName->getSPNameQualifier(), name->getSPNameQualifier())) {
                if (respName)
                    m_log.warnStream() << "ignoring Assertion without strongly matching NameID in Subject: " <<
                        *respName << logging::eol;
                else
                    m_log.warn("ignoring Assertion without NameID in Subject");
                if (!wrapper.get())
                    delete newtoken;
                return true;
            }
        }
    }
    catch (exception& ex) {
        m_log.error("assertion failed policy validation: %s", ex.what());
        if (!wrapper.get())
            delete newtoken;
        return true;
    }

    if (wrapper.get()) {
        newtoken->detach();
        wrapper.release();  // detach blows away the Response
    }
    ctx.getResolvedAssertions().push_back(newtoken);

    // Finally, extract and filter the result.
    try {
        AttributeExtractor* extractor = application.getAttributeExtractor();
        if (extractor) {
            Locker extlocker(extractor);
            extractor->extractAttributes(application, AA, *newtoken, ctx.getResolvedAttributes());
        }

        AttributeFilter* filter = application.getAttributeFilter();
        if (filter) {
            BasicFilteringContext fc(application, ctx.getResolvedAttributes(), AA, ctx.getClassRef(), ctx.getDeclRef());
            Locker filtlocker(filter);
            filter->filterAttributes(fc, ctx.getResolvedAttributes());
        }
    }
    catch (exception& ex) {
        m_log.error("caught exception extracting/filtering attributes from query result: %s", ex.what());
        for_each(ctx.getResolvedAttributes().begin(), ctx.getResolvedAttributes().end(), xmltooling::cleanup<shibsp::Attribute>());
        ctx.getResolvedAttributes().clear();
    }

    return true;
}

void SimpleAggregationResolver::resolveAttributes(ResolutionContext& ctx) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("resolveAttributes");
#endif

    SimpleAggregationContext& qctx = dynamic_cast<SimpleAggregationContext&>(ctx);

    // First we manufacture the appropriate NameID to use.
    NameID* n=NULL;
    for (vector<string>::const_iterator a = m_attributeIds.begin(); !n && a != m_attributeIds.end(); ++a) {
        const Attribute* attr=NULL;
        if (qctx.getSession()) {
            // Input attributes should be available via multimap.
            pair<multimap<string,const Attribute*>::const_iterator, multimap<string,const Attribute*>::const_iterator> range =
                qctx.getSession()->getIndexedAttributes().equal_range(*a);
            for (; !attr && range.first != range.second; ++range.first) {
                if (range.first->second->valueCount() > 0)
                    attr = range.first->second;
            }
        }
        else if (qctx.getInputAttributes()) {
            // Have to loop over unindexed set.
            const vector<Attribute*>* matches = qctx.getInputAttributes();
            for (vector<Attribute*>::const_iterator match = matches->begin(); !attr && match != matches->end(); ++match) {
                if (*a == (*match)->getId() && (*match)->valueCount() > 0)
                    attr = *match;
            }
        }

        if (attr) {
            m_log.debug("using input attribute (%s) as identifier for queries", attr->getId());
            n = NameIDBuilder::buildNameID();
            const NameIDAttribute* down = dynamic_cast<const NameIDAttribute*>(attr);
            if (down) {
                // We can create a NameID directly from the source material.
                const NameIDAttribute::Value& v = down->getValues().front();
                XMLCh* val = fromUTF8(v.m_Name.c_str());
                n->setName(val);
                delete[] val;
                if (!v.m_Format.empty()) {
                    val = fromUTF8(v.m_Format.c_str());
                    n->setFormat(val);
                    delete[] val;
                }
                if (!v.m_NameQualifier.empty()) {
                    val = fromUTF8(v.m_NameQualifier.c_str());
                    n->setNameQualifier(val);
                    delete[] val;
                }
                if (!v.m_SPNameQualifier.empty()) {
                    val = fromUTF8(v.m_SPNameQualifier.c_str());
                    n->setSPNameQualifier(val);
                    delete[] val;
                }
                if (!v.m_SPProvidedID.empty()) {
                    val = fromUTF8(v.m_SPProvidedID.c_str());
                    n->setSPProvidedID(val);
                    delete[] val;
                }
            }
            else {
                // We have to mock up the NameID.
                XMLCh* val = fromUTF8(attr->getSerializedValues().front().c_str());
                n->setName(val);
                delete[] val;
                if (!m_format.empty())
                    n->setFormat(m_format.c_str());
            }
        }
    }

    if (!n) {
        if (qctx.getNameID() && m_attributeIds.empty()) {
            m_log.debug("using authenticated NameID as identifier for queries");
        }
        else {
            m_log.warn("unable to resolve attributes, no suitable query identifier found");
            return;
        }
    }

    auto_ptr<NameID> wrapper(n);

    set<string> history;

    // We have a master loop over all the possible sources of material.
    for (vector< pair<string,bool> >::const_iterator source = m_sources.begin(); source != m_sources.end(); ++source) {
        if (source->second) {
            // A literal entityID to query.
            if (history.count(source->first) == 0) {
                m_log.debug("issuing SAML query to (%s)", source->first.c_str());
                doQuery(qctx, source->first.c_str(), n ? n : qctx.getNameID());
                history.insert(source->first);
            }
            else {
                m_log.debug("skipping previously queried attribute source (%s)", source->first.c_str());
            }
        }
        else {
            m_log.debug("using attribute sources referenced in attribute (%s)", source->first.c_str());
            if (qctx.getSession()) {
                // Input attributes should be available via multimap.
                pair<multimap<string,const Attribute*>::const_iterator, multimap<string,const Attribute*>::const_iterator> range =
                    qctx.getSession()->getIndexedAttributes().equal_range(source->first);
                for (; range.first != range.second; ++range.first) {
                    const vector<string>& links = range.first->second->getSerializedValues();
                    for (vector<string>::const_iterator link = links.begin(); link != links.end(); ++link) {
                        if (history.count(*link) == 0) {
                            m_log.debug("issuing SAML query to (%s)", link->c_str());
                            doQuery(qctx, link->c_str(), n ? n : qctx.getNameID());
                            history.insert(*link);
                        }
                        else {
                            m_log.debug("skipping previously queried attribute source (%s)", link->c_str());
                        }
                    }
                }
            }
            else if (qctx.getInputAttributes()) {
                // Have to loop over unindexed set.
                const vector<Attribute*>* matches = qctx.getInputAttributes();
                for (vector<Attribute*>::const_iterator match = matches->begin(); match != matches->end(); ++match) {
                    if (source->first == (*match)->getId()) {
                        const vector<string>& links = (*match)->getSerializedValues();
                        for (vector<string>::const_iterator link = links.begin(); link != links.end(); ++link) {
                            if (history.count(*link) == 0) {
                                m_log.debug("issuing SAML query to (%s)", link->c_str());
                                doQuery(qctx, link->c_str(), n ? n : qctx.getNameID());
                                history.insert(*link);
                            }
                            else {
                                m_log.debug("skipping previously queried attribute source (%s)", link->c_str());
                            }
                        }
                    }
                }
            }
        }
    }
}

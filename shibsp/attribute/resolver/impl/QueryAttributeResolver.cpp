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
 * QueryAttributeResolver.cpp
 *
 * AttributeResolver based on SAML queries.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "attribute/Attribute.h"
#include "attribute/filtering/AttributeFilter.h"
#include "attribute/filtering/BasicFilteringContext.h"
#include "attribute/resolver/AttributeExtractor.h"
#include "attribute/resolver/AttributeResolver.h"
#include "attribute/resolver/ResolutionContext.h"
#include "binding/SOAPClient.h"
#include "metadata/MetadataProviderCriteria.h"
#include "util/SPConstants.h"

#include <saml/exceptions.h>
#include <saml/binding/SecurityPolicy.h>
#include <saml/saml1/binding/SAML1SOAPClient.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml2/binding/SAML2SOAPClient.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml1;
using namespace opensaml::saml1p;
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL QueryContext : public ResolutionContext
    {
    public:
        QueryContext(const Application& application, const Session& session)
                : m_query(true), m_app(application), m_session(&session), m_metadata(NULL), m_entity(NULL), m_nameid(NULL) {
            m_protocol = XMLString::transcode(session.getProtocol());
            m_class = XMLString::transcode(session.getAuthnContextClassRef());
            m_decl = XMLString::transcode(session.getAuthnContextDeclRef());
        }

        QueryContext(
            const Application& application,
            const EntityDescriptor* issuer,
            const XMLCh* protocol,
            const NameID* nameid=NULL,
            const XMLCh* authncontext_class=NULL,
            const XMLCh* authncontext_decl=NULL,
            const vector<const opensaml::Assertion*>* tokens=NULL
            ) : m_query(true), m_app(application), m_session(NULL), m_metadata(NULL), m_entity(issuer),
                m_protocol(protocol), m_nameid(nameid), m_class(authncontext_class), m_decl(authncontext_decl) {

            if (tokens) {
                for (vector<const opensaml::Assertion*>::const_iterator t = tokens->begin(); t!=tokens->end(); ++t) {
                    const saml2::Assertion* token2 = dynamic_cast<const saml2::Assertion*>(*t);
                    if (token2 && !token2->getAttributeStatements().empty()) {
                        m_query = false;
                    }
                    else {
                        const saml1::Assertion* token1 = dynamic_cast<const saml1::Assertion*>(*t);
                        if (token1 && !token1->getAttributeStatements().empty()) {
                            m_query = false;
                        }
                    }
                }
            }
        }

        ~QueryContext() {
            if (m_session) {
                XMLString::release((XMLCh**)&m_protocol);
                XMLString::release((XMLCh**)&m_class);
                XMLString::release((XMLCh**)&m_decl);
            }
            if (m_metadata)
                m_metadata->unlock();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<shibsp::Attribute>());
            for_each(m_assertions.begin(), m_assertions.end(), xmltooling::cleanup<opensaml::Assertion>());
        }

        bool doQuery() const {
            return m_query;
        }

        const Application& getApplication() const {
            return m_app;
        }
        const EntityDescriptor* getEntityDescriptor() const {
            if (m_entity)
                return m_entity;
            if (m_session && m_session->getEntityID()) {
                m_metadata = m_app.getMetadataProvider(false);
                if (m_metadata) {
                    m_metadata->lock();
                    return m_entity = m_metadata->getEntityDescriptor(MetadataProviderCriteria(m_app, m_session->getEntityID())).first;
                }
            }
            return NULL;
        }
        const XMLCh* getProtocol() const {
            return m_protocol;
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
        vector<shibsp::Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_assertions;
        }

    private:
        bool m_query;
        const Application& m_app;
        const Session* m_session;
        mutable MetadataProvider* m_metadata;
        mutable const EntityDescriptor* m_entity;
        const XMLCh* m_protocol;
        const NameID* m_nameid;
        const XMLCh* m_class;
        const XMLCh* m_decl;
        vector<shibsp::Attribute*> m_attributes;
        vector<opensaml::Assertion*> m_assertions;
    };

    class SHIBSP_DLLLOCAL QueryResolver : public AttributeResolver
    {
    public:
        QueryResolver(const DOMElement* e);
        ~QueryResolver() {
            for_each(m_SAML1Designators.begin(), m_SAML1Designators.end(), xmltooling::cleanup<AttributeDesignator>());
            for_each(m_SAML2Designators.begin(), m_SAML2Designators.end(), xmltooling::cleanup<saml2::Attribute>());
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
            return new QueryContext(application,issuer,protocol,nameid,authncontext_class,authncontext_decl,tokens);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new QueryContext(application,session);
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const {
            // Nothing to do, only the extractor would actually generate them.
        }

    private:
        bool SAML1Query(QueryContext& ctx) const;
        bool SAML2Query(QueryContext& ctx) const;

        Category& m_log;
        string m_policyId;
        vector<AttributeDesignator*> m_SAML1Designators;
        vector<saml2::Attribute*> m_SAML2Designators;
    };

    AttributeResolver* SHIBSP_DLLLOCAL QueryResolverFactory(const DOMElement* const & e)
    {
        return new QueryResolver(e);
    }

    static const XMLCh _policyId[] = UNICODE_LITERAL_8(p,o,l,i,c,y,I,d);
};

QueryResolver::QueryResolver(const DOMElement* e) : m_log(Category::getInstance(SHIBSP_LOGCAT".AttributeResolver.Query"))
{
#ifdef _DEBUG
    xmltooling::NDC ndc("QueryResolver");
#endif

    const XMLCh* pid = e ? e->getAttributeNS(NULL, _policyId) : NULL;
    if (pid && *pid) {
        auto_ptr_char temp(pid);
        m_policyId = temp.get();
    }

    DOMElement* child = XMLHelper::getFirstChildElement(e);
    while (child) {
        try {
            if (XMLHelper::isNodeNamed(child, samlconstants::SAML20_NS, saml2::Attribute::LOCAL_NAME)) {
                auto_ptr<XMLObject> obj(saml2::AttributeBuilder::buildOneFromElement(child));
                saml2::Attribute* down = dynamic_cast<saml2::Attribute*>(obj.get());
                if (down) {
                    m_SAML2Designators.push_back(down);
                    obj.release();
                }
            }
            else if (XMLHelper::isNodeNamed(child, samlconstants::SAML1P_NS, AttributeDesignator::LOCAL_NAME)) {
                auto_ptr<XMLObject> obj(AttributeDesignatorBuilder::buildOneFromElement(child));
                AttributeDesignator* down = dynamic_cast<AttributeDesignator*>(obj.get());
                if (down) {
                    m_SAML1Designators.push_back(down);
                    obj.release();
                }
            }
        }
        catch (exception& ex) {
            m_log.error("exception loading attribute designator: %s", ex.what());
        }
        child = XMLHelper::getNextSiblingElement(child);
    }
}

bool QueryResolver::SAML1Query(QueryContext& ctx) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("query");
#endif

    int version = XMLString::equals(ctx.getProtocol(), samlconstants::SAML11_PROTOCOL_ENUM) ? 1 : 0;
    const AttributeAuthorityDescriptor* AA =
        find_if(ctx.getEntityDescriptor()->getAttributeAuthorityDescriptors(), isValidForProtocol(ctx.getProtocol()));
    if (!AA) {
        m_log.warn("no SAML 1.%d AttributeAuthority role found in metadata", version);
        return false;
    }

    const Application& application = ctx.getApplication();
    const PropertySet* relyingParty = application.getRelyingParty(ctx.getEntityDescriptor());

    // Locate policy key.
    const char* policyId = m_policyId.empty() ? application.getString("policyId").second : m_policyId.c_str();

    // Access policy properties.
    const PropertySet* settings = application.getServiceProvider().getPolicySettings(policyId);
    pair<bool,bool> validate = settings->getBool("validate");

    shibsp::SecurityPolicy policy(application, NULL, validate.first && validate.second, policyId);
    policy.getAudiences().push_back(relyingParty->getXMLString("entityID").second);
    MetadataCredentialCriteria mcc(*AA);
    shibsp::SOAPClient soaper(policy);

    auto_ptr_XMLCh binding(samlconstants::SAML1_BINDING_SOAP);
    saml1p::Response* response=NULL;
    const vector<AttributeService*>& endpoints=AA->getAttributeServices();
    for (vector<AttributeService*>::const_iterator ep=endpoints.begin(); !response && ep!=endpoints.end(); ++ep) {
        if (!XMLString::equals((*ep)->getBinding(),binding.get()) || !(*ep)->getLocation())
            continue;
        auto_ptr_char loc((*ep)->getLocation());
        try {
            NameIdentifier* nameid = NameIdentifierBuilder::buildNameIdentifier();
            nameid->setName(ctx.getNameID()->getName());
            nameid->setFormat(ctx.getNameID()->getFormat());
            nameid->setNameQualifier(ctx.getNameID()->getNameQualifier());
            saml1::Subject* subject = saml1::SubjectBuilder::buildSubject();
            subject->setNameIdentifier(nameid);
            saml1p::AttributeQuery* query = saml1p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject);
            query->setResource(relyingParty->getXMLString("entityID").second);
            for (vector<AttributeDesignator*>::const_iterator ad = m_SAML1Designators.begin(); ad!=m_SAML1Designators.end(); ++ad)
                query->getAttributeDesignators().push_back((*ad)->cloneAttributeDesignator());
            Request* request = RequestBuilder::buildRequest();
            request->setAttributeQuery(query);
            request->setMinorVersion(version);

            SAML1SOAPClient client(soaper, false);
            client.sendSAML(request, application.getId(), mcc, loc.get());
            response = client.receiveSAML();
        }
        catch (exception& ex) {
            m_log.error("exception during SAML query to %s: %s", loc.get(), ex.what());
            soaper.reset();
        }
    }

    if (!response) {
        m_log.error("unable to obtain a SAML response from attribute authority");
        return false;
    }
    else if (!response->getStatus() || !response->getStatus()->getStatusCode() || response->getStatus()->getStatusCode()->getValue()==NULL ||
            *(response->getStatus()->getStatusCode()->getValue()) != saml1p::StatusCode::SUCCESS) {
        delete response;
        m_log.error("attribute authority returned a SAML error");
        return true;
    }

    const vector<saml1::Assertion*>& assertions = const_cast<const saml1p::Response*>(response)->getAssertions();
    if (assertions.empty()) {
        delete response;
        m_log.warn("response from attribute authority was empty");
        return true;
    }
    else if (assertions.size()>1)
        m_log.warn("simple resolver only supports one assertion in the query response");

    auto_ptr<saml1p::Response> wrapper(response);
    saml1::Assertion* newtoken = assertions.front();

    pair<bool,bool> signedAssertions = relyingParty->getBool("requireSignedAssertions");
    if (!newtoken->getSignature() && signedAssertions.first && signedAssertions.second) {
        m_log.error("assertion unsigned, rejecting it based on signedAssertions policy");
        return true;
    }

    try {
        // We're going to insist that the assertion issuer is the same as the peer.
        // Reset the policy's message bits and extract them from the assertion.
        policy.reset(true);
        policy.setMessageID(newtoken->getAssertionID());
        policy.setIssueInstant(newtoken->getIssueInstantEpoch());
        policy.setIssuer(newtoken->getIssuer());
        policy.evaluate(*newtoken);

        // Now we can check the security status of the policy.
        if (!policy.isAuthenticated())
            throw SecurityPolicyException("Security of SAML 1.x query result not established.");
    }
    catch (exception& ex) {
        m_log.error("assertion failed policy validation: %s", ex.what());
        return true;
    }

    newtoken->detach();
    wrapper.release();
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

bool QueryResolver::SAML2Query(QueryContext& ctx) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("query");
#endif

    const AttributeAuthorityDescriptor* AA =
        find_if(ctx.getEntityDescriptor()->getAttributeAuthorityDescriptors(), isValidForProtocol(samlconstants::SAML20P_NS));
    if (!AA) {
        m_log.warn("no SAML 2 AttributeAuthority role found in metadata");
        return false;
    }

    const Application& application = ctx.getApplication();
    const PropertySet* relyingParty = application.getRelyingParty(ctx.getEntityDescriptor());

    // Locate policy key.
    const char* policyId = m_policyId.empty() ? application.getString("policyId").second : m_policyId.c_str();

    // Access policy properties.
    const PropertySet* settings = application.getServiceProvider().getPolicySettings(policyId);
    pair<bool,bool> validate = settings->getBool("validate");

    pair<bool,bool> signedAssertions = relyingParty->getBool("requireSignedAssertions");
    pair<bool,const char*> encryption = relyingParty->getString("encryption");

    shibsp::SecurityPolicy policy(application, NULL, validate.first && validate.second, policyId);
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
                MetadataCredentialCriteria mcc(*AA);
                encrypted->encrypt(
                    *ctx.getNameID(),
                    *(application.getMetadataProvider()),
                    mcc,
                    false,
                    relyingParty->getXMLString("encryptionAlg").second
                    );
                subject->setEncryptedID(encrypted.release());
            }
            else {
                subject->setNameID(ctx.getNameID()->cloneNameID());
            }

            saml2p::AttributeQuery* query = saml2p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject.release());
            Issuer* iss = IssuerBuilder::buildIssuer();
            iss->setName(relyingParty->getXMLString("entityID").second);
            query->setIssuer(iss);
            for (vector<saml2::Attribute*>::const_iterator ad = m_SAML2Designators.begin(); ad!=m_SAML2Designators.end(); ++ad)
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
        m_log.error("unable to obtain a SAML response from attribute authority");
        return false;
    }
    saml2p::Response* response = dynamic_cast<saml2p::Response*>(srt);
    if (!response) {
        delete srt;
        m_log.error("message was not a samlp:Response");
        return true;
    }
    else if (!response->getStatus() || !response->getStatus()->getStatusCode() ||
            !XMLString::equals(response->getStatus()->getStatusCode()->getValue(), saml2p::StatusCode::SUCCESS)) {
        delete srt;
        m_log.error("attribute authority returned a SAML error");
        return true;
    }

    const vector<saml2::Assertion*>& assertions = const_cast<const saml2p::Response*>(response)->getAssertions();
    if (assertions.empty()) {
        delete srt;
        m_log.warn("response from attribute authority was empty");
        return true;
    }
    else if (assertions.size()>1)
        m_log.warn("simple resolver only supports one assertion in the query response");

    auto_ptr<saml2p::StatusResponseType> wrapper(srt);
    saml2::Assertion* newtoken = assertions.front();

    if (!newtoken->getSignature() && signedAssertions.first && signedAssertions.second) {
        m_log.error("assertion unsigned, rejecting it based on signedAssertions policy");
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
    }
    catch (exception& ex) {
        m_log.error("assertion failed policy validation: %s", ex.what());
        return true;
    }

    newtoken->detach();
    wrapper.release();
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

void QueryResolver::resolveAttributes(ResolutionContext& ctx) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("resolveAttributes");
#endif

    QueryContext& qctx = dynamic_cast<QueryContext&>(ctx);
    if (!qctx.doQuery()) {
        m_log.debug("found AttributeStatement in input to new session, skipping query");
        return;
    }

    if (qctx.getNameID() && qctx.getEntityDescriptor()) {
        if (XMLString::equals(qctx.getProtocol(), samlconstants::SAML20P_NS)) {
            m_log.debug("attempting SAML 2.0 attribute query");
            SAML2Query(qctx);
        }
        else if (XMLString::equals(qctx.getProtocol(), samlconstants::SAML11_PROTOCOL_ENUM) ||
                XMLString::equals(qctx.getProtocol(), samlconstants::SAML10_PROTOCOL_ENUM)) {
            m_log.debug("attempting SAML 1.x attribute query");
            SAML1Query(qctx);
        }
        else
            m_log.warn("SSO protocol does not allow for attribute query");
    }
    else
        m_log.warn("can't attempt attribute query, either no NameID or no metadata to use");
}

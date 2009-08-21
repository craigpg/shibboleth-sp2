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
 * XMLAttributeExtractor.cpp
 *
 * AttributeExtractor based on an XML mapping file.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/filtering/AttributeFilter.h"
#include "attribute/filtering/BasicFilteringContext.h"
#include "attribute/resolver/AttributeExtractor.h"
#include "security/SecurityPolicy.h"
#include "util/SPConstants.h"

#include <saml/SAMLConfig.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/saml2/metadata/ObservableMetadataProvider.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;
using saml1::NameIdentifier;
using saml2::NameID;
using saml2::EncryptedAttribute;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLExtractorImpl : public ObservableMetadataProvider::Observer
    {
    public:
        XMLExtractorImpl(const DOMElement* e, Category& log);
        ~XMLExtractorImpl() {
            for (map<const ObservableMetadataProvider*,decoded_t>::iterator i=m_decodedMap.begin(); i!=m_decodedMap.end(); ++i) {
                i->first->removeObserver(this);
                for (decoded_t::iterator attrs = i->second.begin(); attrs!=i->second.end(); ++attrs)
                    for_each(attrs->second.begin(), attrs->second.end(), mem_fun_ref<DDF&,DDF>(&DDF::destroy));
            }
            delete m_attrLock;
            delete m_trust;
            delete m_metadata;
            delete m_filter;
            for (attrmap_t::iterator j = m_attrMap.begin(); j!=m_attrMap.end(); ++j)
                delete j->second.first;
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

        void onEvent(const ObservableMetadataProvider& metadata) const {
            // Destroy attributes we cached from this provider.
            m_attrLock->wrlock();
            decoded_t& d = m_decodedMap[&metadata];
            for (decoded_t::iterator a = d.begin(); a!=d.end(); ++a)
                for_each(a->second.begin(), a->second.end(), mem_fun_ref<DDF&,DDF>(&DDF::destroy));
            d.clear();
            m_attrLock->unlock();
        }

        void extractAttributes(
            const Application& application,
            const char* assertingParty,
            const char* relyingParty,
            const NameIdentifier& nameid,
            vector<Attribute*>& attributes
            ) const;
        void extractAttributes(
            const Application& application,
            const char* assertingParty,
            const char* relyingParty,
            const NameID& nameid,
            vector<Attribute*>& attributes
            ) const;
        void extractAttributes(
            const Application& application,
            const char* assertingParty,
            const char* relyingParty,
            const saml1::Attribute& attr,
            vector<Attribute*>& attributes
            ) const;
        void extractAttributes(
            const Application& application,
            const char* assertingParty,
            const char* relyingParty,
            const saml2::Attribute& attr,
            vector<Attribute*>& attributes
            ) const;
        void extractAttributes(
            const Application& application,
            const ObservableMetadataProvider* observable,
            const XMLCh* entityID,
            const char* relyingParty,
            const Extensions& ext,
            vector<Attribute*>& attributes
            ) const;

        void getAttributeIds(vector<string>& attributes) const {
            attributes.insert(attributes.end(), m_attributeIds.begin(), m_attributeIds.end());
        }

    private:
        Category& m_log;
        DOMDocument* m_document;
#ifdef HAVE_GOOD_STL
        typedef map< pair<xstring,xstring>,pair< AttributeDecoder*,vector<string> > > attrmap_t;
#else
        typedef map< pair<string,string>,pair< AttributeDecoder*,vector<string> > > attrmap_t;
#endif
        attrmap_t m_attrMap;
        vector<string> m_attributeIds;

        // settings for embedded assertions in metadata
        auto_ptr_char m_policyId;
        MetadataProvider* m_metadata;
        TrustEngine* m_trust;
        AttributeFilter* m_filter;
        bool m_entityAssertions;

        // manages caching of decoded Attributes
        mutable RWLock* m_attrLock;
        typedef map< const EntityAttributes*,vector<DDF> > decoded_t;
        mutable map<const ObservableMetadataProvider*,decoded_t> m_decodedMap;
    };

    class XMLExtractor : public AttributeExtractor, public ReloadableXMLFile
    {
    public:
        XMLExtractor(const DOMElement* e) : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT".AttributeExtractor.XML")), m_impl(NULL) {
            load();
        }
        ~XMLExtractor() {
            delete m_impl;
        }

        void extractAttributes(
            const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
            ) const;

        void getAttributeIds(std::vector<std::string>& attributes) const {
            if (m_impl)
                m_impl->getAttributeIds(attributes);
        }

    protected:
        pair<bool,DOMElement*> load();

    private:
        XMLExtractorImpl* m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AttributeExtractor* SHIBSP_DLLLOCAL XMLAttributeExtractorFactory(const DOMElement* const & e)
    {
        return new XMLExtractor(e);
    }

    static const XMLCh _aliases[] =             UNICODE_LITERAL_7(a,l,i,a,s,e,s);
    static const XMLCh _AttributeDecoder[] =    UNICODE_LITERAL_16(A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);
    static const XMLCh _AttributeFilter[] =     UNICODE_LITERAL_15(A,t,t,r,i,b,u,t,e,F,i,l,t,e,r);
    static const XMLCh Attributes[] =           UNICODE_LITERAL_10(A,t,t,r,i,b,u,t,e,s);
    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
    static const XMLCh _name[] =                UNICODE_LITERAL_4(n,a,m,e);
    static const XMLCh nameFormat[] =           UNICODE_LITERAL_10(n,a,m,e,F,o,r,m,a,t);
    static const XMLCh metadataPolicyId[] =     UNICODE_LITERAL_16(m,e,t,a,d,a,t,a,P,o,l,i,c,y,I,d);
    static const XMLCh _TrustEngine[] =         UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
};

XMLExtractorImpl::XMLExtractorImpl(const DOMElement* e, Category& log)
    : m_log(log),
        m_document(NULL),
        m_policyId(e ? e->getAttributeNS(NULL, metadataPolicyId) : NULL),
        m_metadata(NULL),
        m_trust(NULL),
        m_filter(NULL),
        m_entityAssertions(true),
        m_attrLock(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLExtractorImpl");
#endif

    if (!XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, Attributes))
        throw ConfigurationException("XML AttributeExtractor requires am:Attributes at root of configuration.");

    DOMElement* child = XMLHelper::getFirstChildElement(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, _MetadataProvider);
    if (child) {
        try {
            auto_ptr_char type(child->getAttributeNS(NULL, _type));
            if (!type.get() || !*type.get())
                throw ConfigurationException("MetadataProvider element missing type attribute.");
            m_log.info("building MetadataProvider of type %s...", type.get());
            auto_ptr<MetadataProvider> mp(SAMLConfig::getConfig().MetadataProviderManager.newPlugin(type.get(), child));
            mp->init();
            m_metadata = mp.release();
        }
        catch (exception& ex) {
            m_entityAssertions = false;
            m_log.crit("error building/initializing dedicated MetadataProvider: %s", ex.what());
            m_log.crit("disabling support for Assertions in EntityAttributes extension");
        }
    }

    if (m_entityAssertions) {
        child = XMLHelper::getFirstChildElement(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, _TrustEngine);
        if (child) {
            try {
                auto_ptr_char type(child->getAttributeNS(NULL, _type));
                if (!type.get() || !*type.get())
                    throw ConfigurationException("TrustEngine element missing type attribute.");
                m_log.info("building TrustEngine of type %s...", type.get());
                m_trust = XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(type.get(), child);
            }
            catch (exception& ex) {
                m_entityAssertions = false;
                m_log.crit("error building/initializing dedicated TrustEngine: %s", ex.what());
                m_log.crit("disabling support for Assertions in EntityAttributes extension");
            }
        }
    }

    if (m_entityAssertions) {
        child = XMLHelper::getFirstChildElement(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, _AttributeFilter);
        if (child) {
            try {
                auto_ptr_char type(child->getAttributeNS(NULL, _type));
                if (!type.get() || !*type.get())
                    throw ConfigurationException("AttributeFilter element missing type attribute.");
                m_log.info("building AttributeFilter of type %s...", type.get());
                m_filter = SPConfig::getConfig().AttributeFilterManager.newPlugin(type.get(), child);
            }
            catch (exception& ex) {
                m_entityAssertions = false;
                m_log.crit("error building/initializing dedicated AttributeFilter: %s", ex.what());
                m_log.crit("disabling support for Assertions in EntityAttributes extension");
            }
        }
    }

    child = XMLHelper::getFirstChildElement(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
    while (child) {
        // Check for missing name or id.
        const XMLCh* name = child->getAttributeNS(NULL, _name);
        if (!name || !*name) {
            m_log.warn("skipping Attribute with no name");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
            continue;
        }

        auto_ptr_char id(child->getAttributeNS(NULL, _id));
        if (!id.get() || !*id.get()) {
            m_log.warn("skipping Attribute with no id");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
            continue;
        }
        else if (!strcmp(id.get(), "REMOTE_USER")) {
            m_log.warn("skipping Attribute, id of REMOTE_USER is a reserved name");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
            continue;
        }

        AttributeDecoder* decoder=NULL;
        try {
            DOMElement* dchild = XMLHelper::getFirstChildElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, _AttributeDecoder);
            if (dchild) {
                auto_ptr<xmltooling::QName> q(XMLHelper::getXSIType(dchild));
                if (q.get())
                    decoder = SPConfig::getConfig().AttributeDecoderManager.newPlugin(*q.get(), dchild);
            }
            if (!decoder)
                decoder = SPConfig::getConfig().AttributeDecoderManager.newPlugin(StringAttributeDecoderType, NULL);
        }
        catch (exception& ex) {
            m_log.error("skipping Attribute (%s), error building AttributeDecoder: %s", id.get(), ex.what());
        }

        if (!decoder) {
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
            continue;
        }

        // Empty NameFormat implies the usual Shib URI naming defaults.
        const XMLCh* format = child->getAttributeNS(NULL, nameFormat);
        if (!format || XMLString::equals(format, shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI) ||
                XMLString::equals(format, saml2::Attribute::URI_REFERENCE))
            format = &chNull;  // ignore default Format/Namespace values

        // Fetch/create the map entry and see if it's a duplicate rule.
#ifdef HAVE_GOOD_STL
        pair< AttributeDecoder*,vector<string> >& decl = m_attrMap[pair<xstring,xstring>(name,format)];
#else
        auto_ptr_char n(name);
        auto_ptr_char f(format);
        pair< AttributeDecoder*,vector<string> >& decl = m_attrMap[pair<string,string>(n.get(),f.get())];
#endif
        if (decl.first) {
            m_log.warn("skipping duplicate Attribute mapping (same name and nameFormat)");
            delete decoder;
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
            continue;
        }

        if (m_log.isInfoEnabled()) {
#ifdef HAVE_GOOD_STL
            auto_ptr_char n(name);
            auto_ptr_char f(format);
#endif
            m_log.info("creating mapping for Attribute %s%s%s", n.get(), *f.get() ? ", Format/Namespace:" : "", f.get());
        }

        decl.first = decoder;
        decl.second.push_back(id.get());
        m_attributeIds.push_back(id.get());

        name = child->getAttributeNS(NULL, _aliases);
        if (name && *name) {
            auto_ptr_char aliases(name);
            char* pos;
            char* start = const_cast<char*>(aliases.get());
            while (start && *start) {
                while (*start && isspace(*start))
                    start++;
                if (!*start)
                    break;
                pos = strchr(start,' ');
                if (pos)
                    *pos=0;
                if (strcmp(start, "REMOTE_USER")) {
                    decl.second.push_back(start);
                    m_attributeIds.push_back(start);
                }
                else {
                    m_log.warn("skipping alias, REMOTE_USER is a reserved name");
                }
                start = pos ? pos+1 : NULL;
            }
        }

        child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
    }

    m_attrLock = RWLock::create();
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const char* assertingParty,
    const char* relyingParty,
    const NameIdentifier& nameid,
    vector<Attribute*>& attributes
    ) const
{
#ifdef HAVE_GOOD_STL
    map< pair<xstring,xstring>,pair< AttributeDecoder*,vector<string> > >::const_iterator rule;
#else
    map< pair<string,string>,pair< AttributeDecoder*,vector<string> > >::const_iterator rule;
#endif

    const XMLCh* format = nameid.getFormat();
    if (!format || !*format)
        format = NameIdentifier::UNSPECIFIED;
#ifdef HAVE_GOOD_STL
    if ((rule=m_attrMap.find(pair<xstring,xstring>(format,xstring()))) != m_attrMap.end()) {
#else
    auto_ptr_char temp(format);
    if ((rule=m_attrMap.find(pair<string,string>(temp.get(),string()))) != m_attrMap.end()) {
#endif
        Attribute* a = rule->second.first->decode(rule->second.second, &nameid, assertingParty, relyingParty);
        if (a)
            attributes.push_back(a);
    }
    else if (m_log.isDebugEnabled()) {
#ifdef HAVE_GOOD_STL
        auto_ptr_char temp(format);
#endif
        m_log.debug("skipping unmapped NameIdentifier with format (%s)", temp.get());
    }
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const char* assertingParty,
    const char* relyingParty,
    const NameID& nameid,
    vector<Attribute*>& attributes
    ) const
{
#ifdef HAVE_GOOD_STL
    map< pair<xstring,xstring>,pair< AttributeDecoder*,vector<string> > >::const_iterator rule;
#else
    map< pair<string,string>,pair< AttributeDecoder*,vector<string> > >::const_iterator rule;
#endif

    const XMLCh* format = nameid.getFormat();
    if (!format || !*format)
        format = NameID::UNSPECIFIED;
#ifdef HAVE_GOOD_STL
    if ((rule=m_attrMap.find(pair<xstring,xstring>(format,xstring()))) != m_attrMap.end()) {
#else
    auto_ptr_char temp(format);
    if ((rule=m_attrMap.find(pair<string,string>(temp.get(),string()))) != m_attrMap.end()) {
#endif
        Attribute* a = rule->second.first->decode(rule->second.second, &nameid, assertingParty, relyingParty);
        if (a)
            attributes.push_back(a);
    }
    else if (m_log.isDebugEnabled()) {
#ifdef HAVE_GOOD_STL
        auto_ptr_char temp(format);
#endif
        m_log.debug("skipping unmapped NameID with format (%s)", temp.get());
    }
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const char* assertingParty,
    const char* relyingParty,
    const saml1::Attribute& attr,
    vector<Attribute*>& attributes
    ) const
{
#ifdef HAVE_GOOD_STL
    map< pair<xstring,xstring>,pair< AttributeDecoder*,vector<string> > >::const_iterator rule;
#else
    map< pair<string,string>,pair< AttributeDecoder*,vector<string> > >::const_iterator rule;
#endif

    const XMLCh* name = attr.getAttributeName();
    const XMLCh* format = attr.getAttributeNamespace();
    if (!name || !*name)
        return;
    if (!format || XMLString::equals(format, shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI))
        format = &chNull;
#ifdef HAVE_GOOD_STL
    if ((rule=m_attrMap.find(pair<xstring,xstring>(name,format))) != m_attrMap.end()) {
#else
    auto_ptr_char temp1(name);
    auto_ptr_char temp2(format);
    if ((rule=m_attrMap.find(pair<string,string>(temp1.get(),temp2.get()))) != m_attrMap.end()) {
#endif
        Attribute* a = rule->second.first->decode(rule->second.second, &attr, assertingParty, relyingParty);
        if (a)
            attributes.push_back(a);
    }
    else if (m_log.isInfoEnabled()) {
#ifdef HAVE_GOOD_STL
        auto_ptr_char temp1(name);
        auto_ptr_char temp2(format);
#endif
        m_log.info("skipping unmapped SAML 1.x Attribute with Name: %s%s%s", temp1.get(), *temp2.get() ? ", Namespace:" : "", temp2.get());
    }
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const char* assertingParty,
    const char* relyingParty,
    const saml2::Attribute& attr,
    vector<Attribute*>& attributes
    ) const
{
#ifdef HAVE_GOOD_STL
    map< pair<xstring,xstring>,pair< AttributeDecoder*,vector<string> > >::const_iterator rule;
#else
    map< pair<string,string>,pair< AttributeDecoder*,vector<string> > >::const_iterator rule;
#endif

    const XMLCh* name = attr.getName();
    const XMLCh* format = attr.getNameFormat();
    if (!name || !*name)
        return;
    if (!format || !*format)
        format = saml2::Attribute::UNSPECIFIED;
    else if (XMLString::equals(format, saml2::Attribute::URI_REFERENCE))
        format = &chNull;
#ifdef HAVE_GOOD_STL
    if ((rule=m_attrMap.find(pair<xstring,xstring>(name,format))) != m_attrMap.end()) {
#else
    auto_ptr_char temp1(name);
    auto_ptr_char temp2(format);
    if ((rule=m_attrMap.find(pair<string,string>(temp1.get(),temp2.get()))) != m_attrMap.end()) {
#endif
        Attribute* a = rule->second.first->decode(rule->second.second, &attr, assertingParty, relyingParty);
        if (a)
            attributes.push_back(a);
    }
    else if (m_log.isInfoEnabled()) {
#ifdef HAVE_GOOD_STL
        auto_ptr_char temp1(name);
        auto_ptr_char temp2(format);
#endif
        m_log.info("skipping unmapped SAML 2.0 Attribute with Name: %s%s%s", temp1.get(), *temp2.get() ? ", Format:" : "", temp2.get());
    }
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const ObservableMetadataProvider* observable,
    const XMLCh* entityID,
    const char* relyingParty,
    const Extensions& ext,
    vector<Attribute*>& attributes
    ) const
{
    const vector<XMLObject*>& exts = ext.getUnknownXMLObjects();
    for (vector<XMLObject*>::const_iterator i = exts.begin(); i!=exts.end(); ++i) {
        const EntityAttributes* container = dynamic_cast<const EntityAttributes*>(*i);
        if (!container)
            continue;

        bool useCache = false;
        map<const ObservableMetadataProvider*,decoded_t>::iterator cacheEntry;

        // Check for cached result.
        if (observable) {
            m_attrLock->rdlock();
            cacheEntry = m_decodedMap.find(observable);
            if (cacheEntry == m_decodedMap.end()) {
                // We need to elevate the lock and retry.
                m_attrLock->unlock();
                m_attrLock->wrlock();
                cacheEntry = m_decodedMap.find(observable);
                if (cacheEntry==m_decodedMap.end()) {

                    // It's still brand new, so hook it for cache activation.
                    observable->addObserver(this);

                    // Prime the map reference with an empty decoded map.
                    cacheEntry = m_decodedMap.insert(make_pair(observable,decoded_t())).first;

                    // Downgrade the lock.
                    // We don't have to recheck because we never erase the master map entry entirely, even on changes.
                    m_attrLock->unlock();
                    m_attrLock->rdlock();
                }
            }
            useCache = true;
        }

        if (useCache) {
            // We're holding a read lock, so check the cache.
            decoded_t::iterator d = cacheEntry->second.find(container);
            if (d != cacheEntry->second.end()) {
                SharedLock locker(m_attrLock, false);   // pop the lock when we're done
                for (vector<DDF>::iterator obj = d->second.begin(); obj != d->second.end(); ++obj) {
                    auto_ptr<Attribute> wrapper(Attribute::unmarshall(*obj));
                    m_log.debug("recovered cached metadata attribute (%s)", wrapper->getId());
                    attributes.push_back(wrapper.release());
                }
                break;
            }
        }

        // Use a holding area to support caching.
        vector<Attribute*> holding;

        const vector<saml2::Attribute*>& attrs = container->getAttributes();
        for (vector<saml2::Attribute*>::const_iterator attr = attrs.begin(); attr != attrs.end(); ++attr) {
            try {
                extractAttributes(application, NULL, relyingParty, *(*attr), holding);
            }
            catch (...) {
                if (useCache)
                    m_attrLock->unlock();
                for_each(holding.begin(), holding.end(), xmltooling::cleanup<Attribute>());
                throw;
            }
        }

        if (entityID && m_entityAssertions) {
            const vector<saml2::Assertion*>& asserts = container->getAssertions();
            for (vector<saml2::Assertion*>::const_iterator assert = asserts.begin(); assert != asserts.end(); ++assert) {
                if (!(*assert)->getSignature()) {
                    if (m_log.isDebugEnabled()) {
                        auto_ptr_char eid(entityID);
                        m_log.debug("skipping unsigned assertion in metadata extension for entity (%s)", eid.get());
                    }
                    continue;
                }
                else if ((*assert)->getAttributeStatements().empty()) {
                    if (m_log.isDebugEnabled()) {
                        auto_ptr_char eid(entityID);
                        m_log.debug("skipping assertion with no AttributeStatement in metadata extension for entity (%s)", eid.get());
                    }
                    continue;
                }
                else {
                    // Check subject.
                    const NameID* subject = (*assert)->getSubject() ? (*assert)->getSubject()->getNameID() : NULL;
                    if (!subject ||
                            !XMLString::equals(subject->getFormat(), NameID::ENTITY) ||
                            !XMLString::equals(subject->getName(), entityID)) {
                        if (m_log.isDebugEnabled()) {
                            auto_ptr_char eid(entityID);
                            m_log.debug("skipping assertion with improper Subject in metadata extension for entity (%s)", eid.get());
                        }
                        continue;
                    }
                }

                // Use a private holding area for filtering purposes.
                vector<Attribute*> holding2;

                try {
                    // Set up and evaluate a policy for an AA asserting attributes to us.
                    shibsp::SecurityPolicy policy(application, &AttributeAuthorityDescriptor::ELEMENT_QNAME, false, m_policyId.get());
                    Locker locker(m_metadata);
                    if (m_metadata)
                        policy.setMetadataProvider(m_metadata);
                    if (m_trust)
                        policy.setTrustEngine(m_trust);
                    // Populate recipient as audience.
                    const XMLCh* issuer = (*assert)->getIssuer() ? (*assert)->getIssuer()->getName() : NULL;
                    policy.getAudiences().push_back(application.getRelyingParty(issuer)->getXMLString("entityID").second);

                    // Extract assertion information for policy.
                    policy.setMessageID((*assert)->getID());
                    policy.setIssueInstant((*assert)->getIssueInstantEpoch());
                    policy.setIssuer((*assert)->getIssuer());

                    // Look up metadata for issuer.
                    if (policy.getIssuer() && policy.getMetadataProvider()) {
                        if (policy.getIssuer()->getFormat() && !XMLString::equals(policy.getIssuer()->getFormat(), saml2::NameIDType::ENTITY)) {
                            m_log.debug("non-system entity issuer, skipping metadata lookup");
                        }
                        else {
                            m_log.debug("searching metadata for entity assertion issuer...");
                            pair<const EntityDescriptor*,const RoleDescriptor*> lookup;
                            MetadataProvider::Criteria& mc = policy.getMetadataProviderCriteria();
                            mc.entityID_unicode = policy.getIssuer()->getName();
                            mc.role = &AttributeAuthorityDescriptor::ELEMENT_QNAME;
                            mc.protocol = samlconstants::SAML20P_NS;
                            lookup = policy.getMetadataProvider()->getEntityDescriptor(mc);
                            if (!lookup.first) {
                                auto_ptr_char iname(policy.getIssuer()->getName());
                                m_log.debug("no metadata found, can't establish identity of issuer (%s)", iname.get());
                            }
                            else if (!lookup.second) {
                                m_log.debug("unable to find compatible AA role in metadata");
                            }
                            else {
                                policy.setIssuerMetadata(lookup.second);
                            }
                        }
                    }

                    // Authenticate the assertion. We have to clone and marshall it to establish the signature for verification.
                    auto_ptr<saml2::Assertion> tokencopy((*assert)->cloneAssertion());
                    tokencopy->marshall();
                    policy.evaluate(*tokencopy);
                    if (!policy.isAuthenticated()) {
                        if (m_log.isDebugEnabled()) {
                            auto_ptr_char tempid(tokencopy->getID());
                            auto_ptr_char eid(entityID);
                            m_log.debug(
                                "failed to authenticate assertion (%s) in metadata extension for entity (%s)", tempid.get(), eid.get()
                                );
                        }
                        continue;
                    }

                    // Override the asserting/relying party names based on this new issuer.
                    const EntityDescriptor* inlineEntity =
                        policy.getIssuerMetadata() ? dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent()) : NULL;
                    auto_ptr_char inlineAssertingParty(inlineEntity ? inlineEntity->getEntityID() : NULL);
                    relyingParty = application.getRelyingParty(inlineEntity)->getString("entityID").second;
                    const vector<saml2::Attribute*>& attrs2 =
                        const_cast<const saml2::AttributeStatement*>(tokencopy->getAttributeStatements().front())->getAttributes();
                    for (vector<saml2::Attribute*>::const_iterator a = attrs2.begin(); a!=attrs2.end(); ++a)
                        extractAttributes(application, inlineAssertingParty.get(), relyingParty, *(*a), holding2);

                    // Now we locally filter the attributes so that the actual issuer can be properly set.
                    // If we relied on outside filtering, the attributes couldn't be distinguished from the
                    // ones that come from the user's IdP.
                    if (m_filter && !holding2.empty()) {
                        BasicFilteringContext fc(application, holding2, policy.getIssuerMetadata());
                        Locker filtlocker(m_filter);
                        try {
                            m_filter->filterAttributes(fc, holding2);
                        }
                        catch (exception& ex) {
                            m_log.error("caught exception filtering attributes: %s", ex.what());
                            m_log.error("dumping extracted attributes due to filtering exception");
                            for_each(holding2.begin(), holding2.end(), xmltooling::cleanup<Attribute>());
                            holding2.clear();
                        }
                    }

                    if (!holding2.empty()) {
                        // Copy them over to the main holding tank.
                        holding.insert(holding.end(), holding2.begin(), holding2.end());
                    }
                }
                catch (exception& ex) {
                    // Known exceptions are handled gracefully by skipping the assertion.
                    if (m_log.isDebugEnabled()) {
                        auto_ptr_char tempid((*assert)->getID());
                        auto_ptr_char eid(entityID);
                        m_log.debug(
                            "exception authenticating assertion (%s) in metadata extension for entity (%s): %s",
                            tempid.get(),
                            eid.get(),
                            ex.what()
                            );
                    }
                    for_each(holding2.begin(), holding2.end(), xmltooling::cleanup<Attribute>());
                    continue;
                }
                catch (...) {
                    // Unknown exceptions are fatal.
                    if (useCache)
                        m_attrLock->unlock();
                    for_each(holding.begin(), holding.end(), xmltooling::cleanup<Attribute>());
                    for_each(holding2.begin(), holding2.end(), xmltooling::cleanup<Attribute>());
                    throw;
                }
            }
        }

        if (!holding.empty()) {
            if (useCache) {
                m_attrLock->unlock();
                m_attrLock->wrlock();
                SharedLock locker(m_attrLock, false);   // pop the lock when we're done
                if (cacheEntry->second.count(container) == 0) {
                    for (vector<Attribute*>::const_iterator held = holding.begin(); held != holding.end(); ++held)
                        cacheEntry->second[container].push_back((*held)->marshall());
                }
            }
            attributes.insert(attributes.end(), holding.begin(), holding.end());
        }
        else if (useCache) {
            m_attrLock->unlock();
        }

        break;  // only process a single extension element
    }
}

void XMLExtractor::extractAttributes(
    const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
    ) const
{
    if (!m_impl)
        return;

    const EntityDescriptor* entity = issuer ? dynamic_cast<const EntityDescriptor*>(issuer->getParent()) : NULL;
    const char* relyingParty = application.getRelyingParty(entity)->getString("entityID").second;

    // Check for assertions.
    if (XMLString::equals(xmlObject.getElementQName().getLocalPart(), saml1::Assertion::LOCAL_NAME)) {
        const saml2::Assertion* token2 = dynamic_cast<const saml2::Assertion*>(&xmlObject);
        if (token2) {
            auto_ptr_char assertingParty(entity ? entity->getEntityID() : NULL);
            const vector<saml2::AttributeStatement*>& statements = token2->getAttributeStatements();
            for (vector<saml2::AttributeStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
                const vector<saml2::Attribute*>& attrs = const_cast<const saml2::AttributeStatement*>(*s)->getAttributes();
                for (vector<saml2::Attribute*>::const_iterator a = attrs.begin(); a!=attrs.end(); ++a)
                    m_impl->extractAttributes(application, assertingParty.get(), relyingParty, *(*a), attributes);

                const vector<saml2::EncryptedAttribute*>& encattrs = const_cast<const saml2::AttributeStatement*>(*s)->getEncryptedAttributes();
                for (vector<saml2::EncryptedAttribute*>::const_iterator ea = encattrs.begin(); ea!=encattrs.end(); ++ea)
                    extractAttributes(application, issuer, *(*ea), attributes);
            }
            return;
        }

        const saml1::Assertion* token1 = dynamic_cast<const saml1::Assertion*>(&xmlObject);
        if (token1) {
            auto_ptr_char assertingParty(entity ? entity->getEntityID() : NULL);
            const vector<saml1::AttributeStatement*>& statements = token1->getAttributeStatements();
            for (vector<saml1::AttributeStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
                const vector<saml1::Attribute*>& attrs = const_cast<const saml1::AttributeStatement*>(*s)->getAttributes();
                for (vector<saml1::Attribute*>::const_iterator a = attrs.begin(); a!=attrs.end(); ++a)
                    m_impl->extractAttributes(application, assertingParty.get(), relyingParty, *(*a), attributes);
            }
            return;
        }

        throw AttributeExtractionException("Unable to extract attributes, unknown object type.");
    }

    // Check for metadata.
    if (XMLString::equals(xmlObject.getElementQName().getNamespaceURI(), samlconstants::SAML20MD_NS)) {
        const RoleDescriptor* roleToExtract = dynamic_cast<const RoleDescriptor*>(&xmlObject);
        const EntityDescriptor* entityToExtract = roleToExtract ? dynamic_cast<const EntityDescriptor*>(roleToExtract->getParent()) : NULL;
        if (!entityToExtract)
            throw AttributeExtractionException("Unable to extract attributes, unknown metadata object type.");
        const Extensions* ext = entityToExtract->getExtensions();
        if (ext) {
            m_impl->extractAttributes(
                application,
                dynamic_cast<const ObservableMetadataProvider*>(application.getMetadataProvider(false)),
                entityToExtract->getEntityID(),
                relyingParty,
                *ext,
                attributes
                );
        }
        const EntitiesDescriptor* group = dynamic_cast<const EntitiesDescriptor*>(entityToExtract->getParent());
        while (group) {
            ext = group->getExtensions();
            if (ext) {
                m_impl->extractAttributes(
                    application,
                    dynamic_cast<const ObservableMetadataProvider*>(application.getMetadataProvider(false)),
                    NULL,   // not an entity, so inline assertions won't be processed
                    relyingParty,
                    *ext,
                    attributes
                    );
            }
            group = dynamic_cast<const EntitiesDescriptor*>(group->getParent());
        }
        return;
    }

    // Check for attributes.
    if (XMLString::equals(xmlObject.getElementQName().getLocalPart(), saml1::Attribute::LOCAL_NAME)) {
        auto_ptr_char assertingParty(entity ? entity->getEntityID() : NULL);
        const saml2::Attribute* attr2 = dynamic_cast<const saml2::Attribute*>(&xmlObject);
        if (attr2)
            return m_impl->extractAttributes(application, assertingParty.get(), relyingParty, *attr2, attributes);

        const saml1::Attribute* attr1 = dynamic_cast<const saml1::Attribute*>(&xmlObject);
        if (attr1)
            return m_impl->extractAttributes(application, assertingParty.get(), relyingParty, *attr1, attributes);

        throw AttributeExtractionException("Unable to extract attributes, unknown object type.");
    }

    if (XMLString::equals(xmlObject.getElementQName().getLocalPart(), EncryptedAttribute::LOCAL_NAME)) {
        const EncryptedAttribute* encattr = dynamic_cast<const EncryptedAttribute*>(&xmlObject);
        if (encattr) {
            const XMLCh* recipient = application.getXMLString("entityID").second;
            CredentialResolver* cr = application.getCredentialResolver();
            if (!cr) {
                m_log.warn("found encrypted attribute, but no CredentialResolver was available");
                return;
            }

            try {
                Locker credlocker(cr);
                if (issuer) {
                    MetadataCredentialCriteria mcc(*issuer);
                    auto_ptr<XMLObject> decrypted(encattr->decrypt(*cr, recipient, &mcc));
                    if (m_log.isDebugEnabled())
                        m_log.debugStream() << "decrypted Attribute: " << *(decrypted.get()) << logging::eol;
                    return extractAttributes(application, issuer, *(decrypted.get()), attributes);
                }
                else {
                    auto_ptr<XMLObject> decrypted(encattr->decrypt(*cr, recipient));
                    if (m_log.isDebugEnabled())
                        m_log.debugStream() << "decrypted Attribute: " << *(decrypted.get()) << logging::eol;
                    return extractAttributes(application, issuer, *(decrypted.get()), attributes);
                }
            }
            catch (exception& ex) {
                m_log.error("caught exception decrypting Attribute: %s", ex.what());
                return;
            }
        }
    }

    // Check for NameIDs.
    const NameID* name2 = dynamic_cast<const NameID*>(&xmlObject);
    if (name2) {
        auto_ptr_char assertingParty(entity ? entity->getEntityID() : NULL);
        return m_impl->extractAttributes(application, assertingParty.get(), relyingParty, *name2, attributes);
    }

    const NameIdentifier* name1 = dynamic_cast<const NameIdentifier*>(&xmlObject);
    if (name1) {
        auto_ptr_char assertingParty(entity ? entity->getEntityID() : NULL);
        return m_impl->extractAttributes(application, assertingParty.get(), relyingParty, *name1, attributes);
    }

    throw AttributeExtractionException("Unable to extract attributes, unknown object type.");
}

pair<bool,DOMElement*> XMLExtractor::load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : NULL);

    XMLExtractorImpl* impl = new XMLExtractorImpl(raw.second, m_log);

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    delete m_impl;
    m_impl = impl;

    return make_pair(false,(DOMElement*)NULL);
}

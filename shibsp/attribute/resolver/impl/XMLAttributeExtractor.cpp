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
 * XMLAttributeExtractor.cpp
 * 
 * AttributeExtractor based on an XML mapping file.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/resolver/AttributeExtractor.h"
#include "util/SPConstants.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
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

    class XMLExtractorImpl
    {
    public:
        XMLExtractorImpl(const DOMElement* e, Category& log);
        ~XMLExtractorImpl() {
            for (attrmap_t::iterator i = m_attrMap.begin(); i!=m_attrMap.end(); ++i)
                delete i->second.first;
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

        void extractAttributes(
            const Application& application, const char* assertingParty, const NameIdentifier& nameid, vector<Attribute*>& attributes
            ) const;
        void extractAttributes(
            const Application& application, const char* assertingParty, const NameID& nameid, vector<Attribute*>& attributes
            ) const;
        void extractAttributes(
            const Application& application, const char* assertingParty, const saml1::Attribute& attr, vector<Attribute*>& attributes
            ) const;
        void extractAttributes(
            const Application& application, const char* assertingParty, const saml2::Attribute& attr, vector<Attribute*>& attributes
            ) const;
        void extractAttributes(
            const Application& application, const char* assertingParty, const Extensions& ext, vector<Attribute*>& attributes
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
    };
    
    class XMLExtractor : public AttributeExtractor, public ReloadableXMLFile
    {
    public:
        XMLExtractor(const DOMElement* e) : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT".AttributeExtractor")), m_impl(NULL) {
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
    
    static const XMLCh _AttributeDecoder[] =    UNICODE_LITERAL_16(A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);
    static const XMLCh Attributes[] =           UNICODE_LITERAL_10(A,t,t,r,i,b,u,t,e,s);
    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh _aliases[] =             UNICODE_LITERAL_7(a,l,i,a,s,e,s);
    static const XMLCh _name[] =                UNICODE_LITERAL_4(n,a,m,e);
    static const XMLCh nameFormat[] =           UNICODE_LITERAL_10(n,a,m,e,F,o,r,m,a,t);
};

XMLExtractorImpl::XMLExtractorImpl(const DOMElement* e, Category& log) : m_log(log), m_document(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLExtractorImpl");
#endif
    
    if (!XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, Attributes))
        throw ConfigurationException("XML AttributeExtractor requires am:Attributes at root of configuration.");

    DOMElement* child = XMLHelper::getFirstChildElement(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
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
                auto_ptr<QName> q(XMLHelper::getXSIType(dchild));
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
}

void XMLExtractorImpl::extractAttributes(
    const Application& application, const char* assertingParty, const NameIdentifier& nameid, vector<Attribute*>& attributes
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
        Attribute* a = rule->second.first->decode(rule->second.second, &nameid, assertingParty, application.getString("entityID").second);
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
    const Application& application, const char* assertingParty, const NameID& nameid, vector<Attribute*>& attributes
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
        Attribute* a = rule->second.first->decode(rule->second.second, &nameid, assertingParty, application.getString("entityID").second);
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
    const Application& application, const char* assertingParty, const saml1::Attribute& attr, vector<Attribute*>& attributes
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
        Attribute* a = rule->second.first->decode(rule->second.second, &attr, assertingParty, application.getString("entityID").second);
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
    const Application& application, const char* assertingParty, const saml2::Attribute& attr, vector<Attribute*>& attributes
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
        Attribute* a = rule->second.first->decode(rule->second.second, &attr, assertingParty, application.getString("entityID").second);
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
    const Application& application, const char* assertingParty, const Extensions& ext, vector<Attribute*>& attributes
    ) const
{
    const vector<XMLObject*> exts = ext.getUnknownXMLObjects();
    for (vector<XMLObject*>::const_iterator i = exts.begin(); i!=exts.end(); ++i) {
        const saml2::Attribute* attr = dynamic_cast<const saml2::Attribute*>(*i);
        if (attr)
            extractAttributes(application, assertingParty, *attr, attributes);
    }
}

void XMLExtractor::extractAttributes(
    const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
    ) const
{
    if (!m_impl)
        return;

    // Check for assertions.
    if (XMLString::equals(xmlObject.getElementQName().getLocalPart(), saml1::Assertion::LOCAL_NAME)) {
        const saml2::Assertion* token2 = dynamic_cast<const saml2::Assertion*>(&xmlObject);
        if (token2) {
            auto_ptr_char assertingParty(issuer ? dynamic_cast<const EntityDescriptor*>(issuer->getParent())->getEntityID() : NULL);
            const vector<saml2::AttributeStatement*>& statements = token2->getAttributeStatements();
            for (vector<saml2::AttributeStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
                const vector<saml2::Attribute*>& attrs = const_cast<const saml2::AttributeStatement*>(*s)->getAttributes();
                for (vector<saml2::Attribute*>::const_iterator a = attrs.begin(); a!=attrs.end(); ++a)
                    m_impl->extractAttributes(application, assertingParty.get(), *(*a), attributes);

                const vector<saml2::EncryptedAttribute*>& encattrs = const_cast<const saml2::AttributeStatement*>(*s)->getEncryptedAttributes();
                for (vector<saml2::EncryptedAttribute*>::const_iterator ea = encattrs.begin(); ea!=encattrs.end(); ++ea)
                    extractAttributes(application, issuer, *(*ea), attributes);
            }
            return;
        }

        const saml1::Assertion* token1 = dynamic_cast<const saml1::Assertion*>(&xmlObject);
        if (token1) {
            auto_ptr_char assertingParty(issuer ? dynamic_cast<const EntityDescriptor*>(issuer->getParent())->getEntityID() : NULL);
            const vector<saml1::AttributeStatement*>& statements = token1->getAttributeStatements();
            for (vector<saml1::AttributeStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
                const vector<saml1::Attribute*>& attrs = const_cast<const saml1::AttributeStatement*>(*s)->getAttributes();
                for (vector<saml1::Attribute*>::const_iterator a = attrs.begin(); a!=attrs.end(); ++a)
                    m_impl->extractAttributes(application, assertingParty.get(), *(*a), attributes);
            }
            return;
        }

        throw AttributeExtractionException("Unable to extract attributes, unknown object type.");
    }

    // Check for metadata.
    if (XMLString::equals(xmlObject.getElementQName().getNamespaceURI(), samlconstants::SAML20MD_NS)) {
        const EntityDescriptor* entity = dynamic_cast<const EntityDescriptor*>(&xmlObject);
        if (!entity)
            throw AttributeExtractionException("Unable to extract attributes, unknown metadata object type.");
        auto_ptr_char assertingParty(issuer ? dynamic_cast<const EntityDescriptor*>(issuer->getParent())->getEntityID() : NULL);
        const Extensions* ext = entity->getExtensions();
        if (ext)
            m_impl->extractAttributes(application, assertingParty.get(), *ext, attributes);
        const EntitiesDescriptor* group = dynamic_cast<const EntitiesDescriptor*>(entity->getParent());
        while (group) {
            ext = group->getExtensions();
            if (ext)
                m_impl->extractAttributes(application, assertingParty.get(), *ext, attributes);
            group = dynamic_cast<const EntitiesDescriptor*>(group->getParent());
        }
        return;
    }

    // Check for attributes.
    if (XMLString::equals(xmlObject.getElementQName().getLocalPart(), saml1::Attribute::LOCAL_NAME)) {
        auto_ptr_char assertingParty(issuer ? dynamic_cast<const EntityDescriptor*>(issuer->getParent())->getEntityID() : NULL);

        const saml2::Attribute* attr2 = dynamic_cast<const saml2::Attribute*>(&xmlObject);
        if (attr2)
            return m_impl->extractAttributes(application, assertingParty.get(), *attr2, attributes);

        const saml1::Attribute* attr1 = dynamic_cast<const saml1::Attribute*>(&xmlObject);
        if (attr1)
            return m_impl->extractAttributes(application, assertingParty.get(), *attr1, attributes);

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
        auto_ptr_char assertingParty(issuer ? dynamic_cast<const EntityDescriptor*>(issuer->getParent())->getEntityID() : NULL);
        return m_impl->extractAttributes(application, assertingParty.get(), *name2, attributes);
    }

    const NameIdentifier* name1 = dynamic_cast<const NameIdentifier*>(&xmlObject);
    if (name1) {
        auto_ptr_char assertingParty(issuer ? dynamic_cast<const EntityDescriptor*>(issuer->getParent())->getEntityID() : NULL);
        return m_impl->extractAttributes(application, assertingParty.get(), *name1, attributes);
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

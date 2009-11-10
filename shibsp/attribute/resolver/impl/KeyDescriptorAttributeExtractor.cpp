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
 * KeyDescriptorAttributeExtractor.cpp
 *
 * AttributeExtractor for KeyDescriptor information.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/SimpleAttribute.h"
#include "attribute/resolver/AttributeExtractor.h"

#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/SecurityHelper.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class KeyDescriptorExtractor : public AttributeExtractor
    {
    public:
        KeyDescriptorExtractor(const DOMElement* e);
        ~KeyDescriptorExtractor() {}

        Lockable* lock() {
            return this;
        }

        void unlock() {
        }

        void extractAttributes(
            const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
            ) const;

        void getAttributeIds(std::vector<std::string>& attributes) const {
            if (!m_hashId.empty())
                attributes.push_back(m_hashId.front());
            if (!m_signingId.empty())
                attributes.push_back(m_signingId.front());
            if (!m_encryptionId.empty())
                attributes.push_back(m_encryptionId.front());
        }

    private:
        auto_ptr_char m_hashAlg;
        vector<string> m_hashId;
        vector<string> m_signingId;
        vector<string> m_encryptionId;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AttributeExtractor* SHIBSP_DLLLOCAL KeyDescriptorAttributeExtractorFactory(const DOMElement* const & e)
    {
        return new KeyDescriptorExtractor(e);
    }

    static const XMLCh encryptionId[] = UNICODE_LITERAL_12(e,n,c,r,y,p,t,i,o,n,I,d);
    static const XMLCh hashId[] =       UNICODE_LITERAL_6(h,a,s,h,I,d);
    static const XMLCh hashAlg[] =      UNICODE_LITERAL_7(h,a,s,h,A,l,g);
    static const XMLCh signingId[] =    UNICODE_LITERAL_9(s,i,g,n,i,n,g,I,d);
};

KeyDescriptorExtractor::KeyDescriptorExtractor(const DOMElement* e) : m_hashAlg(e ? e->getAttributeNS(NULL, hashAlg) : NULL)
{
    if (e) {
        const XMLCh* a = e->getAttributeNS(NULL, hashId);
        if (a && *a) {
            auto_ptr_char temp(a);
            m_hashId.push_back(temp.get());
        }
        a = e->getAttributeNS(NULL, signingId);
        if (a && *a) {
            auto_ptr_char temp(a);
            m_signingId.push_back(temp.get());
        }
        a = e->getAttributeNS(NULL, encryptionId);
        if (a && *a) {
            auto_ptr_char temp(a);
            m_encryptionId.push_back(temp.get());
        }
    }
    if (m_hashId.empty() && m_signingId.empty() && m_encryptionId.empty())
        throw ConfigurationException("KeyDescriptor AttributeExtractor requires hashId, signingId, or encryptionId property.");
}

void KeyDescriptorExtractor::extractAttributes(
    const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
    ) const
{
    const RoleDescriptor* role = dynamic_cast<const RoleDescriptor*>(&xmlObject);
    if (!role)
        return;

    vector<const Credential*> creds;
    MetadataCredentialCriteria mcc(*role);

    if (!m_signingId.empty() || !m_hashId.empty()) {
        mcc.setUsage(Credential::SIGNING_CREDENTIAL);
        if (application.getMetadataProvider()->resolve(creds, &mcc)) {
            if (!m_hashId.empty()) {
                const char* alg = m_hashAlg.get();
                if (!alg || !*alg)
                    alg = "SHA1";
                auto_ptr<SimpleAttribute> attr(new SimpleAttribute(m_hashId));
                vector<string>& vals = attr->getValues();
                for (vector<const Credential*>::const_iterator c = creds.begin(); c != creds.end(); ++c) {
                    if (vals.empty() || !vals.back().empty())
                        vals.push_back(string());
                    vals.back() = SecurityHelper::getDEREncoding(*(*c), alg);
                }
                if (vals.back().empty())
                    vals.pop_back();
                if (!vals.empty())
                    attributes.push_back(attr.release());
            }
            if (!m_signingId.empty()) {
                auto_ptr<SimpleAttribute> attr(new SimpleAttribute(m_signingId));
                vector<string>& vals = attr->getValues();
                for (vector<const Credential*>::const_iterator c = creds.begin(); c != creds.end(); ++c) {
                    if (vals.empty() || !vals.back().empty())
                        vals.push_back(string());
                    vals.back() = SecurityHelper::getDEREncoding(*(*c));
                }
                if (vals.back().empty())
                    vals.pop_back();
                if (!vals.empty())
                    attributes.push_back(attr.release());
            }
            creds.clear();
        }
    }

    if (!m_encryptionId.empty()) {
        mcc.setUsage(Credential::ENCRYPTION_CREDENTIAL);
        if (application.getMetadataProvider()->resolve(creds, &mcc)) {
            auto_ptr<SimpleAttribute> attr(new SimpleAttribute(m_encryptionId));
            vector<string>& vals = attr->getValues();
            for (vector<const Credential*>::const_iterator c = creds.begin(); c != creds.end(); ++c) {
                if (vals.empty() || !vals.back().empty())
                    vals.push_back(string());
                vals.back() = SecurityHelper::getDEREncoding(*(*c));
            }
            if (vals.back().empty())
                vals.pop_back();
            if (!vals.empty())
                attributes.push_back(attr.release());
        }
    }
}

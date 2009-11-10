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
 * DelegationAttributeExtractor.cpp
 *
 * AttributeExtractor for DelegationRestriction information.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/ExtensibleAttribute.h"
#include "attribute/resolver/AttributeExtractor.h"
#include "util/SPConstants.h"

#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/util/DateTime.h>
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

    class DelegationExtractor : public AttributeExtractor
    {
    public:
        DelegationExtractor(const DOMElement* e);
        ~DelegationExtractor() {}

        Lockable* lock() {
            return this;
        }

        void unlock() {
        }

        void extractAttributes(
            const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
            ) const;

        void getAttributeIds(std::vector<std::string>& attributes) const {
            attributes.push_back(m_attributeId);
        }

    private:
        string m_attributeId,m_formatter;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AttributeExtractor* SHIBSP_DLLLOCAL DelegationAttributeExtractorFactory(const DOMElement* const & e)
    {
        return new DelegationExtractor(e);
    }

    static const XMLCh attributeId[] =  UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,d);
    static const XMLCh formatter[] =    UNICODE_LITERAL_9(f,o,r,m,a,t,t,e,r);
};

DelegationExtractor::DelegationExtractor(const DOMElement* e) : m_attributeId("delegate"), m_formatter("$Name")
{
    if (e) {
        const XMLCh* a = e->getAttributeNS(NULL, attributeId);
        if (a && *a) {
            auto_ptr_char temp(a);
            m_attributeId = temp.get();
        }
        a = e->getAttributeNS(NULL, formatter);
        if (a && *a) {
            auto_ptr_char temp(a);
            m_formatter = temp.get();
        }
    }
}

void DelegationExtractor::extractAttributes(
    const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
    ) const
{
    const saml2::Assertion* assertion = dynamic_cast<const saml2::Assertion*>(&xmlObject);
    if (!assertion || !assertion->getConditions())
        return;

    Category& log = Category::getInstance(SHIBSP_LOGCAT".AttributeExtractor.Delegation");

    const vector<saml2::Condition*>& conditions = const_cast<const saml2::Conditions*>(assertion->getConditions())->getConditions();
    for (vector<saml2::Condition*>::const_iterator c = conditions.begin(); c != conditions.end(); ++c) {
        const saml2::DelegationRestrictionType* drt = dynamic_cast<const saml2::DelegationRestrictionType*>(*c);
        if (drt) {
            auto_ptr<ExtensibleAttribute> attr(new ExtensibleAttribute(vector<string>(1,m_attributeId), m_formatter.c_str()));

            const vector<saml2::Delegate*>& dels = drt->getDelegates();
            for (vector<saml2::Delegate*>::const_iterator d = dels.begin(); d != dels.end(); ++d) {
                if ((*d)->getBaseID()) {
                    log.error("delegate identified by saml:BaseID cannot be processed into an attribute value");
                    continue;
                }

                saml2::NameID* n = NULL;
                if ((*d)->getEncryptedID()) {
                    CredentialResolver* cr = application.getCredentialResolver();
                    if (!cr) {
                        log.warn("found encrypted Delegate, but no CredentialResolver was available");
                    }

                    try {
                        const XMLCh* recipient = application.getRelyingParty(
                            issuer ? dynamic_cast<EntityDescriptor*>(issuer->getParent()) : NULL
                            )->getXMLString("entityID").second;
                        Locker credlocker(cr);
                        if (issuer) {
                            MetadataCredentialCriteria mcc(*issuer);
                            auto_ptr<XMLObject> decrypted((*d)->getEncryptedID()->decrypt(*cr, recipient, &mcc));
                            n = dynamic_cast<saml2::NameID*>(decrypted.release());
                        }
                        else {
                            auto_ptr<XMLObject> decrypted((*d)->getEncryptedID()->decrypt(*cr, recipient));
                            n = dynamic_cast<saml2::NameID*>(decrypted.release());
                        }
                        if (n && log.isDebugEnabled())
                            log.debugStream() << "decrypted Delegate: " << *n << logging::eol;
                    }
                    catch (exception& ex) {
                        log.error("caught exception decrypting Delegate: %s", ex.what());
                    }
                }
                else {
                    n = (*d)->getNameID();
                }

                if (n) {
                    DDF val = DDF(NULL).structure();
                    if ((*d)->getConfirmationMethod()) {
                        auto_ptr_char temp((*d)->getConfirmationMethod());
                        val.addmember("ConfirmationMethod").string(temp.get());
                    }
                    if ((*d)->getDelegationInstant()) {
                        auto_ptr_char temp((*d)->getDelegationInstant()->getRawData());
                        val.addmember("DelegationInstant").string(temp.get());
                    }

                    auto_arrayptr<char> name(toUTF8(n->getName()));
                    if (name.get() && *name.get()) {
                        val.addmember("Name").string(name.get());
                        char* str = toUTF8(n->getFormat());
                        if (str && *str)
                            val.addmember("Format").string(str);
                        delete[] str;

                        str = toUTF8(n->getNameQualifier());
                        if (str && *str)
                            val.addmember("NameQualifier").string(str);
                        delete[] str;

                        str = toUTF8(n->getSPNameQualifier());
                        if (str && *str)
                            val.addmember("SPNameQualifier").string(str);
                        delete[] str;

                        str = toUTF8(n->getSPProvidedID());
                        if (str && *str)
                            val.addmember("SPProvidedID").string(str);
                        delete[] str;
                    }

                    if (n != (*d)->getNameID())
                        delete n;

                    if (val.integer())
                        attr->getValues().add(val);
                    else
                        val.destroy();
                }
            }

            attributes.push_back(attr.release());
        }
    }
}

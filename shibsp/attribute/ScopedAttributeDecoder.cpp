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
 * ScopedAttributeDecoder.cpp
 *
 * Decodes SAML into ScopedAttributes
 */

#include "internal.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/ScopedAttribute.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>

using namespace shibsp;
using namespace opensaml::saml1;
using namespace opensaml::saml2;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    static const XMLCh Scope[] =            UNICODE_LITERAL_5(S,c,o,p,e);
    static const XMLCh scopeDelimeter[] =   UNICODE_LITERAL_14(s,c,o,p,e,D,e,l,i,m,e,t,e,r);

    class SHIBSP_DLLLOCAL ScopedAttributeDecoder : virtual public AttributeDecoder
    {
    public:
        ScopedAttributeDecoder(const DOMElement* e) : AttributeDecoder(e), m_delimeter('@') {
            if (e && e->hasAttributeNS(NULL,scopeDelimeter)) {
                auto_ptr_char d(e->getAttributeNS(NULL,scopeDelimeter));
                m_delimeter = *(d.get());
            }
        }
        ~ScopedAttributeDecoder() {}

        shibsp::Attribute* decode(
            const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty=NULL, const char* relyingParty=NULL
            ) const;

    private:
        char m_delimeter;
    };

    AttributeDecoder* SHIBSP_DLLLOCAL ScopedAttributeDecoderFactory(const DOMElement* const & e)
    {
        return new ScopedAttributeDecoder(e);
    }
};

shibsp::Attribute* ScopedAttributeDecoder::decode(
    const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty, const char* relyingParty
    ) const
{
    char* val;
    char* scope;
    const XMLCh* xmlscope;
    xmltooling::QName scopeqname(NULL,Scope);
    auto_ptr<ScopedAttribute> scoped(new ScopedAttribute(ids, m_delimeter));
    vector< pair<string,string> >& dest = scoped->getValues();
    vector<XMLObject*>::const_iterator v,stop;

    Category& log = Category::getInstance(SHIBSP_LOGCAT".AttributeDecoder.Scoped");

    if (xmlObject && XMLString::equals(opensaml::saml1::Attribute::LOCAL_NAME,xmlObject->getElementQName().getLocalPart())) {
        const opensaml::saml2::Attribute* saml2attr = dynamic_cast<const opensaml::saml2::Attribute*>(xmlObject);
        if (saml2attr) {
            const vector<XMLObject*>& values = saml2attr->getAttributeValues();
            v = values.begin();
            stop = values.end();
            if (log.isDebugEnabled()) {
                auto_ptr_char n(saml2attr->getName());
                log.debug(
                    "decoding ScopedAttribute (%s) from SAML 2 Attribute (%s) with %lu value(s)",
                    ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                    );
            }
        }
        else {
            const opensaml::saml1::Attribute* saml1attr = dynamic_cast<const opensaml::saml1::Attribute*>(xmlObject);
            if (saml1attr) {
                const vector<XMLObject*>& values = saml1attr->getAttributeValues();
                v = values.begin();
                stop = values.end();
                if (log.isDebugEnabled()) {
                    auto_ptr_char n(saml1attr->getAttributeName());
                    log.debug(
                        "decoding ScopedAttribute (%s) from SAML 1 Attribute (%s) with %lu value(s)",
                        ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                        );
                }
            }
            else {
                log.warn("XMLObject type not recognized by ScopedAttributeDecoder, no values returned");
                return NULL;
            }
        }

        for (; v!=stop; ++v) {
            if (!(*v)->hasChildren()) {
                val = toUTF8((*v)->getTextContent());
                if (val && *val) {
                    const AttributeExtensibleXMLObject* aexo=dynamic_cast<const AttributeExtensibleXMLObject*>(*v);
                    xmlscope = aexo ? aexo->getAttribute(scopeqname) : NULL;
                    if (xmlscope && *xmlscope) {
                        scope = toUTF8(xmlscope);
                        dest.push_back(pair<string,string>(val,scope));
                        delete[] scope;
                    }
                    else {
                        scope = strchr(val, m_delimeter);
                        if (scope) {
                            *scope++ = 0;
                            if (*scope)
                                dest.push_back(pair<string,string>(val,scope));
                            else
                                log.warn("ignoring unscoped AttributeValue");
                        }
                        else {
                            log.warn("ignoring unscoped AttributeValue");
                        }
                    }
                }
                else {
                    log.warn("skipping empty AttributeValue");
                }
                delete[] val;
            }
            else {
                log.warn("skipping complex AttributeValue");
            }
        }

        return dest.empty() ? NULL : _decode(scoped.release());
    }

    const NameID* saml2name = dynamic_cast<const NameID*>(xmlObject);
    if (saml2name) {
        if (log.isDebugEnabled()) {
            auto_ptr_char f(saml2name->getFormat());
            log.debug("decoding ScopedAttribute (%s) from SAML 2 NameID with Format (%s)", ids.front().c_str(), f.get() ? f.get() : "unspecified");
        }
        val = toUTF8(saml2name->getName());
    }
    else {
        const NameIdentifier* saml1name = dynamic_cast<const NameIdentifier*>(xmlObject);
        if (saml1name) {
            if (log.isDebugEnabled()) {
                auto_ptr_char f(saml1name->getFormat());
                log.debug(
                    "decoding ScopedAttribute (%s) from SAML 1 NameIdentifier with Format (%s)",
                    ids.front().c_str(), f.get() ? f.get() : "unspecified"
                    );
            }
            val = toUTF8(saml1name->getName());
        }
        else {
            log.warn("XMLObject type not recognized by ScopedAttributeDecoder, no values returned");
            return NULL;
        }
    }

    if (val && *val && *val!=m_delimeter) {
        scope = strchr(val, m_delimeter);
        if (scope) {
            *scope++ = 0;
            if (*scope)
                dest.push_back(pair<string,string>(val,scope));
            else
                log.warn("ignoring NameID with no scope");
        }
        else {
            log.warn("ignoring NameID with no scope delimiter (%c)", m_delimeter);
        }
    }
    else {
        log.warn("ignoring empty NameID");
    }
    delete[] val;
    return dest.empty() ? NULL : _decode(scoped.release());
}

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
 * NameIDAttributeDecoder.cpp
 *
 * Decodes SAML into NameIDAttributes
 */

#include "internal.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/NameIDAttribute.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>

using namespace shibsp;
using namespace opensaml::saml1;
using namespace opensaml::saml2;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    static const XMLCh formatter[] = UNICODE_LITERAL_9(f,o,r,m,a,t,t,e,r);
    static const XMLCh defaultQualifiers[] = UNICODE_LITERAL_17(d,e,f,a,u,l,t,Q,u,a,l,i,f,i,e,r,s);

    class SHIBSP_DLLLOCAL NameIDAttributeDecoder : virtual public AttributeDecoder
    {
    public:
        NameIDAttributeDecoder(const DOMElement* e)
                : AttributeDecoder(e), m_formatter(e ? e->getAttributeNS(NULL, formatter) : NULL), m_defaultQualifiers(false) {
            const XMLCh* flag = e ? e->getAttributeNS(NULL, defaultQualifiers) : NULL;
            if (flag && (*flag == chLatin_t || *flag == chDigit_1))
                m_defaultQualifiers = true;
        }
        ~NameIDAttributeDecoder() {}

        shibsp::Attribute* decode(
            const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty=NULL, const char* relyingParty=NULL
            ) const;

    private:
        void extract(
            const NameIDType* n, vector<NameIDAttribute::Value>& dest, const char* assertingParty, const char* relyingParty
            ) const;
        void extract(
            const NameIdentifier* n, vector<NameIDAttribute::Value>& dest, const char* assertingParty, const char* relyingParty
            ) const;
        auto_ptr_char m_formatter;
        bool m_defaultQualifiers;
    };

    AttributeDecoder* SHIBSP_DLLLOCAL NameIDAttributeDecoderFactory(const DOMElement* const & e)
    {
        return new NameIDAttributeDecoder(e);
    }
};

shibsp::Attribute* NameIDAttributeDecoder::decode(
    const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty, const char* relyingParty
    ) const
{
    auto_ptr<NameIDAttribute> nameid(
        new NameIDAttribute(ids, (m_formatter.get() && *m_formatter.get()) ? m_formatter.get() : DEFAULT_NAMEID_FORMATTER)
        );
    vector<NameIDAttribute::Value>& dest = nameid->getValues();
    vector<XMLObject*>::const_iterator v,stop;

    Category& log = Category::getInstance(SHIBSP_LOGCAT".AttributeDecoder.NameID");

    if (xmlObject && XMLString::equals(opensaml::saml1::Attribute::LOCAL_NAME,xmlObject->getElementQName().getLocalPart())) {
        const opensaml::saml2::Attribute* saml2attr = dynamic_cast<const opensaml::saml2::Attribute*>(xmlObject);
        if (saml2attr) {
            const vector<XMLObject*>& values = saml2attr->getAttributeValues();
            v = values.begin();
            stop = values.end();
            if (log.isDebugEnabled()) {
                auto_ptr_char n(saml2attr->getName());
                log.debug(
                    "decoding NameIDAttribute (%s) from SAML 2 Attribute (%s) with %lu value(s)",
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
                        "decoding NameIDAttribute (%s) from SAML 1 Attribute (%s) with %lu value(s)",
                        ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                        );
                }
            }
            else {
                log.warn("XMLObject type not recognized by NameIDAttributeDecoder, no values returned");
                return NULL;
            }
        }

        for (; v!=stop; ++v) {
            const NameIDType* n2 = dynamic_cast<const NameIDType*>(*v);
            if (n2)
                extract(n2, dest, assertingParty, relyingParty);
            else {
                const NameIdentifier* n1=dynamic_cast<const NameIdentifier*>(*v);
                if (n1)
                    extract(n1, dest, assertingParty, relyingParty);
                else if ((*v)->hasChildren()) {
                    const list<XMLObject*>& values = (*v)->getOrderedChildren();
                    for (list<XMLObject*>::const_iterator vv = values.begin(); vv!=values.end(); ++vv) {
                        if (n2=dynamic_cast<const NameIDType*>(*vv))
                            extract(n2, dest, assertingParty, relyingParty);
                        else if (n1=dynamic_cast<const NameIdentifier*>(*vv))
                            extract(n1, dest, assertingParty, relyingParty);
                        else
                            log.warn("skipping AttributeValue without a recognizable NameID/NameIdentifier");
                    }
                }
            }
        }

        return dest.empty() ? NULL : _decode(nameid.release());
    }

    const NameIDType* saml2name = dynamic_cast<const NameIDType*>(xmlObject);
    if (saml2name) {
        if (log.isDebugEnabled()) {
            auto_ptr_char f(saml2name->getFormat());
            log.debug("decoding NameIDAttribute (%s) from SAML 2 NameID with Format (%s)", ids.front().c_str(), f.get() ? f.get() : "unspecified");
        }
        extract(saml2name, dest, assertingParty, relyingParty);
    }
    else {
        const NameIdentifier* saml1name = dynamic_cast<const NameIdentifier*>(xmlObject);
        if (saml1name) {
            if (log.isDebugEnabled()) {
                auto_ptr_char f(saml1name->getFormat());
                log.debug(
                    "decoding NameIDAttribute (%s) from SAML 1 NameIdentifier with Format (%s)",
                    ids.front().c_str(), f.get() ? f.get() : "unspecified"
                    );
            }
            extract(saml1name, dest, assertingParty, relyingParty);
        }
        else {
            log.warn("XMLObject type not recognized by NameIDAttributeDecoder, no values returned");
            return NULL;
        }
    }

    return dest.empty() ? NULL : _decode(nameid.release());
}

void NameIDAttributeDecoder::extract(
    const NameIDType* n, vector<NameIDAttribute::Value>& dest, const char* assertingParty, const char* relyingParty
    ) const
{
    auto_arrayptr<char> name(toUTF8(n->getName()));
    if (name.get() && *name.get()) {
        dest.push_back(NameIDAttribute::Value());
        NameIDAttribute::Value& val = dest.back();
        val.m_Name = name.get();
        char* str = toUTF8(n->getFormat());
        if (str) {
            val.m_Format = str;
            delete[] str;
        }

        str = toUTF8(n->getNameQualifier());
        if (str && *str)
            val.m_NameQualifier = str;
        else if (m_defaultQualifiers && assertingParty)
            val.m_NameQualifier = assertingParty;
        delete[] str;

        str = toUTF8(n->getSPNameQualifier());
        if (str && *str)
            val.m_SPNameQualifier = str;
        else if (m_defaultQualifiers && relyingParty)
            val.m_SPNameQualifier = relyingParty;
        delete[] str;

        str = toUTF8(n->getSPProvidedID());
        if (str) {
            val.m_SPProvidedID = str;
            delete[] str;
        }
    }
}

void NameIDAttributeDecoder::extract(
    const NameIdentifier* n, vector<NameIDAttribute::Value>& dest, const char* assertingParty, const char* relyingParty
    ) const
{
    auto_arrayptr<char> name(toUTF8(n->getName()));
    if (name.get() && *name.get()) {
        dest.push_back(NameIDAttribute::Value());
        NameIDAttribute::Value& val = dest.back();
        val.m_Name = name.get();
        char* str = toUTF8(n->getFormat());
        if (str) {
            val.m_Format = str;
            delete[] str;
        }

        str = toUTF8(n->getNameQualifier());
        if (str && *str)
            val.m_NameQualifier = str;
        else if (m_defaultQualifiers && assertingParty)
            val.m_NameQualifier = assertingParty;
        delete[] str;

        if (m_defaultQualifiers && relyingParty)
            val.m_SPNameQualifier = relyingParty;
    }
}

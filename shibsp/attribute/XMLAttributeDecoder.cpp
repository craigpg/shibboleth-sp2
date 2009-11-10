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
 * XMLAttributeDecoder.cpp
 *
 * Decodes arbitrary XML into an XMLAttribute.
 */

#include "internal.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/XMLAttribute.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    class SHIBSP_DLLLOCAL XMLAttributeDecoder : virtual public AttributeDecoder
    {
    public:
        XMLAttributeDecoder(const DOMElement* e) : AttributeDecoder(e) {}
        ~XMLAttributeDecoder() {}

        Attribute* decode(
            const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty=NULL, const char* relyingParty=NULL
            ) const;

    private:
        DDF convert(DOMElement* e, bool nameit=true) const;
        auto_ptr_char m_formatter;
        map<pair<xstring,xstring>,string> m_tagMap;
    };

    AttributeDecoder* SHIBSP_DLLLOCAL XMLAttributeDecoderFactory(const DOMElement* const & e)
    {
        return new XMLAttributeDecoder(e);
    }
};


Attribute* XMLAttributeDecoder::decode(
    const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty, const char* relyingParty
    ) const
{
    if (!xmlObject)
        return NULL;

    Category& log = Category::getInstance(SHIBSP_LOGCAT".AttributeDecoder.XML");

    auto_ptr<XMLAttribute> attr(new XMLAttribute(ids));
    vector<string>& dest = attr->getValues();

    // Handle any non-Attribute object directly.
    if (!xmlObject || !XMLString::equals(saml1::Attribute::LOCAL_NAME, xmlObject->getElementQName().getLocalPart())) {
        DOMElement* e = xmlObject->getDOM();
        if (e) {
            if (log.isDebugEnabled()) {
                log.debug(
                    "decoding XMLAttribute (%s) from XMLObject (%s)",
                    ids.front().c_str(),
                    (xmlObject->getSchemaType() ? xmlObject->getSchemaType()->toString() : xmlObject->getElementQName().toString()).c_str()
                    );
            }
            dest.push_back(string());
            XMLHelper::serialize(e, dest.back());
        }
        else {
            log.warn("skipping XMLObject without a backing DOM");
        }
        return dest.empty() ? NULL : _decode(attr.release());
    }

    vector<XMLObject*>::const_iterator v,stop;

    const saml2::Attribute* saml2attr = dynamic_cast<const saml2::Attribute*>(xmlObject);
    if (saml2attr) {
        const vector<XMLObject*>& values = saml2attr->getAttributeValues();
        v = values.begin();
        stop = values.end();
        if (log.isDebugEnabled()) {
            auto_ptr_char n(saml2attr->getName());
            log.debug(
                "decoding XMLAttribute (%s) from SAML 2 Attribute (%s) with %lu value(s)",
                ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                );
        }
    }
    else {
        const saml1::Attribute* saml1attr = dynamic_cast<const saml1::Attribute*>(xmlObject);
        if (saml1attr) {
            const vector<XMLObject*>& values = saml1attr->getAttributeValues();
            v = values.begin();
            stop = values.end();
            if (log.isDebugEnabled()) {
                auto_ptr_char n(saml1attr->getAttributeName());
                log.debug(
                    "decoding XMLAttribute (%s) from SAML 1 Attribute (%s) with %lu value(s)",
                    ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                    );
            }
        }
        else {
            log.warn("XMLObject type not recognized by XMLAttributeDecoder, no values returned");
            return NULL;
        }
    }

    for (; v!=stop; ++v) {
        DOMElement* e = (*v)->getDOM();
        if (e) {
            dest.push_back(string());
            XMLHelper::serialize(e, dest.back());
        }
        else
            log.warn("skipping AttributeValue without a backing DOM");
    }

    return dest.empty() ? NULL : _decode(attr.release());
}

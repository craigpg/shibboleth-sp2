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
 * AttributeValueStringFunctor.cpp
 * 
 * A match function that matches the value of an attribute against the specified value.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/Attribute.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"

using namespace shibsp;
using namespace std;

namespace shibsp {

    static const XMLCh attributeID[] =  UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,D);
    static const XMLCh value[] =        UNICODE_LITERAL_5(v,a,l,u,e);
    static const XMLCh ignoreCase[] =   UNICODE_LITERAL_10(i,g,n,o,r,e,C,a,s,e);

    /**
     * A match function that matches the value of an attribute against the specified value.
     */
    class SHIBSP_DLLLOCAL AttributeValueStringFunctor : public MatchFunctor
    {
        xmltooling::auto_ptr_char m_attributeID;
        char* m_value;

        bool hasValue(const FilteringContext& filterContext) const;
        bool matches(const Attribute& attribute, size_t index) const;

    public:
        AttributeValueStringFunctor(const DOMElement* e)
            : m_value(e ? xmltooling::toUTF8(e->getAttributeNS(NULL,value)) : NULL), m_attributeID(e ? e->getAttributeNS(NULL,attributeID) : NULL) {
            if (!m_value || !*m_value) {
                delete[] m_value;
                throw ConfigurationException("AttributeValueString MatchFunctor requires non-empty value attribute.");
            }
            if (e && e->hasAttributeNS(NULL,ignoreCase)) {
                xmltooling::logging::Category::getInstance(SHIBSP_LOGCAT".AttributeFilter").warn(
                    "ignoreCase property ignored by AttributeValueString MatchFunctor in favor of attribute's caseSensitive property"
                    );
            }
        }

        virtual ~AttributeValueStringFunctor() {
            delete[] m_value;
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (!m_attributeID.get() || !*m_attributeID.get())
                throw AttributeFilteringException("No attributeID specified.");
            return hasValue(filterContext);
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            if (!m_attributeID.get() || !*m_attributeID.get() || XMLString::equals(m_attributeID.get(), attribute.getId()))
                return matches(attribute, index);
            return hasValue(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeValueStringFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AttributeValueStringFunctor(p.second);
    }

};

bool AttributeValueStringFunctor::hasValue(const FilteringContext& filterContext) const
{
    size_t count;
    pair<multimap<string,Attribute*>::const_iterator,multimap<string,Attribute*>::const_iterator> attrs =
        filterContext.getAttributes().equal_range(m_attributeID.get());
    for (; attrs.first != attrs.second; ++attrs.first) {
        count = attrs.first->second->valueCount();
        for (size_t index = 0; index < count; ++index) {
            if (matches(*(attrs.first->second), index))
                return true;
        }
    }
    return false;
}

bool AttributeValueStringFunctor::matches(const Attribute& attribute, size_t index) const
{
    const char* val = attribute.getString(index);
    if (!val)
        return false;
    if (attribute.isCaseSensitive())
        return !strcmp(m_value, val);

#ifdef HAVE_STRCASECMP
    return !strcasecmp(m_value, val);
#else
    return !stricmp(m_value, val);
#endif
}

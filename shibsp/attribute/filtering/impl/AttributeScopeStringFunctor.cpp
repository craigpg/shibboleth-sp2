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
 * AttributeScopeStringFunctor.cpp
 * 
 * A match function that matches the scope of an attribute value against the specified value.
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

    /**
     * A match function that matches the scope of an attribute value against the specified value.
     */
    class SHIBSP_DLLLOCAL AttributeScopeStringFunctor : public MatchFunctor
    {
        xmltooling::auto_ptr_char m_value;
        xmltooling::auto_ptr_char m_attributeID;

        bool hasScope(const FilteringContext& filterContext) const;

    public:
        AttributeScopeStringFunctor(const DOMElement* e)
            : m_value(e ? e->getAttributeNS(NULL,value) : NULL), m_attributeID(e ? e->getAttributeNS(NULL,attributeID) : NULL) {
            if (!m_value.get() || !*m_value.get())
                throw ConfigurationException("AttributeScopeString MatchFunctor requires non-empty value attribute.");
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (!m_attributeID.get() || !*m_attributeID.get())
                throw AttributeFilteringException("No attributeID specified.");
            return hasScope(filterContext);
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            if (!m_attributeID.get() || !*m_attributeID.get() || XMLString::equals(m_attributeID.get(), attribute.getId()))
                return XMLString::equals(attribute.getScope(index), m_value.get());
            return hasScope(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeScopeStringFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AttributeScopeStringFunctor(p.second);
    }

};

bool AttributeScopeStringFunctor::hasScope(const FilteringContext& filterContext) const
{
    size_t count;
    pair<multimap<string,Attribute*>::const_iterator,multimap<string,Attribute*>::const_iterator> attrs =
        filterContext.getAttributes().equal_range(m_attributeID.get());
    for (; attrs.first != attrs.second; ++attrs.first) {
        count = attrs.first->second->valueCount();
        for (size_t index = 0; index < count; ++index) {
            if (XMLString::equals(attrs.first->second->getScope(index), m_value.get()))
                return true;
        }
    }
    return false;
}

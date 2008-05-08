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
 * NumberOfAttributeValuesFunctor.cpp
 * 
 * A match function that evaluates to true if the given attribute has as a number
 * of values that falls between the minimum and maximum.
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
    static const XMLCh maximum[] =      UNICODE_LITERAL_7(m,a,x,i,m,u,m);
    static const XMLCh minimum[] =      UNICODE_LITERAL_7(m,i,n,i,m,u,m);

    /**
     * A match function that evaluates to true if the given attribute has as a number
     * of values that falls between the minimum and maximum.
     */
    class SHIBSP_DLLLOCAL NumberOfAttributeValuesFunctor : public MatchFunctor
    {
        unsigned int m_min,m_max;
        xmltooling::auto_ptr_char m_attributeID;

        size_t count(const FilteringContext& filterContext) const;

    public:
        NumberOfAttributeValuesFunctor(const DOMElement* e)
                : m_min(0), m_max(INT_MAX), m_attributeID(e ? e->getAttributeNS(NULL,attributeID) : NULL) {
            if (!m_attributeID.get() || !*m_attributeID.get())
                throw ConfigurationException("No attributeID specified.");
            const XMLCh* num = e->getAttributeNS(NULL, minimum);
            if (num && *num)
                m_min = XMLString::parseInt(num);
            num = e->getAttributeNS(NULL, maximum);
            if (num && *num)
                m_max = XMLString::parseInt(num);
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            size_t c = count(filterContext);
            return (m_min <= c && c <= m_max);
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            size_t c = count(filterContext);
            return (m_min <= c && c <= m_max);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL NumberOfAttributeValuesFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new NumberOfAttributeValuesFunctor(p.second);
    }

};

size_t NumberOfAttributeValuesFunctor::count(const FilteringContext& filterContext) const
{
    size_t count = 0;
    pair<multimap<string,Attribute*>::const_iterator,multimap<string,Attribute*>::const_iterator> attrs =
        filterContext.getAttributes().equal_range(m_attributeID.get());
    for (; attrs.first != attrs.second; ++attrs.first)
        count += attrs.first->second->valueCount();
    return count;
}

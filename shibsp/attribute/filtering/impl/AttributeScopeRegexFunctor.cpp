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
 * AttributeScopeRegexFunctor.cpp
 * 
 * A match function that evaluates an attribute value's scope against the provided regular expression.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/Attribute.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"

#include <xercesc/util/regx/RegularExpression.hpp>

using namespace shibsp;
using namespace std;

namespace shibsp {

    static const XMLCh attributeID[] =  UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,D);
    static const XMLCh options[] =  UNICODE_LITERAL_7(o,p,t,i,o,n,s);
    static const XMLCh regex[] =    UNICODE_LITERAL_5(r,e,g,e,x);

    /**
     * A match function that evaluates an attribute value's scope against the provided regular expression.
     */
    class SHIBSP_DLLLOCAL AttributeScopeRegexFunctor : public MatchFunctor
    {
        xmltooling::auto_ptr_char m_attributeID;
        RegularExpression* m_regex;

        bool hasScope(const FilteringContext& filterContext) const;
        bool matches(const Attribute& attribute, size_t index) const;

    public:
        AttributeScopeRegexFunctor(const DOMElement* e)
                : m_attributeID(e ? e->getAttributeNS(NULL,attributeID) : NULL) {
            const XMLCh* r = e ? e->getAttributeNS(NULL,regex) : NULL;
            if (!r || !*r)
                throw ConfigurationException("AttributeScopeRegex MatchFunctor requires non-empty regex attribute.");
            try {
                m_regex = new RegularExpression(r, e->getAttributeNS(NULL,options));
            }
            catch (XMLException& ex) {
                xmltooling::auto_ptr_char temp(ex.getMessage());
                throw ConfigurationException(temp.get());
            }
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (!m_attributeID.get() || !*m_attributeID.get())
                throw AttributeFilteringException("No attributeID specified.");
            return hasScope(filterContext);
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            if (!m_attributeID.get() || !*m_attributeID.get() || XMLString::equals(m_attributeID.get(), attribute.getId()))
                return matches(attribute, index);
            return hasScope(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeScopeRegexFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AttributeScopeRegexFunctor(p.second);
    }

};

bool AttributeScopeRegexFunctor::hasScope(const FilteringContext& filterContext) const
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

bool AttributeScopeRegexFunctor::matches(const Attribute& attribute, size_t index) const
{
    const char* val = attribute.getScope(index);
    if (!val)
        return false;
    XMLCh* temp = xmltooling::fromUTF8(val);
    bool ret = m_regex->matches(temp);
    delete[] temp;
    return ret;
}

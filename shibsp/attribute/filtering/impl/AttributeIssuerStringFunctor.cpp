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
 * AttributeIssuerStringFunctor.cpp
 * 
 * A match function that matches the attribute issuer's name against the specified value.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"

namespace shibsp {

    static const XMLCh value[] = UNICODE_LITERAL_5(v,a,l,u,e);

    /**
     * A match function that matches the attribute issuer's name against the specified value.
     */
    class SHIBSP_DLLLOCAL AttributeIssuerStringFunctor : public MatchFunctor
    {
        const XMLCh* m_value;
    public:
        AttributeIssuerStringFunctor(const DOMElement* e) {
            m_value = e ? e->getAttributeNS(NULL,value) : NULL;
            if (!m_value || !*m_value)
                throw ConfigurationException("AttributeIssuerString MatchFunctor requires non-empty value attribute.");
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            return XMLString::equals(m_value, filterContext.getAttributeIssuer());
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return XMLString::equals(m_value, filterContext.getAttributeIssuer());
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeIssuerStringFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AttributeIssuerStringFunctor(p.second);
    }

};

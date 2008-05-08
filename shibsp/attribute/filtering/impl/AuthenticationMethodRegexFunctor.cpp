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
 * AuthenticationMethodRegexFunctor.cpp
 * 
 * A match function that evaluates to true if the user's authentication method matches the provided regular
 * expression.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"

#include <xercesc/util/regx/RegularExpression.hpp>

namespace shibsp {

    static const XMLCh options[] =  UNICODE_LITERAL_7(o,p,t,i,o,n,s);
    static const XMLCh regex[] =    UNICODE_LITERAL_5(r,e,g,e,x);
    
    /**
     * A match function that evaluates to true if the user's authentication method matches the provided regular
     * expression.
     */
    class SHIBSP_DLLLOCAL AuthenticationMethodRegexFunctor : public MatchFunctor
    {
        RegularExpression* m_regex;
    public:
        AuthenticationMethodRegexFunctor(const DOMElement* e) {
            const XMLCh* r = e ? e->getAttributeNS(NULL,regex) : NULL;
            if (!r || !*r)
                throw ConfigurationException("AuthenticationMethodRegex MatchFunctor requires non-empty regex attribute.");
            try {
                m_regex = new RegularExpression(r, e->getAttributeNS(NULL,options));
            }
            catch (XMLException& ex) {
                xmltooling::auto_ptr_char temp(ex.getMessage());
                throw ConfigurationException(temp.get());
            }
        }

        virtual ~AuthenticationMethodRegexFunctor() {
            delete m_regex;
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            return (m_regex->matches(filterContext.getAuthnContextClassRef()) || m_regex->matches(filterContext.getAuthnContextDeclRef()));
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return (m_regex->matches(filterContext.getAuthnContextClassRef()) || m_regex->matches(filterContext.getAuthnContextDeclRef()));
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AuthenticationMethodRegexFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AuthenticationMethodRegexFunctor(p.second);
    }

};

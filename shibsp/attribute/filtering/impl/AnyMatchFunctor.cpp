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
 * AnyMatchFunctor.cpp
 * 
 * A match function that returns true to evaluations.
 */

#include "internal.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

using namespace shibsp;

namespace shibsp {

    /**
     * A match function that returns true to evaluations. Note, the result may still be negated.
     */
    class SHIBSP_DLLLOCAL AnyMatchFunctor : public MatchFunctor
    {
    public:
        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            return true;
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return true;
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AnyMatchFunctorFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AnyMatchFunctor();
    }

};

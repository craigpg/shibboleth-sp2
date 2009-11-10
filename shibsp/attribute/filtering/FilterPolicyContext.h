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
 * @file shibsp/attribute/filtering/FilterPolicyContext.h
 * 
 * Context for lookup of instantiated MatchFunctor objects.
 */

#ifndef __shibsp_filtpolctx_h__
#define __shibsp_filtpolctx_h__

#include <shibsp/base.h>

#include <map>
#include <string>

namespace shibsp {

    class SHIBSP_API MatchFunctor;

    /**
     * Context for lookup of instantiated MatchFunctor objects.
     */
    class SHIBSP_API FilterPolicyContext
    {
        MAKE_NONCOPYABLE(FilterPolicyContext);
    public:
        /**
         * Constructor.
         * 
         * @param functors  reference to a map of id/functor pairs
         */
        FilterPolicyContext(std::multimap<std::string,MatchFunctor*>& functors);

        virtual ~FilterPolicyContext();

        /**
         * Gets a mutable map to store id/functor pairs.
         * 
         * <p>When storing new instances, use an empty string for unnamed objects.
         *
         * @return  reference to a mutable map containing available MatchFunctors 
         */
        std::multimap<std::string,MatchFunctor*>& getMatchFunctors() const;
    
    private:
        std::multimap<std::string,MatchFunctor*>& m_functors;
    };

};

#endif /* __shibsp_filtpolctx_h__ */

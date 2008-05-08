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
 * @file shibsp/attribute/resolver/ResolutionContext.h
 * 
 * A context for a resolution request.
 */

#ifndef __shibsp_resctx_h__
#define __shibsp_resctx_h__

#include <shibsp/base.h>

#include <saml/Assertion.h>

namespace shibsp {

    class SHIBSP_API Attribute;

    /**
     * A context for a resolution request.
     */
    class SHIBSP_API ResolutionContext
    {
        MAKE_NONCOPYABLE(ResolutionContext);
    protected:
        ResolutionContext() {}
    public:
        virtual ~ResolutionContext() {}
        
        /**
         * Returns the set of Attributes resolved and added to the context.
         * 
         * <p>Any Attributes left in the returned container will be freed by the
         * context, so the caller should modify/clear the container after copying
         * objects for its own use.
         * 
         * @return  a mutable array of Attributes.
         */
        virtual std::vector<Attribute*>& getResolvedAttributes()=0;

        /**
         * Returns the set of assertions resolved and added to the context.
         * 
         * <p>Any assertions left in the returned container will be freed by the
         * context, so the caller should modify/clear the container after copying
         * objects for its own use.
         * 
         * @return  a mutable array of Assertions
         */
        virtual std::vector<opensaml::Assertion*>& getResolvedAssertions()=0;
    };
};

#endif /* __shibsp_resctx_h__ */

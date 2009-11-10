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
 * @file shibsp/AccessControl.h
 *
 * Interface to an access control plugin
 */

#ifndef __shibsp_acl_h__
#define __shibsp_acl_h__

#include <shibsp/base.h>
#include <xmltooling/Lockable.h>

namespace shibsp {

    class SHIBSP_API Session;
    class SHIBSP_API SPRequest;

     /**
     * Interface to an access control plugin
     *
     * Access control plugins return authorization decisions based on the intersection
     * of the resource request and the active session. They can be implemented through
     * cross-platform or platform-specific mechanisms.
     */
    class SHIBSP_API AccessControl : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(AccessControl);
    protected:
        AccessControl();
    public:
        virtual ~AccessControl();

        /**
         * Possible results from an access control decision.
         */
        enum aclresult_t {
            shib_acl_true,
            shib_acl_false,
            shib_acl_indeterminate
        };

        /**
         * Perform an authorization check.
         *
         * @param request   SP request information
         * @param session   active user session, if any
         * @return true iff access should be granted
         */
        virtual aclresult_t authorized(const SPRequest& request, const Session* session) const=0;
    };

    /**
     * Registers AccessControl classes into the runtime.
     */
    void SHIBSP_API registerAccessControls();

    /** Chains together multiple plugins. */
    #define CHAINING_ACCESS_CONTROL "Chaining"

    /** AccessControl based on rudimentary XML syntax. */
    #define XML_ACCESS_CONTROL      "XML"

    /** Reserved for Apache-style .htaccess support. */
    #define HT_ACCESS_CONTROL       "htaccess"
};

#endif /* __shibsp_acl_h__ */

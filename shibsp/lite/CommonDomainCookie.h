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
 * @file shibsp/lite/CommonDomainCookie.h
 * 
 * Helper class for maintaining discovery cookie.
 */

#ifndef __shibsp_cdc_h__
#define __shibsp_cdc_h__

#include <shibsp/base.h>

#include <string>
#include <vector> 

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace opensaml {
    /**
     * Helper class for maintaining discovery cookie.
     */
    class SHIBSP_API CommonDomainCookie {
        MAKE_NONCOPYABLE(CommonDomainCookie);
    public:
        /**
         * Parses a cookie for reading or writing.
         * 
         * @param cookie    the raw cookie value
         */
        CommonDomainCookie(const char* cookie);
        
        ~CommonDomainCookie();
        
        /**
         * Returns list of IdPs stored in cookie.
         * 
         * @return  reference to vector of entityIDs
         */
        const std::vector<std::string>& get() const;
        
        /**
         * Adds/moves an IdP to the front of the list.
         * 
         * @param entityID  name of IdP to add
         * @return new value of cookie
         */
        const char* set(const char* entityID);
        
        /** Name of cookie ("_saml_idp") */
        static const char CDCName[];

    private:
        std::string m_encoded;
        std::vector<std::string> m_list;
    };
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

#endif /* __saml_cdc_h__ */

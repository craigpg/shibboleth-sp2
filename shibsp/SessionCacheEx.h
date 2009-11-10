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
 * @file shibsp/SessionCacheEx.h
 * 
 * Extended SessionCache API with additional capabilities
 */

#ifndef __shibsp_sessioncacheex_h__
#define __shibsp_sessioncacheex_h__

#include <shibsp/SessionCache.h>

namespace shibsp {

    /**
     * Extended SessionCache API with additional capabilities
     */
    class SHIBSP_API SessionCacheEx : public SessionCache
    {
    protected:
        SessionCacheEx();
    public:
        virtual ~SessionCacheEx();
        
#ifndef SHIBSP_LITE
        /**
         * Returns active sessions that match particular parameters and records the logout
         * to prevent race conditions.
         *
         * <p>On exit, the mapping between these sessions and the associated information MAY be
         * removed by the cache, so subsequent calls to this method may not return anything.
         *
         * <p>Until logout expiration, any attempt to create a session with the same parameters
         * will be blocked by the cache.
         * 
         * @param application   reference to Application that owns the session(s)
         * @param issuer        source of session(s)
         * @param nameid        name identifier associated with the session(s) to terminate
         * @param indexes       indexes of sessions, or NULL for all sessions associated with other parameters
         * @param expires       logout expiration
         * @param sessions      on exit, contains the IDs of the matching sessions found
         */
        virtual std::vector<std::string>::size_type logout(
            const Application& application,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes,
            time_t expires,
            std::vector<std::string>& sessions
            )=0;
#endif

        /**
         * Locates an existing session by ID.
         * 
         * <p>If the client address is supplied, then a check will be performed against
         * the address recorded in the record.
         * 
         * @param application   reference to Application that owns the Session
         * @param key           session key
         * @param client_addr   network address of client (if known)
         * @param timeout       inactivity timeout to enforce (0 for none, NULL to bypass check/update of last access)
         * @return  pointer to locked Session, or NULL
         */
        virtual Session* find(const Application& application, const char* key, const char* client_addr=NULL, time_t* timeout=NULL)=0;

        /**
         * Deletes an existing session.
         * 
         * @param application   reference to Application that owns the Session
         * @param key           session key
         */
        virtual void remove(const Application& application, const char* key)=0;
    };
};

#endif /* __shibsp_sessioncacheex_h__ */

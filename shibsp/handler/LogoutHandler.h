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
 * @file shibsp/handler/LogoutHandler.h
 * 
 * Base class for logout-related handlers.
 */

#ifndef __shibsp_logout_h__
#define __shibsp_logout_h__

#include <shibsp/handler/RemotedHandler.h>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Base class for logout-related handlers.
     */
    class SHIBSP_API LogoutHandler : public RemotedHandler
    {
    public:
        virtual ~LogoutHandler();

        /**
         * The base method will iteratively attempt front-channel notification
         * of logout of the current session, and after the final round trip will
         * perform back-channel notification. Nothing will be done unless the 
         * handler detects that it is the "top" level logout handler.
         * If the method returns false, then the specialized class should perform
         * its work assuming that the notifications are completed.
         *
         * Note that the current session is NOT removed from the cache.
         * 
         * @param request   SP request context
         * @param isHandler true iff executing in the context of a direct handler invocation
         * @return  a pair containing a "request completed" indicator and a server-specific response code
         */
        std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

        /**
         * A remoted procedure that will perform any necessary back-channel
         * notifications. The input structure must contain an "application_id" member,
         * and a "sessions" list containing the session keys, along with an integer
         * member called "notify" with a value of 1.
         * 
         * @param in    incoming DDF message
         * @param out   stream to write outgoing DDF message to
         */
        void receive(DDF& in, std::ostream& out);

    protected:
        LogoutHandler();
        
        /** Flag indicating whether the subclass is acting as a LogoutInitiator. */
        bool m_initiator;

        /** Array of query string parameters to preserve across front-channel notifications, if present. */
        std::vector<std::string> m_preserve;

        /**
         * Perform front-channel logout notifications for an Application.
         *
         * @param application   the Application to notify
         * @param request       last request from browser
         * @param response      response to use for next notification
         * @param params        map of query string parameters to preserve across this notification
         * @return  indicator of a completed response along with the status code to return from the handler
         */
        std::pair<bool,long> notifyFrontChannel(
            const Application& application,
            const xmltooling::HTTPRequest& request,
            xmltooling::HTTPResponse& response,
            const std::map<std::string,std::string>* params=NULL
            ) const;

        /**
         * Perform back-channel logout notifications for an Application.
         *
         * @param application   the Application to notify
         * @param requestURL    requestURL that resulted in method call
         * @param sessions      array of session keys being logged out
         * @param local         true iff the logout operation is local to the SP, false iff global
         * @return  true iff all notifications succeeded
         */
        bool notifyBackChannel(
            const Application& application, const char* requestURL, const std::vector<std::string>& sessions, bool local
            ) const;

        /**
         * @deprecated
         * Sends a response template to the user agent informing it of the results of a logout attempt.
         *
         * @param application   the Application to use in determining the logout template
         * @param request       the HTTP client request to supply to the template
         * @param response      the HTTP response to use
         * @param local         true iff the logout operation was local to the SP, false iff global
         * @param status        optional logoutStatus key value to add to template
         */
        std::pair<bool,long> sendLogoutPage(
            const Application& application,
            const xmltooling::HTTPRequest& request,
            xmltooling::HTTPResponse& response,
            bool local=true,
            const char* status=NULL
            ) const;

        /**
         * Sends a response template to the user agent informing it of the results of a logout attempt.
         *
         * @param application   the Application to use in determining the logout template
         * @param request       the HTTP client request to supply to the template
         * @param response      the HTTP response to use
         * @param type          designates the prefix of logout template name to use
         */
        std::pair<bool,long> sendLogoutPage(
            const Application& application,
            const xmltooling::HTTPRequest& request,
            xmltooling::HTTPResponse& response,
            const char* type
            ) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    /** LogoutInitiator that iterates through a set of protocol-specific versions. */
    #define CHAINING_LOGOUT_INITIATOR "Chaining"

    /** LogoutInitiator that supports SAML 2.0 LogoutRequests. */
    #define SAML2_LOGOUT_INITIATOR "SAML2"

    /** LogoutInitiator that supports local-only logout. */
    #define LOCAL_LOGOUT_INITIATOR "Local"

};

#endif /* __shibsp_logout_h__ */

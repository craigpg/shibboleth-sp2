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
 * @file shibsp/SessionCache.h
 *
 * Caches and manages user sessions.
 */

#ifndef __shibsp_sessioncache_h__
#define __shibsp_sessioncache_h__

#include <shibsp/base.h>

#include <map>
#include <set>
#include <string>
#include <vector>
#include <ctime>
#include <xmltooling/Lockable.h>

namespace xmltooling {
    class XMLTOOL_API HTTPRequest;
    class XMLTOOL_API HTTPResponse;
};

#ifndef SHIBSP_LITE
# include <set>
namespace opensaml {
    class SAML_API Assertion;
    namespace saml2 {
        class SAML_API NameID;
    };
};
#endif

namespace shibsp {

    class SHIBSP_API Application;
    class SHIBSP_API Attribute;

    /**
     * Encapsulates access to a user's security session.
     *
     * <p>The SessionCache does not itself require locking to manage
     * concurrency, but access to each Session is generally exclusive
     * or at least controlled, and the caller must unlock a Session
     * to dispose of it.
     */
    class SHIBSP_API Session : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(Session);
    protected:
        Session();
        virtual ~Session();
    public:
        /**
         * Returns the session key.
         *
         * @return unique ID of session
         */
        virtual const char* getID() const=0;

        /**
         * Returns the session's application ID.
         *
         * @return unique ID of application bound to session
         */
        virtual const char* getApplicationID() const=0;

        /**
         * Returns the session expiration.
         *
         * @return  the session's expiration time or 0 for none
         */
        virtual time_t getExpiration() const=0;

        /**
         * Returns the last access time of the session.
         *
         * @return  the session's last access time
         */
        virtual time_t getLastAccess() const=0;

        /**
         * Returns the address of the client associated with the session.
         *
         * @return  the client's network address
         */
        virtual const char* getClientAddress() const=0;

        /**
         * Returns the entityID of the IdP that initiated the session.
         *
         * @return the IdP's entityID
         */
        virtual const char* getEntityID() const=0;

        /**
         * Returns the protocol family used to initiate the session.
         *
         * @return the protocol constant that represents the general SSO protocol used
         */
        virtual const char* getProtocol() const=0;

        /**
         * Returns the UTC timestamp on the authentication event at the IdP.
         *
         * @return  the UTC authentication timestamp
         */
        virtual const char* getAuthnInstant() const=0;

#ifndef SHIBSP_LITE
        /**
         * Returns the NameID associated with a session.
         *
         * <p>SAML 1.x identifiers will be promoted to the 2.0 type.
         *
         * @return a SAML 2.0 NameID associated with the session, if any
         */
        virtual const opensaml::saml2::NameID* getNameID() const=0;
#endif

        /**
         * Returns the SessionIndex provided with the session.
         *
         * @return the SessionIndex from the original SSO assertion, if any
         */
        virtual const char* getSessionIndex() const=0;

        /**
         * Returns a URI containing an AuthnContextClassRef provided with the session.
         *
         * <p>SAML 1.x AuthenticationMethods will be returned as class references.
         *
         * @return  a URI identifying the authentication context class
         */
        virtual const char* getAuthnContextClassRef() const=0;

        /**
         * Returns a URI containing an AuthnContextDeclRef provided with the session.
         *
         * @return  a URI identifying the authentication context declaration
         */
        virtual const char* getAuthnContextDeclRef() const=0;

        /**
         * Returns the resolved attributes associated with the session.
         *
         * @return an immutable array of attributes
         */
        virtual const std::vector<Attribute*>& getAttributes() const=0;

        /**
         * Returns the resolved attributes associated with the session, indexed by ID
         *
         * @return an immutable map of attributes keyed by attribute ID
         */
        virtual const std::multimap<std::string,const Attribute*>& getIndexedAttributes() const=0;

        /**
         * Returns the identifiers of the assertion(s) cached by the session.
         *
         * <p>The SSO assertion is guaranteed to be first in the set.
         *
         * @return  an immutable array of AssertionID values
         */
        virtual const std::vector<const char*>& getAssertionIDs() const=0;

#ifndef SHIBSP_LITE
        /**
         * Adds additional attributes to the session.
         *
         * @param attributes    reference to an array of Attributes to cache (will be freed by cache)
         */
        virtual void addAttributes(const std::vector<Attribute*>& attributes)=0;

        /**
         * Returns an assertion cached by the session.
         *
         * @param id    identifier of the assertion to retrieve
         * @return pointer to assertion, or NULL
         */
        virtual const opensaml::Assertion* getAssertion(const char* id) const=0;

        /**
         * Stores an assertion in the session.
         *
         * @param assertion pointer to an assertion to cache (will be freed by cache)
         */
        virtual void addAssertion(opensaml::Assertion* assertion)=0;
#endif
    };

    /**
     * Creates and manages user sessions
     *
     * The cache abstracts a persistent (meaning across requests) cache of
     * instances of the Session interface. Creation of new entries and entry
     * lookup are confined to this interface to enable the implementation to
     * remote and/or optimize calls by implementing custom versions of the
     * Session interface as required.
     */
    class SHIBSP_API SessionCache
    {
        MAKE_NONCOPYABLE(SessionCache);
    protected:
        SessionCache();
    public:
        virtual ~SessionCache();

#ifndef SHIBSP_LITE
        /**
         * Inserts a new session into the cache and binds the session to the outgoing
         * client response.
         *
         * <p>The SSO tokens and Attributes remain owned by the caller and are copied by the cache.
         *
         * @param application       reference to Application that owns the Session
         * @param httpRequest       request that initiated session
         * @param httpResponse      current response to client
         * @param expires           expiration time of session
         * @param issuer            issuing metadata of assertion issuer, if known
         * @param protocol          protocol family used to initiate the session
         * @param nameid            principal identifier, normalized to SAML 2, if any
         * @param authn_instant     UTC timestamp of authentication at IdP, if known
         * @param session_index     index of session between principal and IdP, if any
         * @param authncontext_class    method/category of authentication event, if known
         * @param authncontext_decl specifics of authentication event, if known
         * @param tokens            assertions to cache with session, if any
         * @param attributes        optional array of resolved Attributes to cache with session
         */
        virtual void insert(
            const Application& application,
            const xmltooling::HTTPRequest& httpRequest,
            xmltooling::HTTPResponse& httpResponse,
            time_t expires,
            const opensaml::saml2md::EntityDescriptor* issuer=NULL,
            const XMLCh* protocol=NULL,
            const opensaml::saml2::NameID* nameid=NULL,
            const XMLCh* authn_instant=NULL,
            const XMLCh* session_index=NULL,
            const XMLCh* authncontext_class=NULL,
            const XMLCh* authncontext_decl=NULL,
            const std::vector<const opensaml::Assertion*>* tokens=NULL,
            const std::vector<Attribute*>* attributes=NULL
            )=0;

        /**
         * Determines whether the Session bound to a client request matches a set of input criteria.
         *
         * @param application   reference to Application that owns the Session
         * @param request       request in which to locate Session
         * @param issuer        required source of session(s)
         * @param nameid        required name identifier
         * @param indexes       session indexes
         * @return  true iff the Session exists and matches the input criteria
         */
        virtual bool matches(
            const Application& application,
            const xmltooling::HTTPRequest& request,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes
            )=0;

        /**
         * Executes a test of the cache's general health.
         */
        virtual void test()=0;
#endif

        /**
         * Returns the ID of the session bound to the specified client request, if possible.
         *
         * @param application   reference to Application that owns the Session
         * @param request       request from client containing session, or a reference to it
         * @return  ID of session, if any known, or an empty string
         */
        virtual std::string active(const Application& application, const xmltooling::HTTPRequest& request)=0;

        /**
         * Locates an existing session bound to a request.
         *
         * <p>If the client address is supplied, then a check will be performed against
         * the address recorded in the record.
         *
         * @param application   reference to Application that owns the Session
         * @param request       request from client bound to session
         * @param client_addr   network address of client (if known)
         * @param timeout       inactivity timeout to enforce (0 for none, NULL to bypass check/update of last access)
         * @return  pointer to locked Session, or NULL
         */
        virtual Session* find(
            const Application& application,
            const xmltooling::HTTPRequest& request,
            const char* client_addr=NULL,
            time_t* timeout=NULL
            )=0;

        /**
         * Locates an existing session bound to a request.
         *
         * <p>If the client address is supplied, then a check will be performed against
         * the address recorded in the record.
         *
         * <p>If a bound session is found to have expired, be invalid, etc., and if the request
         * can be used to "clear" the session from subsequent client requests, then it may be cleared.
         *
         * @param application   reference to Application that owns the Session
         * @param request       request from client bound to session
         * @param client_addr   network address of client (if known)
         * @param timeout       inactivity timeout to enforce (0 for none, NULL to bypass check/update of last access)
         * @return  pointer to locked Session, or NULL
         */
        virtual Session* find(
            const Application& application,
            xmltooling::HTTPRequest& request,
            const char* client_addr=NULL,
            time_t* timeout=NULL
            );

        /**
         * Deletes an existing session bound to a request.
         *
         * @param application   reference to Application that owns the Session
         * @param request       request from client containing session, or a reference to it
         * @param response      optional response to client enabling removal of session or reference
         */
        virtual void remove(const Application& application, const xmltooling::HTTPRequest& request, xmltooling::HTTPResponse* response=NULL)=0;
    };

    /** SessionCache implementation backed by a StorageService. */
    #define STORAGESERVICE_SESSION_CACHE    "StorageService"

    /**
     * Registers SessionCache classes into the runtime.
     */
    void SHIBSP_API registerSessionCaches();
};

#endif /* __shibsp_sessioncache_h__ */

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
 * @file shibsp/Application.h
 * 
 * Interface to a Shibboleth Application instance.
 */

#ifndef __shibsp_app_h__
#define __shibsp_app_h__

#include <shibsp/util/PropertySet.h>

#include <set>
#ifndef SHIBSP_LITE
# include <saml/binding/MessageEncoder.h>
# include <saml/saml2/metadata/MetadataProvider.h>
# include <xmltooling/security/CredentialResolver.h>
# include <xmltooling/security/TrustEngine.h>
#endif
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/util/Threads.h>

namespace shibsp {
    
#ifndef SHIBSP_LITE
    class SHIBSP_API AttributeExtractor;
    class SHIBSP_API AttributeFilter;
    class SHIBSP_API AttributeResolver;
#endif
    class SHIBSP_API Attribute;
    class SHIBSP_API Handler;
    class SHIBSP_API ServiceProvider;
    class SHIBSP_API SessionInitiator;
    class SHIBSP_API SPRequest;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Interface to a Shibboleth Application instance.
     * 
     * <p>An Application is a logical set of resources that act as a unit
     * of session management and policy.
     */
    class SHIBSP_API Application : public virtual PropertySet
#ifndef SHIBSP_LITE
        ,public virtual opensaml::MessageEncoder::ArtifactGenerator
#endif
    {
        MAKE_NONCOPYABLE(Application);
    protected:
        /**
         * Constructor.
         *
         * @param sp    parent ServiceProvider instance
         */
        Application(const ServiceProvider* sp);
        
        /** Pointer to parent SP instance. */
        const ServiceProvider* m_sp;

        /** Shared lock for manipulating application state. */
        mutable xmltooling::RWLock* m_lock;

        /** Pairs of raw and normalized CGI header names to clear. */
        mutable std::vector< std::pair<std::string,std::string> > m_unsetHeaders;

    public:
        virtual ~Application();

        /**
         * Returns the owning ServiceProvider instance.
         *
         * @return a locked ServiceProvider
         */
        const ServiceProvider& getServiceProvider() const {
            return *m_sp;
        }

        /**
         * Returns the Application's ID.
         * 
         * @return  the ID
         */        
        virtual const char* getId() const {
            return getString("id").second;
        }

        /**
         * Returns a unique hash for the Application.
         * 
         * @return a value resulting from a computation over the Application's configuration
         */
        virtual const char* getHash() const=0;

        /**
         * Returns the name and cookie properties to use for this Application.
         * 
         * @param prefix    a value to prepend to the base cookie name
         * @param lifetime  if non-null, will be populated with a suggested lifetime for the cookie, or 0 if session-bound
         * @return  a pair containing the cookie name and the string to append to the cookie value
         */
        virtual std::pair<std::string,const char*> getCookieNameProps(const char* prefix, time_t* lifetime=NULL) const;

#ifndef SHIBSP_LITE
        /**
         * Returns a MetadataProvider for use with this Application.
         * 
         * @param required  true iff an exception should be thrown if no MetadataProvider is available
         * @return  a MetadataProvider instance, or NULL
         */
        virtual opensaml::saml2md::MetadataProvider* getMetadataProvider(bool required=true) const=0;
        
        /**
         * Returns a TrustEngine for use with this Application.
         * 
         * @param required  true iff an exception should be thrown if no TrustEngine is available
         * @return  a TrustEngine instance, or NULL
         */
        virtual xmltooling::TrustEngine* getTrustEngine(bool required=true) const=0;

        /**
         * Returns an AttributeExtractor for use with this Application.
         * 
         * @return  an AttributeExtractor, or NULL
         */
        virtual AttributeExtractor* getAttributeExtractor() const=0;

        /**
         * Returns an AttributeFilter for use with this Application.
         * 
         * @return  an AttributeFilter, or NULL
         */
        virtual AttributeFilter* getAttributeFilter() const=0;

        /**
         * Returns an AttributeResolver for use with this Application.
         * 
         * @return  an AttributeResolver, or NULL
         */
        virtual AttributeResolver* getAttributeResolver() const=0;

        /**
         * Returns the CredentialResolver instance associated with this Application.
         * 
         * @return  a CredentialResolver, or NULL
         */
        virtual xmltooling::CredentialResolver* getCredentialResolver() const=0;

        /**
         * Returns configuration properties governing security interactions with a peer.
         * 
         * @param provider  a peer entity's metadata
         * @return  the applicable PropertySet
         */
        virtual const PropertySet* getRelyingParty(const opensaml::saml2md::EntityDescriptor* provider) const=0;

        /**
         * Returns configuration properties governing security interactions with a named peer.
         * 
         * @param entityID  a peer name
         * @return  the applicable PropertySet
         */
        virtual const PropertySet* getRelyingParty(const XMLCh* entityID) const=0;

        /**
         * Returns any additional audience values associated with this Application.
         * 
         * @return additional audience values associated with the Application, or NULL
         */
        virtual const std::vector<const XMLCh*>* getAudiences() const=0;
#endif

        /**
         * Returns the designated notification URL, or an empty string if no more locations are specified.
         *
         * @param request   requested URL to use to fill in missing pieces of notification URL
         * @param front     true iff front channel notification is desired, false iff back channel is desired
         * @param index     zero-based index of URL to return
         * @return  the designated URL, or an empty string
         */
        virtual std::string getNotificationURL(const char* request, bool front, unsigned int index) const=0;

        /**
         * Returns an array of attribute IDs to use as a REMOTE_USER value, in order of preference.
         *
         * @return  an array of attribute IDs, possibly empty
         */
        virtual const std::vector<std::string>& getRemoteUserAttributeIds() const=0;

        /**
         * Clears any headers that may be used to hold attributes after export.
         *
         * @param request   SP request to clear
         */
        virtual void clearAttributeHeaders(SPRequest& request) const;

        /**
         * Returns the default SessionInitiator when automatically requesting a session.
         * 
         * @return the default SessionInitiator, or NULL
         */
        virtual const SessionInitiator* getDefaultSessionInitiator() const=0;
        
        /**
         * Returns a SessionInitiator with a particular ID when automatically requesting a session.
         * 
         * @param id    an identifier unique to the Application
         * @return the designated SessionInitiator, or NULL
         */
        virtual const SessionInitiator* getSessionInitiatorById(const char* id) const=0;

        /**
         * Returns the default AssertionConsumerService Handler
         * for use in AuthnRequest messages.
         * 
         * @return the default AssertionConsumerService, or NULL
         */
        virtual const Handler* getDefaultAssertionConsumerService() const=0;

        /**
         * Returns an AssertionConsumerService Handler with a particular index
         * for use in AuthnRequest messages.
         * 
         * @param index an index unique to an application
         * @return the designated AssertionConsumerService, or NULL
         */
        virtual const Handler* getAssertionConsumerServiceByIndex(unsigned short index) const=0;

        /**
         * Returns one or more AssertionConsumerService Handlers that support
         * a particular protocol binding.
         * 
         * @param binding   a protocol binding identifier
         * @return a set of qualifying AssertionConsumerServices
         */
        virtual const std::vector<const Handler*>& getAssertionConsumerServicesByBinding(const XMLCh* binding) const=0;
        
        /**
         * Returns the Handler associated with a particular path/location.
         * 
         * @param path  the PATH_INFO appended to the end of a base Handler location
         *              that invokes the Handler
         * @return the mapped Handler, or NULL 
         */
        virtual const Handler* getHandler(const char* path) const=0;

        /**
         * Returns all registered Handlers.
         *
         * @param handlers  array to populate
         */
        virtual void getHandlers(std::vector<const Handler*>& handlers) const=0;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_app_h__ */

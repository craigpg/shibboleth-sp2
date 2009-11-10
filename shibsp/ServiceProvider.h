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
 * @file shibsp/ServiceProvider.h
 * 
 * Interface to a Shibboleth ServiceProvider instance.
 */

#ifndef __shibsp_sp_h__
#define __shibsp_sp_h__

#include <shibsp/util/PropertySet.h>

#include <xmltooling/Lockable.h>

namespace xmltooling {
    class XMLTOOL_API SOAPTransport;
    class XMLTOOL_API StorageService;
};

#ifndef SHIBSP_LITE
namespace opensaml {
    class SAML_API SecurityPolicyRule;
};
#endif

namespace shibsp {

    class SHIBSP_API Application;
    class SHIBSP_API Handler;
    class SHIBSP_API ListenerService;
    class SHIBSP_API RequestMapper;
    class SHIBSP_API SessionCache;
    class SHIBSP_API SPRequest;
    class SHIBSP_API TemplateParameters;
#ifndef SHIBSP_LITE
    class SHIBSP_API TransactionLog;
#endif

    /**
     * Interface to a Shibboleth ServiceProvider instance.
     * 
     * <p>A ServiceProvider exposes configuration and infrastructure services required
     * by the SP implementation, allowing a flexible configuration format.
     */
	class SHIBSP_API ServiceProvider : public virtual xmltooling::Lockable, public virtual PropertySet
    {
        MAKE_NONCOPYABLE(ServiceProvider);
    protected:
        ServiceProvider();
    public:
        virtual ~ServiceProvider();
        
        /**
         * Loads a configuration and prepares the instance for use.
         * 
         * <p>Implemented as a separate method so that services can rely on
         * other services while they initialize by accessing the ServiceProvider
         * from the SPConfig singleton.
         */
        virtual void init()=0;

#ifndef SHIBSP_LITE
        /**
         * Returns a TransactionLog instance.
         * 
         * @return  a TransactionLog instance
         */
        virtual TransactionLog* getTransactionLog() const=0;

        /**
         * Returns a StorageService instance based on an ID.
         * 
         * @param id    a NULL-terminated key identifying the StorageService to the configuration 
         * @return  a StorageService if available, or NULL
         */
        virtual xmltooling::StorageService* getStorageService(const char* id) const=0;
#endif

        /**
         * Returns a SessionCache instance.
         * 
         * @param required  true iff an exception should be thrown if no SessionCache is available
         * @return  a SessionCache
         */
        virtual SessionCache* getSessionCache(bool required=true) const=0;

        /**
         * Returns a ListenerService instance.
         * 
         * @param required  true iff an exception should be thrown if no ListenerService is available
         * @return  a ListenerService
         */
        virtual ListenerService* getListenerService(bool required=true) const=0;
        
#ifndef SHIBSP_LITE
        /**
		 * Returns the security policy settings for an identified policy.
         *
		 * @param id    identifies the policy to return
         * @return a PropertySet
		 */
        virtual const PropertySet* getPolicySettings(const char* id) const=0;

        /**
		 * Returns the security policy rules for an identified policy.
         *
		 * @param id    identifies the policy to return
         * @return an array of policy rules
		 */
        virtual const std::vector<const opensaml::SecurityPolicyRule*>& getPolicyRules(const char* id) const=0;

        /**
         * Sets implementation-specific transport options.
         *
         * @param transport a SOAPTransport object
         * @return  true iff all options were successfully set
         */
        virtual bool setTransportOptions(xmltooling::SOAPTransport& transport) const=0;
#endif

        /**
         * Returns a RequestMapper instance.
         * 
         * @param required  true iff an exception should be thrown if no RequestMapper is available
         * @return  a RequestMapper
         */
        virtual RequestMapper* getRequestMapper(bool required=true) const=0;
        
        /**
         * Returns an Application instance matching the specified ID.
         * 
         * @param applicationId the ID of the application
         * @return  pointer to the application, or NULL
         */
        virtual const Application* getApplication(const char* applicationId) const=0;

        /**
         * Enforces requirements for an authenticated session.
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue. 
         * 
         * @param request   SP request interface
         * @param handler   true iff a request to a registered Handler location can be directly executed
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doAuthentication(SPRequest& request, bool handler=false) const;
        
        /**
         * Enforces authorization requirements based on the authenticated session.
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue. 
         * 
         * @param request   SP request interface
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doAuthorization(SPRequest& request) const;
        
        /**
         * Publishes session contents to the request in the form of headers or environment variables.
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue. 
         * 
         * @param request   SP request interface
         * @param requireSession    set to true iff an error should result if no session exists 
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doExport(SPRequest& request, bool requireSession=true) const;

        /**
         * Services requests for registered Handler locations. 
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue. 
         * 
         * @param request   SP request interface
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doHandler(SPRequest& request) const;
    };

    /**
     * Registers ServiceProvider classes into the runtime.
     */
    void SHIBSP_API registerServiceProviders();

    /** SP based on integrated XML and native server configuration. */
    #define XML_SERVICE_PROVIDER "XML"
};

#endif /* __shibsp_sp_h__ */

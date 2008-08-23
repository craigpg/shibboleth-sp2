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
 * @file shibsp/SPConfig.h
 *
 * Library configuration
 */

#ifndef __shibsp_config_h__
#define __shibsp_config_h__

#include <shibsp/base.h>
#ifndef SHIBSP_LITE
# include <saml/binding/MessageDecoder.h>
#endif
#include <xmltooling/PluginManager.h>
#include <xercesc/dom/DOM.hpp>

/**
 * @namespace shibsp
 * Shibboleth Service Provider Library
 */
namespace shibsp {

    class SHIBSP_API AccessControl;
    class SHIBSP_API Handler;
    class SHIBSP_API ListenerService;
    class SHIBSP_API RequestMapper;
    class SHIBSP_API ServiceProvider;
    class SHIBSP_API SessionCache;
    class SHIBSP_API SessionInitiator;

#ifndef SHIBSP_LITE
    class SHIBSP_API AttributeDecoder;
    class SHIBSP_API AttributeExtractor;
    class SHIBSP_API AttributeFilter;
    class SHIBSP_API AttributeResolver;
    class SHIBSP_API FilterPolicyContext;
    class SHIBSP_API MatchFunctor;
#endif

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

    /**
     * Singleton object that manages library startup/shutdown.
     */
    class SHIBSP_API SPConfig
    {
        MAKE_NONCOPYABLE(SPConfig);
    public:
        SPConfig() : attribute_value_delimeter(';'), m_serviceProvider(NULL),
#ifndef SHIBSP_LITE
            m_artifactResolver(NULL),
#endif
            m_features(0) {}

        virtual ~SPConfig() {}

        /**
         * Returns the global configuration object for the library.
         *
         * @return reference to the global library configuration object
         */
        static SPConfig& getConfig();

        /**
         * Bitmask values representing subsystems of the library.
         */
        enum components_t {
            Listener = 1,
            Caching = 2,
#ifndef SHIBSP_LITE
            Metadata = 4,
            Trust = 8,
            Credentials = 16,
            AttributeResolution = 32,
#endif
            RequestMapping = 64,
            OutOfProcess = 128,
            InProcess = 256,
            Logging = 512,
            Handlers = 1024
        };

        /**
         * Set a bitmask of subsystems to activate.
         *
         * @param enabled   bitmask of component constants
         */
        void setFeatures(unsigned long enabled) {
            m_features = enabled;
        }

        /**
         * Test whether a subsystem is enabled.
         *
         * @param feature   subsystem/component to test
         * @return true iff feature is enabled
         */
        bool isEnabled(components_t feature) {
            return (m_features & feature)>0;
        }

        /**
         * Initializes library
         *
         * Each process using the library MUST call this function exactly once
         * before using any library classes.
         *
         * @param catalog_path  delimited set of schema catalog files to load
         * @param inst_prefix   installation prefix for software
         * @return true iff initialization was successful
         */
        virtual bool init(const char* catalog_path=NULL, const char* inst_prefix=NULL);

        /**
         * Shuts down library
         *
         * Each process using the library SHOULD call this function exactly once
         * before terminating itself.
         */
        virtual void term();

        /**
         * Sets the global ServiceProvider instance.
         * This method must be externally synchronized with any code that uses the object.
         * Any previously set object is destroyed.
         *
         * @param serviceProvider   new ServiceProvider instance to store
         */
        void setServiceProvider(ServiceProvider* serviceProvider);

        /**
         * Returns the global ServiceProvider instance.
         *
         * @return  global ServiceProvider or NULL
         */
        ServiceProvider* getServiceProvider() const {
            return m_serviceProvider;
        }

        /**
         * Instantiates and installs a ServiceProvider instance based on an XML configuration string
         * or a configuration pathname.
         *
         * @param config    a snippet of XML to parse (it <strong>MUST</strong> contain a type attribute) or a pathname
         * @param rethrow   true iff caught exceptions should be rethrown instead of just returning the status
         * @return true iff instantiation was successful
         */
        virtual bool instantiate(const char* config=NULL, bool rethrow=false);

#ifndef SHIBSP_LITE
        /**
         * Sets the global ArtifactResolver instance.
         *
         * <p>This method must be externally synchronized with any code that uses the object.
         * Any previously set object is destroyed.
         *
         * @param artifactResolver   new ArtifactResolver instance to store
         */
        void setArtifactResolver(opensaml::MessageDecoder::ArtifactResolver* artifactResolver) {
            delete m_artifactResolver;
            m_artifactResolver = artifactResolver;
        }

        /**
         * Returns the global ArtifactResolver instance.
         *
         * @return  global ArtifactResolver or NULL
         */
        opensaml::MessageDecoder::ArtifactResolver* getArtifactResolver() const {
            return m_artifactResolver;
        }
#endif

        /** Separator for serialized values of multi-valued attributes. */
        char attribute_value_delimeter;

        /**
         * Manages factories for AccessControl plugins.
         */
        xmltooling::PluginManager<AccessControl,std::string,const xercesc::DOMElement*> AccessControlManager;

#ifndef SHIBSP_LITE
        /**
         * Manages factories for AttributeDecoder plugins.
         */
        xmltooling::PluginManager<AttributeDecoder,xmltooling::QName,const xercesc::DOMElement*> AttributeDecoderManager;

        /**
         * Manages factories for AttributeExtractor plugins.
         */
        xmltooling::PluginManager<AttributeExtractor,std::string,const xercesc::DOMElement*> AttributeExtractorManager;

        /**
         * Manages factories for AttributeFilter plugins.
         */
        xmltooling::PluginManager<AttributeFilter,std::string,const xercesc::DOMElement*> AttributeFilterManager;

        /**
         * Manages factories for AttributeResolver plugins.
         */
        xmltooling::PluginManager<AttributeResolver,std::string,const xercesc::DOMElement*> AttributeResolverManager;

        /**
         * Manages factories for MatchFunctor plugins.
         */
        xmltooling::PluginManager< MatchFunctor,xmltooling::QName,std::pair<const FilterPolicyContext*,const xercesc::DOMElement*> > MatchFunctorManager;
#endif

        /**
         * Manages factories for Handler plugins that implement ArtifactResolutionService functionality.
         */
        xmltooling::PluginManager< Handler,std::string,std::pair<const xercesc::DOMElement*,const char*> > ArtifactResolutionServiceManager;

        /**
         * Manages factories for Handler plugins that implement AssertionConsumerService functionality.
         */
        xmltooling::PluginManager< Handler,std::string,std::pair<const xercesc::DOMElement*,const char*> > AssertionConsumerServiceManager;

        /**
         * Manages factories for Handler plugins that implement customized functionality.
         */
        xmltooling::PluginManager< Handler,std::string,std::pair<const xercesc::DOMElement*,const char*> > HandlerManager;

        /**
         * Manages factories for ListenerService plugins.
         */
        xmltooling::PluginManager<ListenerService,std::string,const xercesc::DOMElement*> ListenerServiceManager;

        /**
         * Manages factories for Handler plugins that implement LogoutInitiator functionality.
         */
        xmltooling::PluginManager< Handler,std::string,std::pair<const xercesc::DOMElement*,const char*> > LogoutInitiatorManager;

        /**
         * Manages factories for Handler plugins that implement ManageNameIDService functionality.
         */
        xmltooling::PluginManager< Handler,std::string,std::pair<const xercesc::DOMElement*,const char*> > ManageNameIDServiceManager;

        /**
         * Manages factories for RequestMapper plugins.
         */
        xmltooling::PluginManager<RequestMapper,std::string,const xercesc::DOMElement*> RequestMapperManager;

        /**
         * Manages factories for ServiceProvider plugins.
         */
        xmltooling::PluginManager<ServiceProvider,std::string,const xercesc::DOMElement*> ServiceProviderManager;

        /**
         * Manages factories for SessionCache plugins.
         */
        xmltooling::PluginManager<SessionCache,std::string,const xercesc::DOMElement*> SessionCacheManager;

        /**
         * Manages factories for Handler plugins that implement SessionInitiator functionality.
         */
        xmltooling::PluginManager< SessionInitiator,std::string,std::pair<const xercesc::DOMElement*,const char*> > SessionInitiatorManager;

        /**
         * Manages factories for Handler plugins that implement SingleLogoutService functionality.
         */
        xmltooling::PluginManager< Handler,std::string,std::pair<const xercesc::DOMElement*,const char*> > SingleLogoutServiceManager;

    protected:
        /** Global ServiceProvider instance. */
        ServiceProvider* m_serviceProvider;

#ifndef SHIBSP_LITE
        /** Global ArtifactResolver instance. */
        opensaml::MessageDecoder::ArtifactResolver* m_artifactResolver;
#endif

    private:
        unsigned long m_features;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_config_h__ */

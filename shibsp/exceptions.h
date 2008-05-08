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
 * @file shibsp/exceptions.h
 * 
 * Exception classes
 */
 
#ifndef __shibsp_exceptions_h__
#define __shibsp_exceptions_h__

#include <shibsp/base.h>
#ifndef SHIBSP_LITE
# include <saml/exceptions.h>
#else
# include <xmltooling/exceptions.h>
#endif

namespace shibsp {
    
    DECL_XMLTOOLING_EXCEPTION(AttributeException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,xmltooling::XMLToolingException,Exceptions during attribute processing.);
    DECL_XMLTOOLING_EXCEPTION(AttributeExtractionException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,shibsp::AttributeException,Exceptions during attribute extraction.);
    DECL_XMLTOOLING_EXCEPTION(AttributeFilteringException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,shibsp::AttributeException,Exceptions during attribute filtering.);
    DECL_XMLTOOLING_EXCEPTION(AttributeResolutionException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,shibsp::AttributeException,Exceptions during attribute resolution.);
    DECL_XMLTOOLING_EXCEPTION(ConfigurationException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,xmltooling::XMLToolingException,Exceptions during configuration.);
    DECL_XMLTOOLING_EXCEPTION(ListenerException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp,xmltooling::XMLToolingException,Exceptions during inter-process communication.);

};

#ifdef SHIBSP_LITE
namespace opensaml {
    DECL_XMLTOOLING_EXCEPTION(BindingException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),opensaml,xmltooling::XMLToolingException,Exceptions in SAML binding processing);
    DECL_XMLTOOLING_EXCEPTION(SecurityPolicyException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),opensaml,xmltooling::XMLToolingException,Exceptions in security policy processing);
    DECL_XMLTOOLING_EXCEPTION(ProfileException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),opensaml,xmltooling::ValidationException,Exceptions in SAML profile processing);
    DECL_XMLTOOLING_EXCEPTION(FatalProfileException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),opensaml,ProfileException,Fatal exceptions in SAML profile processing);
    DECL_XMLTOOLING_EXCEPTION(RetryableProfileException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),opensaml,ProfileException,Non-fatal exceptions in SAML profile processing);

    namespace saml2md {
        DECL_XMLTOOLING_EXCEPTION(MetadataException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),opensaml::saml2md,xmltooling::XMLToolingException,Exceptions related to metadata use);
    };
};
#endif

#endif /* __shibsp_exceptions_h__ */

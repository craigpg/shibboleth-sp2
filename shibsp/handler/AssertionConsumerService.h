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
 * @file shibsp/handler/AssertionConsumerService.h
 * 
 * Base class for handlers that create sessions by consuming SSO protocol responses. 
 */

#ifndef __shibsp_acshandler_h__
#define __shibsp_acshandler_h__

#include <shibsp/handler/AbstractHandler.h>
#include <shibsp/handler/RemotedHandler.h>
#ifndef SHIBSP_LITE
# include <saml/binding/MessageDecoder.h>
# include <saml/saml1/core/Assertions.h>
# include <saml/saml2/metadata/Metadata.h>
#endif
#include <xmltooling/unicode.h>

namespace shibsp {

    class SHIBSP_API Attribute;
    class SHIBSP_API ResolutionContext;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    /**
     * Base class for handlers that create sessions by consuming SSO protocol responses.
     */
    class SHIBSP_API AssertionConsumerService : public AbstractHandler, public RemotedHandler 
    {
    public:
        virtual ~AssertionConsumerService();

        std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, std::ostream& out);

    protected:
        /**
         * Constructor
         * 
         * @param e     root of DOM configuration
         * @param appId ID of application that "owns" the handler
         * @param log   a logging object to use
         */
        AssertionConsumerService(const xercesc::DOMElement* e, const char* appId, xmltooling::logging::Category& log);

        /**
         * Enforce address checking requirements.
         * 
         * @param application   reference to application receiving message
         * @param httpRequest   client request that initiated session
         * @param issuedTo      address for which security assertion was issued
         */
        void checkAddress(const Application& application, const xmltooling::HTTPRequest& httpRequest, const char* issuedTo) const;
        
#ifndef SHIBSP_LITE
        void generateMetadata(opensaml::saml2md::SPSSODescriptor& role, const char* handlerURL) const;
        
        /**
         * Implement protocol-specific handling of the incoming decoded message.
         * 
         * <p>The result of implementing the protocol should be an exception or
         * modifications to the request/response objects to reflect processing
         * of the message.
         * 
         * @param application   reference to application receiving message
         * @param httpRequest   client request that included message
         * @param httpResponse  response to client
         * @param policy        the SecurityPolicy in effect, after having evaluated the message
         * @param settings      policy configuration settings in effect
         * @param xmlObject     a protocol-specific message object
         */
        virtual void implementProtocol(
            const Application& application,
            const xmltooling::HTTPRequest& httpRequest,
            xmltooling::HTTPResponse& httpResponse,
            opensaml::SecurityPolicy& policy,
            const PropertySet* settings,
            const xmltooling::XMLObject& xmlObject
            ) const=0;

        /**
         * Extracts policy-relevant assertion details.
         * 
         * @param assertion the incoming assertion
         * @param protocol  the protocol family in use
         * @param policy    SecurityPolicy to provide various components and track message data
         */
        virtual void extractMessageDetails(
            const opensaml::Assertion& assertion, const XMLCh* protocol, opensaml::SecurityPolicy& policy
            ) const;

        /**
         * Attempt SSO-initiated attribute resolution using the supplied information,
         * including NameID and token extraction and filtering followed by
         * secondary resolution.
         * 
         * <p>The caller must free the returned context handle.
         * 
         * @param application           reference to application receiving message
         * @param issuer                source of SSO tokens
         * @param protocol              SSO protocol used
         * @param v1nameid              identifier of principal in SAML 1.x form, if any
         * @param nameid                identifier of principal in SAML 2.0 form
         * @param authncontext_class    method/category of authentication event, if known
         * @param authncontext_decl     specifics of authentication event, if known
         * @param tokens                available assertions, if any
         */
        ResolutionContext* resolveAttributes(
            const Application& application,
            const opensaml::saml2md::RoleDescriptor* issuer=NULL,
            const XMLCh* protocol=NULL,
            const opensaml::saml1::NameIdentifier* v1nameid=NULL,
            const opensaml::saml2::NameID* nameid=NULL,
            const XMLCh* authncontext_class=NULL,
            const XMLCh* authncontext_decl=NULL,
            const std::vector<const opensaml::Assertion*>* tokens=NULL
            ) const;

    public:
        const char* getType() const {
            return "AssertionConsumerService";
        }

#endif
    private:
        std::pair<bool,long> processMessage(
            const Application& application, const xmltooling::HTTPRequest& httpRequest, xmltooling::HTTPResponse& httpResponse
            ) const;
        
        std::pair<bool,long> sendRedirect(
            const Application& application,
            const xmltooling::HTTPRequest& request,
            xmltooling::HTTPResponse& response,
            const char* entityID,
            const char* relayState
            ) const;

        void maintainHistory(
            const Application& application, const xmltooling::HTTPRequest& request, xmltooling::HTTPResponse& response, const char* entityID
            ) const;
                
#ifndef SHIBSP_LITE
        opensaml::MessageDecoder* m_decoder;
        xmltooling::QName m_role;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_acshandler_h__ */

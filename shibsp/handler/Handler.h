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
 * @file shibsp/handler/Handler.h
 * 
 * Pluggable runtime functionality that implement protocols and services 
 */

#ifndef __shibsp_handler_h__
#define __shibsp_handler_h__

#include <shibsp/util/PropertySet.h>
#ifndef SHIBSP_LITE
# include <saml/saml2/metadata/Metadata.h>
#endif

namespace shibsp {

    class SHIBSP_API SPRequest;

    /**
     * Pluggable runtime functionality that implement protocols and services
     */
    class SHIBSP_API Handler : public virtual PropertySet
    {
        MAKE_NONCOPYABLE(Handler);
    protected:
        Handler() {}
    public:
        virtual ~Handler() {}

        /**
         * Executes handler functionality as an incoming request.
         * 
         * <p>Handlers can be run either directly by incoming web requests
         * or indirectly/implicitly during other SP processing.
         * 
         * @param request   SP request context
         * @param isHandler true iff executing in the context of a direct handler invocation
         * @return  a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const=0;

#ifndef SHIBSP_LITE
        /**
         * Generates and/or modifies metadata reflecting the Handler.
         *
         * <p>The default implementation does nothing.
         *
         * @param role          metadata role to decorate
         * @param handlerURL    base location of handler's endpoint
         */
        virtual void generateMetadata(opensaml::saml2md::SPSSODescriptor& role, const char* handlerURL) const {
        }

        /**
         * Returns the "type" of the Handler plugin.
         *
         * @return  a Handler type
         */
        virtual const char* getType() const {
            return getString("type").second;
        }
#endif
    };
    
    /** Registers Handler implementations. */
    void SHIBSP_API registerHandlers();

    /** Handler for metadata generation. */
    #define METADATA_GENERATOR_HANDLER "MetadataGenerator"

    /** Handler for status information. */
    #define STATUS_HANDLER "Status"

    /** Handler for session diagnostic information. */
    #define SESSION_HANDLER "Session"
};

#endif /* __shibsp_handler_h__ */

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
 * @file shibsp/RequestMapper.h
 * 
 * Interface to a request mapping plugin
 */

#ifndef __shibsp_reqmap_h__
#define __shibsp_reqmap_h__

#include <shibsp/base.h>
#include <xmltooling/Lockable.h>
#include <xmltooling/io/HTTPRequest.h>

namespace shibsp {

    class SHIBSP_API AccessControl;
    class SHIBSP_API PropertySet;

    /**
     * Interface to a request mapping plugin
     * 
     * Request mapping plugins return configuration settings that apply to resource requests.
     * They can be implemented through cross-platform or platform-specific mechanisms.
     */
    class SHIBSP_API RequestMapper : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(RequestMapper);
    protected:
        RequestMapper() {}
    public:
        virtual ~RequestMapper() {}

        /** Combination of configuration settings and effective access control. */
        typedef std::pair<const PropertySet*,AccessControl*> Settings;

        /**
         * Map request to settings.
         * 
         * @param request   SP request
         * @return configuration settings and effective AccessControl plugin, if any
         */        
        virtual Settings getSettings(const xmltooling::HTTPRequest& request) const=0;
    };

    /**
     * Registers RequestMapper classes into the runtime.
     */
    void SHIBSP_API registerRequestMappers();

    /** XML-based RequestMapper implementation. */
    #define XML_REQUEST_MAPPER      "XML"

    /** Hybrid of XML and platform-specific configuration. */
    #define NATIVE_REQUEST_MAPPER   "Native"
};

#endif /* __shibsp_reqmap_h__ */

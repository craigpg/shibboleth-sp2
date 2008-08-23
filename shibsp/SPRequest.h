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
 * @file shibsp/SPRequest.h
 * 
 * Interface to server request being processed  
 */

#ifndef __shibsp_req_h__
#define __shibsp_req_h__

#include <shibsp/RequestMapper.h>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/io/HTTPResponse.h>

namespace shibsp {
    
    class SHIBSP_API Application;
    class SHIBSP_API ServiceProvider;
    class SHIBSP_API Session;
    
    /**
     * Interface to server request being processed
     * 
     * <p>To supply information from the surrounding web server environment,
     * a shim must be supplied in the form of this interface to adapt the
     * library to different proprietary server APIs.
     * 
     * <p>This interface need not be threadsafe.
     */
    class SHIBSP_API SPRequest : public virtual xmltooling::HTTPRequest, public virtual xmltooling::HTTPResponse
    {
    protected:
        SPRequest() {}
    public:
        virtual ~SPRequest() {}
        
        /**
         * Returns the locked ServiceProvider processing the request.
         * 
         * @return reference to ServiceProvider
         */
        virtual const ServiceProvider& getServiceProvider() const=0;

        /**
         * Returns RequestMapper Settings associated with the request, guaranteed
         * to be valid for the request's duration.
         * 
         * @return copy of settings
         */
        virtual RequestMapper::Settings getRequestSettings() const=0;
        
        /**
         * Returns the Application governing the request.
         * 
         * @return reference to Application
         */
        virtual const Application& getApplication() const=0;

        /**
         * Returns a locked Session associated with the request.
         *
         * @param checkTimeout  true iff the last-used timestamp should be updated and any timeout policy enforced
         * @param ignoreAddress true iff all address checking should be ignored, regardless of policy
         * @param cache         true iff the request should hold the Session lock itself and unlock during cleanup
         * @return pointer to Session, or NULL
         */
        virtual Session* getSession(bool checkTimeout=true, bool ignoreAddress=false, bool cache=true)=0;

        /**
         * Returns the effective base Handler URL for a resource,
         * or the current request URL.
         * 
         * @param resource  resource URL to compute handler for
         * @return  base location of handler
         */
        virtual const char* getHandlerURL(const char* resource=NULL) const=0;

        /**
         * Returns a non-spoofable request header value, if possible.
         * Platforms that support environment export can redirect header
         * lookups by overriding this method.
         * 
         * @param name  the name of the secure header to return
         * @return the header's value, or an empty string
         */
        virtual std::string getSecureHeader(const char* name) const {
            return getHeader(name);
        }

        /**
         * Ensures no value exists for a request header.
         * 
         * @param rawname  raw name of header to clear
         * @param cginame  CGI-equivalent name of header
         */
        virtual void clearHeader(const char* rawname, const char* cginame)=0;

        /**
         * Sets a value for a request header.
         * 
         * @param name  name of header to set
         * @param value value to set
         */
        virtual void setHeader(const char* name, const char* value)=0;

        /**
         * Establish REMOTE_USER identity in request.
         * 
         * @param user  REMOTE_USER value to set or NULL to clear
         */
        virtual void setRemoteUser(const char* user)=0;
        
        /** Portable logging levels. */
        enum SPLogLevel {
          SPDebug,
          SPInfo,
          SPWarn,
          SPError,
          SPCrit
        };

        /**
         * Log to native server environment.
         * 
         * @param level logging level
         * @param msg   message to log
         */
        virtual void log(SPLogLevel level, const std::string& msg) const=0;

        /**
         * Test logging level.
         * 
         * @param level logging level
         * @return true iff logging level is enabled
         */
        virtual bool isPriorityEnabled(SPLogLevel level) const=0;

        /**
         * Indicates that processing was declined, meaning no action is required during this phase of processing.
         * 
         * @return  a status code to pass back to the server-specific layer
         */        
        virtual long returnDecline()=0;

        /**
         * Indicates that processing was completed.
         * 
         * @return  a status code to pass back to the server-specific layer
         */        
        virtual long returnOK()=0;
    };
};

#endif /* __shibsp_req_h__ */

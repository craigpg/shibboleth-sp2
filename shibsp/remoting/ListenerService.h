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
 * @file shibsp/remoting/ListenerService.h
 * 
 * Interprocess remoting engine.
 */

#ifndef __shibsp_listener_h__
#define __shibsp_listener_h__

#include <shibsp/remoting/ddf.h>
#include <map>

namespace shibsp {

    /**
     * Interface to a remoted service
     * 
     * Classes that support remoted messages delivered by the Listener runtime
     * support this interface and register themselves with the runtime to receive
     * particular messages.
     */
    class SHIBSP_API Remoted
    {
        MAKE_NONCOPYABLE(Remoted);
    protected:
        Remoted() {}
    public:
        virtual ~Remoted() {}

        /**
         * Remoted classes implement this method to process incoming messages.
         * 
         * @param in    incoming DDF message
         * @param out   stream to write outgoing DDF message to
         */
        virtual void receive(DDF& in, std::ostream& out)=0;
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

    /**
     * Interface to a remoting engine.
     * 
     * A ListenerService supports the remoting of DDF objects, which are dynamic data trees
     * that other class implementations can use to remote themselves by calling an
     * out-of-process peer implementation with arbitrary data to carry out tasks
     * on the implementation's behalf that require isolation from the dynamic process
     * fluctuations that web servers are prone to. The ability to pass arbitrary data
     * trees across the boundary allows arbitrary separation of duty between the
     * in-process and out-of-process "halves". The ListenerService is responsible
     * for marshalling and transmitting messages, as well as managing connections
     * and communication errors.
     */
    class SHIBSP_API ListenerService : public virtual Remoted
    {
    public:
        virtual ~ListenerService() {}

        /**
         * Send a remoted message and return the response.
         * 
         * @param in    input message to send
         * @return      response from remote service
         */
        virtual DDF send(const DDF& in)=0;
        
        void receive(DDF& in, std::ostream& out);

        // Remoted classes register and unregister for messages using these methods.
        // Registration returns any existing listeners, allowing message hooking.
        
        /**
         * Register for a message. Returns existing remote service, allowing message hooking.
         * 
         * @param address   message address to register
         * @param svc       pointer to remote service
         * @return  previous service registered for message, if any
         */
        virtual Remoted* regListener(const char* address, Remoted* svc);
        
        /**
         * Unregisters service from an address, possibly restoring an original.
         * 
         * @param address   message address to modify
         * @param current   pointer to unregistering service
         * @param restore   service to "restore" registration for
         * @return  true iff the current service was still registered
         */
        virtual bool unregListener(const char* address, Remoted* current, Remoted* restore=NULL);
        
        /**
         * Returns current service registered at an address, if any.
         * 
         * @param address message address to access
         * @return  registered service, or NULL
         */
        virtual Remoted* lookup(const char* address) const;

        /**
         * OutOfProcess servers can implement server-side transport handling by
         * calling the run method and supplying a flag to monitor for shutdown.
         * 
         * @param shutdown  pointer to flag that caller will set when shutdown is required
         * @return true iff ListenerService initialization was successful
         */
        virtual bool run(bool* shutdown)=0;

    private:
        std::map<std::string,Remoted*> m_listenerMap;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    /**
     * Registers ListenerService classes into the runtime.
     */
    void SHIBSP_API registerListenerServices();

    /** Listener based on TCP socket remoting. */
    #define TCP_LISTENER_SERVICE "TCPListener"

    /** Listener based on UNIX domain socket remoting. */
    #define UNIX_LISTENER_SERVICE "UnixListener"
};

#endif /* __shibsp_listener_h__ */

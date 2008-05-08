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
 * SocketListener.h
 * 
 * Berkeley Socket-based ListenerService implementation
 */

#ifndef __shibsp_socklisten_h__
#define __shibsp_socklisten_h__

#ifndef FD_SETSIZE
# define FD_SETSIZE 1024
#endif

#include <shibsp/remoting/ListenerService.h>

#include <xercesc/dom/DOM.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/util/Threads.h>

#ifdef WIN32
# include <winsock.h>
#endif

namespace shibsp {

    class SocketPool;
    class ServerThread;
    
    /**
     * Berkeley Socket-based ListenerService implementation
     */
    class SocketListener : public virtual ListenerService
    {
    public:
        /// @cond OFF
        SocketListener(const xercesc::DOMElement* e);
        ~SocketListener();

        DDF send(const DDF& in);
        bool run(bool* shutdown);

        // Implemented by socket-specific subclasses.
#ifdef WIN32
        typedef SOCKET ShibSocket;
#else
        typedef int ShibSocket;
#endif
        virtual bool create(ShibSocket& s) const=0;
        virtual bool connect(ShibSocket& s) const=0;
        virtual bool bind(ShibSocket& s, bool force=false) const=0;
        virtual bool accept(ShibSocket& listener, ShibSocket& s) const=0;
        virtual bool close(ShibSocket& s) const=0;
        virtual int send(ShibSocket& s, const char* buf, int len) const=0;
        virtual int recv(ShibSocket& s, char* buf, int buflen) const=0;

        bool m_catchAll;
    protected:
        bool log_error() const; // for OS-level errors
        xmltooling::logging::Category* log;
        /// @endcond
    
    private:
        mutable SocketPool* m_socketpool;
        bool* m_shutdown;

        // Manage child threads
        friend class ServerThread;
        std::map<ShibSocket,xmltooling::Thread*> m_children;
        xmltooling::Mutex* m_child_lock;
        xmltooling::CondWait* m_child_wait;

        // Primary socket
        ShibSocket m_socket;
    };
}

#endif /* __shibsp_socklisten_h__ */

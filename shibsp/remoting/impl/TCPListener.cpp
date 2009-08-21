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
 * TCPListener.cpp
 *
 * TCP-based SocketListener implementation
 */

#include "internal.h"
#include "remoting/impl/SocketListener.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/unicode.h>

#ifdef HAVE_UNISTD_H
# include <sys/socket.h>
# include <sys/un.h>
# include <unistd.h>
# include <arpa/inet.h>
# include <netinet/in.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>		/* for chmod() */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

namespace shibsp {
    static const XMLCh address[] = UNICODE_LITERAL_7(a,d,d,r,e,s,s);
    static const XMLCh port[] = UNICODE_LITERAL_4(p,o,r,t);
    static const XMLCh acl[] = UNICODE_LITERAL_3(a,c,l);

    class TCPListener : virtual public SocketListener
    {
    public:
        TCPListener(const DOMElement* e);
        ~TCPListener() {}

        bool create(ShibSocket& s) const;
        bool bind(ShibSocket& s, bool force=false) const;
        bool connect(ShibSocket& s) const;
        bool close(ShibSocket& s) const;
        bool accept(ShibSocket& listener, ShibSocket& s) const;

        int send(ShibSocket& s, const char* buf, int len) const {
            return ::send(s, buf, len, 0);
        }

        int recv(ShibSocket& s, char* buf, int buflen) const {
            return ::recv(s, buf, buflen, 0);
        }

    private:
        void setup_tcp_sockaddr(struct sockaddr_in* addr) const;

        string m_address;
        unsigned short m_port;
        set<string> m_acl;
    };

    ListenerService* SHIBSP_DLLLOCAL TCPListenerServiceFactory(const DOMElement* const & e)
    {
        return new TCPListener(e);
    }
};

TCPListener::TCPListener(const DOMElement* e) : SocketListener(e), m_address("127.0.0.1"), m_port(12345)
{
    // We're stateless, but we need to load the configuration.
    const XMLCh* tag=e->getAttributeNS(NULL,address);
    if (tag && *tag) {
        auto_ptr_char a(tag);
        m_address=a.get();
    }

    tag=e->getAttributeNS(NULL,port);
    if (tag && *tag) {
        m_port=XMLString::parseInt(tag);
        if (m_port==0)
            m_port=12345;
    }

    tag=e->getAttributeNS(NULL,acl);
    if (tag && *tag) {
        auto_ptr_char temp(tag);
        string sockacl=temp.get();
        if (sockacl.length()) {
            int j = 0;
            for (unsigned int i=0;  i < sockacl.length();  i++) {
                if (sockacl.at(i)==' ') {
                    m_acl.insert(sockacl.substr(j, i-j));
                    j = i+1;
                }
            }
            m_acl.insert(sockacl.substr(j, sockacl.length()-j));
        }
    }
    else
        m_acl.insert("127.0.0.1");
}

void TCPListener::setup_tcp_sockaddr(struct sockaddr_in* addr) const
{
    // Split on host:port boundary. Default to port only.
    memset(addr,0,sizeof(struct sockaddr_in));
    addr->sin_family=AF_INET;
    addr->sin_port=htons(m_port);
    addr->sin_addr.s_addr=inet_addr(m_address.c_str());
}

bool TCPListener::create(ShibSocket& s) const
{
    s=socket(AF_INET,SOCK_STREAM,0);
#ifdef WIN32
    if(s==INVALID_SOCKET)
#else
    if (s < 0)
#endif
        return log_error();
    return true;
}

bool TCPListener::bind(ShibSocket& s, bool force) const
{
    struct sockaddr_in addr;
    setup_tcp_sockaddr(&addr);

    // XXX: Do we care about the return value from setsockopt?
    int opt = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

#ifdef WIN32
    if (SOCKET_ERROR==::bind(s,(struct sockaddr *)&addr,sizeof(addr)) || SOCKET_ERROR==::listen(s,3)) {
        log_error();
        close(s);
        return false;
    }
#else
    if (::bind(s, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
        log_error();
        close(s);
        return false;
    }
    ::listen(s,3);
#endif
    return true;
}

bool TCPListener::connect(ShibSocket& s) const
{
    struct sockaddr_in addr;
    setup_tcp_sockaddr(&addr);
#ifdef WIN32
    if(SOCKET_ERROR==::connect(s,(struct sockaddr *)&addr,sizeof(addr)))
        return log_error();
#else
    if (::connect(s, (struct sockaddr*)&addr, sizeof (addr)) < 0)
        return log_error();
#endif
    return true;
}

bool TCPListener::close(ShibSocket& s) const
{
#ifdef WIN32
    closesocket(s);
#else
    ::close(s);
#endif
    return true;
}

bool TCPListener::accept(ShibSocket& listener, ShibSocket& s) const
{
    struct sockaddr_in addr;

#ifdef WIN32
    int size=sizeof(addr);
    s=::accept(listener,(struct sockaddr*)&addr,&size);
    if(s==INVALID_SOCKET)
#else
    socklen_t size=sizeof(addr);
    s=::accept(listener,(struct sockaddr*)&addr,&size);
    if (s < 0)
#endif
        return log_error();
    char* client=inet_ntoa(addr.sin_addr);
    if (m_acl.count(client) == 0) {
        close(s);
        s=-1;
        log->error("accept() rejected client at %s", client);
        return false;
    }
    return true;
}

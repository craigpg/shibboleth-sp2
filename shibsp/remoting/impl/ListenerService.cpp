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
 * ListenerService.cpp
 * 
 * Interprocess remoting engine.
 */

#include "internal.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "remoting/ListenerService.h"

#include <xercesc/dom/DOM.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL PluginManager<ListenerService,string,const DOMElement*>::Factory TCPListenerServiceFactory;
#ifndef WIN32
    SHIBSP_DLLLOCAL PluginManager<ListenerService,string,const DOMElement*>::Factory UnixListenerServiceFactory;
#endif
};

void SHIBSP_API shibsp::registerListenerServices()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.ListenerServiceManager.registerFactory(TCP_LISTENER_SERVICE, TCPListenerServiceFactory);
#ifndef WIN32
    conf.ListenerServiceManager.registerFactory(UNIX_LISTENER_SERVICE, UnixListenerServiceFactory);
#endif
}

Remoted* ListenerService::regListener(const char* address, Remoted* listener)
{
    Remoted* ret=NULL;
    map<string,Remoted*>::const_iterator i=m_listenerMap.find(address);
    if (i!=m_listenerMap.end())
        ret=i->second;
    m_listenerMap[address]=listener;
    Category::getInstance(SHIBSP_LOGCAT".Listener").info("registered remoted message endpoint (%s)",address);
    return ret;
}

bool ListenerService::unregListener(const char* address, Remoted* current, Remoted* restore)
{
    map<string,Remoted*>::const_iterator i=m_listenerMap.find(address);
    if (i!=m_listenerMap.end() && i->second==current) {
        if (restore)
            m_listenerMap[address]=restore;
        else
            m_listenerMap.erase(address);
        Category::getInstance(SHIBSP_LOGCAT".Listener").info("unregistered remoted message endpoint (%s)",address);
        return true;
    }
    return false;
}

Remoted* ListenerService::lookup(const char *address) const
{
    map<string,Remoted*>::const_iterator i=m_listenerMap.find(address);
    return (i==m_listenerMap.end()) ? NULL : i->second;
}

void ListenerService::receive(DDF &in, ostream& out)
{
    if (!in.name())
        throw ListenerException("Incoming message with no destination address rejected.");
    else if (!strcmp("ping",in.name())) {
        DDF outmsg=DDF(NULL).integer(in.integer() + 1);
        DDFJanitor jan(outmsg);
        out << outmsg;
    }

    Locker locker(SPConfig::getConfig().getServiceProvider());
    Remoted* dest=lookup(in.name());
    if (!dest)
        throw ListenerException("No destination registered for incoming message addressed to ($1).",params(1,in.name()));
    
    dest->receive(in, out);
}

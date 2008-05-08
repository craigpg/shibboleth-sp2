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
 * DOMPropertySet.cpp
 * 
 * DOM-based property set implementation.
 */

#include "internal.h"
#include "util/DOMPropertySet.h"

#include <algorithm>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLConstants.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

DOMPropertySet::~DOMPropertySet()
{
    for (map<string,pair<char*,const XMLCh*> >::iterator i=m_map.begin(); i!=m_map.end(); i++)
        XMLString::release(&(i->second.first));
    for_each(m_nested.begin(),m_nested.end(),cleanup_pair<string,DOMPropertySet>());
}

void DOMPropertySet::load(
    const DOMElement* e,
    Category* log,
    DOMNodeFilter* filter,
    const std::map<std::string,std::string>* remapper
    )
{
#ifdef _DEBUG
    NDC ndc("load");
#endif
    if (!e)
        return;
    m_root=e;
    if (!log)
        log = &Category::getInstance(SHIBSP_LOGCAT".PropertySet");

    // Process each attribute as a property.
    DOMNamedNodeMap* attrs=m_root->getAttributes();
    for (XMLSize_t i=0; i<attrs->getLength(); i++) {
        DOMNode* a=attrs->item(i);
        if (!XMLString::compareString(a->getNamespaceURI(),xmlconstants::XMLNS_NS))
            continue;
        char* val=XMLString::transcode(a->getNodeValue());
        if (val && *val) {
            auto_ptr_char ns(a->getNamespaceURI());
            auto_ptr_char name(a->getLocalName());
            const char* realname=name.get();
            map<string,string>::const_iterator remap;
            if (remapper) {
                remap=remapper->find(realname);
                if (remap!=remapper->end()) {
                    log->warn("remapping property (%s) to (%s)",realname,remap->second.c_str());
                    realname=remap->second.c_str();
                }
            }
            if (ns.get()) {
                if (remapper && (remap=remapper->find(ns.get()))!=remapper->end())
                    m_map[string("{") + remap->second.c_str() + '}' + realname]=pair<char*,const XMLCh*>(val,a->getNodeValue());
                else
                    m_map[string("{") + ns.get() + '}' + realname]=pair<char*,const XMLCh*>(val,a->getNodeValue());
                log->debug("added property {%s}%s (%s)",ns.get(),realname,val);
            }
            else {
                m_map[realname]=pair<char*,const XMLCh*>(val,a->getNodeValue());
                log->debug("added property %s (%s)",realname,val);
            }
        }
    }
    
    // Process non-excluded elements as nested sets.
    DOMTreeWalker* walker=
        static_cast<DOMDocumentTraversal*>(
            m_root->getOwnerDocument())->createTreeWalker(const_cast<DOMElement*>(m_root),DOMNodeFilter::SHOW_ELEMENT,filter,false
            );
    e=static_cast<DOMElement*>(walker->firstChild());
    while (e) {
        auto_ptr_char ns(e->getNamespaceURI());
        auto_ptr_char name(e->getLocalName());
        const char* realname=name.get();
        map<string,string>::const_iterator remap;
        if (remapper) {
            remap=remapper->find(realname);
            if (remap!=remapper->end()) {
                log->warn("remapping property set (%s) to (%s)",realname,remap->second.c_str());
                realname=remap->second.c_str();
            }
        }
        string key;
        if (ns.get()) {
            if (remapper && (remap=remapper->find(ns.get()))!=remapper->end())
                key=string("{") + remap->second.c_str() + '}' + realname;
            else
                key=string("{") + ns.get() + '}' + realname;
        }
        else
            key=realname;
        if (m_nested.find(key)!=m_nested.end())
            log->warn("load() skipping duplicate property set: %s",key.c_str());
        else {
            DOMPropertySet* set=new DOMPropertySet();
            set->load(e,log,filter,remapper);
            m_nested[key]=set;
            log->debug("added nested property set: %s",key.c_str());
        }
        e=static_cast<DOMElement*>(walker->nextSibling());
    }
    walker->release();
}

pair<bool,bool> DOMPropertySet::getBool(const char* name, const char* ns) const
{
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end())
        return make_pair(true,(!strcmp(i->second.first,"true") || !strcmp(i->second.first,"1")));
    else if (m_parent)
        return m_parent->getBool(name,ns);
    return make_pair(false,false);
}

pair<bool,const char*> DOMPropertySet::getString(const char* name, const char* ns) const
{
    pair<bool,const char*> ret(false,NULL);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end())
        return pair<bool,const char*>(true,i->second.first);
    else if (m_parent)
        return m_parent->getString(name,ns);
    return pair<bool,const char*>(false,NULL);
}

pair<bool,const XMLCh*> DOMPropertySet::getXMLString(const char* name, const char* ns) const
{
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end())
        return make_pair(true,i->second.second);
    else if (m_parent)
        return m_parent->getXMLString(name,ns);
    return pair<bool,const XMLCh*>(false,NULL);
}

pair<bool,unsigned int> DOMPropertySet::getUnsignedInt(const char* name, const char* ns) const
{
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end())
        return pair<bool,unsigned int>(true,strtol(i->second.first,NULL,10));
    else if (m_parent)
        return m_parent->getUnsignedInt(name,ns);
    return pair<bool,unsigned int>(false,0);
}

pair<bool,int> DOMPropertySet::getInt(const char* name, const char* ns) const
{
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end())
        return pair<bool,int>(true,atoi(i->second.first));
    else if (m_parent)
        return m_parent->getInt(name,ns);
    return pair<bool,int>(false,0);
}

void DOMPropertySet::getAll(std::map<std::string,const char*>& properties) const
{
    if (m_parent)
        m_parent->getAll(properties);
    for (map< string,pair<char*,const XMLCh*> >::const_iterator i = m_map.begin(); i != m_map.end(); ++i)
        properties[i->first] = i->second.first;
}

const PropertySet* DOMPropertySet::getPropertySet(const char* name, const char* ns) const
{
    map<string,DOMPropertySet*>::const_iterator i;

    if (ns)
        i=m_nested.find(string("{") + ns + '}' + name);
    else
        i=m_nested.find(name);

    return (i!=m_nested.end()) ? i->second : (m_parent ? m_parent->getPropertySet(name,ns) : NULL);
}

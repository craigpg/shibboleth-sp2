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
 * shibsp/attribute/Attribute.cpp
 *
 * A resolved attribute.
 */

#include "internal.h"
#include "SPConfig.h"
#ifndef SHIBSP_LITE
# include "attribute/AttributeDecoder.h"
#endif
#include "attribute/SimpleAttribute.h"
#include "attribute/ScopedAttribute.h"
#include "attribute/NameIDAttribute.h"
#include "attribute/ExtensibleAttribute.h"
#include "attribute/XMLAttribute.h"
#include "util/SPConstants.h"

#include <xercesc/util/Base64.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    SHIBSP_DLLLOCAL Attribute* SimpleAttributeFactory(DDF& in) {
        return new SimpleAttribute(in);
    }

    SHIBSP_DLLLOCAL Attribute* ScopedAttributeFactory(DDF& in) {
        return new ScopedAttribute(in);
    }

    SHIBSP_DLLLOCAL Attribute* NameIDAttributeFactory(DDF& in) {
        return new NameIDAttribute(in);
    }

    SHIBSP_DLLLOCAL Attribute* ExtensibleAttributeFactory(DDF& in) {
        return new ExtensibleAttribute(in);
    }

    SHIBSP_DLLLOCAL Attribute* XMLAttributeFactory(DDF& in) {
        return new XMLAttribute(in);
    }

#ifndef SHIBSP_LITE
    SHIBSP_DLLLOCAL PluginManager<AttributeDecoder,xmltooling::QName,const DOMElement*>::Factory StringAttributeDecoderFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeDecoder,xmltooling::QName,const DOMElement*>::Factory ScopedAttributeDecoderFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeDecoder,xmltooling::QName,const DOMElement*>::Factory NameIDAttributeDecoderFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeDecoder,xmltooling::QName,const DOMElement*>::Factory NameIDFromScopedAttributeDecoderFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeDecoder,xmltooling::QName,const DOMElement*>::Factory KeyInfoAttributeDecoderFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeDecoder,xmltooling::QName,const DOMElement*>::Factory DOMAttributeDecoderFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeDecoder,xmltooling::QName,const DOMElement*>::Factory XMLAttributeDecoderFactory;

    static const XMLCh _StringAttributeDecoder[] = UNICODE_LITERAL_22(S,t,r,i,n,g,A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);
    static const XMLCh _ScopedAttributeDecoder[] = UNICODE_LITERAL_22(S,c,o,p,e,d,A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);
    static const XMLCh _NameIDAttributeDecoder[] = UNICODE_LITERAL_22(N,a,m,e,I,D,A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);
    static const XMLCh _NameIDFromScopedAttributeDecoder[] = UNICODE_LITERAL_32(N,a,m,e,I,D,F,r,o,m,S,c,o,p,e,d,A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);
    static const XMLCh _KeyInfoAttributeDecoder[] =UNICODE_LITERAL_23(K,e,y,I,n,f,o,A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);
    static const XMLCh _DOMAttributeDecoder[] =    UNICODE_LITERAL_19(D,O,M,A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);
    static const XMLCh _XMLAttributeDecoder[] =    UNICODE_LITERAL_19(X,M,L,A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);

    static const XMLCh caseSensitive[] =           UNICODE_LITERAL_13(c,a,s,e,S,e,n,s,i,t,i,v,e);
    static const XMLCh internal[] =                UNICODE_LITERAL_8(i,n,t,e,r,n,a,l);
#endif
};

#ifndef SHIBSP_LITE
xmltooling::QName shibsp::StringAttributeDecoderType(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _StringAttributeDecoder);
xmltooling::QName shibsp::ScopedAttributeDecoderType(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _ScopedAttributeDecoder);
xmltooling::QName shibsp::NameIDAttributeDecoderType(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _NameIDAttributeDecoder);
xmltooling::QName shibsp::NameIDFromScopedAttributeDecoderType(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _NameIDFromScopedAttributeDecoder);
xmltooling::QName shibsp::KeyInfoAttributeDecoderType(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _KeyInfoAttributeDecoder);
xmltooling::QName shibsp::DOMAttributeDecoderType(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _DOMAttributeDecoder);
xmltooling::QName shibsp::XMLAttributeDecoderType(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _XMLAttributeDecoder);

void shibsp::registerAttributeDecoders()
{
    SPConfig& conf = SPConfig::getConfig();
    conf.AttributeDecoderManager.registerFactory(StringAttributeDecoderType, StringAttributeDecoderFactory);
    conf.AttributeDecoderManager.registerFactory(ScopedAttributeDecoderType, ScopedAttributeDecoderFactory);
    conf.AttributeDecoderManager.registerFactory(NameIDAttributeDecoderType, NameIDAttributeDecoderFactory);
    conf.AttributeDecoderManager.registerFactory(NameIDFromScopedAttributeDecoderType, NameIDFromScopedAttributeDecoderFactory);
    conf.AttributeDecoderManager.registerFactory(KeyInfoAttributeDecoderType, KeyInfoAttributeDecoderFactory);
    conf.AttributeDecoderManager.registerFactory(DOMAttributeDecoderType, DOMAttributeDecoderFactory);
    conf.AttributeDecoderManager.registerFactory(XMLAttributeDecoderType, XMLAttributeDecoderFactory);
}

AttributeDecoder::AttributeDecoder(const DOMElement *e) : m_caseSensitive(true), m_internal(false)
{
    if (e) {
        const XMLCh* flag = e->getAttributeNS(NULL, caseSensitive);
        if (flag && (*flag == chLatin_f || *flag == chDigit_0))
            m_caseSensitive = false;

        flag = e->getAttributeNS(NULL, internal);
        if (flag && (*flag == chLatin_t || *flag == chDigit_1))
            m_internal = true;
    }
}
#endif

void shibsp::registerAttributeFactories()
{
    Attribute::registerFactory("", SimpleAttributeFactory);
    Attribute::registerFactory("Simple", SimpleAttributeFactory);
    Attribute::registerFactory("Scoped", ScopedAttributeFactory);
    Attribute::registerFactory("NameID", NameIDAttributeFactory);
    Attribute::registerFactory("Extensible", ExtensibleAttributeFactory);
    Attribute::registerFactory("XML", XMLAttributeFactory);
}

map<string,Attribute::AttributeFactory*> Attribute::m_factoryMap;

Attribute::Attribute(DDF& in) : m_caseSensitive(in["case_insensitive"].isnull()), m_internal(!in["internal"].isnull())
{
    const char* id = in.first().name();
    if (id && *id)
        m_id.push_back(id);
    else
        throw AttributeException("No id found in marshalled attribute content.");
    DDF aliases = in["aliases"];
    if (aliases.islist()) {
        DDF alias = aliases.first();
        while (alias.isstring()) {
            m_id.push_back(alias.string());
            alias = aliases.next();
        }
    }
}

DDF Attribute::marshall() const
{
    DDF ddf(NULL);
    ddf.structure().addmember(m_id.front().c_str()).list();
    if (!m_caseSensitive)
        ddf.addmember("case_insensitive");
    if (m_internal)
        ddf.addmember("internal");
    if (m_id.size() > 1) {
        DDF alias;
        DDF aliases = ddf.addmember("aliases").list();
        for (std::vector<std::string>::const_iterator a = m_id.begin() + 1; a != m_id.end(); ++a) {
            alias = DDF(NULL).string(a->c_str());
            aliases.add(alias);
        }
    }
    return ddf;
}

Attribute* Attribute::unmarshall(DDF& in)
{
    map<string,AttributeFactory*>::const_iterator i = m_factoryMap.find(in.name() ? in.name() : "");
    if (i == m_factoryMap.end())
        throw AttributeException("No registered factory for Attribute of type ($1).", params(1,in.name()));
    return (i->second)(in);
}

const vector<string>& XMLAttribute::getSerializedValues() const
{
    xsecsize_t len;
    XMLByte *pos, *pos2;
    if (m_serialized.empty()) {
        for (vector<string>::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
            XMLByte* enc = Base64::encode(reinterpret_cast<const XMLByte*>(i->data()), i->size(), &len);
            if (enc) {
                for (pos=enc, pos2=enc; *pos2; pos2++)
                    if (isgraph(*pos2))
                        *pos++=*pos2;
                *pos=0;
                m_serialized.push_back(reinterpret_cast<char*>(enc));
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
                XMLString::release(&enc);
#else
                XMLString::release((char**)&enc);
#endif
            }
        }
    }
    return Attribute::getSerializedValues();
}

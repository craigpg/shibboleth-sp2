/*
 *  Copyright 2009 Internet2
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
 * XMLAttribute.cpp
 *
 * An Attribute whose values are serialized XML.
 */

#include "internal.h"
#include "attribute/XMLAttribute.h"

#include <xercesc/util/Base64.hpp>

#ifndef SHIBSP_LITE
# include <xsec/framework/XSECDefs.hpp>
#endif

using namespace shibsp;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL Attribute* XMLAttributeFactory(DDF& in) {
        return new XMLAttribute(in);
    }
};

XMLAttribute::XMLAttribute(const vector<string>& ids) : Attribute(ids)
{
}

XMLAttribute::XMLAttribute(DDF& in) : Attribute(in)
{
    DDF val = in.first().first();
    while (val.string()) {
        m_values.push_back(val.string());
        val = in.first().next();
    }
}

XMLAttribute::~XMLAttribute()
{
}

vector<string>& XMLAttribute::getValues()
{
    return m_values;
}

const vector<string>& XMLAttribute::getValues() const
{
    return m_values;
}

size_t XMLAttribute::valueCount() const
{
    return m_values.size();
}

void XMLAttribute::clearSerializedValues()
{
    m_serialized.clear();
}

const char* XMLAttribute::getString(size_t index) const
{
    return m_values[index].c_str();
}

void XMLAttribute::removeValue(size_t index)
{
    Attribute::removeValue(index);
    if (index < m_values.size())
        m_values.erase(m_values.begin() + index);
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

DDF XMLAttribute::marshall() const
{
    DDF ddf = Attribute::marshall();
    ddf.name("XML");
    DDF vlist = ddf.first();
    for (vector<string>::const_iterator i=m_values.begin(); i!=m_values.end(); ++i)
        vlist.add(DDF(NULL).string(i->c_str()));
    return ddf;
}

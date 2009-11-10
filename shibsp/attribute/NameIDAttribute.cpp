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
 * NameIDAttribute.cpp
 *
 * An Attribute whose values are derived from or mappable to a SAML NameID.
 */

#include "internal.h"
#include "attribute/NameIDAttribute.h"

#include <xmltooling/exceptions.h>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL Attribute* NameIDAttributeFactory(DDF& in) {
        return new NameIDAttribute(in);
    }
};

NameIDAttribute::NameIDAttribute(const vector<string>& ids, const char* formatter) : Attribute(ids), m_formatter(formatter)
{
}

NameIDAttribute::NameIDAttribute(DDF& in) : Attribute(in)
{
    DDF val = in["_formatter"];
    if (val.isstring())
        m_formatter = val.string();
    else
        m_formatter = DEFAULT_NAMEID_FORMATTER;
    const char* pch;
    val = in.first().first();
    while (val.name()) {
        m_values.push_back(Value());
        Value& v = m_values.back();
        v.m_Name = val.name();
        pch = val["Format"].string();
        if (pch)
            v.m_Format = pch;
        pch = val["NameQualifier"].string();
        if (pch)
            v.m_NameQualifier = pch;
        pch = val["SPNameQualifier"].string();
        if (pch)
            v.m_SPNameQualifier = pch;
        pch = val["SPProvidedID"].string();
        if (pch)
            v.m_SPProvidedID = pch;
        val = in.first().next();
    }
}

NameIDAttribute::~NameIDAttribute()
{
}

vector<NameIDAttribute::Value>& NameIDAttribute::getValues()
{
    return m_values;
}

const vector<NameIDAttribute::Value>& NameIDAttribute::getValues() const
{
    return m_values;
}

size_t NameIDAttribute::valueCount() const
{
    return m_values.size();
}

void NameIDAttribute::clearSerializedValues()
{
    m_serialized.clear();
}

const char* NameIDAttribute::getString(size_t index) const
{
    return m_values[index].m_Name.c_str();
}

const char* NameIDAttribute::getScope(size_t index) const
{
    return m_values[index].m_NameQualifier.c_str();
}

void NameIDAttribute::removeValue(size_t index)
{
    Attribute::removeValue(index);
    if (index < m_values.size())
        m_values.erase(m_values.begin() + index);
}

const vector<string>& NameIDAttribute::getSerializedValues() const
{
    if (m_serialized.empty()) {
        for (vector<Value>::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
            // This is kind of a hack, but it's a good way to reuse some code.
            XMLToolingException e(
                m_formatter,
                namedparams(
                    5,
                    "Name", i->m_Name.c_str(),
                    "Format", i->m_Format.c_str(),
                    "NameQualifier", i->m_NameQualifier.c_str(),
                    "SPNameQualifier", i->m_SPNameQualifier.c_str(),
                    "SPProvidedID", i->m_SPProvidedID.c_str()
                    )
                );
            m_serialized.push_back(e.what());
        }
    }
    return Attribute::getSerializedValues();
}

DDF NameIDAttribute::marshall() const
{
    DDF ddf = Attribute::marshall();
    ddf.name("NameID");
    ddf.addmember("_formatter").string(m_formatter.c_str());
    DDF vlist = ddf.first();
    for (vector<Value>::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
        DDF val = DDF(i->m_Name.c_str()).structure();
        if (!i->m_Format.empty())
            val.addmember("Format").string(i->m_Format.c_str());
        if (!i->m_NameQualifier.empty())
            val.addmember("NameQualifier").string(i->m_NameQualifier.c_str());
        if (!i->m_SPNameQualifier.empty())
            val.addmember("SPNameQualifier").string(i->m_SPNameQualifier.c_str());
        if (!i->m_SPProvidedID.empty())
            val.addmember("SPProvidedID").string(i->m_SPProvidedID.c_str());
        vlist.add(val);
    }
    return ddf;
}

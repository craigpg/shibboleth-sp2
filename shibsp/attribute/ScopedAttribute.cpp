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
 * ScopedAttribute.cpp
 *
 * An Attribute whose values are relations of a value and a scope.
 */

#include "internal.h"
#include "attribute/ScopedAttribute.h"

using namespace shibsp;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL Attribute* ScopedAttributeFactory(DDF& in) {
        return new ScopedAttribute(in);
    }
};

ScopedAttribute::ScopedAttribute(const vector<string>& ids, char delimeter) : Attribute(ids), m_delimeter(delimeter)
{
}

ScopedAttribute::ScopedAttribute(DDF& in) : Attribute(in), m_delimeter('@')
{
    DDF val = in["_delimeter"];
    if (val.isint())
        m_delimeter = static_cast<char>(val.integer());
    val = in.first().first();
    while (val.name() && val.string()) {
        m_values.push_back(make_pair(string(val.name()), string(val.string())));
        val = in.first().next();
    }
}

ScopedAttribute::~ScopedAttribute()
{
}

vector< pair<string,string> >& ScopedAttribute::getValues()
{
    return m_values;
}

const vector< pair<string,string> >& ScopedAttribute::getValues() const
{
    return m_values;
}

size_t ScopedAttribute::valueCount() const
{
    return m_values.size();
}

void ScopedAttribute::clearSerializedValues()
{
    m_serialized.clear();
}

const char* ScopedAttribute::getString(size_t index) const
{
    return m_values[index].first.c_str();
}

const char* ScopedAttribute::getScope(size_t index) const
{
    return m_values[index].second.c_str();
}

void ScopedAttribute::removeValue(size_t index)
{
    Attribute::removeValue(index);
    if (index < m_values.size())
        m_values.erase(m_values.begin() + index);
}

const vector<string>& ScopedAttribute::getSerializedValues() const
{
    if (m_serialized.empty()) {
        for (vector< pair<string,string> >::const_iterator i=m_values.begin(); i!=m_values.end(); ++i)
            m_serialized.push_back(i->first + m_delimeter + i->second);
    }
    return Attribute::getSerializedValues();
}

DDF ScopedAttribute::marshall() const
{
    DDF ddf = Attribute::marshall();
    ddf.name("Scoped");
    if (m_delimeter != '@')
        ddf.addmember("_delimeter").integer(m_delimeter);
    DDF vlist = ddf.first();
    for (vector< pair<string,string> >::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
        DDF val = DDF(i->first.c_str()).string(i->second.c_str());
        vlist.add(val);
    }
    return ddf;
}

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
 * SimpleAttribute.cpp
 *
 * An Attribute whose values are simple strings.
 */

#include "internal.h"
#include "attribute/SimpleAttribute.h"

using namespace shibsp;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL Attribute* SimpleAttributeFactory(DDF& in) {
        return new SimpleAttribute(in);
    }
};

SimpleAttribute::SimpleAttribute(const vector<string>& ids) : Attribute(ids)
{
}

SimpleAttribute::SimpleAttribute(DDF& in) : Attribute(in)
{
    DDF val = in.first().first();
    while (val.string()) {
        m_serialized.push_back(val.string());
        val = in.first().next();
    }
}

SimpleAttribute::~SimpleAttribute()
{
}

vector<string>& SimpleAttribute::getValues()
{
    return m_serialized;
}

void SimpleAttribute::clearSerializedValues()
{
    // Do nothing, since our values are already serialized.
}

DDF SimpleAttribute::marshall() const
{
    DDF ddf = Attribute::marshall();
    DDF vlist = ddf.first();
    for (vector<string>::const_iterator i=m_serialized.begin(); i!=m_serialized.end(); ++i)
        vlist.add(DDF(NULL).string(i->c_str()));
    return ddf;
}

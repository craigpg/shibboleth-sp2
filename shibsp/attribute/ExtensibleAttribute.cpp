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
 * shibsp/attribute/ExtensibleAttribute.cpp
 *
 * An Attribute whose values are arbitrary structures.
 */

#include "internal.h"
#include "SPConfig.h"
#include "attribute/ExtensibleAttribute.h"
#include "util/SPConstants.h"

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL Attribute* ExtensibleAttributeFactory(DDF& in) {
        return new ExtensibleAttribute(in);
    }
};

ExtensibleAttribute::ExtensibleAttribute(const vector<string>& ids, const char* formatter) : Attribute(ids)
{
    m_obj = Attribute::marshall();
    m_obj.name("Extensible");
    m_obj.addmember("_formatter").string(formatter);
}

ExtensibleAttribute::ExtensibleAttribute(DDF& in) : Attribute(in), m_obj(in.copy())
{
}

ExtensibleAttribute::~ExtensibleAttribute()
{
    m_obj.destroy();
}

DDF ExtensibleAttribute::getValues()
{
    return m_obj.first();
}

size_t ExtensibleAttribute::valueCount() const
{
    return m_obj.first().integer();
}

void ExtensibleAttribute::clearSerializedValues()
{
    m_serialized.clear();
}

const char* ExtensibleAttribute::getString(size_t index) const
{
    return m_obj.first()[static_cast<unsigned long>(index)].string();
}

const char* ExtensibleAttribute::getScope(size_t index) const
{
    return NULL;
}

void ExtensibleAttribute::removeValue(size_t index)
{
    Attribute::removeValue(index);
    DDF vals = m_obj.first();
    if (index < static_cast<size_t>(vals.integer()))
        vals[static_cast<unsigned long>(index)].remove().destroy();
}

const vector<string>& ExtensibleAttribute::getSerializedValues() const
{
    if (m_serialized.empty()) {
        const char* formatter = m_obj["_formatter"].string();
        if (formatter) {
            string msg = formatter;
            DDF val = m_obj.first().first();
            while (!val.isnull()) {

                static const char* legal="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890_.[]";

                m_serialized.push_back(string());
                string& processed = m_serialized.back();

                string::size_type i=0,start=0;
                while (start!=string::npos && start<msg.length() && (i=msg.find("$",start))!=string::npos) {
                    if (i>start)
                        processed += msg.substr(start,i-start); // append everything in between
                    start=i+1;                                  // move start to the beginning of the token name
                    i=msg.find_first_not_of(legal,start);       // find token delimiter
                    if (i==start) {                             // append a non legal character
                       processed+=msg[start++];
                       continue;
                    }
                    
                    string tag = msg.substr(start,(i==string::npos) ? i : i-start);
                    if (tag == "_string" && val.string()) {
                        processed += val.string();
                        start=i;
                    }
                    else {
                        DDF child = val.getmember(tag.c_str());
                        if (child.string())
                            processed += child.string();
                        else if (child.isstruct() && child["_string"].string())
                            processed += child["_string"].string();
                        start=i;
                    }
                }
                if (start!=string::npos && start<msg.length())
                    processed += msg.substr(start,i);    // append rest of string

                val = m_obj.first().next();
            }
        }
    }
    return Attribute::getSerializedValues();
}

DDF ExtensibleAttribute::marshall() const
{
    if (!isCaseSensitive())
        m_obj.addmember("case_insensitive");
    if (isInternal())
        m_obj.addmember("internal");
    return m_obj.copy();
}

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
 * TemplateParameters.cpp
 * 
 * Supplies xmltooling TemplateEngine with additional parameters from a PropertySet. 
 */

#include "internal.h"
#include "util/PropertySet.h"
#include "util/TemplateParameters.h"

#include <ctime>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

TemplateParameters::TemplateParameters(const exception* e, const PropertySet* props)
    : m_exception(e), m_toolingException(dynamic_cast<const XMLToolingException*>(e))
{
    setPropertySet(props);
}

TemplateParameters::~TemplateParameters()
{
}

void TemplateParameters::setPropertySet(const PropertySet* props)
{
    m_props = props;

    // Create a timestamp.
    time_t now = time(NULL);
#if defined(HAVE_CTIME_R_2)
    char timebuf[32];
    m_map["now"] = ctime_r(&now,timebuf);
#elif defined(HAVE_CTIME_R_3)
    char timebuf[32];
    m_map["now"] = ctime_r(&now,timebuf,sizeof(timebuf));
#else
    m_map["now"] = ctime(&now);
#endif
}

const XMLToolingException* TemplateParameters::getRichException() const
{
    return m_toolingException;
}

const char* TemplateParameters::getParameter(const char* name) const
{
    if (m_exception) {
        if (!strcmp(name, "errorType"))
            return m_toolingException ? m_toolingException->getClassName() : "std::exception";
        else if (!strcmp(name, "errorText"))
            return m_exception->what();
    }

    const char* pch = TemplateEngine::TemplateParameters::getParameter(name);
    if (pch || !m_props)
        return pch;
    pair<bool,const char*> p = m_props->getString(name);
    return p.first ? p.second : NULL;
}

string TemplateParameters::toQueryString() const
{
    // Capture local stuff.
    string q;

    const URLEncoder* enc = XMLToolingConfig::getConfig().getURLEncoder();
    for (map<string,string>::const_iterator i=m_map.begin(); i!=m_map.end(); i++)
        q = q + '&' + i->first + '=' + enc->encode(i->second.c_str());

    // Add in the exception content.
    if (m_exception) {
        q = q + "&errorType=" + enc->encode(getParameter("errorType")) + "&errorText=" + enc->encode(getParameter("errorText"));
        if (m_toolingException)
            q = q + '&' + m_toolingException->toQueryString();
    }

    q.erase(0,1);
    return q;
}

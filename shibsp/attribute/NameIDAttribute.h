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
 * @file shibsp/attribute/NameIDAttribute.h
 * 
 * An Attribute whose values are derived from or mappable to a SAML NameID.
 */

#ifndef __shibsp_nameidattr_h__
#define __shibsp_nameidattr_h__

#include <shibsp/attribute/Attribute.h>
#include <xmltooling/exceptions.h>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /** Default serialization format for NameIDs */
    #define DEFAULT_NAMEID_FORMATTER    "$Name!!$NameQualifier!!$SPNameQualifier"

    /**
     * An Attribute whose values are derived from or mappable to a SAML NameID.
     */
    class SHIBSP_API NameIDAttribute : public Attribute
    {
    public:
        /**
         * Constructor.
         * 
         * @param ids       array with primary identifier in first position, followed by any aliases
         * @param formatter template for serialization of tuple
         */
        NameIDAttribute(const std::vector<std::string>& ids, const char* formatter=DEFAULT_NAMEID_FORMATTER)
            : Attribute(ids), m_formatter(formatter) {
        }

        /**
         * Constructs based on a remoted NameIDAttribute.
         * 
         * @param in    input object containing marshalled NameIDAttribute
         */
        NameIDAttribute(DDF& in) : Attribute(in) {
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
        
        virtual ~NameIDAttribute() {}
        
        /**
         * Holds all the fields associated with a NameID.
         */
        struct SHIBSP_API Value
        {
            std::string m_Name;
            std::string m_Format;
            std::string m_NameQualifier;
            std::string m_SPNameQualifier;
            std::string m_SPProvidedID;
        };
        
        /**
         * Returns the set of values encoded as UTF-8 strings.
         * 
         * @return  a mutable vector of the values
         */
        std::vector<Value>& getValues() {
            return m_values;
        }

        /**
         * Returns the set of values encoded as UTF-8 strings.
         * 
         * @return  an immutable vector of the values
         */
        const std::vector<Value>& getValues() const {
            return m_values;
        }

        size_t valueCount() const {
            return m_values.size();
        }
        
        void clearSerializedValues() {
            m_serialized.clear();
        }

        const char* getString(size_t index) const {
            return m_values[index].m_Name.c_str();
        }

        const char* getScope(size_t index) const {
            return m_values[index].m_NameQualifier.c_str();
        }

        void removeValue(size_t index) {
            Attribute::removeValue(index);
            if (index < m_values.size())
                m_values.erase(m_values.begin() + index);
        }

        const std::vector<std::string>& getSerializedValues() const {
            if (m_serialized.empty()) {
                for (std::vector<Value>::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
                    // This is kind of a hack, but it's a good way to reuse some code.
                    xmltooling::XMLToolingException e(
                        m_formatter,
                        xmltooling::namedparams(
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
    
        DDF marshall() const {
            DDF ddf = Attribute::marshall();
            ddf.name("NameID");
            ddf.addmember("_formatter").string(m_formatter.c_str());
            DDF vlist = ddf.first();
            for (std::vector<Value>::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
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
    
    private:
        std::vector<Value> m_values;
        std::string m_formatter;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_nameidattr_h__ */

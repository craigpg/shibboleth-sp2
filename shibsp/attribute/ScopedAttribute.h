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
 * @file shibsp/attribute/ScopedAttribute.h
 * 
 * An Attribute whose values are relations of a value and a scope.
 */

#ifndef __shibsp_scopedattr_h__
#define __shibsp_scopedattr_h__

#include <shibsp/attribute/Attribute.h>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * An Attribute whose values are relations of a value and a scope.
     * 
     * <p>In practice, scoped attributes are simple pairs of strings instead
     * of a single string. They can be expressed as a string easily using a delimeter,
     * typically an '@' symbol. The scope concept allows certain kinds of filtering to
     * be performed more intelligently and efficiently, although not all scoped
     * attributes can be effectively filtered (e.g. if the set of scope values is
     * unconstrained).
     */
    class SHIBSP_API ScopedAttribute : public Attribute
    {
    public:
        /**
         * Constructor.
         * 
         * @param ids   array with primary identifier in first position, followed by any aliases
         * @param delimeter value/scope delimeter when serializing
         */
        ScopedAttribute(const std::vector<std::string>& ids, char delimeter='@')
            : Attribute(ids), m_delimeter(delimeter) {
        }

        /**
         * Constructs based on a remoted ScopedAttribute.
         * 
         * @param in    input object containing marshalled ScopedAttribute
         */
        ScopedAttribute(DDF& in) : Attribute(in), m_delimeter('@') {
            DDF val = in["_delimeter"];
            if (val.isint())
                m_delimeter = static_cast<char>(val.integer());
            val = in.first().first();
            while (val.name() && val.string()) {
                m_values.push_back(std::make_pair(std::string(val.name()), std::string(val.string())));
                val = in.first().next();
            }
        }
        
        virtual ~ScopedAttribute() {}

        /**
         * Returns the set of values encoded as UTF-8 strings.
         * 
         * <p>Each compound value is a pair containing the simple value and the scope. 
         * 
         * @return  a mutable vector of the values
         */
        std::vector< std::pair<std::string,std::string> >& getValues() {
            return m_values;
        }

        size_t valueCount() const {
            return m_values.size();
        }
        
        void clearSerializedValues() {
            m_serialized.clear();
        }
        
        const char* getString(size_t index) const {
            return m_values[index].first.c_str();
        }

        const char* getScope(size_t index) const {
            return m_values[index].second.c_str();
        }

        void removeValue(size_t index) {
            Attribute::removeValue(index);
            if (index < m_values.size())
                m_values.erase(m_values.begin() + index);
        }

        const std::vector<std::string>& getSerializedValues() const {
            if (m_serialized.empty()) {
                for (std::vector< std::pair<std::string,std::string> >::const_iterator i=m_values.begin(); i!=m_values.end(); ++i)
                    m_serialized.push_back(i->first + m_delimeter + i->second);
            }
            return Attribute::getSerializedValues();
        }

        DDF marshall() const {
            DDF ddf = Attribute::marshall();
            ddf.name("Scoped");
            if (m_delimeter != '@')
                ddf.addmember("_delimeter").integer(m_delimeter);
            DDF vlist = ddf.first();
            for (std::vector< std::pair<std::string,std::string> >::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
                DDF val = DDF(i->first.c_str()).string(i->second.c_str());
                vlist.add(val);
            }
            return ddf;
        }
    
    private:
        char m_delimeter;
        std::vector< std::pair<std::string,std::string> > m_values;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_scopedattr_h__ */

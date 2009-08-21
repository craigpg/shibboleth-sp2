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
 * @file shibsp/attribute/Attribute.h
 *
 * A resolved attribute.
 */

#ifndef __shibsp_attribute_h__
#define __shibsp_attribute_h__

#include <shibsp/exceptions.h>
#include <shibsp/remoting/ddf.h>

#include <map>
#include <string>
#include <vector>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * A resolved attribute.
     *
     * <p>Resolved attributes are a neutral construct that represent both simple and
     * complex attribute data structures that might be found in SAML assertions
     * or obtained from other sources.
     *
     * <p>Attributes consist of an id/name that is locally unique (that is, unique to a
     * configuration at any given point in time) and zero or more values. Values can
     * be of any type or structure, but will generally be made available to applications
     * only if a serialized string form exists. More complex values can be used with
     * access control plugins and other components that understand them, however.
     */
    class SHIBSP_API Attribute
    {
        MAKE_NONCOPYABLE(Attribute);
    protected:
        /**
         * Constructor
         *
         * @param ids   array with primary identifier in first position, followed by any aliases
         */
        Attribute(const std::vector<std::string>& ids) : m_id(ids), m_caseSensitive(true), m_internal(false) {
        }

        /**
         * Constructs based on a remoted Attribute.
         *
         * <p>This allows Attribute objects to be recreated after marshalling.
         * The DDF supplied must be a struct containing a single list member named
         * with the Attribute's "id" and containing the values.
         *
         * @param in    input object containing marshalled Attribute
         */
        Attribute(DDF& in);

        /**
         * Maintains a copy of serialized attribute values, when possible.
         *
         * <p>Implementations should maintain the array when values are added or removed.
         */
        mutable std::vector<std::string> m_serialized;

    public:
        virtual ~Attribute() {}

        /**
         * Returns the Attribute identifier.
         *
         * @return the Attribute identifier
         */
        const char* getId() const {
            return m_id.front().c_str();
        }

        /**
         * Returns all of the effective names for the Attribute.
         *
         * @return immutable array of identifiers, with the primary ID in the first position
         */
        const std::vector<std::string>& getAliases() const {
            return m_id;
        }

        /**
         * Returns all of the effective names for the Attribute.
         *
         * @return mutable array of identifiers, with the primary ID in the first position
         */
        std::vector<std::string>& getAliases() {
            return m_id;
        }

        /**
         * Sets whether case sensitivity should apply to basic value comparisons.
         *
         * @param caseSensitive  true iff value comparisons should be case sensitive
         */
        void setCaseSensitive(bool caseSensitive) {
            m_caseSensitive = caseSensitive;
        }

        /**
         * Sets whether the attribute should be exported for CGI use.
         *
         * @param export  true iff the attribute should <strong>NOT</strong> be exported
         */
        void setInternal(bool internal) {
            m_internal = internal;
        }

        /**
         * Indicates whether case sensitivity should apply to basic value comparisons.
         *
         * @return  true iff value comparisons should be case sensitive
         */
        bool isCaseSensitive() const {
            return m_caseSensitive;
        }

        /**
         * Indicates whether the attribute should be exported for CGI use.
         *
         * @return  true iff the attribute should <strong>NOT</strong> be exported
         */
        bool isInternal() const {
            return m_internal;
        }

        /**
         * Returns the number of values.
         *
         * @return  number of values
         */
        virtual size_t valueCount() const {
            return m_serialized.size();
        }

        /**
         * Returns serialized Attribute values encoded as UTF-8 strings.
         *
         * @return  an immutable vector of values
         */
        virtual const std::vector<std::string>& getSerializedValues() const {
            return m_serialized;
        }

        /**
         * Informs the Attribute that values have changed and any serializations
         * must be cleared.
         */
        virtual void clearSerializedValues()=0;

        /**
         * Gets the string equivalent of the value at the specified position (starting from zero).
         *
         * @param index position of value
         * @return the specified value in its "string" form, or NULL if undefined
         */
        virtual const char* getString(size_t index) const {
            return m_serialized[index].c_str();
        }

        /**
         * Gets the "scope" of the value at the specified position (starting from zero).
         *
         * @param index position of value
         * @return the specified value's "scope", or NULL if attribute is unscoped
         */
        virtual const char* getScope(size_t index) const {
            return NULL;
        }

        /**
         * Removes the value at the specified position (starting from zero).
         *
         * @param index position of value to remove
         */
        virtual void removeValue(size_t index) {
            if (index < m_serialized.size())
                m_serialized.erase(m_serialized.begin() + index);
        }

        /**
         * Marshalls an Attribute for remoting.
         *
         * <p>This allows Attribute objects to be communicated across process boundaries
         * without excess XML parsing. The DDF returned must be a struct containing
         * a single list member named with the Attribute's "id". The name of the struct
         * should contain the registered name of the Attribute implementation.
         */
        virtual DDF marshall() const;

        /**
         * Unmarshalls a remoted Attribute.
         *
         * @param in    remoted Attribute data
         * @return  a resolved Attribute of the proper subclass
         */
        static Attribute* unmarshall(DDF& in);

        /** A function that unmarshalls remoted data into the proper Attribute subclass. */
        typedef Attribute* AttributeFactory(DDF& in);

        /**
         * Registers an AttributeFactory function for a given attribute "type".
         *
         * @param type      string used at the root of remoted Attribute structures
         * @param factory   factory function
         */
        static void registerFactory(const char* type, AttributeFactory* factory) {
            m_factoryMap[type] = factory;
        }

        /**
         * Deregisters an AttributeFactory function for a given attribute "type".
         *
         * @param type      string used at the root of remoted Attribute structures
         */
        static void deregisterFactory(const char* type) {
            m_factoryMap.erase(type);
        }

        /**
         * Clears the map of factories.
         */
        static void deregisterFactories() {
            m_factoryMap.clear();
        }

    private:
        static std::map<std::string,AttributeFactory*> m_factoryMap;
        std::vector<std::string> m_id;
        bool m_caseSensitive,m_internal;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    /** Registers built-in Attribute types into the runtime. */
    void registerAttributeFactories();

};

#endif /* __shibsp_attribute_h__ */

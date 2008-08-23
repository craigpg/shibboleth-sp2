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
 * @file shibsp/attribute/AttributeDecoder.h
 *
 * Decodes SAML NameID/Attribute objects into resolved Attributes.
 */

#ifndef __shibsp_attrdecoder_h__
#define __shibsp_attrdecoder_h__

#include <shibsp/attribute/Attribute.h>
#include <xmltooling/XMLObject.h>

namespace shibsp {

    /**
     * Decodes XML objects into resolved Attributes.
     */
    class SHIBSP_API AttributeDecoder
    {
        MAKE_NONCOPYABLE(AttributeDecoder);
    protected:
        /**
         * Constructor.
         *
         * @param e root of DOM to configure the decoder
         */
        AttributeDecoder(const xercesc::DOMElement* e);

        /** Flag for case sensitivity of decoded attributes. */
        bool m_caseSensitive;

    public:
        virtual ~AttributeDecoder() {}

        /**
         * Decodes an XMLObject into a resolved Attribute.
         *
         * @param ids               array containing primary identifier in first position, followed by any aliases
         * @param xmlObject         XMLObject to decode
         * @param assertingParty    name of the party asserting the attribute
         * @param relyingParty      name of the party relying on the attribute
         * @return a resolved Attribute, or NULL
         */
        virtual Attribute* decode(
            const std::vector<std::string>& ids,
            const xmltooling::XMLObject* xmlObject,
            const char* assertingParty=NULL,
            const char* relyingParty=NULL
            ) const=0;
    };


    /** Decodes into a SimpleAttribute. */
    extern SHIBSP_API xmltooling::QName StringAttributeDecoderType;

    /** Decodes scoped and NameID attributes into a ScopedAttribute. */
    extern SHIBSP_API xmltooling::QName ScopedAttributeDecoderType;

    /** Decodes NameID information into a NameIDAttribute. */
    extern SHIBSP_API xmltooling::QName NameIDAttributeDecoderType;

    /** Decodes scoped attributes into a NameIDAttribute. */
    extern SHIBSP_API xmltooling::QName NameIDFromScopedAttributeDecoderType;

    /** Registers built-in AttributeDecoders into the runtime. */
    void registerAttributeDecoders();
};

#endif /* __shibsp_attrdecoder_h__ */

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
 * MetadataExtImpl.cpp
 * 
 * Implementation classes for Shibboleth metadata extensions schema
 */

#include "internal.h"
#include "exceptions.h"
#include "metadata/MetadataExt.h"

#include <xmltooling/AbstractComplexElement.h>
#include <xmltooling/AbstractSimpleElement.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/io/AbstractXMLObjectMarshaller.h>
#include <xmltooling/io/AbstractXMLObjectUnmarshaller.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

using xmlconstants::XMLSIG_NS;
using xmlconstants::XML_BOOL_NULL;
using shibspconstants::SHIBMD_NS;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace shibsp {

    class SHIBSP_DLLLOCAL ScopeImpl : public virtual Scope,
        public AbstractSimpleElement,
        public AbstractDOMCachingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
        void init() {
            m_Regexp=XML_BOOL_NULL;
        }

    public:

        ScopeImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            init();
        }
            
        ScopeImpl(const ScopeImpl& src)
                : AbstractXMLObject(src), AbstractSimpleElement(src), AbstractDOMCachingXMLObject(src) {
            init();
            Regexp(src.m_Regexp);
        }
        
        IMPL_XMLOBJECT_CLONE(Scope);
        IMPL_BOOLEAN_ATTRIB(Regexp);

    protected:
        void marshallAttributes(DOMElement* domElement) const {
            MARSHALL_BOOLEAN_ATTRIB(Regexp,REGEXP,NULL);
        }

        void processAttribute(const DOMAttr* attribute) {
            PROC_BOOLEAN_ATTRIB(Regexp,REGEXP,NULL);
            AbstractXMLObjectUnmarshaller::processAttribute(attribute);
        }
    };

    class SHIBSP_DLLLOCAL KeyAuthorityImpl : public virtual KeyAuthority,
            public AbstractComplexElement,
            public AbstractAttributeExtensibleXMLObject,
            public AbstractDOMCachingXMLObject,
            public AbstractXMLObjectMarshaller,
            public AbstractXMLObjectUnmarshaller
    {
        void init() {
            m_VerifyDepth=NULL;
        }
    public:
        virtual ~KeyAuthorityImpl() {
            XMLString::release(&m_VerifyDepth);
        }

        KeyAuthorityImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            init();
        }
            
        KeyAuthorityImpl(const KeyAuthorityImpl& src)
                : AbstractXMLObject(src), AbstractComplexElement(src),
                    AbstractAttributeExtensibleXMLObject(src), AbstractDOMCachingXMLObject(src) {
            init();
            setVerifyDepth(src.m_VerifyDepth);
            VectorOf(KeyInfo) v=getKeyInfos();
            for (vector<KeyInfo*>::const_iterator i=src.m_KeyInfos.begin(); i!=src.m_KeyInfos.end(); ++i)
                v.push_back((*i)->cloneKeyInfo());
        }
        
        IMPL_XMLOBJECT_CLONE(KeyAuthority);
        IMPL_INTEGER_ATTRIB(VerifyDepth);
        IMPL_TYPED_CHILDREN(KeyInfo,m_children.end());
        
    public:
        void setAttribute(const xmltooling::QName& qualifiedName, const XMLCh* value, bool ID=false) {
            if (!qualifiedName.hasNamespaceURI()) {
                if (XMLString::equals(qualifiedName.getLocalPart(),VERIFYDEPTH_ATTRIB_NAME)) {
                    setVerifyDepth(value);
                    return;
                }
            }
            AbstractAttributeExtensibleXMLObject::setAttribute(qualifiedName, value, ID);
        }

    protected:
        void marshallAttributes(DOMElement* domElement) const {
            MARSHALL_INTEGER_ATTRIB(VerifyDepth,VERIFYDEPTH,NULL);
            marshallExtensionAttributes(domElement);
        }

        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_TYPED_CHILDREN(KeyInfo,XMLSIG_NS,false);
            AbstractXMLObjectUnmarshaller::processChildElement(childXMLObject,root);
        }

        void processAttribute(const DOMAttr* attribute) {
            unmarshallExtensionAttribute(attribute);
        }
    };

};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

// Builder Implementations

IMPL_XMLOBJECTBUILDER(Scope);
IMPL_XMLOBJECTBUILDER(KeyAuthority);

const XMLCh Scope::LOCAL_NAME[] =                       UNICODE_LITERAL_5(S,c,o,p,e);
const XMLCh Scope::REGEXP_ATTRIB_NAME[] =               UNICODE_LITERAL_6(r,e,g,e,x,p);
const XMLCh KeyAuthority::LOCAL_NAME[] =                UNICODE_LITERAL_12(K,e,y,A,u,t,h,o,r,i,t,y);
const XMLCh KeyAuthority::VERIFYDEPTH_ATTRIB_NAME[] =   UNICODE_LITERAL_11(V,e,r,i,f,y,D,e,p,t,h);

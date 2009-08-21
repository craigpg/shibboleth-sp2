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
 * MatchFunctor.cpp
 * 
 * A function that evaluates whether an expressed criteria is met by the current filter context.
 */

#include "internal.h"
#include "attribute/filtering/MatchFunctor.h"
#include "util/SPConstants.h"

#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

#define DECL_FACTORY(name) \
    SHIBSP_DLLLOCAL PluginManager< MatchFunctor,xmltooling::QName,pair<const FilterPolicyContext*,const DOMElement*> >::Factory name##Factory

#define DECL_BASIC_QNAME(name,lit) \
    xmltooling::QName shibsp::name##Type(shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, lit)

#define DECL_SAML_QNAME(name,lit) \
    xmltooling::QName shibsp::name##Type(shibspconstants::SHIB2ATTRIBUTEFILTER_MF_SAML_NS, lit)

#define REGISTER_FACTORY(name) \
    mgr.registerFactory(name##Type, name##Factory)

namespace shibsp {
    DECL_FACTORY(AnyMatchFunctor);
    DECL_FACTORY(AndMatchFunctor);
    DECL_FACTORY(OrMatchFunctor);
    DECL_FACTORY(NotMatchFunctor);
    DECL_FACTORY(AttributeIssuerString);
    DECL_FACTORY(AttributeRequesterString);
    DECL_FACTORY(AuthenticationMethodString);
    DECL_FACTORY(AttributeValueString);
    DECL_FACTORY(AttributeScopeString);
    DECL_FACTORY(AttributeIssuerRegex);
    DECL_FACTORY(AttributeRequesterRegex);
    DECL_FACTORY(AuthenticationMethodRegex);
    DECL_FACTORY(AttributeValueRegex);
    DECL_FACTORY(AttributeScopeRegex);
    DECL_FACTORY(NumberOfAttributeValues);
    DECL_FACTORY(AttributeIssuerInEntityGroup);
    DECL_FACTORY(AttributeRequesterInEntityGroup);
    DECL_FACTORY(AttributeScopeMatchesShibMDScope);


    static const XMLCh ANY[] =                          UNICODE_LITERAL_3(A,N,Y);
    static const XMLCh AND[] =                          UNICODE_LITERAL_3(A,N,D);
    static const XMLCh OR[] =                           UNICODE_LITERAL_2(O,R);
    static const XMLCh NOT[] =                          UNICODE_LITERAL_3(N,O,T);
    static const XMLCh AttributeIssuerString[] =        UNICODE_LITERAL_21(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,S,t,r,i,n,g);
    static const XMLCh AttributeRequesterString[] =     UNICODE_LITERAL_24(A,t,t,r,i,b,u,t,e,R,e,q,u,e,s,t,e,r,S,t,r,i,n,g);
    static const XMLCh AuthenticationMethodString[] =   UNICODE_LITERAL_26(A,u,t,h,e,n,t,i,c,a,t,i,o,n,M,e,t,h,o,d,S,t,r,i,n,g);
    static const XMLCh AttributeValueString[] =         UNICODE_LITERAL_20(A,t,t,r,i,b,u,t,e,V,a,l,u,e,S,t,r,i,n,g);
    static const XMLCh AttributeScopeString[] =         UNICODE_LITERAL_20(A,t,t,r,i,b,u,t,e,S,c,o,p,e,S,t,r,i,n,g);
    static const XMLCh AttributeIssuerRegex[] =         UNICODE_LITERAL_20(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,R,e,g,e,x);
    static const XMLCh AttributeRequesterRegex[] =      UNICODE_LITERAL_23(A,t,t,r,i,b,u,t,e,R,e,q,u,e,s,t,e,r,R,e,g,e,x);
    static const XMLCh AuthenticationMethodRegex[] =    UNICODE_LITERAL_25(A,u,t,h,e,n,t,i,c,a,t,i,o,n,M,e,t,h,o,d,R,e,g,e,x);
    static const XMLCh AttributeValueRegex[] =          UNICODE_LITERAL_19(A,t,t,r,i,b,u,t,e,V,a,l,u,e,R,e,g,e,x);
    static const XMLCh AttributeScopeRegex[] =          UNICODE_LITERAL_19(A,t,t,r,i,b,u,t,e,S,c,o,p,e,R,e,g,e,x);
    static const XMLCh NumberOfAttributeValues[] =      UNICODE_LITERAL_23(N,u,m,b,e,r,O,f,A,t,t,r,i,b,u,t,e,V,a,l,u,e,s);
    static const XMLCh AttributeIssuerInEntityGroup[] = UNICODE_LITERAL_28(A,t,t,r,i,b,u,t,e,I,s,s,u,e,r,I,n,E,n,t,i,t,y,G,r,o,u,p);
    static const XMLCh AttributeRequesterInEntityGroup[] = UNICODE_LITERAL_31(A,t,t,r,i,b,u,t,e,R,e,q,u,e,s,t,e,r,I,n,E,n,t,i,t,y,G,r,o,u,p);
    static const XMLCh AttributeScopeMatchesShibMDScope[] = UNICODE_LITERAL_32(A,t,t,r,i,b,u,t,e,S,c,o,p,e,M,a,t,c,h,e,s,S,h,i,b,M,D,S,c,o,p,e);
};

DECL_BASIC_QNAME(AnyMatchFunctor, ANY);
DECL_BASIC_QNAME(AndMatchFunctor, AND);
DECL_BASIC_QNAME(OrMatchFunctor, OR);
DECL_BASIC_QNAME(NotMatchFunctor, NOT);
DECL_BASIC_QNAME(AttributeIssuerString, AttributeIssuerString);
DECL_BASIC_QNAME(AttributeRequesterString, AttributeRequesterString);
DECL_BASIC_QNAME(AuthenticationMethodString, AuthenticationMethodString);
DECL_BASIC_QNAME(AttributeValueString, AttributeValueString);
DECL_BASIC_QNAME(AttributeScopeString, AttributeScopeString);
DECL_BASIC_QNAME(AttributeIssuerRegex, AttributeIssuerRegex);
DECL_BASIC_QNAME(AttributeRequesterRegex, AttributeRequesterRegex);
DECL_BASIC_QNAME(AuthenticationMethodRegex, AuthenticationMethodRegex);
DECL_BASIC_QNAME(AttributeValueRegex, AttributeValueRegex);
DECL_BASIC_QNAME(AttributeScopeRegex, AttributeScopeRegex);
DECL_BASIC_QNAME(NumberOfAttributeValues, NumberOfAttributeValues);
DECL_SAML_QNAME(AttributeIssuerInEntityGroup, AttributeIssuerInEntityGroup);
DECL_SAML_QNAME(AttributeRequesterInEntityGroup, AttributeRequesterInEntityGroup);
DECL_SAML_QNAME(AttributeScopeMatchesShibMDScope, AttributeScopeMatchesShibMDScope);

void SHIBSP_API shibsp::registerMatchFunctors()
{
    PluginManager< MatchFunctor,xmltooling::QName,pair<const FilterPolicyContext*,const DOMElement*> >& mgr =
        SPConfig::getConfig().MatchFunctorManager;
    REGISTER_FACTORY(AnyMatchFunctor);
    REGISTER_FACTORY(AndMatchFunctor);
    REGISTER_FACTORY(OrMatchFunctor);
    REGISTER_FACTORY(NotMatchFunctor);
    REGISTER_FACTORY(AttributeIssuerString);
    REGISTER_FACTORY(AttributeRequesterString);
    REGISTER_FACTORY(AuthenticationMethodString);
    REGISTER_FACTORY(AttributeValueString);
    REGISTER_FACTORY(AttributeScopeString);
    REGISTER_FACTORY(AttributeIssuerRegex);
    REGISTER_FACTORY(AttributeRequesterRegex);
    REGISTER_FACTORY(AuthenticationMethodRegex);
    REGISTER_FACTORY(AttributeValueRegex);
    REGISTER_FACTORY(AttributeScopeRegex);
    REGISTER_FACTORY(NumberOfAttributeValues);
    REGISTER_FACTORY(AttributeIssuerInEntityGroup);
    REGISTER_FACTORY(AttributeRequesterInEntityGroup);
    REGISTER_FACTORY(AttributeScopeMatchesShibMDScope);
}

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
 * @file shibsp/attribute/filtering/MatchFunctor.h
 * 
 * A function that evaluates whether an expressed criteria is met by the current filter context.
 */

#ifndef __shibsp_matchfunc_h__
#define __shibsp_matchfunc_h__

#include <shibsp/base.h>

namespace shibsp {

    class SHIBSP_API Attribute;
    class SHIBSP_API FilteringContext;

    /**
     * A function that evaluates whether an expressed criteria is met by the current filter context.
     */
    class SHIBSP_API MatchFunctor
    {
        MAKE_NONCOPYABLE(MatchFunctor);
    protected:
        MatchFunctor();
    public:
        virtual ~MatchFunctor();

        /**
         * Evaluates this matching criteria. This evaluation is used when a filtering engine determines policy
         * applicability.
         * 
         * @param filterContext current filtering context
         * @return true if the criteria for this matching function are met
         * @throws AttributeFilteringException thrown if the function can not be evaluated
         */
        virtual bool evaluatePolicyRequirement(const FilteringContext& filterContext) const=0;

        /**
         * Evaluates this matching criteria. This evaluation is used when a filtering engine is filtering attribute
         * values.
         * 
         * @param filterContext the current filtering context
         * @param attribute     the attribute being evaluated
         * @param index         the index of the attribute value being evaluated
         * @return true if the criteria for this matching function are met
         * @throws AttributeFilteringException thrown if the function can not be evaluated
         */
        virtual bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const=0;
    };

    /** Always evaluates to true. */
    extern SHIBSP_API xmltooling::QName AnyMatchFunctorType;

    /** Conjunction MatchFunctor. */
    extern SHIBSP_API xmltooling::QName AndMatchFunctorType;

    /** Disjunction MatchFunctor. */
    extern SHIBSP_API xmltooling::QName OrMatchFunctorType;

    /** Negating MatchFunctor. */
    extern SHIBSP_API xmltooling::QName NotMatchFunctorType;

    /** Matches the issuing entity's name. */
    extern SHIBSP_API xmltooling::QName AttributeIssuerStringType;

    /** Matches the requesting entity's name. */
    extern SHIBSP_API xmltooling::QName AttributeRequesterStringType;

    /** Matches the principal's authentication method/class or context reference. */
    extern SHIBSP_API xmltooling::QName AuthenticationMethodStringType;

    /** Matches an attribute's string value. */
    extern SHIBSP_API xmltooling::QName AttributeValueStringType;

    /** Matches an attribute's "scope". */
    extern SHIBSP_API xmltooling::QName AttributeScopeStringType;

    /** Matches the issuing entity's name. */
    extern SHIBSP_API xmltooling::QName AttributeIssuerRegexType;

    /** Matches the requesting entity's name. */
    extern SHIBSP_API xmltooling::QName AttributeRequesterRegexType;

    /** Matches the principal's authentication method/class or context reference. */
    extern SHIBSP_API xmltooling::QName AuthenticationMethodRegexType;

    /** Matches an attribute's string value. */
    extern SHIBSP_API xmltooling::QName AttributeValueRegexType;

    /** Matches an attribute's "scope". */
    extern SHIBSP_API xmltooling::QName AttributeScopeRegexType;

    /** Matches based on the number of values. */
    extern SHIBSP_API xmltooling::QName NumberOfAttributeValuesType;

    /** Matches based on metadata groups of issuer. */
    extern SHIBSP_API xmltooling::QName AttributeIssuerInEntityGroupType;

    /** Matches based on metadata groups of requester. */
    extern SHIBSP_API xmltooling::QName AttributeRequesterInEntityGroupType;

    /** Matches based on metadata Scope extensions. */
    extern SHIBSP_API xmltooling::QName AttributeScopeMatchesShibMDScopeType;

    /**
     * Registers MatchFunctor classes into the runtime.
     */
    void SHIBSP_API registerMatchFunctors();
};

#endif /* __shibsp_matchfunc_h__ */

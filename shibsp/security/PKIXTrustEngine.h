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
 * @file shibsp/security/PKIXTrustEngine.h
 * 
 * Shibboleth-specific PKIX-validation TrustEngine 
 */

#ifndef __shibsp_pkixtrust_h__
#define __shibsp_pkixtrust_h__

#include <shibsp/base.h>

namespace shibsp {
    /**
     * Registers trust engine plugin.
     */
    void SHIBSP_API registerPKIXTrustEngine();

    /** TrustEngine based on Shibboleth PKIX metadata extension. */
    #define SHIBBOLETH_PKIX_TRUSTENGINE  "PKIX"
};

#endif /* __shibsp_pkixtrust_h__ */

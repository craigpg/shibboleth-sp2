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
 * version.h
 *
 * Library version macros and constants
 */

#ifndef __shibsp_version_h__
#define __shibsp_version_h__

// This is all based on Xerces, on the theory it might be useful to
// support this kind of stuff in the future. If they ever yank some
// of this stuff, it can be copied into here.

#include <xercesc/util/XercesVersion.hpp>

// ---------------------------------------------------------------------------
// V E R S I O N   S P E C I F I C A T I O N

/**
 * MODIFY THESE NUMERIC VALUES TO COINCIDE WITH SHIBSP LIBRARY VERSION
 * AND DO NOT MODIFY ANYTHING ELSE IN THIS VERSION HEADER FILE
 */

#define SHIBSP_VERSION_MAJOR 1
#define SHIBSP_VERSION_MINOR 3
#define SHIBSP_VERSION_REVISION 0

/** DO NOT MODIFY BELOW THIS LINE */

/**
 * MAGIC THAT AUTOMATICALLY GENERATES THE FOLLOWING:
 *
 *	gShibSPVersionStr, gShibSPFullVersionStr, gShibSPMajVersion, gShibSPMinVersion, gShibSPRevision
 */

// ---------------------------------------------------------------------------
// V E R S I O N   I N F O R M A T I O N

// ShibSP version strings; these particular macros cannot be used for
// conditional compilation as they are not numeric constants

#define SHIBSP_FULLVERSIONSTR INVK_CAT3_SEP_UNDERSCORE(SHIBSP_VERSION_MAJOR,SHIBSP_VERSION_MINOR,SHIBSP_VERSION_REVISION)
#define SHIBSP_FULLVERSIONDOT INVK_CAT3_SEP_PERIOD(SHIBSP_VERSION_MAJOR,SHIBSP_VERSION_MINOR,SHIBSP_VERSION_REVISION)
#define SHIBSP_FULLVERSIONNUM INVK_CAT3_SEP_NIL(SHIBSP_VERSION_MAJOR,SHIBSP_VERSION_MINOR,SHIBSP_VERSION_REVISION)
#define SHIBSP_VERSIONSTR     INVK_CAT2_SEP_UNDERSCORE(SHIBSP_VERSION_MAJOR,SHIBSP_VERSION_MINOR)

const char* const    gShibSPVersionStr = SHIBSP_VERSIONSTR;
const char* const    gShibSPFullVersionStr = SHIBSP_FULLVERSIONSTR;
const unsigned int   gShibSPMajVersion = SHIBSP_VERSION_MAJOR;
const unsigned int   gShibSPMinVersion = SHIBSP_VERSION_MINOR;
const unsigned int   gShibSPRevision   = SHIBSP_VERSION_REVISION;

// ShibSP version numeric constants that can be used for conditional
// compilation purposes.

#define _SHIBSP_VERSION CALC_EXPANDED_FORM (SHIBSP_VERSION_MAJOR,SHIBSP_VERSION_MINOR,SHIBSP_VERSION_REVISION)

#endif /* __shibsp_version_h__ */

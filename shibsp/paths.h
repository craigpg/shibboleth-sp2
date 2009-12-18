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
 * @file shibsp/paths.h
 * 
 * Default configuration paths.
 */

#ifndef __shibsp_paths_h__
#define __shibsp_paths_h__

/** Default schema catalogs. */
#define SHIBSP_SCHEMAS "/opt/shibboleth-sp/share/xml/xmltooling/catalog.xml:/usr/share/xml/opensaml/saml20-catalog.xml:/usr/share/xml/opensaml/saml11-catalog.xml:/opt/shibboleth-sp/share/xml/shibboleth/catalog.xml"

/** Default name of SP configuration file. */
#define SHIBSP_CONFIG "shibboleth2.xml"

/** Default name of SP console tool logging file. */
#define SHIBSP_LOGGING "console.logger"

/** Default prefix for installation (used to resolve relative paths). */
#define SHIBSP_PREFIX  "/opt/shibboleth-sp"

/** Library directory for installation (used to resolve relative paths). */
#define SHIBSP_LIBDIR  "/opt/shibboleth-sp/lib"

/** Log directory for installation (used to resolve relative paths). */
#define SHIBSP_LOGDIR  "/opt/shibboleth-sp/var/log"

/** Configuration directory for installation (used to resolve relative paths). */
#define SHIBSP_CFGDIR  "/opt/shibboleth-sp/etc"

/** Runtime state directory for installation (used to resolve relative paths). */
#define SHIBSP_RUNDIR  "/opt/shibboleth-sp/var/run"

/** XML directory for installation (used to resolve relative paths). */
#define SHIBSP_XMLDIR  "/opt/shibboleth-sp/share/xml"

#endif /* __shibsp_paths_h__ */

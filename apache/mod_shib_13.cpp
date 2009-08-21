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

/* mod_shib_13.cpp -- a wrapper around the apache module code to
 * 		      build for Apache 1.3
 *
 * Created by:  Derek Atkins <derek@ihtfp.com>
 *
 */

#define SHIB_APACHE_13 1

#define SH_AP_POOL pool
#define SH_AP_TABLE table
#define SH_AP_CONFIGFILE configfile_t
#define SH_AP_R(r) r
#define SH_AP_USER(r) r->connection->user
#define SH_AP_AUTH_TYPE(r) r->connection->ap_auth_type

#ifdef WIN32
# define _USE_32BIT_TIME_T
#endif

#define apr_pool_userdata_setn(n,k,d,p)
#define apr_pool_cleanup_register(p1,p2,f,d)

#include "mod_apache.cpp"

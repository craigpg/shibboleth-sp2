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

/* mod_shib_22.cpp -- a wrapper around the apache module code to
 * 		      build for Apache 2.2
 *
 * Created by:  Scott Cantor
 *
 */

#define SHIB_APACHE_22 1

#define MODULE_VAR_EXPORT AP_MODULE_DECLARE_DATA
#define SH_AP_POOL apr_pool_t
#define SH_AP_TABLE apr_table_t
#define SH_AP_CONFIGFILE ap_configfile_t
#define array_header apr_array_header_t

#define SH_AP_R(r) 0,r
#define SH_AP_USER(r) r->user

#define SERVER_ERROR HTTP_INTERNAL_SERVER_ERROR
#define REDIRECT HTTP_MOVED_TEMPORARILY
#define ap_pcalloc apr_pcalloc
#define ap_pstrdup apr_pstrdup
#define ap_pstrcat apr_pstrcat
#define ap_psprintf apr_psprintf
#define ap_table_get apr_table_get
#define ap_table_add apr_table_add
#define ap_table_addn apr_table_addn
#define ap_table_setn apr_table_setn
#define ap_table_unset apr_table_unset
#define ap_table_set apr_table_set
#define ap_copy_table apr_table_copy
#define ap_overlay_tables apr_table_overlay
#define ap_overlap_tables apr_table_overlap
#define ap_table_elts apr_table_elts
#define ap_is_empty_table apr_is_empty_table
#define ap_clear_pool apr_pool_clear
#define ap_destroy_pool apr_pool_destroy
#define ap_make_table apr_table_make
#define AP_OVERLAP_TABLES_SET APR_OVERLAP_TABLES_SET

#define ap_send_http_header(r)
#define ap_hard_timeout(str,r)
#define ap_reset_timeout(r)
#define ap_kill_timeout(r)

#define ap_http_method ap_http_scheme

#include "mod_apache.cpp"

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
 * CGIParser.cpp
 * 
 * CGI GET/POST parameter parsing
 */

#include "internal.h"
#include "util/CGIParser.h"

#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace xmltooling;
using namespace std;


CGIParser::CGIParser(const HTTPRequest& request)
{
    const char* pch=NULL;
    if (!strcmp(request.getMethod(),"POST"))
        pch=request.getRequestBody();
    else
        pch=request.getQueryString();
    size_t cl=pch ? strlen(pch) : 0;
    
    const URLEncoder* dec = XMLToolingConfig::getConfig().getURLEncoder();
    while (cl && pch) {
        char *name;
        char *value;
        value=fmakeword('&',&cl,&pch);
        plustospace(value);
        dec->decode(value);
        name=makeword(value,'=');
        kvp_map.insert(pair<const string,char*>(name,value));
        free(name);
    }
}

CGIParser::~CGIParser()
{
    for (multimap<string,char*>::iterator i=kvp_map.begin(); i!=kvp_map.end(); i++)
        free(i->second);
}

pair<CGIParser::walker,CGIParser::walker> CGIParser::getParameters(const char* name) const
{
    return kvp_map.equal_range(name);
}

/* Parsing routines modified from NCSA source. */
char* CGIParser::makeword(char *line, char stop)
{
    int x = 0,y;
    char *word = (char *) malloc(sizeof(char) * (strlen(line) + 1));

    for(x=0;((line[x]) && (line[x] != stop));x++)
        word[x] = line[x];

    word[x] = '\0';
    if(line[x])
        ++x;
    y=0;

    while(line[x])
      line[y++] = line[x++];
    line[y] = '\0';
    return word;
}

char* CGIParser::fmakeword(char stop, size_t *cl, const char** ppch)
{
    int wsize;
    char *word;
    int ll;

    wsize = 1024;
    ll=0;
    word = (char *) malloc(sizeof(char) * (wsize + 1));

    while(1)
    {
        word[ll] = *((*ppch)++);
        if(ll==wsize-1)
        {
            word[ll+1] = '\0';
            wsize+=1024;
            word = (char *)realloc(word,sizeof(char)*(wsize+1));
        }
        --(*cl);
        if((word[ll] == stop) || word[ll] == EOF || (!(*cl)))
        {
            if(word[ll] != stop)
                ll++;
            word[ll] = '\0';
            return word;
        }
        ++ll;
    }
}

void CGIParser::plustospace(char *str)
{
    register int x;

    for(x=0;str[x];x++)
        if(str[x] == '+') str[x] = ' ';
}

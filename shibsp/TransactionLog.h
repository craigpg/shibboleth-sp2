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
 * @file shibsp/TransactionLog.h
 * 
 * Interface to a synchronized logging object.
 */

#ifndef __shibsp_txlog_h__
#define __shibsp_txlog_h__

#include <shibsp/base.h>
#include <xmltooling/logging.h>
#include <xmltooling/Lockable.h>

namespace xmltooling {
    class XMLTOOL_API Mutex;
};

namespace shibsp {
    /**
     * Interface to a synchronized logging object.
     * 
     * <p>This is platform/logging specific, but we can at least hide the details here.
     */
    class SHIBSP_API TransactionLog : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(TransactionLog);
    public:
        TransactionLog();

        virtual ~TransactionLog();
        
        xmltooling::Lockable* lock();

        void unlock();

        /** Logging object. */
        xmltooling::logging::Category& log;

    private:
        xmltooling::Mutex* m_lock;
    };
};

#endif /* __shibsp_txlog_h__ */

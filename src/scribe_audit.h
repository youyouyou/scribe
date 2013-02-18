//  Copyright (c) 2007-2008 Facebook
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
// See accompanying file LICENSE or visit the Scribe site at:
// http://developers.facebook.com/scribe/
//
// @author Satish Mittal

#ifndef SCRIBE_AUDIT_H
#define SCRIBE_AUDIT_H

#include "common.h"
#include "src/gen-cpp/audit_types.h"

struct AuditMsg {
  std::string topic;
  std::map<long, long> received;
  std::map<long, long> sent;
  unsigned long long receivedCount;
  unsigned long long sentCount;
  pthread_mutex_t mutex;
};

typedef AuditMsg audit_msg_t;
typedef std::map<std::string, boost::shared_ptr<audit_msg_t> > audit_map_t;

class StoreQueue;

static const std::string auditTopic = "_audit";

class AuditManager  {
 public:
  AuditManager(const boost::shared_ptr<StoreQueue> pAuditStore);
  ~AuditManager();

  // this method allows various threads to audit a message when it is received/sent 
  void auditMessage(const scribe::thrift::LogEntry& entry, bool received);
  void auditMessages(boost::shared_ptr<logentry_vector_t>& messages, const std::string& category,
       unsigned long offset, unsigned long count, bool received);
  // this method is called by audit store thread to periodically generate audit messages
  // for all categories and add them to message queue. 
  void performAuditTask();
  
 private:
  // get the audit message entry in audit map for the given category
  boost::shared_ptr<audit_msg_t> getAuditMsg(const std::string& category);
  // method to validate message headers. If message is valid it returns timestamp else 0.
  unsigned long long validateMessageAndGetTimestamp(const scribe::thrift::LogEntry& entry);
  // update the audit message counter for the given message
  void updateAuditMessageCounter(boost::shared_ptr<audit_msg_t>& audit_msg,
       unsigned long long timestampKey, bool received);
  // serialize the audit message
  logentry_ptr_t serializeAuditMsg(boost::shared_ptr<audit_msg_t>& audit_msg,
       long timeInMillis);
 
  // audit configuration
  boost::shared_ptr<StoreQueue> auditStore;
  std::string hostName;
  std::string tier;
  long int windowSize;
  audit_map_t auditMap;
  boost::shared_ptr<apache::thrift::concurrency::ReadWriteMutex> auditRWMutex;
};

#endif //!defined SCRIBE_AUDIT_H

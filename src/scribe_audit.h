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
// @author Satish Mittal

#ifndef SCRIBE_AUDIT_H
#define SCRIBE_AUDIT_H

#include "common.h"
#include "src/gen-cpp/audit_types.h"

// this struct holds audit info about msgs received/sent for a given topic 
struct AuditMsg {
  std::string topic;
  std::map<long, long> received;
  std::map<long, long> sent;
  unsigned long long receivedCount;
  unsigned long long sentCount;
  pthread_mutex_t mutex;
};

// this struct holds audit info about mgs written in a given hdfs file 
struct FileAuditMsg {
  std::string topic;
  std::map<long, long> received;
  unsigned long long receivedCount;
  bool fileClosed;
  std::string filename;
};

typedef AuditMsg audit_msg_t;
typedef FileAuditMsg file_audit_msg_t;

// this audit map has key as category and value as audit_msg_t instance
typedef std::map<std::string, boost::shared_ptr<audit_msg_t> > audit_map_t;
// this audit map has key as filename and value as file_audit_msg_t instance
typedef std::map<std::string, boost::shared_ptr<file_audit_msg_t> > file_audit_map_t;

class StoreQueue;

static const std::string auditTopic = "_audit";

class AuditManager  {
 public:
  AuditManager(const boost::shared_ptr<StoreQueue> pAuditStore);
  ~AuditManager();

  // this method allows various threads to audit the event that a message is received/sent 
  void auditMessage(const scribe::thrift::LogEntry& entry, bool received);
  // this method allows various threads to audit the event that a batch of messages are 
  // received/sent. Additionally, if scribe sends messages to a file store and auditFileStore 
  // flag is set to true, this method audits on behalf of file store the event that the
  // file store received the messages,
  void auditMessages(boost::shared_ptr<logentry_vector_t>& messages, unsigned long offset,
       unsigned long count, const std::string& category, bool received, bool auditFileStore, 
       const std::string& filename);
  // this method audits the event that the given file is closed. This would allow audit 
  // store thread to generate audit message for this file.
  void auditFileClosed(const std::string& filename);
  // this method is called by audit store thread periodically to generate audit messages
  // for all categories/file stores and add them to message queue. 
  void performAuditTask();
  
 private:
  // get the audit message entry in audit map for the given category
  boost::shared_ptr<audit_msg_t> getAuditMsg(const std::string& category);
  // get the file audit message entry in file audit map for the given filename
  boost::shared_ptr<file_audit_msg_t> getFileAuditMsg(const std::string& filename, 
       const std::string& category);
  // method to validate message headers. If message header is valid, this method returns
  // timestamp key else returns 0.
  unsigned long long validateMessageAndGetTimestamp(const scribe::thrift::LogEntry& entry);
  // update the audit message counter for the given message
  void updateAuditMessageCounter(boost::shared_ptr<audit_msg_t>& audit_msg,
      unsigned long long timestampKey, bool received);
  // update file audit message counter for the given message key. This method will be called
  // only when messages are sent to a file store and file audit is enabled.
  void updateFileAuditMessageCounter(boost::shared_ptr<file_audit_msg_t>& file_audit_msg,
      unsigned long long timestampKey);
  // serialize the audit message
  logentry_ptr_t serializeAuditMsg(boost::shared_ptr<audit_msg_t>& audit_msg,
      long timeInMillis);
  // serialize the file audit message
  logentry_ptr_t serializeFileAuditMsg(boost::shared_ptr<file_audit_msg_t>& file_audit_msg,
      long timeInMillis);
 
  // audit configuration
  boost::shared_ptr<StoreQueue> auditStore;
  std::string hostName;
  std::string tier;
  long int windowSize;
  audit_map_t auditMap;
  file_audit_map_t fileAuditMap;
  boost::shared_ptr<apache::thrift::concurrency::ReadWriteMutex> auditRWMutex;
};

#endif //!defined SCRIBE_AUDIT_H

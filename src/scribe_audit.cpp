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

#include "common.h"
#include "scribe_server.h"

using namespace std;
using namespace boost;
using namespace scribe::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace audit::thrift;

// magic bytes used to validate message header
unsigned char const magicBytes[] = {0xAB, 0xCD, 0xEF};
// assuming that logEntry message is of the format:
// [<version><magic bytes><timestamp><message size>]<message>
// number of bytes taken by header = 1 + 3 + 8 + 4 = 16
const int headerLength = 16;

AuditManager::AuditManager(const shared_ptr<StoreQueue> pAuditStore) {
  auditStore = pAuditStore;
  auditRWMutex = scribe::concurrency::createReadWriteMutex();
  // get hostname
  char hostname[255];
  int error = gethostname(hostname, sizeof(hostname));
  if (error) {
    LOG_OPER("[Audit] WARNING: gethostname returned error: %d ", error);
  }
  string hostString(hostname);
  if (hostString.empty()) {
    LOG_OPER("[Audit] WARNING: could not get host name");
  } else {
    hostName = hostString;
  }
  // get tier and windowSize from audit config
  pStoreConf pConf = auditStore->getStoreConfig();
  if (pConf != NULL) {
    pConf->getString("tier", tier);
    pConf->getInt("window_size", windowSize);
  } else {
    // set default values
    tier = "scribe";
    windowSize = 60;
  }
}

AuditManager::~AuditManager() {
  shared_ptr<audit_msg_t> audit_msg;
  audit_map_t::iterator audit_iter;
  // destroy mutex instance for each audit message in the map
  for (audit_iter = auditMap.begin(); audit_iter != auditMap.end(); audit_iter++) {
    audit_msg = audit_iter->second;
    pthread_mutex_destroy(&(audit_msg->mutex));
  } 
}

void AuditManager::auditMessage(const LogEntry& entry, bool received) {
  // this store queue must be configured for audit topic 
  if (!auditStore->isAuditStore()) {
    return;
  }

  // acquire read lock on auditRWMutex. This allows multiple threads to audit
  // their messages concurrently when audit store queue thread is not attempting
  // to write audit message.
  auditRWMutex->acquireRead();
  
  try {
    // get the audit message entry in audit map for the given category 
    shared_ptr<audit_msg_t> audit_msg = getAuditMsg(entry.category);

    // update the audit message counter for the given message
    updateAuditMessageCounter(entry, audit_msg, received);

    // finally, release the audit RW mutex
    auditRWMutex->release();
  } catch (const std::exception& e) {
    LOG_OPER("[Audit] Failed to audit message. Error <%s>", e.what());
    // release audit RW mutex, else it could block other threads waiting on mutex
    auditRWMutex->release();
    return;
  } catch (...) { 
    LOG_OPER("[Audit] Failed to audit message. Unexpected error.");
    // release audit RW mutex, else it could block other threads waiting on mutex
    auditRWMutex->release();
    return;
  }
}

void AuditManager::auditMessages(shared_ptr<logentry_vector_t>& messages, 
     const string& category, unsigned long offset, unsigned long count, bool received) {
  // this store queue must be configured for audit topic 
  if (!auditStore->isAuditStore()) {
    return;
  }

  // acquire read lock on auditRWMutex. This allows multiple threads to audit
  // their messages concurrently when audit store queue thread is not attempting
  // to write audit message.
  auditRWMutex->acquireRead();

  try {
    // get the audit message entry in audit map for the given category 
    shared_ptr<audit_msg_t> audit_msg = getAuditMsg(category);

    // update audit message counter for the given messages
    for (unsigned long index = offset; index < offset + count; index++) {
      updateAuditMessageCounter(*(messages->at(index)), audit_msg, received);
    }

    // finally, release the audit RW mutex
    auditRWMutex->release();
  } catch (const std::exception& e) {
    LOG_OPER("[Audit] Failed to audit message. Error <%s>", e.what());
    // release audit RW mutex, else it could block other threads waiting on mutex
    auditRWMutex->release();
    return;
  } catch (...) { 
    LOG_OPER("[Audit] Failed to audit message. Unexpected error.");
    // release audit RW mutex, else it could block other threads waiting on mutex
    auditRWMutex->release();
    return;
  }
}

shared_ptr<audit_msg_t> AuditManager::getAuditMsg(const string& category) {
  shared_ptr<audit_msg_t> audit_msg;
  audit_map_t::iterator audit_iter;
  if ((audit_iter = auditMap.find(category)) != auditMap.end()) {
    audit_msg = audit_iter->second;
  }

  if (audit_msg == NULL) {
    // acquire write lock to add a new audit message for this category
    auditRWMutex->release();
    auditRWMutex->acquireWrite();

    if ((audit_iter = auditMap.find(category)) != auditMap.end()) {
      audit_msg = audit_iter->second;
    } else {
      // create a new audit message for this category
      audit_msg = shared_ptr<audit_msg_t>(new audit_msg_t);
      audit_msg->topic = category;
      // initialize the mutex associated with this audit message
      pthread_mutex_init(&(audit_msg->mutex), NULL);
      // add audit msg to audit map
      auditMap[category] = audit_msg;
    }
  }

  return audit_msg;
}

void AuditManager::updateAuditMessageCounter(const LogEntry& entry,
       shared_ptr<audit_msg_t>& audit_msg, bool received) {
  // get the timestamp of message and update the appropriate counter in audit msg
  unsigned long long tsKey = validateMessageAndGetTimestamp(entry);
  
  // if tsKey is 0, then probably message doesn't have a valid header; hence skip it
  if (tsKey == 0)
    return;

  // acquire mutex to synchronize access to map and insert/increment counter
  pthread_mutex_lock(&(audit_msg->mutex));
  if (received) {
    unsigned long long counter = audit_msg->received[tsKey];
    audit_msg->received[tsKey] = ++counter;
  } else {
    unsigned long long counter = audit_msg->sent[tsKey];
    audit_msg->sent[tsKey] = ++counter;
  }
  pthread_mutex_unlock(&(audit_msg->mutex));
}

unsigned long long AuditManager::validateMessageAndGetTimestamp(const LogEntry& entry) {
  // assuming that logEntry message is of the format:
  // <version><magic bytes><timestamp><message size><message>
  
  // first check that total message length should be at least 16
  if ((int)entry.message.length() < headerLength) {
    return 0;
  }

  const char* data = entry.message.data();

  // first validate the version byte
  int version = (int)(data[0]);
  if (version != 1) {
    LOG_OPER("Audit: ERROR: version byte mismatch; expected [1] but received [%d]", version);
    return 0;
  }

  // now validate magic bytes
  if ((((unsigned char)data[1]) != magicBytes[0]) || (((unsigned char)data[2]) != magicBytes[1]) ||
      (((unsigned char)data[3]) != magicBytes[2])) {
    LOG_OPER("Audit: ERROR: magic bytes mismatch");
    return 0;
  }

  // now get timestamp  bytes
  unsigned long long timestamp =
    ((long)(data[4]  & 0xff) << 56) |
    ((long)(data[5]  & 0xff) << 48) |
    ((long)(data[6]  & 0xff) << 40) |
    ((long)(data[7]  & 0xff) << 32) |
    ((long)(data[8]  & 0xff) << 24) |
    ((long)(data[9]  & 0xff) << 16) |
    ((long)(data[10] & 0xff) <<  8) |
    ((long)(data[11] & 0xff));

  // now validate message size
  int size =
    ((int)(data[12] & 0xff) << 24) |
    ((int)(data[13] & 0xff) << 16) |
    ((int)(data[14] & 0xff) <<  8) |
    ((int)(data[15] & 0xff));
  if ((int)entry.message.length() != size + headerLength) {
    LOG_OPER("Audit: ERROR: message length mismatch; expected [%d] but received [%d]",
             size, (int)entry.message.length() - headerLength);
    return 0;
  }

  return timestamp - timestamp % (windowSize * 1000);
}

void AuditManager::performAuditTask() {
  // find current time in millis. This time will be set in audit messages for all topics.
  struct timeval tv;
  gettimeofday(&tv, NULL);
  long timeInMillis = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);

  // acquire write lock on auditRWMutex using RWGuard 
  RWGuard rwMonitor(*auditRWMutex, true);

  try {
    shared_ptr<audit_msg_t> audit_msg;
    audit_map_t::iterator audit_iter;
    // create a LogEntry instance from audit message per store and add it to message queue
    for (audit_iter = auditMap.begin(); audit_iter != auditMap.end(); audit_iter++) {
      audit_msg = audit_iter->second;
      // skip auditing if received & sent maps are empty
      if (audit_msg->received.size() == 0 && audit_msg->sent.size() == 0)
        continue;

      LOG_OPER("[Audit] Info: Audit Task found entry for category %s, received map size [%llu], sent map size [%llu]",
        audit_msg->topic.c_str(), (long long)audit_msg->received.size(), (long long)audit_msg->sent.size());

      // create a LogEntry instance from audit msg
      shared_ptr<LogEntry> entry = serializeAuditMsg(audit_msg, timeInMillis);

      // add the LogEntry instance to store queue
      auditStore->addMessage(entry);

      // finally, clear the contents of received/sent maps within audit message instance
      audit_msg->received.clear();
      audit_msg->sent.clear();
    }
  } catch (const std::exception& e) {
    LOG_OPER("[Audit] Store thread failed to perform audit task . Error <%s>", e.what());
  } catch (...) {
    LOG_OPER("[Audit] Store thread failed to perform audit task . Unexpected error");
  }
}

shared_ptr<LogEntry> AuditManager::serializeAuditMsg(shared_ptr<audit_msg_t>& audit_msg, 
    long timeInMillis) {
  // create an instance of Thrift AuditMessage from the given audit_msg
  boost::shared_ptr<AuditMessage> Audit = boost::shared_ptr<AuditMessage>(new AuditMessage);
  
  Audit->timestamp = timeInMillis;
  Audit->topic = audit_msg->topic;
  Audit->hostname = hostName;
  Audit->tier = tier;
  Audit->windowSize = windowSize;
  Audit->received = audit_msg->received; 
  Audit->sent = audit_msg->sent;

  // Perform in-memory Thrift serialization of Audit message content
  shared_ptr<TMemoryBuffer> tmembuf(new TMemoryBuffer);
  shared_ptr<TBinaryProtocol> tprot(new TBinaryProtocol(tmembuf));
  Audit->write(tprot.get());

  // create a LogEntry instance using the serialized payload as string
  shared_ptr<LogEntry> entry(new LogEntry);
  entry->category = "audit";
  entry->message = tmembuf->getBufferAsString();

  return entry; 
}

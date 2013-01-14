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
// @author Bobby Johnson
// @author James Wang
// @author Jason Sobel
// @author Anthony Giardullo
// @author John Song

#include "common.h"
#include "scribe_server.h"

using namespace std;
using namespace boost;
using namespace scribe::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

#define DEFAULT_TARGET_WRITE_SIZE  16384LL
#define DEFAULT_MAX_WRITE_INTERVAL 1

void* threadStatic(void *this_ptr) {
  StoreQueue *queue_ptr = (StoreQueue*)this_ptr;
  queue_ptr->threadMember();
  return NULL;
}

StoreQueue::StoreQueue(const string& type, const string& category,
                       unsigned check_period, bool is_model, bool multi_category)
  : msgQueueSize(0),
    hasWork(false),
    stopping(false),
    isModel(is_model),
    multiCategory(multi_category),
    categoryHandled(category),
    checkPeriod(check_period),
    targetWriteSize(DEFAULT_TARGET_WRITE_SIZE),
    maxWriteInterval(DEFAULT_MAX_WRITE_INTERVAL),
    mustSucceed(true) {

  store = Store::createStore(this, type, category,
                            false, multiCategory);
  if (!store) {
    throw std::runtime_error("createStore failed in StoreQueue constructor. Invalid type?");
  }
  storeInitCommon();
}

StoreQueue::StoreQueue(const boost::shared_ptr<StoreQueue> example,
                       const std::string &category)
  : msgQueueSize(0),
    hasWork(false),
    stopping(false),
    isModel(false),
    multiCategory(example->multiCategory),
    categoryHandled(category),
    checkPeriod(example->checkPeriod),
    targetWriteSize(example->targetWriteSize),
    maxWriteInterval(example->maxWriteInterval),
    mustSucceed(example->mustSucceed) {

  store = example->copyStore(category);
  if (!store) {
    throw std::runtime_error("createStore failed copying model store");
  }
  storeInitCommon();
}


StoreQueue::~StoreQueue() {
  if (!isModel) {
    pthread_mutex_destroy(&cmdMutex);
    pthread_mutex_destroy(&msgMutex);
    pthread_mutex_destroy(&hasWorkMutex);
    pthread_cond_destroy(&hasWorkCond);
  }
}

void StoreQueue::auditMessage(const LogEntry& entry, bool received) {
  // If current queue is not for audit category, route the call to audit queue
  if (!isAuditStore) {
    // check if audit queue is configured
    if (auditStore != NULL) {
      return auditStore->auditMessage(entry, received);
    } else {
      return;
    }
  }

  // acquire read lock on auditRWMutex. This allows multiple threads to
  // audit their messages concurrently when audit store queue thread is not
  // attempting to write audit message.
  auditRWMutex->acquireRead();

  // iterate through auditMap and find the audit message corresponding
  // to the category of this entry.
  shared_ptr<audit_msg_t> audit_msg;
  audit_map_t::iterator audit_iter;
  if ((audit_iter = auditMap.find(entry.category)) != auditMap.end()) {
    audit_msg = audit_iter->second;
    LOG_OPER("[Audit] Info: Found an audit message instance for category: %s", entry.category.c_str());
  }

  if (audit_msg == NULL) {
    // acquire write lock to add a new audit message for this category
    auditRWMutex->release();
    auditRWMutex->acquireWrite();

    if ((audit_iter = auditMap.find(entry.category)) != auditMap.end()) {
      audit_msg = audit_iter->second;
    } else {
        audit_msg = shared_ptr<audit_msg_t>(new audit_msg_t);
        audit_msg->topic = entry.category;
        auditMap[entry.category] = audit_msg;
        LOG_OPER("[Audit] Info: Added an audit message instance for category: %s", entry.category.c_str());
    }
  } 
    
  // get the timestamp of message and update the appropriate counter in audit msg
  unsigned long long tsKey = getTimestampKeyFromMessage(entry);
  
  //TODO: add appropriate synchronization to atomically increment the counter
  if (received) {
    unsigned long long counter = audit_msg->received[tsKey];
    LOG_OPER("[Audit] Info: existing counter for timestamp is: %llu", counter);
    audit_msg->received[tsKey] = ++counter;
    LOG_OPER("[Audit] Info: updated recv counter for timestamp to: %llu", counter); 
  } else {
    unsigned long long counter = audit_msg->sent[tsKey];
    audit_msg->sent[tsKey] = ++counter;
    LOG_OPER("[Audit] Info: updated sent counter for timestamp to: %llu", counter); 
  }

  // finally, release the audit RW mutex
  auditRWMutex->release();
}

unsigned long long StoreQueue::getTimestampKeyFromMessage(const LogEntry& entry) {
  // assuming that logEntry message is of the format <timestamp><data>
  // TODO: perform other checks required to handle older version messages.
  // e.g. check that message length >= 8
  unsigned long long timestamp = byteArrayToLong(entry.message.data());;
  LOG_OPER("[Audit] Info: Message entry has timestamp long: %llu", timestamp);

  // TODO: assume windowSizeInMins to be a part of audit config inside scribe.conf
  // Also check whether we can achieve it like (x - x % window)
  int windowSizeInMins = 1;
  return (timestamp/(windowSizeInMins * 60 * 1000)) * (windowSizeInMins * 60 * 1000);
}

unsigned long long StoreQueue::byteArrayToLong(const char* buf) {
  int off = 0;
  return
    ((long)(buf[off]   & 0xff) << 56) |
    ((long)(buf[off+1] & 0xff) << 48) |
    ((long)(buf[off+2] & 0xff) << 40) |
    ((long)(buf[off+3] & 0xff) << 32) |
    ((long)(buf[off+4] & 0xff) << 24) |
    ((long)(buf[off+5] & 0xff) << 16) |
    ((long)(buf[off+6] & 0xff) <<  8) |
    ((long)(buf[off+7] & 0xff));
}

void StoreQueue::performAuditTask() {
  RWGuard rwMonitor(*auditRWMutex, true);
 
  shared_ptr<audit_msg_t> audit_msg;
  audit_map_t::iterator audit_iter;
  // create a LogEntry instance from audit message per store and add it to message queue
  for (audit_iter = auditMap.begin(); audit_iter != auditMap.end(); audit_iter++) {
    audit_msg = audit_iter->second;
    // skip auditing if received & sent maps are empty
    if (audit_msg->received.size() == 0 && audit_msg->sent.size() == 0)
      continue;

    LOG_OPER("[Audit] Info: Audit task found entry for category %s, received map size [%llu], sent map size [%llu]", 
      audit_msg->topic.c_str(), audit_msg->received.size(), audit_msg->sent.size());
 
    // Perform in-memory Thrift serialization of audit message content
    // TODO: try to reuse the tmembuf across calls by calling resetBuffer() once done
    shared_ptr<TMemoryBuffer> tmembuf(new TMemoryBuffer);
    shared_ptr<TBinaryProtocol> tprot(new TBinaryProtocol(tmembuf));
    audit_msg->write(tprot.get());
    
    // create a LogEntry instance using the serialized payload as string
    std::string serializedMsg = tmembuf->getBufferAsString();
    shared_ptr<LogEntry> entry(new LogEntry);
    entry->category = audit_msg->topic;
    entry->message = serializedMsg;

    addMessage(entry);

    // finally, clear the contents of received/sent maps within audit message instance
    audit_msg->received.clear();
    audit_msg->sent.clear(); 
  } 
}

void StoreQueue::addMessage(boost::shared_ptr<LogEntry> entry) {
  if (isModel) {
    LOG_OPER("ERROR: called addMessage on model store");
  } else {
    bool waitForWork = false;

    pthread_mutex_lock(&msgMutex);
    msgQueue->push_back(entry);
    msgQueueSize += entry->message.size();

    waitForWork = (msgQueueSize >= targetWriteSize) ? true : false;
    pthread_mutex_unlock(&msgMutex);

    // Wake up store thread if we have enough messages
    if (waitForWork == true) {
      // signal that there is work to do if not already signaled
      pthread_mutex_lock(&hasWorkMutex);
      if (!hasWork) {
        hasWork = true;
        pthread_cond_signal(&hasWorkCond);
      }
      pthread_mutex_unlock(&hasWorkMutex);
    }
  }
}

void StoreQueue::configureAndOpen(pStoreConf configuration) {
  // model store has to handle this inline since it has no queue
  if (isModel) {
    configureInline(configuration);
  } else {
    pthread_mutex_lock(&cmdMutex);
    StoreCommand cmd(CMD_CONFIGURE, configuration);
    cmdQueue.push(cmd);
    pthread_mutex_unlock(&cmdMutex);

    // signal that there is work to do if not already signaled
    pthread_mutex_lock(&hasWorkMutex);
    if (!hasWork) {
      hasWork = true;
      pthread_cond_signal(&hasWorkCond);
    }
    pthread_mutex_unlock(&hasWorkMutex);
  }
}

void StoreQueue::stop() {
  if (isModel) {
    LOG_OPER("ERROR: called stop() on model store");
  } else if(!stopping) {
    pthread_mutex_lock(&cmdMutex);
    StoreCommand cmd(CMD_STOP);
    cmdQueue.push(cmd);
    stopping = true;
    pthread_mutex_unlock(&cmdMutex);

    // signal that there is work to do if not already signaled
    pthread_mutex_lock(&hasWorkMutex);
    if (!hasWork) {
      hasWork = true;
      pthread_cond_signal(&hasWorkCond);
    }
    pthread_mutex_unlock(&hasWorkMutex);

    pthread_join(storeThread, NULL);
  }
}

void StoreQueue::open() {
  if (isModel) {
    LOG_OPER("ERROR: called open() on model store");
  } else {
    pthread_mutex_lock(&cmdMutex);
    StoreCommand cmd(CMD_OPEN);
    cmdQueue.push(cmd);
    pthread_mutex_unlock(&cmdMutex);

    // signal that there is work to do if not already signaled
    pthread_mutex_lock(&hasWorkMutex);
    if (!hasWork) {
      hasWork = true;
      pthread_cond_signal(&hasWorkCond);
    }
    pthread_mutex_unlock(&hasWorkMutex);
  }
}

shared_ptr<Store> StoreQueue::copyStore(const std::string &category) {
  return store->copy(category);
}

std::string StoreQueue::getCategoryHandled() {
  return categoryHandled;
}


std::string StoreQueue::getStatus() {
  return store->getStatus();
}

std::string StoreQueue::getBaseType() {
  return store->getType();
}

void StoreQueue::threadMember() {
  LOG_OPER("store thread starting");
  if (isModel) {
    LOG_OPER("ERROR: store thread starting on model store, exiting");
    return;
  }

  if (!store) {
    LOG_OPER("store is NULL, store thread exiting");
    return;
  }

  // init time of last periodic check to time of 0
  time_t last_periodic_check = 0;

  time_t last_handle_messages;
  time(&last_handle_messages);

  struct timespec abs_timeout;

  bool stop = false;
  bool open = false;
  while (!stop) {

    // handle commands
    //
    pthread_mutex_lock(&cmdMutex);
    while (!cmdQueue.empty()) {
      StoreCommand cmd = cmdQueue.front();
      cmdQueue.pop();

      switch (cmd.command) {
      case CMD_CONFIGURE:
        configureInline(cmd.configuration);
        openInline();
        open = true;
        break;
      case CMD_OPEN:
        openInline();
        open = true;
        break;
      case CMD_STOP:
        stop = true;
        break;
      default:
        LOG_OPER("LOGIC ERROR: unknown command to store queue");
        break;
      }
    }

    // handle periodic tasks
    time_t this_loop;
    time(&this_loop);
    if (!stop && ((this_loop - last_periodic_check) >= checkPeriod)) {
      if (open) store->periodicCheck();
      last_periodic_check = this_loop;
    }

    // perform audit specific task if it is an audit store
    if (isAuditStore && (stop || 
        (this_loop - last_handle_messages >= maxWriteInterval) ||
        msgQueueSize >= targetWriteSize)) {
      performAuditTask();
    }

    pthread_mutex_lock(&msgMutex);
    pthread_mutex_unlock(&cmdMutex);

    boost::shared_ptr<logentry_vector_t> messages;

    // handle messages if stopping, enough time has passed, or queue is large
    //
    if (stop ||
        (this_loop - last_handle_messages >= maxWriteInterval) ||
        msgQueueSize >= targetWriteSize) {

      if (failedMessages) {
        // process any messages we were not able to process last time
        messages = failedMessages;
        failedMessages = boost::shared_ptr<logentry_vector_t>();
      } else if (msgQueueSize > 0) {
        // process message in queue
        messages = msgQueue;
        msgQueue = boost::shared_ptr<logentry_vector_t>(new logentry_vector_t);
        msgQueueSize = 0;
      }

      // reset timer
      last_handle_messages = this_loop;
    }

    pthread_mutex_unlock(&msgMutex);

    if (messages) {
      if (!store->handleMessages(messages)) {
        // Store could not handle these messages
        processFailedMessages(messages);
      }
      store->flush();
    }

    if (!stop) {
      // set timeout to when we need to handle messages or do a periodic check
      abs_timeout.tv_sec = min(last_periodic_check + checkPeriod,
          last_handle_messages + maxWriteInterval);
      abs_timeout.tv_nsec = 0;

      // wait until there's some work to do or we timeout
      pthread_mutex_lock(&hasWorkMutex);
      if (!hasWork) {
	pthread_cond_timedwait(&hasWorkCond, &hasWorkMutex, &abs_timeout);
      }
      hasWork = false;
      pthread_mutex_unlock(&hasWorkMutex);
    }

  } // while (!stop)

  store->close();
}

void StoreQueue::processFailedMessages(shared_ptr<logentry_vector_t> messages) {
  // If the store was not able to process these messages, we will either
  // requeue them or give up depending on the value of mustSucceed

  if (mustSucceed) {
    // Save failed messages
    failedMessages = messages;

    LOG_OPER("[%s] WARNING: Re-queueing %lu messages!",
             categoryHandled.c_str(), messages->size());
    g_Handler->incCounter(categoryHandled, "requeue", messages->size());
  } else {
    // record messages as being lost
    LOG_OPER("[%s] WARNING: Lost %lu messages!",
             categoryHandled.c_str(), messages->size());
    g_Handler->incCounter(categoryHandled, "lost", messages->size());
  }
}

void StoreQueue::storeInitCommon() {
  // model store doesn't need this stuff
  if (!isModel) {
    msgQueue = boost::shared_ptr<logentry_vector_t>(new logentry_vector_t);
    pthread_mutex_init(&cmdMutex, NULL);
    pthread_mutex_init(&msgMutex, NULL);
    pthread_mutex_init(&hasWorkMutex, NULL);
    pthread_cond_init(&hasWorkCond, NULL);

    // if this is an audit store then initialise audit specific members
    if (categoryHandled.compare("audit") == 0) {
      isAuditStore = true;
      auditRWMutex = scribe::concurrency::createReadWriteMutex(); 
    }

    pthread_create(&storeThread, NULL, threadStatic, (void*) this);
  }
}

void StoreQueue::configureInline(pStoreConf configuration) {
  // Constructor defaults are fine if these don't exist
  configuration->getUnsignedLongLong("target_write_size", targetWriteSize);
  configuration->getUnsigned("max_write_interval",
                            (unsigned long&) maxWriteInterval);
  if (maxWriteInterval == 0) {
    maxWriteInterval = 1;
  }

  string tmp;
  if (configuration->getString("must_succeed", tmp) && tmp == "no") {
    mustSucceed = false;
  }

  store->configure(configuration, pStoreConf());
}

void StoreQueue::openInline() {
  if (store->isOpen()) {
    store->close();
  }
  if (!isModel) {
    store->open();
  }
}

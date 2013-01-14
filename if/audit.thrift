#!/usr/local/bin/thrift --gen cpp:pure_enums --gen php

namespace cpp audit.thrift
namespace java com.inmobi.audit.thrift

struct AuditMessage
{
  1:  i64 timestamp,
  2:  string topic,
  3:  map<i64, i64> received,
  4:  map<i64, i64> sent
}

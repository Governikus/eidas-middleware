/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.paosservlet.paos.handler;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


public class MessageSessionMapper
{

  private static final MessageSessionMapper SINGLETON = new MessageSessionMapper();

  private final Map<String, String> msgId2sessId = new ConcurrentHashMap<>();


  private MessageSessionMapper()
  {}


  static MessageSessionMapper getInstance()
  {
    return SINGLETON;
  }

  String getSessionId(String messageId)
  {
    return msgId2sessId.get(messageId);
  }

  void add(String msgId, String sessionId)
  {
    msgId2sessId.put(msgId, sessionId);
  }

  void overwriteMessageId(String oldMsgId, String newMsgId)
  {
    String sessionId = msgId2sessId.remove(oldMsgId);
    if (sessionId == null)
    {
      throw new IllegalArgumentException("No sessionId found for messageId " + oldMsgId);
    }
    msgId2sessId.put(newMsgId, sessionId);
  }

  void remove(String msgId)
  {
    msgId2sessId.remove(msgId);
  }
}

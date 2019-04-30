/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.accounting;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.annotation.PostConstruct;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Counter64;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TimeTicks;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


/**
 * Sends SNMP traps with specified parameters.
 *
 * @author nagel, am
 */

@Component
public final class SNMPTrapSender
{

  private static final Log LOG = LogFactory.getLog(SNMPTrapSender.class);

  private static final long SYSTEM_START_TIME = System.currentTimeMillis();

  private static Snmp snmp;

  private static boolean initialized = false;

  private static String managementHost;

  private static String managementHostTrapListenPort;

  private static String communityString = "public";

  private static UdpAddress targetAddress;

  private static final String MESSAGE_OID = "1.3.6.1.4.1.28939.2.8";

  @Value("${poseidas.snmp.managementhost:#{null}}")
  public void setManagementHost(String host)
  {
    managementHost = host;
  }

  @Value("${poseidas.snmp.managementport:162}")
  public void setManagementHostTrapListenPort(String port)
  {
    managementHostTrapListenPort = port;
  }

  @Value("${poseidas.snmp.community:public}")
  public void setCommunityString(String community)
  {
    communityString = community;
  }

  @PostConstruct
  public void init()
  {
    try
    {
      LOG.debug("Initialize default SNMPTrapSender");
      if (managementHost == null)
      {
        LOG.info("No management host specified for SNMP notifications, won't send any messages.");
      }
      else
      {
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);
        targetAddress = new UdpAddress(managementHost + "/" + managementHostTrapListenPort);
        initialized = true;
      }
    }
    catch (IOException e)
    {
      LOG.error("init failed ", e);
    }
  }

  /**
   * Sends an SNMP notification with the given OID as an SnmpTagValue (UTF-8 encoded, max. 255 bytes long)
   *
   * @param applicationTrapOID
   * @param message
   */
  static void sendNotification(String applicationTrapOID, String message)
  {
    sendNotification(applicationTrapOID,
                     new String[]{MESSAGE_OID},
                     new Variable[]{new OctetString(message.getBytes(StandardCharsets.UTF_8))});
  }

  /**
   * Sends a complex SNMP notification with the given OID and a list of variable bindings. In addition to
   * instances of {@link Variable} this method currently accepts Strings (OctetStrings), Integer (Integer32)
   * and Long (Counter64) values for the variable bindings. Other objects or different lengths of given arrays
   * cause the method to return, logging a warning.
   *
   * @param applicationTrapOID the notification's OID
   * @param varBindOIDs array containing the OIDs of the variable bindings
   * @param varBindValues the values of the variable bindings
   */
  private static void sendNotification(String applicationTrapOID,
                                       String[] varBindOIDs,
                                       Object[] varBindValues)
  {
    if (!initialized)
    {
      LOG.warn("sendNotification() could not be processed because SNMP was not initialized");
      return;
    }

    if (varBindOIDs.length != varBindValues.length)
    {
      LOG.warn("sendNotification() aborted, different numbers of OIDs and Variables (" + varBindOIDs.length
               + "/" + varBindValues.length + ")");
      return;
    }

    Variable[] values = new Variable[varBindValues.length];

    for ( int i = 0 ; i < varBindOIDs.length ; i++ )
    {
      if (varBindValues[i] instanceof String)
      {
        values[i] = new OctetString(((String)varBindValues[i]).getBytes(StandardCharsets.UTF_8));
      }
      else if (varBindValues[i] instanceof Integer)
      {
        values[i] = new Integer32(((Integer)varBindValues[i]).intValue());
      }
      else if (varBindValues[i] instanceof Long)
      {
        values[i] = new Counter64(((Long)varBindValues[i]).longValue());
      }
      else if (varBindValues[i] instanceof Variable)
      {
        values[i] = (Variable)varBindValues[i];
      }
      else
      {
        LOG.warn("sendNotification() aborted, unsupported varBindValue found " + varBindValues[i]);
        return;
      }
    }

    try
    {
      // Create trap PDU
      PDU trap = createPDU();

      // Add Payload
      trap.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(applicationTrapOID)));

      for ( int i = 0 ; i < varBindOIDs.length ; i++ )
      {
        trap.add(new VariableBinding(new OID(varBindOIDs[i]), values[i]));
      }

      // specify receiver
      CommunityTarget target = new CommunityTarget();
      target.setCommunity(new OctetString(communityString));
      target.setAddress(targetAddress);
      target.setRetries(2);
      target.setTimeout(2000);
      target.setVersion(SnmpConstants.version2c);

      // send trap
      snmp.notify(trap, target);
    }
    catch (IOException ex)
    {
      LOG.error("An error occurred sending SNMP trap: ", ex);
    }
  }

  // creating default PDU trap with system uptime
  private static PDU createPDU()
  {
    PDU pdu = new PDU();
    pdu.setType(PDU.TRAP);
    long sysUpTime = (System.currentTimeMillis() - SYSTEM_START_TIME) / 10;
    pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(sysUpTime)));
    return pdu;
  }

}

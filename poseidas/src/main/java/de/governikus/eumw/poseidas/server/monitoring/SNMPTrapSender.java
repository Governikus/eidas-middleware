/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.monitoring;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.snmp4j.PDU;
import org.snmp4j.SNMP4JSettings;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthHMAC128SHA224;
import org.snmp4j.security.AuthHMAC192SHA256;
import org.snmp4j.security.AuthHMAC256SHA384;
import org.snmp4j.security.AuthHMAC384SHA512;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
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

import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * Sends SNMP traps with specified parameters.
 *
 * @author nagel, am
 */

@Slf4j
@Component
public final class SNMPTrapSender
{

  private static final long SYSTEM_START_TIME = System.currentTimeMillis();

  @Getter(AccessLevel.PACKAGE)
  private static Snmp snmp;

  private static boolean initialized = false;

  private static String userName;

  private static UdpAddress targetAddress;

  private String managementHost;

  private String managementHostTrapListenPort;

  private String authPassword;

  private OID authAlgo;

  private String privPassword;

  private OID privAlgo;

  private String agentHost;

  private String agentPort;

  private OctetString engineId;

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

  @Value("${poseidas.snmp.username:#{null}}")
  public void setUserName(String name)
  {
    userName = name;
  }

  @Value("${poseidas.snmp.authpwd:#{null}}")
  public void setAuthPassword(String pwd)
  {
    authPassword = pwd;
  }

  @Value("${poseidas.snmp.authalgo:hmac384sha512}")
  public void setAuthAlgo(String algo)
  {
    String tmp = algo.toLowerCase();
    switch (tmp)
    {
      case "md5":
        authAlgo = AuthMD5.ID;
        SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());
        break;
      case "sha":
        authAlgo = AuthSHA.ID;
        SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
        break;
      case "hmac128sha224":
        authAlgo = AuthHMAC128SHA224.ID;
        break;
      case "hmac192sha256":
        authAlgo = AuthHMAC192SHA256.ID;
        break;
      case "hmac256sha384":
        authAlgo = AuthHMAC256SHA384.ID;
        break;
      case "hmac384sha512":
      default:
        authAlgo = AuthHMAC384SHA512.ID;
    }
  }

  @Value("${poseidas.snmp.privpwd:#{null}}")
  public void setPrivPassword(String pwd)
  {
    privPassword = pwd;
  }

  @Value("${poseidas.snmp.privalgo:aes256}")
  public void setPrivAlgo(String algo)
  {
    String tmp = algo.toLowerCase();
    switch (tmp)
    {
      case "des":
        privAlgo = PrivDES.ID;
        break;
      case "3des":
        privAlgo = Priv3DES.ID;
        SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());
        break;
      case "aes128":
        privAlgo = PrivAES128.ID;
        break;
      case "aes192":
        privAlgo = PrivAES192.ID;
        break;
      case "aes256":
      default:
        privAlgo = PrivAES256.ID;
    }
  }

  @Value("${poseidas.snmp.agenthost:#{null}}")
  public void setAgentHost(String host)
  {
    agentHost = host;
  }

  @Value("${poseidas.snmp.agentport:161}")
  public void setAgentPort(String port)
  {
    agentPort = port;
  }

  @Value("${poseidas.snmp.engineid:eidasmw}")
  public void setEngineId(String id)
  {
    engineId = new OctetString(id);
  }

  @PostConstruct
  public void init()
  {
    if (agentHost == null || userName == null || authPassword == null || privPassword == null)
    {
      log.info("SNMP not properly configured: You need poseidas.snmp.agenthost, poseidas.snmp.username, poseidas.snmp.authpwd and poseidas.snmp.privpwd to be set. At least one of them is missing, so SNMP will be disabled");
      return;
    }
    log.debug("Initialize SNMP");
    SNMP4JSettings.setEnterpriseID(28939);
    byte[] localEngineId = MPv3.createLocalEngineID(engineId);
    USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(localEngineId), 0);
    SecurityModels.getInstance().addSecurityModel(usm);

    if (managementHost == null)
    {
      log.info("No management host specified for SNMP notifications, won't send any messages");
    }
    else
    {
      targetAddress = new UdpAddress(managementHost + "/" + managementHostTrapListenPort);
    }

    try
    {
      TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping(new UdpAddress(agentHost + "/"
                                                                                             + agentPort));
      snmp = new Snmp(transport);
      snmp.setLocalEngine(localEngineId, 0, 0);
      snmp.getUSM()
          .addUser(new OctetString(userName),
                   new UsmUser(new OctetString(userName), authAlgo, new OctetString(authPassword), privAlgo,
                               new OctetString(privPassword)));
      snmp.listen();
      initialized = true;
    }
    catch (IOException e)
    {
      log.error("SNMP init failed, will be disabled", e);
    }
  }

  @PreDestroy
  public void closeSnmpConnection()
  {
    if (snmp != null)
    {
      try
      {
        snmp.close();
        snmp = null;
      }
      catch (IOException e)
      {
        log.warn("Closing SNMP instance failed", e);
      }
    }
  }

  /**
   * Send an SNMP trap with optional message(s).
   *
   * @param oid
   * @param message optional
   */
  public static void sendSNMPTrap(SNMPConstants.TrapOID oid, String... message)
  {
    StringBuilder text = new StringBuilder();
    for ( String msg : message )
    {
      text.append(msg).append(' ');
    }
    sendNotification(oid.getValue(),
                     new String[]{SNMPConstants.TrapOID.TRAP_TYPE_MESSAGE.getValue()},
                     new OctetString(text.substring(0, text.length() - 1).getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Send an SNMP trap with an int value.
   *
   * @param oid
   * @param val
   */
  public static void sendSNMPTrap(SNMPConstants.TrapOID oid, int val)
  {
    sendNotification(oid.getValue(), new String[]{SNMPConstants.TrapOID.TRAP_TYPE_INT.getValue()}, new Integer32(val));
  }

  /**
   * Send an SNMP trap with a long value.
   *
   * @param oid
   * @param val
   */
  public static void sendSNMPTrap(SNMPConstants.TrapOID oid, long val)
  {
    sendNotification(oid.getValue(), new String[]{SNMPConstants.TrapOID.TRAP_TYPE_LONG.getValue()}, new Counter64(val));
  }

  /**
   * Sends a complex SNMP notification with the given OID and a list of variable bindings.
   *
   * @param applicationTrapOID the notification's OID
   * @param varBindOIDs array containing the OIDs of the variable bindings
   * @param varBindValues the values of the variable bindings
   */
  private static void sendNotification(String applicationTrapOID, String[] varBindOIDs, Variable... varBindValues)
  {
    if (!initialized || targetAddress == null)
    {
      log.debug("sendNotification() could not be processed because SNMP was not initialized / properly configured");
      return;
    }

    if (varBindOIDs.length != varBindValues.length)
    {
      log.warn("sendNotification() aborted, different numbers of OIDs and Variables ({}/{})",
               varBindOIDs.length,
               varBindValues.length);
      return;
    }

    try
    {
      // Create trap PDU
      PDU trap = createPDU();

      // Add Payload
      trap.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(applicationTrapOID)));

      for ( int i = 0 ; i < varBindOIDs.length ; i++ )
      {
        trap.add(new VariableBinding(new OID(varBindOIDs[i]), varBindValues[i]));
      }

      UserTarget target = new UserTarget();
      target.setAddress(targetAddress);
      target.setRetries(2);
      target.setTimeout(2000);
      target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
      target.setSecurityName(new OctetString(userName));

      // send trap
      snmp.notify(trap, target);
    }
    catch (IOException ex)
    {
      log.error("An error occurred sending SNMP trap: ", ex);
    }
  }

  // creating default PDU trap with system uptime
  private static PDU createPDU()
  {
    PDU pdu = new ScopedPDU();
    pdu.setType(PDU.TRAP);
    long sysUpTime = System.currentTimeMillis() - SYSTEM_START_TIME;
    // note: TimeTicks wants 1 / 100 seconds
    pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(sysUpTime / 10)));
    return pdu;
  }
}

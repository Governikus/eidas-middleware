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
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.PostConstruct;

import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.PDU;
import org.snmp4j.agent.mo.snmp.DateAndTime;
import org.snmp4j.mp.StatusInformation;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescription;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * SNMP Agent implementation, listens for SNMP GET and GET NEXT requests.
 */
@Slf4j
@Component
@DependsOn("SNMPTrapSender")
@AllArgsConstructor
public final class SNMPAgent implements CommandResponder
{

  private static final Pattern SERVICE_PROVIDER_PREFIX_PATTERN = Pattern.compile(SNMPConstants.PROVIDER_SPECIFIC_PREFIX
                                                                                 + "(\\d+).(\\d+)");

  private final TerminalPermissionAO facade;

  private final PermissionDataHandlingMBean permissionDataHandling;

  private final RequestSignerCertificateService rscService;

  private static VariableBinding getDateAndTime(String oid, Date date)
  {
    GregorianCalendar calendar = GregorianCalendar.from(ZonedDateTime.now());
    calendar.setTime(date);
    return new VariableBinding(new OID(oid), DateAndTime.makeDateAndTime(calendar));
  }

  @PostConstruct
  public void initialize()
  {
    if (SNMPTrapSender.getSnmp() == null)
    {
      log.info("Snmp was not initialized. SNMP Agent can not listen for SNMP GET and GET NEXT request.");
      return;
    }
    SNMPTrapSender.getSnmp().addCommandResponder(this);
  }

  private void setErrorInfos(PDU ret, int error, int index)
  {
    ret.setErrorStatus(error);
    ret.setErrorIndex(index);
  }

  @Override
  public synchronized void processPdu(CommandResponderEvent event)
  {
    // accept only SNMPv3 with authentication and encryption
    if (event.getSecurityModel() != 3 || event.getSecurityLevel() != 3)
    {
      return;
    }

    PDU command = event.getPDU();
    if (command == null)
    {
      return;
    }

    log.debug("Start processing received command: {}", command);
    int type = command.getType();
    PDU re = command;
    re.setType(PDU.RESPONSE);

    if (type == PDU.GET || type == PDU.GETNEXT)
    {
      List<? extends VariableBinding> vbs = command.getVariableBindings();
      int i = 0;
      try
      {
        for ( ; i < vbs.size() ; i++ )
        {
          String oid = vbs.get(i).getOid().toString();
          if (type == PDU.GETNEXT)
          {
            try
            {
              oid = nextOID(oid);
            }
            catch (IllegalStateException e)
            {
              setErrorInfos(re, PDU.noSuchName, i + 1);
              break;
            }
          }
          re.set(i, getValue(oid));
        }
      }
      catch (Exception e)
      {
        log.debug("Cannot create SNMP response", e);
        setErrorInfos(re, PDU.resourceUnavailable, i + 1);
      }
    }
    else
    {
      setErrorInfos(re, PDU.genErr, 0);
    }

    try
    {
      event.getMessageDispatcher()
           .returnResponsePdu(event.getMessageProcessingModel(),
                              event.getSecurityModel(),
                              event.getSecurityName(),
                              event.getSecurityLevel(),
                              re,
                              event.getMaxSizeResponsePDU(),
                              event.getStateReference(),
                              new StatusInformation());
    }
    catch (Exception ex)
    {
      log.error("Failed to process SNMP request {}", command, ex);
    }
  }

  private VariableBinding getValue(String oid) throws Exception
  {
    // handle everything provider specific
    if (oid.startsWith(SNMPConstants.PROVIDER_SPECIFIC_PREFIX))
    {
      return getProviderSpecificData(oid);
    }

    SNMPConstants.GetOID oidConstant;
    try
    {
      oidConstant = SNMPConstants.GetOID.getOID(oid);
    }
    catch (IllegalArgumentException e)
    {
      log.error(e.getMessage());
      throw e;
    }

    switch (oidConstant)
    {
      case CRL_GET_AVAILABLE:
        if (CertificationRevocationListImpl.isInitialized())
        {
          return new VariableBinding(oidConstant.toSNMPOid(), new Integer32(1));
        }
        else
        {
          return new VariableBinding(oidConstant.toSNMPOid(), new Integer32(0));
        }
      case CRL_GET_LAST_SUCCESSFUL_RETRIEVAL:
        long latestRetrieval = CertificationRevocationListImpl.latestRetrieval();
        if (latestRetrieval == 0)
        {
          throw new IOException("Certificate revocation list was never successfully retrieved");
        }
        else
        {
          return getDateAndTime(oid, new Date(latestRetrieval));
        }
      case GET_TLS_CERTIFICATE_VALID:
        return getDateAndTime(oid, new CvcTlsCheck(facade).getTLSExpirationDate());
      default:
        log.warn("No matching case for this OID: {}", oidConstant.getValue());
        throw new IllegalArgumentException("No matching case for this OID: " + oidConstant.getValue());
    }
  }

  private VariableBinding getProviderSpecificData(String oid) throws IOException
  {
    Matcher matcher = SERVICE_PROVIDER_PREFIX_PATTERN.matcher(oid);
    if (matcher.find())
    {
      String stringType = matcher.group(1);
      Integer type = Integer.valueOf(stringType);
      String stringId = matcher.group(2);
      Integer id = Integer.valueOf(stringId);

      CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
      List<ServiceProviderDto> spList = new ArrayList<>(config.getServiceProvider().values());
      if (spList.size() <= id)
      {
        throw new IllegalArgumentException("Invalid SP index: " + id);
      }
      ServiceProviderDto sp = spList.get(id);
      TerminalPermission tp = facade.getTerminalPermission(sp.getEpaConnectorConfiguration().getCVCRefID());
      switch (type)
      {
        case SNMPConstants.PROVIDER_NAME:
          return new VariableBinding(new OID(oid), new OctetString(sp.getEntityID()));
        case SNMPConstants.BLACKLIST_LIST_AVAILABLE:
          return new VariableBinding(new OID(oid), new Integer32(tp.getBlackListVersion() == null ? 0 : 1));
        case SNMPConstants.BLACKLIST_LAST_SUCCESSFUL_RETRIEVAL:
          return getDateAndTime(oid, tp.getBlackListStoreDate());
        case SNMPConstants.BLACKLIST_DVCA_AVAILABILITY:
          return new VariableBinding(new OID(oid),
                                     new Integer32(permissionDataHandling.pingRIService(sp.getEntityID()) ? 1 : 0));
        case SNMPConstants.MASTERLIST_LIST_AVAILABLE:
          return new VariableBinding(new OID(oid), new Integer32(tp.getMasterList() == null ? 0 : 1));
        case SNMPConstants.MASTERLIST_LAST_SUCCESSFUL_RETRIEVAL:
          return getDateAndTime(oid, tp.getMasterListStoreDate());
        case SNMPConstants.DEFECTLIST_LIST_AVAILABLE:
          return new VariableBinding(new OID(oid), new Integer32(tp.getDefectList() == null ? 0 : 1));
        case SNMPConstants.DEFECTLIST_LAST_SUCCESSFUL_RETRIEVAL:
          return getDateAndTime(oid, tp.getDefectListStoreDate());
        case SNMPConstants.MASTERLIST_DVCA_AVAILABILITY:
        case SNMPConstants.DEFECTLIST_DVCA_AVAILABILITY:
          return new VariableBinding(new OID(oid),
                                     new Integer32(permissionDataHandling.pingPAService(sp.getEntityID()) ? 1 : 0));
        case SNMPConstants.RSC_PENDING_AVAILABLE:
          return new VariableBinding(new OID(oid),
                                     new Integer32(rscService.getRequestSignerCertificate(sp.getEntityID(),
                                                                                          false) == null ? 0 : 1));
        case SNMPConstants.RSC_CURRENT_CERTIFICATE_VALID_UNTIL:
          return getDateAndTime(oid, rscService.getRequestSignerCertificate(sp.getEntityID(), true).getNotAfter());
        case SNMPConstants.CVC_PRESENT:
          return new VariableBinding(new OID(oid), new Integer32(tp.getCvc() == null ? 0 : 1));
        case SNMPConstants.CVC_SUBJECT_URL:
          return new VariableBinding(new OID(oid),
                                     new OctetString(new CertificateDescription(tp.getCvcDescription()).getSubjectUrl()));
        case SNMPConstants.CVC_VALID_UNTIL:
          return getDateAndTime(oid, new TerminalData(tp.getCvc()).getExpirationDate());
        case SNMPConstants.CVC_TLS_CERTIFICATE_LINK_STATUS:
          return new VariableBinding(new OID(oid),
                                     new Integer32(new CvcTlsCheck(facade).checkCvcProvider(sp.getEntityID())
                                                                          .isCvcTlsMatch() ? 1 : 0));
        default:
      }
    }
    throw new IllegalArgumentException("Invalid OID: " + oid);
  }

  private static String nextOID(String oidStr)
  {
    // if we are in the table, go to next row if there is one
    if (oidStr.startsWith(SNMPConstants.PROVIDER_SPECIFIC_PREFIX))
    {
      Matcher matcher = SERVICE_PROVIDER_PREFIX_PATTERN.matcher(oidStr);
      if (matcher.find())
      {
        Integer id = Integer.valueOf(matcher.group(2));
        if (id + 1 < PoseidasConfigurator.getInstance().getCurrentConfig().getServiceProvider().size())
        {
          return oidStr.substring(0, oidStr.lastIndexOf('.') + 1) + (id + 1);
        }
      }
      // or go to the first row if we are just at the beginning
      else
      {
        try
        {
          return SNMPConstants.GetOID.getOID(oidStr).getValue() + ".0";
        }
        catch (IllegalArgumentException e)
        {
          // nothing
        }
      }
    }

    // go to the next valid OID after given oidStr
    SortedSet<OID> copy = new TreeSet<>(SNMPConstants.SORTED_OIDS);
    OID split = new OID(oidStr);
    copy.add(split);
    SortedSet<OID> tail = copy.tailSet(split);
    if (tail.size() > 1)
    {
      tail.remove(split);
      return tail.first().toString() + ".0";
    }

    throw new IllegalStateException("end of OIDs reached");
  }
}

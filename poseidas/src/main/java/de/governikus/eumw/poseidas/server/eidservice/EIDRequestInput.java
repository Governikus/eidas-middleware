/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import java.util.HashSet;
import java.util.Set;

import de.bund.bsi.eid20.PSCRequestType;
import de.bund.bsi.eid20.SpecificAttributeRequestType;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;


/**
 * A object of this class contains the input for a eID Request like a useID Request. This data is them
 * processed by the {@link EIDInternal} class.
 * 
 * @author Hauke Mehrtens
 */
public class EIDRequestInput
{

  private byte[] psk;

  private String transactionInfo;

  private String requestedCommunityIDPattern;

  private int requestedMinAge;

  private byte[] messagePSM;

  private PSCRequestType parametersPSC;

  private SpecificAttributeRequestType parametersSART;

  private String requestId;

  private String sessionId;

  private final boolean sessionIdMayDiffer;

  private CoreConfigurationDto config;

  private final boolean saml;

  private byte[] samlHash;

  private final Set<EIDKeys> requiredFields = new HashSet<>();

  private final Set<EIDKeys> optionalFields = new HashSet<>();

  /**
   * @param saml true if this is from SAML
   * @param sessionIdMayDiffer true if the {@link #sessionId} and {@link #requestId} are allowed to differ
   */
  public EIDRequestInput(boolean saml, boolean sessionIdMayDiffer)
  {
    this.saml = saml;
    this.sessionIdMayDiffer = sessionIdMayDiffer;
  }

  public void addRequiredFields(EIDKeys key)
  {
    requiredFields.add(key);
  }

  public void addOptionalFields(EIDKeys key)
  {
    optionalFields.add(key);
  }

  public void setRequestedCommunityIDPattern(String requestedCommunityIDPattern)
  {
    this.requestedCommunityIDPattern = requestedCommunityIDPattern;
  }

  public void setRequestedMinAge(int requestedMinAge)
  {
    this.requestedMinAge = requestedMinAge;
  }

  public String getRequestedCommunityIDPattern()
  {
    return requestedCommunityIDPattern;
  }

  public int getRequestedMinAge()
  {
    return requestedMinAge;
  }

  public byte[] getPsk()
  {
    return psk;
  }

  public String getTransactionInfo()
  {
    return transactionInfo;
  }

  public Set<EIDKeys> getRequiredFields()
  {
    return requiredFields;
  }

  public Set<EIDKeys> getOptionalFields()
  {
    return optionalFields;
  }

  public void setPsk(byte[] psk)
  {
    this.psk = psk;
  }

  public void setTransactionInfo(String transactionInfo)
  {
    this.transactionInfo = transactionInfo;
  }

  /**
   * This is the ID used by the service provider or SAML to access this session.
   */
  public String getRequestId()
  {
    return requestId;
  }

  /**
   * This is the ID used by the service provider or SAML to access this session.
   */
  public void setRequestId(String requestId)
  {
    this.requestId = requestId;
  }

  /**
   * This is the ID used by the eID Client to talk to the PAOS servlet.
   */
  public String getSessionId()
  {
    return sessionId;
  }

  /**
   * This is the ID used by the eID Client to talk to the PAOS servlet.
   */
  public void setSessionId(String sessionId)
  {
    this.sessionId = sessionId;
  }

  public CoreConfigurationDto getConfig()
  {
    return config;
  }

  public void setConfig(CoreConfigurationDto config)
  {
    this.config = config;
  }

  public boolean isSaml()
  {
    return saml;
  }

  public boolean isSessionIdMayDiffer()
  {
    return sessionIdMayDiffer;
  }

  public byte[] getSamlHash()
  {
    return samlHash;
  }

  public void setSamlHash(byte[] samlHash)
  {
    this.samlHash = samlHash;
  }

  public byte[] getMessagePSM()
  {
    return messagePSM;
  }

  public void setMessagePSM(byte[] messagePSM)
  {
    this.messagePSM = messagePSM;
  }

  public void setParametersPSC(PSCRequestType pscRequest)
  {
    this.parametersPSC = pscRequest;
  }

  public PSCRequestType getParametersPSC()
  {
    return this.parametersPSC;
  }

  public void setParametersSART(SpecificAttributeRequestType parametersSART)
  {
    this.parametersSART = parametersSART;
  }

  public SpecificAttributeRequestType getParametersSART()
  {
    return this.parametersSART;
  }
}

/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.ps;

import java.util.List;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PSInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PSPublicKeyInfo;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionParameter;


/**
 * Pseudonymous signature input parameter.
 */
public class PseudonymousSignatureParameter implements FunctionParameter
{

  /**
   * Pseudonymous Signature Info (from SecurityInfos).
   */
  private final PSInfo psInfo;

  /**
   * Pseudonymous Signature Public Key Info (from SecurityInfos).
   */
  private final PSPublicKeyInfo psPubKeyInfo;

  /**
   * Pseudonymous signature key.
   */
  private final byte[] pseudonymousSignatureKey;

  /**
   * Input to signature (usually PSM, can also be used for PSA).
   */
  private byte[] signatureInput = null;

  /**
   * List fo file IDs to be included for signature of credentials (PSC).
   */
  private final List<byte[]> fidList;

  /**
   * Flag indicating if terminal specific attribute is to be included in PSC.
   */
  private final boolean includeSpecificAttribute;

  /**
   * Constructor.
   * 
   * @param psInfo {@link PSInfo}, <code>null</code> not permitted
   * @param psKey pseudonymous signature key, <code>null</code> or empty not permitted
   * @param signatureInput for PSM, <code>null</code> possible
   * @param fidList list of fileIDs for PSC, <code>null</code> possible
   * @param includeSpecific flag indicating if terminal specific attribute is to be included in PSC, ignored
   *          if signature other than PSC is used
   * @throws IllegalArgumentException
   */
  public PseudonymousSignatureParameter(PSInfo psInfo,
                                        PSPublicKeyInfo psPubKeyInfo,
                                        byte[] psKey,
                                        byte[] signatureInput,
                                        List<byte[]> fidList,
                                        boolean includeSpecific)
  {
    AssertUtil.notNull(psInfo, "PseudonymousSignatureInfo");
    AssertUtil.notNull(psPubKeyInfo, "PseudonymousSignaturePublicKeyInfo");
    AssertUtil.notNullOrEmpty(psKey, "pseudonymous signature key");
    this.psInfo = psInfo;
    this.psPubKeyInfo = psPubKeyInfo;
    this.pseudonymousSignatureKey = psKey;
    this.signatureInput = signatureInput;
    this.fidList = fidList;
    this.includeSpecificAttribute = includeSpecific;
  }

  /**
   * Gets {@link PSInfo}.
   * 
   * @return {@link PSInfo}
   */
  public PSInfo getPsInfo()
  {
    return this.psInfo;
  }

  /**
   * Gets {@link PSPublicKeyInfo}.
   * 
   * @return {@link PSPublicKeyInfo}
   */
  public PSPublicKeyInfo getPsPubKeyInfo()
  {
    return this.psPubKeyInfo;
  }

  /**
   * Gets pseudonymous signature key.
   * 
   * @return pseudonymous signature key
   */
  public byte[] getPseudonymousSignatureKey()
  {
    return this.pseudonymousSignatureKey;
  }

  /**
   * Gets input to signature.
   * 
   * @return signature input
   */
  public byte[] getSignatureInput()
  {
    return this.signatureInput;
  }

  /**
   * Gets list of file IDs for PSC.
   * 
   * @return list of file IDs for PSC
   */
  public List<byte[]> getFidList()
  {
    return this.fidList;
  }

  /**
   * Gets flag indicating if terminal specific attribute is to be included in PSC.
   * 
   * @return Flag indicating if terminal specific attribute is to be included in PSC
   */
  public boolean isIncludeSpecificAttribute()
  {
    return this.includeSpecificAttribute;
  }
}

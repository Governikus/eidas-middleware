/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.npa;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import de.governikus.autent.asn1.OIDConstants;
import de.governikus.autent.asn1.si.AlgorithmIdentifier;
import de.governikus.autent.asn1.si.ChipAuthenticationDomainParameterInfo;
import de.governikus.autent.asn1.si.ChipAuthenticationInfo;
import de.governikus.autent.asn1.si.ChipAuthenticationPublicKeyInfo;
import de.governikus.autent.asn1.si.PACEDomainParameterInfo;
import de.governikus.autent.asn1.si.PACEInfo;
import de.governikus.autent.asn1.si.TerminalAuthenticationInfo;
import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * Selector for several kinds of info as {@link PACEInfo}, {@link PACEDomainParameterInfo},
 * {@link TerminalAuthenticationInfo}, {@link ChipAuthenticationInfo} and {@link ChipAuthenticationDomainParameterInfo}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
@Slf4j
public final class InfoSelector
{

  /**
   * Current lowest domain parameter ID.
   */
  public static final int MIN_DOMAIN_PARAMETER_ID = 8;

  /**
   * Current highest domain parameter ID.
   */
  public static final int MAX_DOMAIN_PARAMETER_ID = 18;

  /**
   * Selects a set of domain parameters for CA.
   *
   * @param setCADomainParameterInfos set of available {@link ChipAuthenticationDomainParameterInfo}, <code>null</code>
   *          or empty not permitted
   * @return selected {@link ChipAuthenticationDomainParameterInfo}, <code>null</code> if no acceptable selection
   *         possible
   * @throws IllegalArgumentException if given set <code>null</code> or empty
   */
  private static ChipAuthenticationDomainParameterInfo selectCADomainParameterInfo(Collection<ChipAuthenticationDomainParameterInfo> setCADomainParameterInfos)
  {
    AssertUtil.notNullOrEmpty(setCADomainParameterInfos, "list of domain parameter info");

    // only use standardized parameters in specified range
    for ( ChipAuthenticationDomainParameterInfo info : setCADomainParameterInfos )
    {
      AlgorithmIdentifier ai = info.getDomainParameter();
      if (OIDConstants.OID_STANDARDIZED_DOMAIN_PARAMETERS.equals(ai.getAlgorithm())
          && ai.getParameterId().compareTo(BigInteger.valueOf(MIN_DOMAIN_PARAMETER_ID)) >= 0
          && ai.getParameterId().compareTo(BigInteger.valueOf(MAX_DOMAIN_PARAMETER_ID)) <= 0)
      {
        return info;
      }
    }
    return null;
  }

  /**
   * Selects Chip Authentication variant to be used.
   *
   * @param listCAInfos list of {@link ChipAuthenticationInfo} from which to select, <code>null</code> or empty not
   *          permitted
   * @return selected {@link ChipAuthenticationData}, <code>null</code> if no selection possible
   * @throws IllegalArgumentException if any parameter <code>null</code> or empty
   */
  public static ChipAuthenticationData selectCAData(Collection<ChipAuthenticationInfo> listCAInfos,
                                                    Collection<ChipAuthenticationDomainParameterInfo> listCaDomParams)
    throws IOException
  {
    AssertUtil.notNullOrEmpty(listCAInfos, "list of chip authentication info");
    AssertUtil.notNullOrEmpty(listCaDomParams, "list of chip authentication domain parameter info");

    Map<ChipAuthenticationDomainParameterInfo, ChipAuthenticationInfo> matchingDomParamInfoMap = new HashMap<>();
    for ( ChipAuthenticationInfo caInfo : listCAInfos )
    {
      for ( ChipAuthenticationDomainParameterInfo cadpi : listCaDomParams )
      {
        if (caInfo.getVersion().hasValue(2)
            && ((caInfo.getKeyId() == null && cadpi.getKeyId() == null)
                || (caInfo.getKeyId() != null && caInfo.getKeyId().equals(cadpi.getKeyId()))))
        {
          matchingDomParamInfoMap.put(cadpi, caInfo);
        }
      }
    }

    ChipAuthenticationDomainParameterInfo selectedDomainParams = selectCADomainParameterInfo(matchingDomParamInfoMap.keySet());
    if (selectedDomainParams != null)
    {
      return new ChipAuthenticationData(matchingDomParamInfoMap.get(selectedDomainParams), selectedDomainParams);
    }
    return null;
  }

  /**
   * Selects {@link PACEInfo} to be used.
   *
   * @param listPACEInfos list of {@link PACEInfo} from which to select, <code>null</code> or empty list not permitted
   * @return selected {@link PACEInfo}
   * @throws IllegalArgumentException if given list <code>null</code> or empty
   */
  public static PACEInfo selectPACEInfo(Collection<PACEInfo> listPACEInfos)
  {
    AssertUtil.notNullOrEmpty(listPACEInfos, "paceList");

    // if only one element present, use it
    if (listPACEInfos.size() == 1)
    {
      return listPACEInfos.iterator().next();
    }

    for ( PACEInfo info : listPACEInfos )
    {
      int pID = info.getParameterId().intValueExact();

      // prefer standard domain parameters
      if (pID >= MIN_DOMAIN_PARAMETER_ID && pID <= MAX_DOMAIN_PARAMETER_ID)
      {
        return info;
      }
    }
    return listPACEInfos.iterator().next();
  }


  /**
   * Selects {@link ChipAuthenticationPublicKeyInfo} to be used.
   *
   * @param caPubKeyList list of {@link ChipAuthenticationPublicKeyInfo} from which to select, <code>null</code> or
   *          empty not permitted
   * @param caInfo previously selected {@link ChipAuthenticationInfo}, <code>null</code> not permitted
   * @return selected {@link ChipAuthenticationPublicKeyInfo}, <code>null</code> if no selection possible
   * @throws IllegalArgumentException if any parameter <code>null</code> or empty
   */
  public static ChipAuthenticationPublicKeyInfo selectCAPubKeyInfo(Collection<ChipAuthenticationPublicKeyInfo> caPubKeyList,
                                                                   ChipAuthenticationInfo caInfo)
  {
    AssertUtil.notNullOrEmpty(caPubKeyList, "list of chip authentication public keys");
    AssertUtil.notNull(caInfo, "chip authentication info");

    if (caInfo.getKeyId() != null)
    {
      for ( ChipAuthenticationPublicKeyInfo caPK : caPubKeyList )
      {
        if (caInfo.getKeyId().equals(caPK.getKeyId()))
        {
          return caPK;
        }
      }
      // coming here would mean inconsistent data
      log.debug("No matching ChipAuthenticationPublicKeyInfo found for keyId {}", caInfo.getKeyId());
      return null;
    }

    if (caPubKeyList.size() == 1)
    {
      return caPubKeyList.iterator().next();
    }

    return null;
  }

  /**
   * Constructor.
   */
  private InfoSelector()
  {
    super();
  }

  /**
   * Container class holding a pair of {@link ChipAuthenticationData} and matching
   * {@link ChipAuthenticationDomainParameterInfo}.
   */
  @Getter
  public static class ChipAuthenticationData
  {

    private final ChipAuthenticationInfo caInfo;

    private final ChipAuthenticationDomainParameterInfo caDomParamInfo;


    private ChipAuthenticationData(ChipAuthenticationInfo caInfo, ChipAuthenticationDomainParameterInfo caDomParamInfo)
    {
      super();
      AssertUtil.notNull(caInfo, "ca info");
      AssertUtil.notNull(caDomParamInfo, "ca domain parameter info");
      this.caInfo = caInfo;
      this.caDomParamInfo = caDomParamInfo;
    }

  }
}

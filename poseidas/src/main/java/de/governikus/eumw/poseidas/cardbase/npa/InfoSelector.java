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
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.AlgorithmIdentifier;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationDomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.ChipAuthenticationPublicKeyInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.DomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PACEDomainParameterInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.PACEInfo;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.TerminalAuthenticationInfo;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;


/**
 * Selector for several kinds of info as {@link PACEInfo}, {@link PACEDomainParameterInfo}, {@link DomainParameterInfo},
 * {@link TerminalAuthenticationInfo}, {@link ChipAuthenticationInfo} and {@link ChipAuthenticationDomainParameterInfo}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class InfoSelector
{

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
      try
      {
        AlgorithmIdentifier ai = info.getDomainParameter();
        if (OIDConstants.OID_STANDARDIZED_DOMAIN_PARAMETERS.equals(ai.getAlgorithm())
            && ai.getParameterID() >= DomainParameterInfo.MIN_DOMAIN_PARAMETER_ID
            && ai.getParameterID() <= DomainParameterInfo.MAX_DOMAIN_PARAMETER_ID)
        {
          return info;
        }
      }
      catch (IOException e)
      {
        // nothing
      }
    }
    return null;
  }

  /**
   * Selects Chip Authentication variant to be used.
   *
   * @param listCAInfos list of {@link ChipAuthenticationInfo} from which to select, <code>null</code> or empty not
   *          permitted
   * @param caDomainParameterInfo previously selected {@link ChipAuthenticationDomainParameterInfo}, <code>null</code>
   *          not permitted
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
        if (caInfo.getVersion() == 2 && ((caInfo.getKeyID() == null && cadpi.getKeyID() == null)
                                         || (caInfo.getKeyID() != null && caInfo.getKeyID().equals(cadpi.getKeyID()))))
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
      Integer pID = null;
      try
      {
        pID = info.getParameterID();
      }
      catch (IOException e)
      {
        continue;
      }

      // prefer standard domain parameters
      if (pID != null && pID >= DomainParameterInfo.MIN_DOMAIN_PARAMETER_ID
          && pID <= DomainParameterInfo.MAX_DOMAIN_PARAMETER_ID)
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

    try
    {
      if (caInfo.getKeyID() != null)
      {
        for ( ChipAuthenticationPublicKeyInfo caPK : caPubKeyList )
        {
          try
          {
            if (caInfo.getKeyID().equals(caPK.getKeyID()))
            {
              return caPK;
            }
          }
          catch (IOException e)
          {
            // nothing
          }
        }
        // coming here would mean inconsistent data
        return null;
      }
    }
    catch (IOException e)
    {
      // nothing to do
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

    public ChipAuthenticationInfo getCaInfo()
    {
      return this.caInfo;
    }

    public ChipAuthenticationDomainParameterInfo getCaDomParamInfo()
    {
      return this.caDomParamInfo;
    }
  }
}

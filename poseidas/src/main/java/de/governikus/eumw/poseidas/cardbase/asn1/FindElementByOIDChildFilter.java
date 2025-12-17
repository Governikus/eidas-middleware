/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.cardbase.Filter;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCPath;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;


/**
 * Filter for finding ASN.1 child with OID child matching special OID.
 *
 * @see ECCVCertificate
 * @see ECCVCPath
 * @see ECCVCPath#TERMINAL_SECTOR_RI_FILTER
 * @see ECCVCPath#CERTIFICATE_DESCRIPTION_FILTER
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class FindElementByOIDChildFilter implements Filter<ASN1>
{

  /**
   * LOGGER.
   */
  private static final Log LOG = LogFactory.getLog(FindElementByOIDChildFilter.class.getName());

  // oid
  private final String oidString;

  /**
   * Constructor.
   *
   * @param oidString oid of child to be matched
   */
  public FindElementByOIDChildFilter(String oidString)
  {
    super();
    this.oidString = oidString;
  }

  /** {@inheritDoc} */
  @Override
  public boolean accept(ASN1 asn1)
  {
    boolean result = false;
    if (asn1 != null)
    {
      try
      {
        ASN1[] children = asn1.getChildElements();
        if (children != null)
        {
          for ( ASN1 child : children )
          {
            if (child.getDTag().intValue() == ASN1Constants.UNIVERSAL_TAG_OID)
            {
              OID oid = new OID(child.getEncoded());
              if (oid.getOIDString().equals(this.oidString))
              {
                result = true;
                break;
              }
            }
          }
        }
      }
      catch (IOException e)
      {
        LOG.debug("checking ASN.1 object for child with OID failed: " + e.getMessage());
      }
    }
    return result;
  }

  /** {@inheritDoc} */
  @Override
  public Class<ASN1> getFilterClass()
  {
    return ASN1.class;
  }
}

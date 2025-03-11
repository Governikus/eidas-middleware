/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1;

import java.math.BigInteger;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class ASN1Integer extends AbstractASN1Encoder
{

  private Integer intValue = null;

  /**
   * Default Encoder Constructor.
   */
  public ASN1Integer()
  {
    super(ASN1Constants.UNIVERSAL_TAG_INTEGER, new byte[0]);
  }

  public Integer getInteger()
  {
    if (this.intValue == null)
    {
      try
      {
        this.intValue = new BigInteger(this.getValue()).intValueExact();
      }
      catch (NullPointerException | NumberFormatException e)
      {
        if (log.isDebugEnabled())
        {
          log.debug("Failed to parse integer value", e);
        }
        this.intValue = null;
      }
    }
    return this.intValue;
  }

  @Override
  protected void update()
  {
    this.intValue = null;
  }

  @Override
  public boolean equals(Object object)
  {
    return super.equals(object);
  }

  @Override
  public int hashCode()
  {
    return super.hashCode();
  }
}

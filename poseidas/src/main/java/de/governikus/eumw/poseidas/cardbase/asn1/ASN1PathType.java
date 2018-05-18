/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1;



/**
 * Enum for types of ASN1Path - for validity checks of ASN.1 objects by checking existing of child elements.
 * 
 * @see ASN1Path
 * @author Jens Wothe, jw@bos-bremen.de
 */
public enum ASN1PathType
{

  /**
   * no information - child element might or might not exist, does not affect validity
   */
  NO_INFORMATION("", "", ""),
  /**
   * for valid ASN.1 a child at path must exist
   */
  REQUIRED("m", "MUST / SHALL", "required"),
  /**
   * for valid ASN.1 a child at path must not exist
   */
  NOT("x", "MUST NOT / SHALL NOT", "-"),
  /**
   * for valid ASN.1 a child at path can exist
   */
  RECOMMENDED("r", "SHOULD", "recommended"),
  /**
   * for valid ASN.1 a child at path can exist
   */
  OPTIONAL("o", "MAY", "optional"),
  /**
   * for valid ASN.1 a child at path can exist
   */
  CONDITIONAL("c", "-", "conditional");

  private String abbreviation = null;

  private String keyWord1 = null;

  private String keyWord2 = null;

  /**
   * Constructor.
   * 
   * @param abbreviation abbreviation
   * @param keyWord1 key word (variant 1)
   * @param keyWord2 key word (variant 2)
   */
  private ASN1PathType(String abbreviation, String keyWord1, String keyWord2)
  {
    this.abbreviation = abbreviation;
    this.keyWord1 = keyWord1;
    this.keyWord2 = keyWord2;

  }

  /**
   * Gets abbreviation.
   * 
   * @return abbreviation
   */
  public String getAbbreviation()
  {
    return abbreviation;
  }

  /**
   * Gets key word (variant 1).
   * 
   * @return key word
   */
  public String getKeyWord1()
  {
    return keyWord1;
  }


  /**
   * Gets key word (variant 2).
   * 
   * @return key word
   */
  public String getKeyWord2()
  {
    return keyWord2;
  }

}

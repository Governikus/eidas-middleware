/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.model.signeddata;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;


/**
 * A single defect is defined by one or more known defects.<br/>
 * <code>
 * <br />
 * KnownDefect :: = SEQUENCE{<br />
 *   defectType OBJECT IDENTIFIER,<br />
 *   parameters ANY defined by defectType OPTIONAL<br />
 * }
 * </code>
 *
 * @author Ole Behrens
 */
public class DefectKnown
{

  private static final Log LOGGER = LogFactory.getLog(DefectKnown.class.getName());

  private DefectType defectType;

  private DefectKnownParameter defectParameter;

  /**
   * There are three types of defect documents
   */
  private enum DefectCategory
  {
    AUTHENTICATION_DEFECT, APPLICATION_DEFECT, DOCUMENT_DEFECT
  }

  /**
   * The defect categories for a known defect<br>
   * Note that application defects are split into ePassport and eID
   */
  private enum DefectCategoryID
  {
    ID_AUTH_DEFECT("id-AuthDefect",
                   "Authentication Defects",
                   "Category describes defects realated to"
                     + " Passive Authentication, Chip Authentication and Active Authentication."
                     + " If a document is affected by an authentication defect with unknown interpretation,"
                     + " the electronic part of the document MUST NOT be used",
                   DefectCategory.APPLICATION_DEFECT),
    ID_EPASSPORT_DEFECT("id-ePassportDefect",
                        "Personalisation Defects of the ePassport Application",
                        "Category describes defects related to"
                          + " the personalisation of the ePassport application."
                          + " If a document is affected by an personalization defect of the"
                          + " Passport application with unknown interpretation,"
                          + "the ePassport application MUST NOT be used",
                        DefectCategory.APPLICATION_DEFECT),
    ID_EID_DEFECT("id-eIDDefect",
                  "Personalisation Defects of the eID Application",
                  "Category describes defects related to the personalisation of the eID application."
                    + " If a document is affected by an personalization defect of the eID application"
                    + " with unknown interpretation, the eID application SHOULD NOT be used",
                  DefectCategory.APPLICATION_DEFECT),
    ID_DOCUMENT_DEFECT("id-DocumentDefect",
                       "General Document Defects",
                       "Category describes defects related to the document in general."
                         + " If a document is affected by a general defect with unknown interpretation, "
                         + " the electronic part of the document SHOULD NOT be used",
                       DefectCategory.DOCUMENT_DEFECT);

    private final String name;

    private final String headline;

    private final String description;

    private final DefectCategory category;

    private final int oid;

    private DefectCategoryID(String name, String headline, String description, DefectCategory category)
    {
      this.name = name;
      this.headline = headline;
      this.description = description;
      this.category = category;
      this.oid = ordinal() + 1;
    }

    @Override
    public String toString()
    {
      return headline + " (" + name + ")";
    }

    /**
     * Detailed informations about this specific defect
     *
     * @return informations as string
     */
    public String toStringDetail()
    {
      StringBuilder detail = new StringBuilder(System.lineSeparator());
      detail.append("  [")
            .append(name())
            .append(" - ")
            .append(category.name())
            .append(']')
            .append(System.lineSeparator())
            .append("Name       : ")
            .append(name)
            .append(System.lineSeparator())
            .append("Headline   : ")
            .append(headline)
            .append(System.lineSeparator())
            .append("Description: ")
            .append(description)
            .append(System.lineSeparator())
            .append("OID        : ")
            .append(ordinal());
      return detail.toString();
    }

    /**
     * Get the single identifier. NOTE: Do not return the full defect list OID
     *
     * @return OID as integer
     */
    private int getOID()
    {
      return oid;
    }
  }

  /**
   * DefectType describes a known defect in detail
   */
  public enum DefectType
  {
    ID_CERT_REVOKED(DefectCategoryID.ID_AUTH_DEFECT,
                    "id-CertRevoked",
                    "Document Signer Certificate Revoked",
                    "The private key of the Document Signer is compromised."
                      + " The electronic part of the document MUST NOT be used",
                    1,
                    new char[]{'m', 'm', 'm'},
                    true),
    ID_CERT_REPLACED(DefectCategoryID.ID_AUTH_DEFECT,
                     "id-CertReplaced",
                     "Document Signer Certificate Malformed",
                     "The Document Signer Certificate cannot be"
                       + " decoded correctly using standardized mechanisms."
                       + " A replacement certificate is provided (parameters)",
                     2,
                     new char[]{'m', 'm', 'm'},
                     true),
    ID_CHIP_AUTH_KEY_REVOKED(DefectCategoryID.ID_AUTH_DEFECT,
                             "id-ChipAuthKeyRevoked",
                             "Chip Authentication Private Keys Compromised",
                             "The Chip Authentication Private Keys habe been compromised."
                               + " Chip Authentication SHOULD be used, but the successful execution does"
                               + " neither guarantee that the document nor the transerred data is genuine",
                             3,
                             new char[]{'m', 'm', 'm'},
                             false),
    ID_ACTIVE_AUTH_KEY_REVOKED(DefectCategoryID.ID_AUTH_DEFECT,
                               "id-ActiveAuthKeyRevoked",
                               "Active Authentication Private Keys Compromised",
                               "The Active Authentication Private Keys habe been compromised."
                                 + " Active Authentication SHOULD be used, but the successful execution does"
                                 + " neither guarantee that the document nor the transerred data is genuine",
                               4,
                               new char[]{'m', 'm', 'm'},
                               false),
    ID_EPASSPORT_DG_MALFORMED(DefectCategoryID.ID_EPASSPORT_DEFECT,
                              "id-ePassportDGMalformed",
                              "Data Group Malformed",
                              "The indicated data groups might be incorrectly encoded."
                                + "In this case the data group SHOULD be ignored"
                                + " and manual inspection is REQUIRED",
                              1,
                              new char[]{'m', 'm', 'o'},
                              true),
    ID_SOD_INVALID(DefectCategoryID.ID_EPASSPORT_DEFECT,
                   "id-SODInvalid",
                   "Document Security Object Malformed",
                   "The validation of the Document Security Object might fail."
                     + " In this case the electronic part of the document MUST NOT be used",
                   2,
                   new char[]{'m', 'm', 'o'},
                   false),
    ID_EID_DG_MALFORMED(DefectCategoryID.ID_EID_DEFECT,
                        "id-eIDDGMalformed",
                        "Data Group Malformed",
                        "The indicated data groups might be incorretly encoded. "
                          + " In this case the data group SHOULD be ignored",
                        1,
                        new char[]{'m', 'o', 'r'},
                        true),
    ID_EID_INTEGRITY(DefectCategoryID.ID_EID_DEFECT,
                     "id-eIDIntegrity",
                     "Application Integrity Uncertain",
                     "The integrity of unsigned data groups is not guaranteed",
                     2,
                     new char[]{'m', 'o', 'r'},
                     false),
    ID_CARD_SECURITY_MALFORMED(DefectCategoryID.ID_DOCUMENT_DEFECT,
                               "id-CardSecurityMalformed",
                               "Card Security Object Malformed",
                               "The Card Security Object is incorrectly encoded. "
                                 + "A corrected Card Security Object is provided that SHOULD be used instead",
                               1,
                               new char[]{'m', 'o', 'm'},
                               true),

    ID_CHIP_SECURITY_MALFORMED(DefectCategoryID.ID_DOCUMENT_DEFECT,
                               "id-ChipSecurityMalformed",
                               "Card Security Object Malformed",
                               "The Chip Security Object might be incorrectly encoded."
                                 + " The Card Security Object SHOULD be used instead",
                               2,
                               new char[]{'m', 'o', 'r'},
                               false),
    ID_POWER_DOWN_REQ(DefectCategoryID.ID_DOCUMENT_DEFECT,
                      "id-PowerDownReq",
                      "Powerdown Required",
                      "The chip denies multiple successive authentication"
                        + " using the General Authentication Procedure."
                        + " Either the reader MUST powerdown the chip or the document MUST be removed"
                        + " from the reader in between two authentications",
                      3,
                      new char[]{'m', 'o', 'm'},
                      false);

    private DefectCategoryID categoryID;

    private String name;

    private String headline;

    private String description;

    private int oid;

    private char[] purposes;

    private boolean requiresParameters;

    private DefectType(DefectCategoryID categoryID,
                       String name,
                       String headline,
                       String description,
                       int oid,
                       char[] purposes,
                       boolean requiresParameters)
    {
      this.categoryID = categoryID;
      this.name = name;
      this.headline = headline;
      this.description = description;
      this.oid = oid;
      this.purposes = purposes;
      this.requiresParameters = requiresParameters;
    }

    /**
     * Get the name of this defect type
     *
     * @return the name of the defect type
     */
    public String getName()
    {
      return name;
    }

    /**
     * Specification headline for this defect type
     *
     * @return headline as string
     */
    public String getHeadline()
    {
      return headline;
    }

    /**
     * Specification description for this defect type
     *
     * @return text as string
     */
    public String getDescription()
    {
      return description;
    }

    /**
     * Get the full OID for this known defect
     *
     * @return OID as string
     */
    public String getOID()
    {
      return DefectList.OID_DEFECT_LIST + "." + categoryID.getOID() + "." + oid;
    }

    /**
     * Get the purposes for this defect type. NOTE for EID only the commercial part should be used
     * (purposes[2])
     *
     * @return the purposes mapping
     */
    public char[] getPurposes()
    {
      return purposes.clone();
    }

    /**
     * Get the category of this defect type
     *
     * @return category for this type
     */
    public DefectCategoryID getCategory()
    {
      return categoryID;
    }

    @Override
    public String toString()
    {
      return headline + " (" + name + ") - " + categoryID.toString();
    }

    /**
     * Get a more detailed information text for this defect type
     *
     * @return text as string
     */
    public String toStringDetail()
    {
      StringBuilder detail = new StringBuilder(System.lineSeparator());
      detail.append("  [")
            .append(name())
            .append(" - ")
            .append(categoryID.name())
            .append(']')
            .append(System.lineSeparator())
            .append("Name       : ")
            .append(name)
            .append(System.lineSeparator())
            .append("Headline   : ")
            .append(headline)
            .append(System.lineSeparator())
            .append("Description: ")
            .append(description)
            .append(System.lineSeparator())
            .append("OID        : ")
            .append(getOID())
            .append(System.lineSeparator())
            .append("Category   : ")
            .append(categoryID.toString());
      return detail.toString();
    }

    /**
     * Get all informations about this defect type including category trace
     *
     * @return text as string
     */
    public String toStringTrace()
    {
      return toStringDetail() + categoryID.toStringDetail() + System.lineSeparator();
    }

    /**
     * Indicates if this defect requires parameters to be handled
     *
     * @return true if parameters are required for this defect type
     */
    private boolean requiresParameters()
    {
      return requiresParameters;
    }
  }

  /**
   * Known defect to set the behavior for a defect
   *
   * @param knownDefect ASN1 representation
   * @throws IOException if parsing fails
   */
  DefectKnown(ASN1Sequence knownDefect) throws IOException
  {
    // Check if min. one element is available to identify the defect type
    int size = knownDefect.size();
    if (size < 1)
    {
      throw new IOException("ASN1Sequence to get known defect from has no entry");
    }
    ASN1Encodable objectAt = knownDefect.getObjectAt(0);
    if (objectAt instanceof ASN1ObjectIdentifier)
    {
      ASN1ObjectIdentifier defectTypeOID = (ASN1ObjectIdentifier)objectAt;
      // Get the defect by OID
      setDefectType(defectTypeOID);
    }
    else
    {
      throw new IOException("Expected ASN1ObjectIdentifier not available. Found: " + objectAt);
    }

    // Second step is to identify parameters if they are required by defect type
    if (requiresParamters())
    {
      // Check if a second element is available for parameters
      if (size < 2)
      {
        throw new IOException("Defect type requires parameters"
                              + " but no more elements are available in sequence");
      }
      objectAt = knownDefect.getObjectAt(1);
      setDefectParameter(objectAt);
      if (size > 2)
      {
        throw new IOException("Known defect data is overload. Elements left: " + (size - 2));
      }
    }
    LOGGER.debug("Type for this known defect: " + defectType.toStringTrace());
  }

  /**
   * If existing return the defect parameter from this known defect
   *
   * @return parameters
   */
  public DefectKnownParameter getParameter()
  {
    return defectParameter;
  }

  /**
   * Get the defect type representing behavior of this known defect
   *
   * @return defect type
   */
  public DefectType getDefectType()
  {
    return defectType;
  }

  /**
   * Get the name for this known defect
   *
   * @return name as string
   */
  public String getKnownDefectName()
  {
    return defectType.getName();
  }

  /**
   * Get the name set in specification with category name
   *
   * @return name as string
   */
  public String getKnownDefectSpecificationName()
  {
    return defectType.name() + " - " + defectType.getCategory().name();
  }

  /**
   * Get a description for this known defect
   *
   * @return text as string
   */
  public String getKnownDefectDescription()
  {
    return defectType.getDescription();
  }

  /**
   * Checks if this KnownDefect is of a specific type
   *
   * @param type to be checked for
   * @return true if types are matching
   */
  boolean isType(DefectType type)
  {
    return type.equals(this.defectType);
  }

  /**
   * Indicates if the known defect has parameters beyond the OID
   *
   * @return true if parameters are required
   */
  private boolean requiresParamters()
  {
    return defectType.requiresParameters();
  }

  /**
   * Set the inner defect type for this known defect
   *
   * @param defectTypeOID identifying the known defect
   * @throws IOException if no defect type is found for this known defect
   */
  private void setDefectType(String defectTypeOID) throws IOException
  {
    for ( DefectType dt : DefectType.values() )
    {
      if (defectTypeOID.equals(dt.getOID()))
      {
        this.defectType = dt;
      }
    }
    if (this.defectType == null)
    {
      throw new IOException("Defect type OID unknown: " + defectTypeOID);
    }
  }

  /**
   * Set the inner defect type for this known defect
   *
   * @param defectTypeOID identifying the known defect after getting the IOD value
   * @throws IOException if no defect type is found for this known defect
   */
  private void setDefectType(ASN1ObjectIdentifier defectTypeOID) throws IOException
  {
    setDefectType(defectTypeOID.getId());
  }

  /**
   * Set a defect parameter for the known defect. Parameters are only required by some defects
   *
   * @param parameter to be parsed
   * @throws IOException
   */
  private void setDefectParameter(ASN1Encodable parameter) throws IOException
  {
    defectParameter = new DefectKnownParameter(defectType, parameter);
  }

}

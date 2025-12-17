/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.constants;


/**
 * Constants for eID application.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, arne.stahlbock@governikus.com
 */
public final class EIDConstants
{

  /**
   * AID of eID application: <code>#e80704007f00070302</code>.
   */
  public static final String EID_APPLICATION_AID = "e80704007f00070302";

  /**
   * Name of DG01: Document Type.
   *
   * @see #EID_FID_DG01_DOCUMENT_TYPE
   * @see #EID_SFID_DG01_DOCUMENT_TYPE
   */
  public static final String EID_NAME_DG01_DOCUMENT_TYPE = "Document Type";

  /**
   * Name of DG02: Issuing State.
   *
   * @see #EID_FID_DG02_ISSUING_STATE
   * @see #EID_SFID_DG02_ISSUING_STATE
   */
  public static final String EID_NAME_DG02_ISSUING_STATE = "Issuing State, Region and Municipality";

  /**
   * Name of DG03: Date of Expiry.
   *
   * @see #EID_FID_DG03_DATE_OF_EXPIRY
   * @see #EID_SFID_DG03_DATE_OF_EXPIRY
   */
  public static final String EID_NAME_DG03_DATE_OF_EXPIRY = "Date of Expiry";

  /**
   * Name of DG04: Given Names.
   *
   * @see #EID_FID_DG04_GIVEN_NAMES
   * @see #EID_SFID_DG04_GIVEN_NAMES
   */
  public static final String EID_NAME_DG04_GIVEN_NAMES = "Given Names";

  /**
   * Name of DG05: Family Names.
   *
   * @see #EID_FID_DG05_FAMILY_NAMES
   * @see #EID_SFID_DG05_FAMILY_NAMES
   */
  public static final String EID_NAME_DG05_FAMILY_NAMES = "Family Names";

  /**
   * Name of DG06: Nom de Plume.
   *
   * @see #EID_FID_DG06_NOM_DE_PLUME
   * @see #EID_SFID_DG06_NOM_DE_PLUME
   */
  public static final String EID_NAME_DG06_NOM_DE_PLUME = "Nom de Plume";

  /**
   * Name of DG07: Academic Title.
   *
   * @see #EID_FID_DG07_ACADEMIC_TITLE
   * @see #EID_SFID_DG07_ACADEMIC_TITLE
   */
  public static final String EID_NAME_DG07_ACADEMIC_TITLE = "Academic Title";

  /**
   * Name of DG08: Date of Birth.
   *
   * @see #EID_FID_DG08_DATE_OF_BIRTH
   * @see #EID_SFID_DG08_DATE_OF_BIRTH
   */
  public static final String EID_NAME_DG08_DATE_OF_BIRTH = "Date of Birth";

  /**
   * Name of DG09: Place of Birth.
   *
   * @see #EID_FID_DG09_PLACE_OF_BIRTH
   * @see #EID_SFID_DG09_PLACE_OF_BIRTH
   */
  public static final String EID_NAME_DG09_PLACE_OF_BIRTH = "Place of Birth";

  /**
   * Name of DG10: Nationality.
   *
   * @see #EID_FID_DG10_NATIONALITY
   * @see #EID_SFID_DG10_NATIONALITY
   */
  public static final String EID_NAME_DG10_NATIONALITY = "Nationality";

  /**
   * Name of DG11: Sex.
   *
   * @see #EID_FID_DG11_SEX
   * @see #EID_SFID_DG11_SEX
   */
  public static final String EID_NAME_DG11_SEX = "Sex";

  /**
   * Name of DG12: Optional Data R.
   *
   * @see #EID_FID_DG12_OPTIONAL_DATA_R
   * @see #EID_SFID_DG12_OPTIONAL_DATA_R
   */
  public static final String EID_NAME_DG12_OPTIONAL_DATA_R = "Optional Data";

  /**
   * Name of DG13: Birth Name.
   *
   * @see #EID_FID_DG13_BIRTH_NAME
   * @see #EID_SFID_DG13_BIRTH_NAME
   */
  public static final String EID_NAME_DG13_BIRTH_NAME = "Birth Name";

  /**
   * Name of DG14: Written Signature.
   *
   * @see #EID_FID_DG14_WRITTEN_SIGNATURE
   * @see #EID_SFID_DG14_WRITTEN_SIGNATURE
   */
  public static final String EID_NAME_DG14_WRITTEN_SIGNATURE = "Written Signature";

  /**
   * Name of DG15: Date of Issuance.
   *
   * @see #EID_FID_DG15_DATE_OF_ISSUANCE
   * @see #EID_SFID_DG15_DATE_OF_ISSUANCE
   */
  public static final String EID_NAME_DG15_DATE_OF_ISSUANCE = "Date of Issuance";

  /**
   * Name of DG16: RFU 4.
   *
   * @see #EID_FID_DG16_RFU04
   * @see #EID_SFID_DG16_RFU04
   */
  public static final String EID_NAME_DG16_RFU04 = "RFU 4";

  /**
   * Name of DG17: Normal Place Of Residence.
   *
   * @see #EID_FID_DG17_PLACE_OF_RESIDENCE
   * @see #EID_SFID_DG17_PLACE_OF_RESIDENCE
   */
  public static final String EID_NAME_DG17_PLACE_OF_RESIDENCE = "Normal Place of Residence";

  /**
   * Name of DG18: Municipality ID.
   *
   * @see #EID_FID_DG18_MUNICIPALITY_ID
   * @see #EID_SFID_DG18_MUNICIPALITY_ID
   */
  public static final String EID_NAME_DG18_MUNICIPALITY_ID = "Municipality ID";

  /**
   * Name of DG19: Residence Permit I.
   *
   * @see #EID_FID_DG19_RESIDENCE_PERMIT_I
   * @see #EID_SFID_DG19_RESIDENCE_PERMIT_I
   */
  public static final String EID_NAME_DG19_RESIDENCE_PERMIT_I = "Residence Permit I";

  /**
   * Name of DG20: Residence Permit II.
   *
   * @see #EID_FID_DG20_RESIDENCE_PERMIT_II
   * @see #EID_SFID_DG20_RESIDENCE_PERMIT_II
   */
  public static final String EID_NAME_DG20_RESIDENCE_PERMIT_II = "Residence Permit II";

  /**
   * Name of DG21: Phone Number.
   *
   * @see #EID_FID_DG21_PHONE_NUMBER
   * @see #EID_SFID_DG21_PHONE_NUMBER
   */
  public static final String EID_NAME_DG21_PHONE_NUMBER = "Phone Number";

  /**
   * Name of DG22: Email Address.
   *
   * @see #EID_FID_DG22_EMAIL_ADDRESS
   * @see #EID_SFID_DG22_EMAIL_ADDRESS
   */
  public static final String EID_NAME_DG22_EMAIL_ADDRESS = "Email Address";

  /**
   * FID of DG01: 0101.
   *
   * @see #EID_NAME_DG01_DOCUMENT_TYPE
   * @see #EID_SFID_DG01_DOCUMENT_TYPE
   */
  public static final String EID_FID_DG01_DOCUMENT_TYPE = "0101";

  /**
   * FID of DG02: 0102.
   *
   * @see #EID_NAME_DG02_ISSUING_STATE
   * @see #EID_SFID_DG02_ISSUING_STATE
   */
  public static final String EID_FID_DG02_ISSUING_STATE = "0102";

  /**
   * FID of DG03: 0103.
   *
   * @see #EID_NAME_DG03_DATE_OF_EXPIRY
   * @see #EID_SFID_DG03_DATE_OF_EXPIRY
   */
  public static final String EID_FID_DG03_DATE_OF_EXPIRY = "0103";

  /**
   * FID of DG04: 0104.
   *
   * @see #EID_NAME_DG04_GIVEN_NAMES
   * @see #EID_SFID_DG04_GIVEN_NAMES
   */
  public static final String EID_FID_DG04_GIVEN_NAMES = "0104";

  /**
   * FID of DG05: 0105.
   *
   * @see #EID_NAME_DG05_FAMILY_NAMES
   * @see #EID_SFID_DG05_FAMILY_NAMES
   */
  public static final String EID_FID_DG05_FAMILY_NAMES = "0105";

  /**
   * FID of DG06: 0106.
   *
   * @see #EID_NAME_DG06_NOM_DE_PLUME
   * @see #EID_SFID_DG06_NOM_DE_PLUME
   */
  public static final String EID_FID_DG06_NOM_DE_PLUME = "0106";

  /**
   * FID of DG07: 0107.
   *
   * @see #EID_NAME_DG07_ACADEMIC_TITLE
   * @see #EID_SFID_DG07_ACADEMIC_TITLE
   */
  public static final String EID_FID_DG07_ACADEMIC_TITLE = "0107";

  /**
   * FID of DG08: 0108.
   *
   * @see #EID_NAME_DG08_DATE_OF_BIRTH
   * @see #EID_SFID_DG08_DATE_OF_BIRTH
   */
  public static final String EID_FID_DG08_DATE_OF_BIRTH = "0108";

  /**
   * FID of DG09: 0109.
   *
   * @see #EID_NAME_DG09_PLACE_OF_BIRTH
   * @see #EID_SFID_DG09_PLACE_OF_BIRTH
   */
  public static final String EID_FID_DG09_PLACE_OF_BIRTH = "0109";

  /**
   * FID of DG10: 010a.
   *
   * @see #EID_NAME_DG10_NATIONALITY
   * @see #EID_SFID_DG10_NATIONALITY
   */
  public static final String EID_FID_DG10_NATIONALITY = "010a";

  /**
   * FID of DG11: 010b.
   *
   * @see #EID_NAME_DG11_SEX
   * @see #EID_SFID_DG11_SEX
   */
  public static final String EID_FID_DG11_SEX = "010b";

  /**
   * FID of DG12: 010c.
   *
   * @see #EID_NAME_DG12_OPTIONAL_DATA_R
   * @see #EID_SFID_DG12_OPTIONAL_DATA_R
   */
  public static final String EID_FID_DG12_OPTIONAL_DATA_R = "010c";

  /**
   * FID of DG13: 010d.
   *
   * @see #EID_NAME_DG13_BIRTH_NAME
   * @see #EID_SFID_DG13_BIRTH_NAME
   */
  public static final String EID_FID_DG13_BIRTH_NAME = "010d";

  /**
   * FID of DG14: 010e.
   *
   * @see #EID_NAME_DG14_WRITTEN_SIGNATURE
   * @see #EID_SFID_DG14_WRITTEN_SIGNATURE
   */
  public static final String EID_FID_DG14_WRITTEN_SIGNATURE = "010e";

  /**
   * FID of DG15: 010f.
   *
   * @see #EID_NAME_DG15_DATE_OF_ISSUANCE
   * @see #EID_SFID_DG15_DATE_OF_ISSUANCE
   */
  public static final String EID_FID_DG15_DATE_OF_ISSUANCE = "010f";

  /**
   * FID of DG16: 0110
   *
   * @see #EID_NAME_DG16_RFU04
   * @see #EID_SFID_DG16_RFU04
   */
  public static final String EID_FID_DG16_RFU04 = "0110";

  /**
   * FID of DG17: 0111.
   *
   * @see #EID_NAME_DG17_PLACE_OF_RESIDENCE
   * @see #EID_SFID_DG17_PLACE_OF_RESIDENCE
   */
  public static final String EID_FID_DG17_PLACE_OF_RESIDENCE = "0111";

  /**
   * FID of DG18: 0112.
   *
   * @see #EID_NAME_DG18_MUNICIPALITY_ID
   * @see #EID_SFID_DG18_MUNICIPALITY_ID
   */
  public static final String EID_FID_DG18_MUNICIPALITY_ID = "0112";

  /**
   * FID of DG19: 0113.
   *
   * @see #EID_NAME_DG19_RESIDENCE_PERMIT_I
   * @see #EID_SFID_DG19_RESIDENCE_PERMIT_I
   */
  public static final String EID_FID_DG19_RESIDENCE_PERMIT_I = "0113";

  /**
   * FID of DG20: 0114.
   *
   * @see #EID_NAME_DG20_RESIDENCE_PERMIT_II
   * @see #EID_SFID_DG20_RESIDENCE_PERMIT_II
   */
  public static final String EID_FID_DG20_RESIDENCE_PERMIT_II = "0114";

  /**
   * FID of DG21: 0115.
   *
   * @see #EID_NAME_DG21_PHONE_NUMBER
   * @see #EID_SFID_DG21_PHONE_NUMBER
   */
  public static final String EID_FID_DG21_PHONE_NUMBER = "0115";

  /**
   * FID of DG22: 0116.
   *
   * @see #EID_NAME_DG22_EMAIL_ADDRESS
   * @see #EID_SFID_DG22_EMAIL_ADDRESS
   */
  public static final String EID_FID_DG22_EMAIL_ADDRESS = "0116";

  /**
   * SFID of DG01: 01.
   *
   * @see #EID_NAME_DG01_DOCUMENT_TYPE
   * @see #EID_FID_DG01_DOCUMENT_TYPE
   */
  public static final String EID_SFID_DG01_DOCUMENT_TYPE = "01";

  /**
   * SFID of DG02: 02.
   *
   * @see #EID_NAME_DG02_ISSUING_STATE
   * @see #EID_FID_DG02_ISSUING_STATE
   */
  public static final String EID_SFID_DG02_ISSUING_STATE = "02";

  /**
   * SFID of DG03: 03.
   *
   * @see #EID_NAME_DG03_DATE_OF_EXPIRY
   * @see #EID_FID_DG03_DATE_OF_EXPIRY
   */
  public static final String EID_SFID_DG03_DATE_OF_EXPIRY = "03";

  /**
   * SFID of DG04: 04.
   *
   * @see #EID_NAME_DG04_GIVEN_NAMES
   * @see #EID_FID_DG04_GIVEN_NAMES
   */
  public static final String EID_SFID_DG04_GIVEN_NAMES = "04";

  /**
   * SFID of DG05: 05.
   *
   * @see #EID_NAME_DG05_FAMILY_NAMES
   * @see #EID_FID_DG05_FAMILY_NAMES
   */
  public static final String EID_SFID_DG05_FAMILY_NAMES = "05";

  /**
   * SFID of DG06: 06.
   *
   * @see #EID_NAME_DG06_NOM_DE_PLUME
   * @see #EID_FID_DG06_NOM_DE_PLUME
   */
  public static final String EID_SFID_DG06_NOM_DE_PLUME = "06";

  /**
   * SFID of DG07: 07.
   *
   * @see #EID_NAME_DG07_ACADEMIC_TITLE
   * @see #EID_FID_DG07_ACADEMIC_TITLE
   */
  public static final String EID_SFID_DG07_ACADEMIC_TITLE = "07";

  /**
   * SFID of DG08: 08.
   *
   * @see #EID_NAME_DG08_DATE_OF_BIRTH
   * @see #EID_FID_DG08_DATE_OF_BIRTH
   */
  public static final String EID_SFID_DG08_DATE_OF_BIRTH = "08";

  /**
   * SFID of DG09: 09.
   *
   * @see #EID_NAME_DG09_PLACE_OF_BIRTH
   * @see #EID_FID_DG09_PLACE_OF_BIRTH
   */
  public static final String EID_SFID_DG09_PLACE_OF_BIRTH = "09";

  /**
   * SFID of DG10: 0a.
   *
   * @see #EID_NAME_DG10_NATIONALITY
   * @see #EID_FID_DG10_NATIONALITY
   */
  public static final String EID_SFID_DG10_NATIONALITY = "0a";

  /**
   * SFID of DG11: 0b.
   *
   * @see #EID_NAME_DG11_SEX
   * @see #EID_FID_DG11_SEX
   */
  public static final String EID_SFID_DG11_SEX = "0b";

  /**
   * SFID of DG12: 0c.
   *
   * @see #EID_NAME_DG12_OPTIONAL_DATA_R
   * @see #EID_FID_DG12_OPTIONAL_DATA_R
   */
  public static final String EID_SFID_DG12_OPTIONAL_DATA_R = "0c";

  /**
   * SFID of DG13: 0d.
   *
   * @see #EID_NAME_DG13_BIRTH_NAME
   * @see #EID_FID_DG13_BIRTH_NAME
   */
  public static final String EID_SFID_DG13_BIRTH_NAME = "0d";

  /**
   * SFID of DG14: 0e.
   *
   * @see #EID_NAME_DG14_WRITTEN_SIGNATURE
   * @see #EID_FID_DG14_WRITTEN_SIGNATURE
   */
  public static final String EID_SFID_DG14_WRITTEN_SIGNATURE = "0e";

  /**
   * SFID of DG15: 0f.
   *
   * @see #EID_NAME_DG15_DATE_OF_ISSUANCE
   * @see #EID_FID_DG15_DATE_OF_ISSUANCE
   */
  public static final String EID_SFID_DG15_DATE_OF_ISSUANCE = "0f";

  /**
   * SFID of DG16: 10.
   *
   * @see #EID_NAME_DG16_RFU04
   * @see #EID_FID_DG16_RFU04
   */
  public static final String EID_SFID_DG16_RFU04 = "10";

  /**
   * SFID of DG17: 11.
   *
   * @see #EID_NAME_DG17_PLACE_OF_RESIDENCE
   * @see #EID_FID_DG17_PLACE_OF_RESIDENCE
   */
  public static final String EID_SFID_DG17_PLACE_OF_RESIDENCE = "11";

  /**
   * SFID of DG18: 12.
   *
   * @see #EID_NAME_DG18_MUNICIPALITY_ID
   * @see #EID_FID_DG18_MUNICIPALITY_ID
   */
  public static final String EID_SFID_DG18_MUNICIPALITY_ID = "12";

  /**
   * SFID of DG19: 13.
   *
   * @see #EID_NAME_DG19_RESIDENCE_PERMIT_I
   * @see #EID_FID_DG19_RESIDENCE_PERMIT_I
   */
  public static final String EID_SFID_DG19_RESIDENCE_PERMIT_I = "13";

  /**
   * SFID of DG20: 14.
   *
   * @see #EID_NAME_DG20_RESIDENCE_PERMIT_II
   * @see #EID_FID_DG20_RESIDENCE_PERMIT_II
   */
  public static final String EID_SFID_DG20_RESIDENCE_PERMIT_II = "14";

  /**
   * SFID of DG21: 15.
   *
   * @see #EID_NAME_DG21_PHONE_NUMBER
   * @see #EID_FID_DG21_PHONE_NUMBER
   */
  public static final String EID_SFID_DG21_PHONE_NUMBER = "15";

  /**
   * SFID of DG22: 16.
   *
   * @see #EID_NAME_DG22_EMAIL_ADDRESS
   * @see #EID_FID_DG22_EMAIL_ADDRESS
   */
  public static final String EID_SFID_DG22_EMAIL_ADDRESS = "16";

  private EIDConstants()
  {}
}

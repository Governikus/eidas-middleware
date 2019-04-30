/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver;

import java.math.BigInteger;

import javax.smartcardio.CommandAPDU;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;


/**
 * Implementation of convenience methods for converting / creating ASN.1 structures in ePA context.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class EACServerUtil
{

  public static final String COMMAND_CHAINING_DISABLED = "00";

  public static final String CLA_PROPRIETARY = "80";

  public static final String MSE_INS = "22";

  public static final String MSE_SET_AT_PARAM_RI = "41A4";

  public static final String MSE_SET_AT_RESTORE_SESSION = "01A4";

  public static final String MSE_OID_TAG = "80";

  public static final String MSE_FILE_REFERENCE_TAG = "E1";

  public static final String MSE_PRIVATE_KEY_REFERENCE_TAG = "84";

  public static final String MSE_SET_AT_RESTORE_SESSION_TAG = "E1";

  public static final String MSE_SET_DST_PARAM_COMP = "41B6";

  public static final String GENERAL_AUTHENTICATE_HEADER = "860000";

  public static final String GA_DATA_TAG = "7C";

  public static final String PSO_COMPUTE_SIGNATURE_HEADER = "2AAEAC";

  public static final String DISCRETIONARY_DATA_TAG = "73";

  public static final String PRESENT_USER_HEADER = "140080";

  public static final String PRESENT_USER_DATA_TAG = "7F21";

  public static final String PRESENT_USER_SECTOR_PUBLIC_KEY_HASH_TAG = "80";

  public static final String PUT_DATA_INS = "DA";

  public static final String PUT_DATA_ATTR_REQ = "FF01";

  public static final String PUT_DATA_SPEC_ATTR = "00FF";

  public static final String PUT_DATA_DATA_TAG = "53";

  public static final String GET_DATA_INS = "CA";

  public static final String GET_DATA_ATTR_REQ = "FF01";

  public static final String GET_DATA_SPEC_ATTR = "00FF";

  public static final String GET_DATA_ATTRIBUTE_TAG = "53";

  public static final String LENGTH_EXPECTED_NONE = null;

  public static final String LENGTH_EXPECTED_MAX = "00";

  public static final String LENGTH_EXPECTED_MAX_EXTENDED = "0000";

  /**
   * Produces hex string of TLV.
   *
   * @param tagHexString hex string of tag, <code>null</code> or empty not permitted
   * @param valueHexString hex string of value, <code>null</code> or empty not permitted
   * @return hex string of complete TLV
   * @throws IllegalArgumentException if any argument <code>null</code> or empty
   */
  public static String makeTag(String tagHexString, String valueHexString)
  {
    AssertUtil.notNullOrEmpty(tagHexString, "hex string of tag");
    AssertUtil.notNull(valueHexString, "value string of tag");

    int valueLength = valueHexString.length() / 2;
    String additionalLength = valueLength > 255 ? "82" : valueLength > 127 ? "81" : "";
    return tagHexString + additionalLength + Hex.hexify(valueHexString.length() / 2) + valueHexString;
  }

  /**
   * Produces {@link CommandAPDU} from hex strings of header, data and expected length.
   *
   * @param header hex string of header, <code>null</code> or empty string not permitted
   * @param data hex string of data, <code>null</code> permitted
   * @param expectedLength hex string of expected length, <code>null</code> permitted
   * @return generated {@link CommandAPDU}
   * @throws IllegalArgumentException if header <code>null</code> or empty
   */
  public static CommandAPDU commandFromString(String header, String data, String expectedLength)
  {
    AssertUtil.notNullOrEmpty(header, "hex string of header");

    byte[] headerBytes = Hex.parse(header);
    byte[] dataBytes = null;
    Integer el = null;

    if (data != null)
    {
      dataBytes = Hex.parse(data);
    }
    if (expectedLength != null)
    {
      el = new BigInteger(1, Hex.parse(expectedLength)).intValue();
      if (el == 0)
      {
        if ((dataBytes != null && dataBytes.length > 255)
            || expectedLength.length() == LENGTH_EXPECTED_MAX_EXTENDED.length())
        {
          el = 65536;
        }
        else
        {
          el = 256;
        }
      }
    }
    if (el != null)
    {
      return new CommandAPDU(headerBytes[0], headerBytes[1], headerBytes[2], headerBytes[3], dataBytes, el);
    }
    return new CommandAPDU(headerBytes[0], headerBytes[1], headerBytes[2], headerBytes[3], dataBytes);
  }
}

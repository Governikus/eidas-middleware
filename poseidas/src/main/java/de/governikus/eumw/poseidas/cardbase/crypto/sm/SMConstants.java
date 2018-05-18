/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.sm;

/**
 * Several ISO 7816-4 related Secure Messaging Constants.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class SMConstants
{

  /**
   * Byte constant of padding indicator at cryptogram for used padding (algorithm may differ according to
   * card): <code>0x01</code>
   */
  public static final byte PADDING_INDICATOR_BYTE_ISO = (byte)0x01;

  /**
   * Constant of byte used for padding of header, cryptogram and checksum calculation: <code>0x00</code>
   */
  public static final byte PAD_BYTE_DEFAULT = (byte)0x00;

  /**
   * Constant of leading pad byte (first byte indicating start of padding): <code>0x80</code> (note: some
   * cards use <code>0x00</code>).
   */
  public static final byte PAD_BYTE_LEADING_ISO = (byte)0x80;

  /**
   * Constant of tag byte of processing status DO (response only, DO contains response code of secure
   * messaging command execution, exists: according to execution and requested/delivered data exists):
   * <code>0x99</code>.
   */
  public static final byte TAG_BYTE_DO_PROCESSING_STATUS = (byte)0x99;

  /**
   * Constant of tag byte of cryptogram DO (command and response, DO contains encrypted command/response data,
   * exists: according to execution and requested/delivered data exists): <code>0x87</code>.
   */
  public static final byte TAG_BYTE_DO_CRYPTOGRAM = (byte)0x87;

  /**
   * Constant of tag byte of cryptogram DO (command and response, DO contains encrypted command/response data,
   * exists: according to execution and requested/delivered data exists): <code>0x85</code>.
   */
  public static final byte TAG_BYTE_DO_CRYPTOGRAM_85 = (byte)0x85;

  /**
   * Constant of tag byte of LE DO (command, DO contains LE of command, exists: according to command case and
   * data is requested): <code>0x97</code>.
   */
  public static final byte TAG_BYTE_DO_NE = (byte)0x97;

  /**
   * Constant of tag byte of cryptographic checksum DO (command and response, DO contains checksum of
   * command/response, exists: according to execution and requested/delivered data exists): <code>0x8e</code>.
   */
  public static final byte TAG_BYTE_DO_CRYPTOGRPAHIC_CHECKSUM = (byte)0x8e;

  private SMConstants()
  {}
}

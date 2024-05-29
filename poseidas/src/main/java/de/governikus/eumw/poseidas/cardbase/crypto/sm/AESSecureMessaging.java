/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.sm;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.card.CommandAPDUConstants;
import de.governikus.eumw.poseidas.cardbase.card.SecureMessaging;
import de.governikus.eumw.poseidas.cardbase.card.SecureMessagingException;
import de.governikus.eumw.poseidas.cardbase.crypto.CipherUtil;
import lombok.extern.slf4j.Slf4j;


/**
 * Implementation of secure messaging related using AES keys as it is used for nPA.
 *
 * @see AESKeyMaterial
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@Slf4j
public class AESSecureMessaging implements SecureMessaging
{

  private static final String CIPHER_ALGORITHM = "AES/CBC/NoPadding";

  /**
   * Key material.
   */
  protected AESKeyMaterial material;

  /**
   * Constructor.
   *
   * @param keyMaterial key material, <code>null</code> not permitted
   * @throws IllegalArgumentException if key material <code>null</code>
   */
  public AESSecureMessaging(AESKeyMaterial keyMaterial)
  {
    super();
    AssertUtil.notNull(keyMaterial, "key material");
    this.material = keyMaterial;
  }

  /**
   * Enciphers a single command.
   *
   * @param command command to encipher, <code>null</code> not permitted
   * @return enciphered command
   * @throws IllegalArgumentException if command <code>null</code>
   * @throws SecureMessagingException
   */
  @Override
  public CommandAPDU encipherCommand(CommandAPDU command) throws SecureMessagingException
  {
    AssertUtil.notNull(command, "command");
    this.material.getIvParameterSpec().increaseSSC();

    boolean extended = command.getNc() > CommandAPDUConstants.SHORT_MAX_LC
                       || command.getNe() > CommandAPDUConstants.SHORT_MAX_LE;
    byte[] header = new byte[]{(byte)command.getCLA(), (byte)command.getINS(), (byte)command.getP1(),
                               (byte)command.getP2()};
    byte[] le = createLe(command, extended);
    byte[] secureHeaderBytes = createSecureHeader(header);
    byte[] secureHeaderPaddedBytes = pad(secureHeaderBytes);
    byte[] cryptogramDOBytes = createCryptogramDO(command);
    byte[] neDOBytes = createNeDO(le);
    byte[] macDOBytes = createMacDO(secureHeaderPaddedBytes, cryptogramDOBytes, neDOBytes);
    byte[] dataFieldBytes = ByteUtil.combine(new byte[][]{cryptogramDOBytes, neDOBytes, macDOBytes});
    int l = getNewLe(neDOBytes, dataFieldBytes);
    return new CommandAPDU(secureHeaderBytes[0], secureHeaderBytes[1], secureHeaderBytes[2], secureHeaderBytes[3],
                           dataFieldBytes, l);
  }

  private int getNewLe(byte[] neDOBytes, byte[] dataFieldBytes)
  {

    int l = CommandAPDUConstants.SHORT_MAX_LE;
    if ((neDOBytes != null && neDOBytes.length == 4)
        || (dataFieldBytes != null && dataFieldBytes.length >= CommandAPDUConstants.SHORT_MAX_LE))
    {
      l = CommandAPDUConstants.EXTENDED_MAX_LE;
    }
    return l;
  }

  private byte[] createLe(CommandAPDU command, boolean extended)
  {
    if (command.getNe() == 0)
    {
      return null;
    }
    if (command.getNe() == CommandAPDUConstants.SHORT_MAX_LE && !extended)
    {
      return new byte[1];
    }
    if (command.getNe() == CommandAPDUConstants.EXTENDED_MAX_LE)
    {
      return new byte[2];
    }
    return ByteUtil.trimByteArray(BigInteger.valueOf(command.getNe()).toByteArray(), extended ? 2 : 1);
  }

  /**
   * Deciphers a single response.
   *
   * @param response enciphered response, <code>null</code> not permitted
   * @return deciphered response
   * @throws IllegalArgumentException if response <code>null</code>
   * @throws SecureMessagingException
   */
  @Override
  public ResponseAPDU decipherResponse(ResponseAPDU response) throws SecureMessagingException
  {
    AssertUtil.notNull(response, "response");
    this.material.getIvParameterSpec().increaseSSC();

    byte[] responseData = response.getData();
    if (ArrayUtil.isNullOrEmpty(responseData))
    {
      log.warn("Error 6419: no data");
      throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, "response is not encrypted", null);
    }
    ASN1[] childs = getDataChilds(responseData);
    byte[] encDataDOBytes = null;
    int encTag = 0;
    byte[] processDOBytes = null;
    byte[] macDOBytes = null;
    byte[] macData = null;

    for ( ASN1 child : childs )
    {
      int tag = (int)child.getDTag().longValue();
      if (SMConstants.TAG_BYTE_DO_CRYPTOGRAM == tag || SMConstants.TAG_BYTE_DO_CRYPTOGRAM_85 == tag)
      {
        if (encDataDOBytes == null)
        {
          macData = ByteUtil.combine(macData, child.getEncoded());
          encDataDOBytes = child.getValue();
          encTag = tag;
        }
        else
        {
          throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE,
                                             "response contain more than one cryptogram", null);
        }
      }
      else if (SMConstants.TAG_BYTE_DO_PROCESSING_STATUS == tag)
      {
        if (processDOBytes == null)
        {
          macData = ByteUtil.combine(macData, child.getEncoded());
          processDOBytes = child.getValue();
        }
        else
        {
          throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE,
                                             "response contain more than one le", null);
        }
      }
      else if (SMConstants.TAG_BYTE_DO_CRYPTOGRPAHIC_CHECKSUM == tag)
      {
        if (macDOBytes == null)
        {
          macDOBytes = child.getValue();
        }
        else
        {
          throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE,
                                             "response contain more than one cryptogram checksum", null);
        }
      }
      else
      {
        if (tag >= 0x61 && tag <= 0x76)
        {
          log.warn("Error 6419: data object {}", Hex.hexify(child.getEncoded()));
        }
        throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, "unrecognized DO at response", null);
      }
    }
    checkMac(macDOBytes, macData);
    byte[] dataBytes = getDataBytes(encDataDOBytes, encTag);
    byte[] responseBytes = response.getBytes();
    byte[] result = ByteUtil.combine(new byte[][]{dataBytes, processDOBytes == null
      ? ByteUtil.subbytes(responseBytes, responseBytes.length - 2) : processDOBytes});
    return new ResponseAPDU(result);
  }

  private ASN1[] getDataChilds(byte[] responseData) throws SecureMessagingException
  {
    ASN1[] childs = null;
    ASN1 asn1data = new ASN1(ASN1Constants.UNIVERSAL_TAG_SEQUENCE_CONSTRUCTED, responseData);
    try
    {
      childs = asn1data.getChildElements();
    }
    catch (IOException e)
    {
      throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, e.getMessage(), e);
    }
    return childs;
  }

  private byte[] getDataBytes(byte[] encDataDOBytes, int encTag) throws SecureMessagingException
  {
    byte[] dataBytes = null;
    if (!ArrayUtil.isNullOrEmpty(encDataDOBytes))
    {
      try
      {
        dataBytes = CipherUtil.decipherAES(CIPHER_ALGORITHM,
                                           this.material.getAESEncKey(),
                                           this.material.getIvParameterSpec().getEncryptedIV(),
                                           encTag == SMConstants.TAG_BYTE_DO_CRYPTOGRAM
                                             ? ByteUtil.subbytes(encDataDOBytes, 1) : encDataDOBytes,
                                           null);
      }
      catch (IllegalBlockSizeException | BadPaddingException e)
      {
        throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, e.getMessage(), e);
      }
      dataBytes = SMUtil.unpadISO(dataBytes, 16);
    }
    return dataBytes;
  }

  private void checkMac(byte[] macDOBytes, byte[] macData) throws SecureMessagingException
  {
    if (ArrayUtil.isNullOrEmpty(macDOBytes))
    {
      // invalidate key material so the channel can no longer be used
      this.material = null;
      throw new SecureMessagingException(SecureMessagingException.CODE_CARD, "no checksum received from card", null);
    }
    else
    {
      byte[] tmpMacData = pad(macData);
      byte[] cMac = null;
      cMac = cMac(tmpMacData);
      if (!Arrays.equals(cMac, macDOBytes))
      {
        // invalidate key material so the channel can no longer be used
        this.material = null;
        throw new SecureMessagingException(SecureMessagingException.CODE_CARD, "checksum not verified", null);
      }
    }
  }

  private byte[] createMacDO(byte[] secureHeaderBytes, byte[] cryptogramDOBytes, byte[] neDOBytes)
  {
    byte[] macData = ByteUtil.combine(new byte[][]{secureHeaderBytes, cryptogramDOBytes, neDOBytes});
    if (!ArrayUtil.isNullOrEmpty(cryptogramDOBytes) || !ArrayUtil.isNullOrEmpty(neDOBytes))
    {
      macData = pad(macData);
    }
    byte[] cMac = this.cMac(macData);
    ASN1 result = new ASN1(SMConstants.TAG_BYTE_DO_CRYPTOGRPAHIC_CHECKSUM, cMac);
    return result.getEncoded();
  }

  private byte[] cMac(byte[] macData)
  {
    IvParameterSpec ivSpec = new IvParameterSpec(this.material.getIvParameterSpec().getIV());
    return CipherUtil.cMAC(macData, this.material.getAESMacKey(), ivSpec, CipherUtil.AES_CMAC_DEFAULT_LENGTH);
  }

  private static byte[] createNeDO(byte[] le)
  {
    if (ArrayUtil.isNullOrEmpty(le))
    {
      return null;
    }
    byte[] leTmp = le;
    if (le.length == CommandAPDUConstants.COUNT_EXTENDED)
    {
      leTmp = ByteUtil.subbytes(le, 1, CommandAPDUConstants.COUNT_EXTENDED);
    }
    return new ASN1(SMConstants.TAG_BYTE_DO_NE, leTmp).getEncoded();
  }

  private byte[] createCryptogramDO(CommandAPDU command) throws SecureMessagingException
  {
    try
    {
      byte[] data = command.getData();
      if (ArrayUtil.isNullOrEmpty(data))
      {
        return null;
      }
      byte[] paddedData = pad(data);
      IvParameterSpec encIv = this.material.getIvParameterSpec().getEncryptedIV();
      byte[] cryptogram = CipherUtil.encipherAES(CIPHER_ALGORITHM,
                                                 this.material.getAESEncKey(),
                                                 encIv,
                                                 paddedData,
                                                 null);
      ASN1 result;
      if (command.getINS() % 2 == 0)
      {
        byte[] paddedCryptogram = ByteUtil.combine(new byte[]{SMConstants.PADDING_INDICATOR_BYTE_ISO}, cryptogram);
        result = new ASN1(SMConstants.TAG_BYTE_DO_CRYPTOGRAM, paddedCryptogram);
      }
      else
      {
        result = new ASN1(SMConstants.TAG_BYTE_DO_CRYPTOGRAM_85, cryptogram);
      }
      return result.getEncoded();
    }
    catch (IllegalBlockSizeException | BadPaddingException e)
    {
      throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, e.getMessage(), e);
    }
  }

  private static byte[] createSecureHeader(byte[] header)
  {
    byte[] result = header;
    ByteUtil.setBits(result, 0, (byte)0x0c);
    return result;
  }

  private static byte[] pad(byte[] data)
  {
    return SMUtil.padISO(data, CipherUtil.AES_IV_LENGTH);
  }
}

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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.card.CommandAPDUConstants;
import de.governikus.eumw.poseidas.cardbase.card.SecureMessaging;
import de.governikus.eumw.poseidas.cardbase.card.SecureMessagingException;
import de.governikus.eumw.poseidas.cardbase.crypto.CipherUtil;
import de.governikus.eumw.poseidas.cardserver.EACServerUtil;
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

    // prepare header for MAC calculation
    byte[] header = {(byte)command.getCLA(), (byte)command.getINS(), (byte)command.getP1(), (byte)command.getP2()};
    byte[] secureHeaderBytes = createSecureHeader(header);
    byte[] paddedSecureHeaderBytes = pad(secureHeaderBytes);

    // encrypt payload
    byte[] cryptogramDOBytes = createCryptogramDO(command);

    // calculate expected length
    boolean extended = command.getNc() > CommandAPDUConstants.SHORT_MAX_LC
                       || command.getNe() > CommandAPDUConstants.SHORT_MAX_LE;
    byte[] le = createLe(command, extended);
    byte[] neDOBytes = createNeDO(le);

    // calculate MAC
    byte[] macDOBytes = createMacDO(paddedSecureHeaderBytes, cryptogramDOBytes, neDOBytes);

    // finally construct APDU
    byte[] dataFieldBytes = ByteUtil.combine(new byte[][]{cryptogramDOBytes, neDOBytes, macDOBytes});
    int newLe = getNewLe(neDOBytes, dataFieldBytes);
    return new CommandAPDU(secureHeaderBytes[0], secureHeaderBytes[1], secureHeaderBytes[2], secureHeaderBytes[3],
                           dataFieldBytes, newLe);
  }

  private static int getNewLe(byte[] neDOBytes, byte[] dataFieldBytes)
  {

    int l = CommandAPDUConstants.SHORT_MAX_LE;
    if (neDOBytes != null && neDOBytes.length == 4
        || dataFieldBytes != null && dataFieldBytes.length >= CommandAPDUConstants.SHORT_MAX_LE)
    {
      l = CommandAPDUConstants.EXTENDED_MAX_LE;
    }
    return l;
  }

  private static byte[] createLe(CommandAPDU command, boolean extended)
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

    // for own mac calculation
    byte[] dataForMacComparison = null;

    byte[] encDataDOBytes = null;
    int encTag = 0;
    byte[] processDOBytes = null;
    byte[] macDOBytes = null;

    try
    {
      for ( ASN1TaggedObject child : getDataChilds(responseData) )
      {
        int tag = child.getTagNo();
        if (toApplicationTag(SMConstants.TAG_BYTE_DO_CRYPTOGRAM) == tag
            || toApplicationTag(SMConstants.TAG_BYTE_DO_CRYPTOGRAM_85) == tag)
        {
          if (encDataDOBytes == null)
          {
            dataForMacComparison = org.bouncycastle.util.Arrays.concatenate(dataForMacComparison, child.getEncoded());
            encDataDOBytes = ((ASN1OctetString)child.getBaseObject()).getOctets();
            encTag = tag;
          }
          else
          {
            throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE,
                                               "response contains more than one cryptogram", null);
          }
        }
        else if (toApplicationTag(SMConstants.TAG_BYTE_DO_PROCESSING_STATUS) == tag)
        {
          if (processDOBytes == null)
          {
            dataForMacComparison = org.bouncycastle.util.Arrays.concatenate(dataForMacComparison, child.getEncoded());
            processDOBytes = ((ASN1OctetString)child.getBaseObject()).getOctets();
          }
          else
          {
            throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE,
                                               "response contains more than one status", null);
          }
          if (!Arrays.equals(processDOBytes, new byte[]{(byte)response.getSW1(), (byte)response.getSW2()}))
          {
            throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE,
                                               "status appears to be manipulated", null);
          }
        }
        else if (toApplicationTag(SMConstants.TAG_BYTE_DO_CRYPTOGRPAHIC_CHECKSUM) == tag)
        {
          if (macDOBytes == null)
          {
            macDOBytes = ((ASN1OctetString)child.getBaseObject()).getOctets();
          }
          else
          {
            throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE,
                                               "response contains more than one cryptogram checksum", null);
          }
        }
        else
        {
          if (tag >= 0x61 && tag <= 0x76)
          {
            log.warn("Error 6419: data object {} - full response {}",
                     org.apache.commons.codec.binary.Hex.encodeHexString(child.getEncoded()),
                     Hex.encodeHexString(response.getBytes()));
          }
          throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, "unrecognized DO at response",
                                             null);
        }
      }
    }
    catch (IOException e)
    {
      throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, e.getMessage(), e);
    }

    checkMac(macDOBytes, dataForMacComparison);
    byte[] dataBytes = getDataBytes(encDataDOBytes, encTag);
    byte[] responseBytes = response.getBytes();
    byte[] result = ByteUtil.combine(new byte[][]{dataBytes, processDOBytes == null
      ? ByteUtil.subbytes(responseBytes, responseBytes.length - 2) : processDOBytes});
    return new ResponseAPDU(result);
  }

  private static List<ASN1TaggedObject> getDataChilds(byte[] responseData) throws SecureMessagingException
  {
    ASN1Sequence seq;
    try
    {
      // responseData contains concatenated ASN.1 objects, combine them in a sequence to facilitate parsing
      byte[] seqBytes = Hex.decodeHex(EACServerUtil.makeTag("30", Hex.encodeHexString(responseData)));
      seq = (ASN1Sequence)ASN1Primitive.fromByteArray(seqBytes);
    }
    catch (DecoderException | IOException e)
    {
      throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, e.getMessage(), e);
    }

    List<ASN1TaggedObject> childs = new ArrayList<>();
    for ( ASN1Encodable asn1 : seq )
    {
      if (!(asn1 instanceof ASN1TaggedObject))
      {
        try
        {
          log.warn("Error 6419: data object {} - response data {}",
                   asn1.toASN1Primitive().getEncoded(),
                   Hex.encodeHexString(responseData));
        }
        catch (IOException _)
        {
          // nothing, just the logging has failed
        }
        throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, "unrecognized DO at response", null);
      }
      childs.add((ASN1TaggedObject)asn1);
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
                                           encTag == toApplicationTag(SMConstants.TAG_BYTE_DO_CRYPTOGRAM)
                                             ? ByteUtil.subbytes(encDataDOBytes, 1) : encDataDOBytes);
      }
      catch (IllegalBlockSizeException | BadPaddingException e)
      {
        throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, e.getMessage(), e);
      }
      dataBytes = SMUtil.unpadISO(dataBytes, CipherUtil.AES_IV_LENGTH);
    }
    return dataBytes;
  }

  private void checkMac(byte[] receivedMac, byte[] dataForMacComparison) throws SecureMessagingException
  {
    if (ArrayUtil.isNullOrEmpty(receivedMac))
    {
      // invalidate key material so the channel can no longer be used
      this.material = null;
      throw new SecureMessagingException(SecureMessagingException.CODE_CARD, "no checksum received from card", null);
    }

    byte[] calculatedMac = cMac(pad(dataForMacComparison));
    if (!Arrays.equals(calculatedMac, receivedMac))
    {
      // invalidate key material so the channel can no longer be used
      this.material = null;
      throw new SecureMessagingException(SecureMessagingException.CODE_CARD, "checksum not verified", null);
    }
  }

  private byte[] createMacDO(byte[] secureHeaderBytes, byte[] cryptogramDOBytes, byte[] neDOBytes)
    throws SecureMessagingException
  {
    byte[] macData = ByteUtil.combine(new byte[][]{secureHeaderBytes, cryptogramDOBytes, neDOBytes});
    if (!ArrayUtil.isNullOrEmpty(cryptogramDOBytes) || !ArrayUtil.isNullOrEmpty(neDOBytes))
    {
      macData = pad(macData);
    }
    byte[] cMac = cMac(macData);
    try
    {
      return Hex.decodeHex(EACServerUtil.makeTag(Hex.encodeHexString(new byte[]{SMConstants.TAG_BYTE_DO_CRYPTOGRPAHIC_CHECKSUM}),
                                                 Hex.encodeHexString(cMac)));
    }
    catch (DecoderException | IllegalArgumentException e)
    {
      throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, e.getMessage(), e);
    }
  }

  private byte[] cMac(byte[] macData)
  {
    IvParameterSpec ivSpec = new IvParameterSpec(this.material.getIvParameterSpec().getIV());
    return CipherUtil.cMAC(macData, this.material.getAESMacKey(), ivSpec, CipherUtil.AES_CMAC_DEFAULT_LENGTH);
  }

  private static byte[] createNeDO(byte[] le) throws SecureMessagingException
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
    try
    {
      return Hex.decodeHex(EACServerUtil.makeTag(Hex.encodeHexString(new byte[]{SMConstants.TAG_BYTE_DO_NE}),
                                                 Hex.encodeHexString(leTmp)));
    }
    catch (DecoderException | IllegalArgumentException e)
    {
      throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, e.getMessage(), e);
    }
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
      byte[] cryptogram = CipherUtil.encipherAES(CIPHER_ALGORITHM, this.material.getAESEncKey(), encIv, paddedData);

      if (command.getINS() % 2 == 0)
      {
        byte[] paddedCryptogram = ByteUtil.combine(new byte[]{SMConstants.PADDING_INDICATOR_BYTE_ISO}, cryptogram);
        return Hex.decodeHex(EACServerUtil.makeTag(Hex.encodeHexString(new byte[]{SMConstants.TAG_BYTE_DO_CRYPTOGRAM}),
                                                   Hex.encodeHexString(paddedCryptogram)));
      }
      else
      {
        return Hex.decodeHex(EACServerUtil.makeTag(Hex.encodeHexString(new byte[]{SMConstants.TAG_BYTE_DO_CRYPTOGRAM_85}),
                                                   Hex.encodeHexString(cryptogram)));
      }
    }
    catch (IllegalBlockSizeException | BadPaddingException | DecoderException e)
    {
      throw new SecureMessagingException(SecureMessagingException.CODE_SOFTWARE, e.getMessage(), e);
    }
  }

  private static byte[] createSecureHeader(byte[] header)
  {
    byte[] result = header;
    result[0] |= 0x0c;
    return result;
  }

  private static byte[] pad(byte[] data)
  {
    return SMUtil.padISO(data, CipherUtil.AES_IV_LENGTH);
  }

  private static final byte toApplicationTag(byte tag)
  {
    return (byte)(tag - 0x80);
  }
}

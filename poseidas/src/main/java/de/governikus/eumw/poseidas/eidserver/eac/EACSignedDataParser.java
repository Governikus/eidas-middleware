/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.eac;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.pkcs.SignedData;


/**
 * EACSignedDataParser to support Master- and Defect-List handling for the {@link EACSignedDataChecker} and
 * the {@link EACSignedDataParser}
 *
 * @author Ole Behrens
 */
public abstract class EACSignedDataParser
{

  static final Log LOG = LogFactory.getLog(EACSignedDataParser.class.getName());

  protected final String logPrefix;

  EACSignedDataParser(String logPrefix)
  {
    this.logPrefix = logPrefix;
  }

  /**
   * Get an ASN1 SignedData object from the given data
   *
   * @param data to be parsed to element signed data
   * @return SignedData object
   * @throws IOException thrown if byte array could not been handled
   */
  SignedData getSignedData(byte[] data) throws IOException
  {
    // Get signature data format object
    ASN1Sequence seq = (ASN1Sequence)ASN1Primitive.fromByteArray(data);
    int signatureObjectSize = seq.size();
    if (signatureObjectSize != 2)
    {
      LOG.debug(logPrefix + "Unexpected size of signature data for ASN1: " + signatureObjectSize);
    }
    ASN1TaggedObject dto = (ASN1TaggedObject)(seq.getObjectAt(1));
    SignedData signedDataFromCard = new SignedData((ASN1Sequence)(dto.getBaseObject()));
    LOG.debug(logPrefix + "Check signature data:\n  "
              + signedDataFromCard.getSignerInfos().toString());
    return signedDataFromCard;
  }
}

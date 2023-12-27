/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import jakarta.xml.ws.BindingProvider;

import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import uri.eac_pki_is_protocol._1.termAuth.dv.EACDVProtocolService;
import uri.eac_pki_is_protocol._1.termAuth.dv.EACPKIDVProtocolType;
import uri.eacbt._1.termAuth.dv.CallbackIndicatorType;
import uri.eacbt._1.termAuth.dv.GetCACertificatesResult;
import uri.eacbt._1.termAuth.dv.GetCACertificatesReturnCodeType;
import uri.eacbt._1.termAuth.dv.OptionalMessageIDType;
import uri.eacbt._1.termAuth.dv.OptionalStringType;
import uri.eacbt._1.termAuth.dv.RequestCertificateResult;
import uri.eacbt._1.termAuth.dv.RequestCertificateReturnCodeType;


/**
 * Wrapper around uri.eac_pki_is_protocol._1_1.termAuth.dv.EACDVProtocolService
 *
 * @author tautenhahn
 */
public class TermAuthService
{

  private final EACPKIDVProtocolType port;

  /**
   * create new instance
   *
   * @param con
   * @param uri
   * @throws URISyntaxException
   */
  public TermAuthService(PKIServiceConnector con, String uri) throws URISyntaxException
  {
    EACDVProtocolService service = new EACDVProtocolService(getClass().getResource("/META-INF/wsdl/CA-Services/TermAuth/WS_DV_TerminalAuth.wsdl"));
    EACPKIDVProtocolType tmpPort = service.getEACDVProtocolServicePort();
    con.setHttpsConnectionSetting((BindingProvider)tmpPort, uri);
    port = tmpPort;
  }

  /**
   * When we get a certificate chain of CA certificates this will fetch the last one which does not sign any other
   * certificate.
   *
   * @param certList list of certificates
   */
  protected static byte[] getCertificate(List<byte[]> certList)
  {
    Map<String, TerminalData> caRefMap = new HashMap<>();
    for ( byte[] cvcBytes : certList )
    {
      try
      {
        TerminalData cvc = new TerminalData(cvcBytes);
        caRefMap.put(new String(cvc.getCAReference(), StandardCharsets.UTF_8), cvc);
      }
      catch (IOException e)
      {
        throw new IllegalArgumentException("unable to parse given cvc", e);
      }
    }
    for ( Entry<String, TerminalData> entry : caRefMap.entrySet() )
    {
      if (!caRefMap.containsKey(entry.getValue().getHolderReferenceString()))
      {
        return entry.getValue().getEncoded();
      }
    }
    return null;
  }

  public byte[][] getCACertificates() throws GovManagementException
  {
    OptionalMessageIDType id = new OptionalMessageIDType();
    OptionalStringType responseURL = new OptionalStringType();
    GetCACertificatesResult result = port.getCACertificates(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE,
                                                            id,
                                                            responseURL);
    GetCACertificatesReturnCodeType code = result.getReturnCode();
    if (!GetCACertificatesReturnCodeType.OK_CERT_AVAILABLE.equals(code))
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, "getCACerts returned " + code);
    }
    List<byte[]> certSeq = result.getCertificateSeq().getCertificate();
    return certSeq.toArray(new byte[certSeq.size()][]);
  }

  public byte[] requestCertificate(byte[] request, String messageId, String returnUrl) throws GovManagementException
  {
    boolean isAsync = returnUrl != null;
    OptionalMessageIDType id = new OptionalMessageIDType();
    OptionalStringType responseURL = new OptionalStringType();
    if (isAsync)
    {
      id.setMessageID(messageId);
      responseURL.setString(returnUrl);
    }
    CallbackIndicatorType callbackIndicator = isAsync ? CallbackIndicatorType.CALLBACK_POSSIBLE
      : CallbackIndicatorType.CALLBACK_NOT_POSSIBLE;

    RequestCertificateResult result = port.requestCertificate(callbackIndicator, id, responseURL, request);

    RequestCertificateReturnCodeType returnCode = result.getReturnCode();
    RequestCertificateReturnCodeType expected = isAsync ? RequestCertificateReturnCodeType.OK_SYNTAX
      : RequestCertificateReturnCodeType.OK_CERT_AVAILABLE;
    if (returnCode != expected)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "send request returned " + returnCode);
    }
    return isAsync ? null : getCertificate(result.getCertificateSeq().getCertificate());
  }
}

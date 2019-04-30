/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.net.URISyntaxException;
import java.util.List;

import javax.xml.ws.BindingProvider;

import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import uri.eac_pki_is_protocol._1_0.termAuth.dv.EACDVProtocolService;
import uri.eac_pki_is_protocol._1_0.termAuth.dv.EACPKIDVProtocolType;
import uri.eacbt._1_0.termAuth.dv.CallbackIndicatorType;
import uri.eacbt._1_0.termAuth.dv.GetCACertificatesResult;
import uri.eacbt._1_0.termAuth.dv.GetCACertificatesReturnCodeType;
import uri.eacbt._1_0.termAuth.dv.OptionalMessageIDType;
import uri.eacbt._1_0.termAuth.dv.OptionalStringType;
import uri.eacbt._1_0.termAuth.dv.RequestCertificateResult;
import uri.eacbt._1_0.termAuth.dv.RequestCertificateReturnCodeType;


/**
 * Wrapper around uri.eac_pki_is_protocol._1_0.termAuth.dv.EACDVProtocolService
 *
 * @author tautenhahn
 */
public class TermAuthServiceWrapper10 implements TermAuthServiceWrapper
{

  private final EACPKIDVProtocolType port;

  /**
   * create new instance
   *
   * @param con
   * @param uri
   * @throws URISyntaxException
   */
  TermAuthServiceWrapper10(PKIServiceConnector con, String uri) throws URISyntaxException
  {
    EACDVProtocolService service = new EACDVProtocolService();
    EACPKIDVProtocolType tmpPort = service.getEACDVProtocolServicePort();
    con.setHttpsConnectionSetting((BindingProvider)tmpPort, uri);
    port = tmpPort;
  }

  @Override
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
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, "getCACerts returned "
                                                                                  + code);
    }
    List<byte[]> certSeq = result.getCertificateSeq().getCertificate();
    return certSeq.toArray(new byte[certSeq.size()][]);
  }

  @Override
  public byte[] requestCertificate(byte[] request, String messageId, String returnUrl)
    throws GovManagementException
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
    if (!returnCode.equals(expected))
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, "send request returned "
                                                                                  + returnCode);
    }
    return isAsync ? null : TermAuthServiceWrapper11.getCertificate(result.getCertificateSeq()
                                                                          .getCertificate());
  }
}

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

import org.apache.commons.lang3.ArrayUtils;

import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.CallbackIndicatorType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.CertificateReference;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.ConditionalCertificateSeqType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificateDescriptionRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificateDescriptionResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificatesDescriptionReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificatesRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificatesResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificatesReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetPKICommunicationCertRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetPKICommunicationCertResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetPKICommunicationCertReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.OptionalNoPollBeforeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestCertificateRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestCertificateResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestCertificateReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestPKICommunicationCertRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestPKICommunicationCertResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestPKICommunicationCertReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendRSCCertRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendRSCCertResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendRSCCertReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendeIDServerCertsRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendeIDServerCertsReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.TerminalAuthWebService_1_4_0;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.TerminalAuthWebserviceClient_1_4_0;
import lombok.Getter;
import lombok.RequiredArgsConstructor;


/**
 * Wrapper around Terminal Auth for version 1.4.0
 *
 * @author tautenhahn
 */
public class TermAuthService
{

  private final TerminalAuthWebService_1_4_0 port;

  /**
   * create new instance
   *
   * @param con the PKI Service Connector
   * @param uri the URI to send the calls
   * @throws URISyntaxException
   */
  TermAuthService(PKIServiceConnector con, String uri) throws URISyntaxException
  {
    TerminalAuthWebserviceClient_1_4_0 service = new TerminalAuthWebserviceClient_1_4_0(getClass().getResource("/META-INF/wsdl/CA-Services-1-4-0/part-3/termAuth/WS_DV_TerminalAuth.wsdl"));
    TerminalAuthWebService_1_4_0 tmpPort = service.getEACDVProtocolServicePort();
    con.setHttpsConnectionSetting((BindingProvider)tmpPort, uri);
    con.setMessageLogger((BindingProvider)tmpPort);
    port = tmpPort;
  }

  /**
   * When we get a certificate chain of CA certificates this will fetch the last one which does not sign any other
   * certificate.
   *
   * @param certList list of certificates
   */
  private static byte[] getCertificate(List<byte[]> certList)
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
    GetCertificatesRequest certificatesRequest = new GetCertificatesRequest();
    certificatesRequest.setCallbackIndicator(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE);
    CertificateReference certificateReference = new CertificateReference();
    // The DVCA ignores the certificate reference and always sends the whole chain. Therefore, we just send an empty
    // byte array
    certificateReference.setValue(ArrayUtils.EMPTY_BYTE_ARRAY);
    certificatesRequest.setCertReference(certificateReference);

    GetCertificatesResult result = port.getCertificates(certificatesRequest);
    GetCertificatesReturnCodeType code = result.getReturnCode();
    if (GetCertificatesReturnCodeType.OK_CERT_AVAILABLE != code)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, "GetCertificates returned " + code);
    }
    List<byte[]> certSeq = result.getCertificateSeq().getCertificate();
    return certSeq.toArray(new byte[certSeq.size()][]);
  }

  /**
   * Request a generation of a new certificate from the DVCA. This message is processed synchronously.
   *
   * @param request the certificate request as byte array
   * @return the new certificate as byte array
   * @throws GovManagementException when the return code is not ok_cert_available
   */
  public byte[] requestCertificate(byte[] request) throws GovManagementException
  {
    RequestCertificateRequest certificateRequest = new RequestCertificateRequest();
    certificateRequest.setCallbackIndicator(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE);
    certificateRequest.setCertReq(request);
    RequestCertificateResult result = port.requestCertificate(certificateRequest);

    RequestCertificateReturnCodeType returnCode = result.getReturnCode();
    if (RequestCertificateReturnCodeType.OK_CERT_AVAILABLE != returnCode)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "send request returned " + returnCode);
    }
    return getCertificate(result.getCertificateSeq().getCertificate());
  }

  /**
   * Returns a certificate Description for a given hash.
   *
   * @param hash the hash of the certificate description
   */
  public byte[] getCertificateDescription(byte[] hash) throws GovManagementException
  {
    GetCertificateDescriptionRequest request = new GetCertificateDescriptionRequest();
    request.setHash(hash);
    GetCertificateDescriptionResult result = port.getCertificateDescription(request);
    GetCertificatesDescriptionReturnCodeType returnCode = result.getReturnCode();
    if (GetCertificatesDescriptionReturnCodeType.OK_RECEIVED_CORRECTLY != returnCode)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "send request returned " + returnCode);
    }
    return result.getCertificateDescription().getCertificateDescription();
  }

  /**
   * Send a new TLS certificate to the DVCA for entanglement.
   *
   * @param cmsData CMS containing the new TLS certificated signed with a RSC
   * @throws GovManagementException
   */
  public void sendeIDServerCerts(byte[] cmsData) throws GovManagementException
  {
    SendeIDServerCertsRequest request = new SendeIDServerCertsRequest();
    request.setCmsContainer(cmsData);
    var result = port.sendeIDServerCerts(request);
    SendeIDServerCertsReturnCodeType returnCode = result.getReturnCode();
    if (SendeIDServerCertsReturnCodeType.OK_ENTANGLEMENT_SUCCESSFUL != returnCode)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "send request returned %s".formatted(returnCode));
    }
  }

  /**
   * Send a new RSC to the DVCA.
   *
   * @param cms CMS containing the new RSC
   * @throws GovManagementException
   */
  public void updateRsc(byte[] cms) throws GovManagementException
  {
    SendRSCCertRequest request = new SendRSCCertRequest();
    request.setCmsContainer(cms);
    SendRSCCertResult result = port.sendRSCCert(request);
    SendRSCCertReturnCodeType returnCode = result.getReturnCode();
    if (SendRSCCertReturnCodeType.OK_RECEIVED_CORRECTLY != returnCode)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, "sendRSCCert returned " + returnCode);
    }
  }

  /**
   * Send a CSR for a new TLS client certificate.
   *
   * @param cms CMS containing the CSR
   * @param messageId a message ID
   * @throws GovManagementException
   */
  public OptionalNoPollBeforeType requestNewTls(byte[] cms, String messageId) throws GovManagementException
  {
    RequestPKICommunicationCertRequest request = new RequestPKICommunicationCertRequest();
    request.setCmsContainer(cms);
    request.setMessageID(messageId);
    RequestPKICommunicationCertResult result = port.requestPKICommunicationCert(request);
    RequestPKICommunicationCertReturnCodeType returnCode = result.getReturnCode();
    if (RequestPKICommunicationCertReturnCodeType.OK_RECEIVED_CORRECTLY != returnCode)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "requestPKICommunicationCert returned " + returnCode);
    }
    return result.getNoPollBefore();
  }

  /**
   * Try to retrieve new TLS client certificate.
   *
   * @param messageId message ID
   * @throws GovManagementException
   */
  public ConditionalCertificateSeqType tryFetchNewTls(String messageId) throws GovManagementException, NoPollException
  {
    GetPKICommunicationCertRequest request = new GetPKICommunicationCertRequest();
    request.setMessageID(messageId);
    GetPKICommunicationCertResult result = port.getPKICommunicationCert(request);
    GetPKICommunicationCertReturnCodeType returnCode = result.getReturnCode();
    if (GetPKICommunicationCertReturnCodeType.FAILURE_CERT_NOT_AVAILABLE == returnCode)
    {
      throw new NoPollException(result.getNoPollBefore());
    }
    if (GetPKICommunicationCertReturnCodeType.OK_CERT_AVAILABLE != returnCode)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "getPKICommunicationCert returned " + returnCode);
    }
    return result.getCertificateSeq();
  }

  @RequiredArgsConstructor
  @Getter
  public static class NoPollException extends Exception
  {

    private static final long serialVersionUID = 1L;

    private final OptionalNoPollBeforeType noPollBefore;
  }
}

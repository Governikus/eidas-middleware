/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.annotation.Resource;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.server.idprovider.accounting.SNMPDelegate;
import de.governikus.eumw.poseidas.server.idprovider.config.EPAConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.PkiConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.idprovider.config.SslKeysDto;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PKIServiceConnector;
import uri.eac_pki_is_protocol._1.termAuth.termcontr.EACPKITermContrProtocolType;
import uri.eacbt._1.termAuth.termcontr.CertificateSeqType;
import uri.eacbt._1.termAuth.termcontr.GetCertificateChainResult;
import uri.eacbt._1.termAuth.termcontr.GetTASignatureResult;
import uri.eacbt._1.termAuth.termcontr.OptionalBinaryType;
import uri.eacbt._1.termAuth.termcontr.OptionalMessageIDType;
import uri.eacbt._1.termAuth.termcontr.SendCertificatesResult;
import uri.eacbt._1.termAuth.termcontr.SendCertificatesReturnCodeType;
import uri.eacbt._1.termAuth.termcontr.SendCertificatesStatusInfoType;


/**
 * poseidas side service to receive certificates. Uses one of BSIs WSDL files found in
 * TermAuth/Terminal/IS_termcontr which is obviously for another purpose and does not specify correct policy.
 * 
 * @author tautenhahn
 */
@WebService(name = "EAC-PKI-TermContr-ProtocolType", portName = "EAC-TermContr-ProtocolServicePort", serviceName = "EAC-TermContr-ProtocolService", targetNamespace = "uri:EAC-PKI-TermContr-Protocol/1.1", wsdlLocation = "WEB-INF/wsdl/CA-Services/TermAuth/Terminal/IS_termcontr/WS_IS_termcontr_TerminalAuth.wsdl")
@SOAPBinding(style = SOAPBinding.Style.RPC)
public class CertificateReceiverService implements EACPKITermContrProtocolType
{

  private static final Log LOG = LogFactory.getLog(CertificateReceiverService.class);

  /**
   * Unsupported. Please note that the combination "portName" and "SOAPBinding.Style.RPC" causes JAXWS to
   * demand copies of all the methods annotations in this class.
   */
  @Override
  @WebMethod(operationName = "GetCertificateChain")
  @WebResult(name = "Result", partName = "Result")
  public GetCertificateChainResult getCertificateChain(@WebParam(name = "keyCAR", partName = "keyCAR") byte[] keyCAR)
  {
    LOG.error("getCertificateChain() is not supported");
    throw new UnsupportedOperationException("The operation getCertificateChain() is not supported");
  }

  /**
   * Unsupported
   */
  @Override
  @WebMethod(operationName = "GetTASignature")
  @WebResult(name = "Result", partName = "Result")
  public GetTASignatureResult getTASignature(@WebParam(name = "hashTBS", partName = "hashTBS") OptionalBinaryType hashTBS,
                                             @WebParam(name = "idPICC", partName = "idPICC") OptionalBinaryType idPICC,
                                             @WebParam(name = "challengePICC", partName = "challengePICC") OptionalBinaryType challengePICC,
                                             @WebParam(name = "hashPK", partName = "hashPK") OptionalBinaryType hashPK,
                                             @WebParam(name = "auxPCD", partName = "auxPCD") OptionalBinaryType auxPCD,
                                             @WebParam(name = "keyCHR", partName = "keyCHR") byte[] keyCHR)
  {
    LOG.error("getTASignature() is not supported");
    throw new UnsupportedOperationException("The operation getTASignature() is not supported");
  }

  /**
   * Implements callback to receive a requested certificate asynchronously
   */
  @Override
  @WebMethod(operationName = "SendCertificates")
  @WebResult(name = "Result", partName = "Result")
  public SendCertificatesResult sendCertificates(@WebParam(name = "messageID", partName = "messageID") OptionalMessageIDType messageID,
                                                 @WebParam(name = "statusInfo", partName = "statusInfo") SendCertificatesStatusInfoType statusInfo,
                                                 @WebParam(name = "certificateSeq", partName = "certificateSeq") CertificateSeqType certificateSeq)
  {
    LOG.debug("(starting) sendCertificates");
    X509Certificate clientCert = identifyClient();
    PKIServiceConnector.SSL_LOGGER.debug("Got certificate request (sendCertificates(messageID, statusInfo, certificateSeq) with ssl client certificate: "
                                         + PKIServiceConnector.certificateToString(clientCert));
    if (certificateSeq != null && certificateSeq.getCertificate() != null)
    {
      for ( byte[] cert : certificateSeq.getCertificate() )
      {
        LOG.info("#############################################\ngot certificate:\n"
                 + Utils.breakAfter76Chars(DatatypeConverter.printBase64Binary(cert))
                 + "\n#############################################");
      }
    }
    String entityID = null;
    try
    {
      if (clientCert == null)
      {
        throw new SecurityException(
                                    "Received certificate message was not secured by SSL with client authentication.");
      }
      TerminalPermission tp = facade.getTerminalPermissionByMessage(messageID.getMessageID());
      if (tp == null)
      {
        return createResult(SendCertificatesReturnCodeType.FAILURE_MESSAGE_ID_UNKNOWN,
                            entityID + ":message ID \"" + messageID.getMessageID() + "\" not fond");
      }
      String cvcRefID = tp.getRefID();
      Collection<ServiceProviderDto> spMap = PoseidasConfigurator.getInstance()
                                                               .getCurrentConfig()
                                                               .getServiceProvider()
                                                               .values();

      ServiceProviderDto sp = null;
      for ( ServiceProviderDto spd : spMap )
      {
        if (spd.getEpaConnectorConfiguration() != null
            && cvcRefID.equals(spd.getEpaConnectorConfiguration().getCVCRefID())
            && spd.getEpaConnectorConfiguration().isUpdateCVC())
        {
          entityID = spd.getEntityID();
          sp = spd;
          break;
        }
      }

      if (sp == null)
      {
        return createResult(SendCertificatesReturnCodeType.FAILURE_INTERNAL_ERROR,
                            entityID + ": service provider not found");
      }
      EPAConnectorConfigurationDto nPaConf = sp.getEpaConnectorConfiguration();
      if (nPaConf == null)
      {
        return createResult(SendCertificatesReturnCodeType.FAILURE_INTERNAL_ERROR, entityID
                                                                                   + ": no nPA config found");
      }
      PkiConnectorConfigurationDto pkiConf = nPaConf.getPkiConnectorConfiguration();
      if (pkiConf == null)
      {
        return createResult(SendCertificatesReturnCodeType.FAILURE_INTERNAL_ERROR,
                            entityID + ": no pkiConf config found");
      }
      if (!pkiConnectorContainsServerCert(pkiConf, clientCert))
      {
        return createResult(SendCertificatesReturnCodeType.FAILURE_INTERNAL_ERROR,
                            entityID + ": ssl client certificate not in ssl server keys");
      }

      if (statusInfo == SendCertificatesStatusInfoType.OK_CERT_AVAILABLE)
      {
        if (certificateSeq == null || certificateSeq.getCertificate() == null)
        {
          return createResult(SendCertificatesReturnCodeType.FAILURE_SYNTAX, entityID
                                                                             + ": no certificate given");
        }
        CVCRequestHandler handler = new CVCRequestHandler(nPaConf, facade);
        handler.installNewCertificate(certificateSeq.getCertificate().get(0));
      }
      else
      {
        facade.storeCVCObtainedError(tp.getRefID(),
                                     "obtained certificate callback with status " + statusInfo.toString());
      }
      return createResult(SendCertificatesReturnCodeType.OK_RECEIVED_CORRECTLY);
    }
    catch (Throwable t)
    {
      LOG.error(entityID + ": cannot receive new certificate", t);
      SNMPDelegate.getInstance().sendSNMPTrap(SNMPDelegate.OID.CERT_RENEWAL_FAILED,
                                              SNMPDelegate.CERT_RENEWAL_FAILED + " " + t.getMessage());
      return createResult(SendCertificatesReturnCodeType.FAILURE_INTERNAL_ERROR,
                          entityID + ": cannot receive new certificate");
    }
  }

  private boolean pkiConnectorContainsServerCert(PkiConnectorConfigurationDto pkiConf,
                                                 X509Certificate clientCert)
  {
    for ( SslKeysDto sslKey : pkiConf.getSslKeys().values() )
    {
      if (clientCert.equals(sslKey.getServerCertificate()))
      {
        return true;
      }
    }
    return false;
  }

  private SendCertificatesResult createResult(SendCertificatesReturnCodeType code, String errorMessage)
  {
    LOG.error(errorMessage + ", will answer with " + code);
    return createResult(code);
  }

  private SendCertificatesResult createResult(SendCertificatesReturnCodeType code)
  {
    SendCertificatesResult result = new SendCertificatesResult();
    result.setReturnCode(code);
    return result;
  }

  @Autowired
  TerminalPermissionAO facade;

  @Resource
  WebServiceContext context;

  private X509Certificate identifyClient()
  {
    HttpServletRequest httpRequest = ((HttpServletRequest)context.getMessageContext()
                                                                 .get(MessageContext.SERVLET_REQUEST));
    if (!httpRequest.isSecure())
    {
      return null;
    }
    Object certAttrib = httpRequest.getAttribute("javax.servlet.request.X509Certificate");
    if (certAttrib != null && ((X509Certificate[])certAttrib).length > 0)
    {
      return ((X509Certificate[])certAttrib)[0];
    }
    return null;
  }
}

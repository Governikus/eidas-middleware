/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.soap.SOAPFaultException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.xml.rpc.encoding.soap.SOAP12Constants;
import com.sun.xml.wss.impl.MessageConstants;

import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * Generic eID web service implementation. This Class just provied some functions which are not depending on
 * any specific eID-Webservice version.
 *
 * @author CM, TT
 * @author Hauke Mehrtens
 */

public class EIDImpl
{

  private static final Log LOG = LogFactory.getLog(EIDImpl.class);

  /* Where is this specified? */
  protected final ThreadLocal<String> refId = new ThreadLocal<>();

  private static boolean initialized = false;

  private static X509Certificate frontendCert = null;

  protected EIDImpl()
  {
    if (!initialized)
    {
      initialize();
    }
  }

  private static void initialize()
  {
    String filePath = System.getProperty("de.bos_bremen.eid.service.ssl.frontend.cert");
    if (filePath != null)
    {
      try (FileInputStream fin = new FileInputStream(filePath))
      {
        frontendCert = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(fin);
      }
      catch (Exception e)
      {
        LOG.error("Error reading configured frontend certificate '"
                  + filePath + "'",
                  e);
        return;
      }
    }
    EIDInternal.getInstance().init();
    initialized = true;
  }

  protected TerminalData getCVC(String cvcRefId)
  {
    EIDInternal eid = EIDInternal.getInstance();
    return eid.getCVCData(cvcRefId).getFullCvc();
  }

  protected static XMLGregorianCalendar createXMLDate(String input, String logPrefix)
  {
    if (input == null || input.trim().length() != 8)
    {
      return null;
    }
    try
    {
      int day = Integer.parseInt(input.substring(6, 8));
      int month = Integer.parseInt(input.substring(4, 6));
      int year = Integer.parseInt(input.substring(0, 4));
      GregorianCalendar date = (GregorianCalendar)Calendar.getInstance();
      date.set(Calendar.DAY_OF_MONTH, day);
      // WARNING: GregorianCalendar counts month beginning with january=0!
      date.set(Calendar.MONTH, month - 1);
      date.set(Calendar.YEAR, year);
      date.set(Calendar.HOUR_OF_DAY, 0);
      date.set(Calendar.MINUTE, 0);
      date.set(Calendar.SECOND, 0);
      date.set(Calendar.MILLISECOND, 0);
      return DatatypeFactory.newInstance().newXMLGregorianCalendar(date);
    }
    catch (DatatypeConfigurationException e)
    {
      LOG.error(logPrefix + "date construction failed", e);
      return null;
    }
  }

  protected String resultToString(Result result)
  {
    StringBuilder builder = new StringBuilder("ResultMajor: ");
    builder.append(result.getResultMajor());
    if (result.getResultMinor() != null)
    {
      builder.append(", ResultMinor: ");
      builder.append(result.getResultMinor());
    }
    if (result.getResultMessage() != null && result.getResultMessage().getValue() != null)
    {
      builder.append(", ResultMessage: ");
      builder.append(result.getResultMessage().getValue());
    }
    return builder.toString();
  }

  /**
   * Get the certificate from the XML signature of the SOAP request
   *
   * @param ctx
   * @param config
   * @return
   */
  private static ServiceProviderDto identifyClientByXmlSigCert(MessageContext ctx,
                                                               CoreConfigurationDto config)
  {
    Subject subject = (Subject)ctx.get(Subject.class.getName());
    if (subject != null)
    {
      Set<X509Certificate> certs = subject.getPublicCredentials(X509Certificate.class);
      if (certs.size() == 1)
      {
        X509Certificate cert = certs.iterator().next();
        ServiceProviderDto prov = config.findProviderForCertificate(cert);
        if (prov == null)
        {
          LOG.error("can not identify client by ssl cert: SubjectDN: " + cert.getSubjectDN());
        }
        return prov;
      }
    }

    BigInteger serial = (BigInteger)ctx.get(MessageConstants.REQUESTER_SERIAL);
    String issuer = (String)ctx.get(MessageConstants.REQUESTER_ISSUERNAME);
    if (issuer != null && serial != null)
    {
      ServiceProviderDto prov = config.findProviderForCertificate(issuer, serial);
      if (prov == null)
      {
        LOG.error("can not identify client by ssl cert: issuer: " + issuer + " serial: " + serial);
      }
      return prov;
    }
    return null;
  }

  /**
   * Get the certificate from the CCL Client auth
   *
   * @param httpRequest
   * @param config
   * @param frontend
   * @return
   * @throws CertificateException
   */
  private static ServiceProviderDto identifyClientBySslCert(HttpServletRequest httpRequest,
                                                            CoreConfigurationDto config,
                                                            boolean frontend)
    throws CertificateException
  {
    X509Certificate cert = null;
    if (frontend)
    {
      cert = (X509Certificate)CertificateFactory.getInstance("X.509")
                                                .generateCertificate(new ByteArrayInputStream(DatatypeConverter.parseHexBinary(httpRequest.getHeader("GovernikusFrontendAuthCert"))));
    }
    else
    {
      Object certAttrib = httpRequest.getAttribute("javax.servlet.request.X509Certificate");
      if (certAttrib instanceof X509Certificate[])
      {
        cert = ((X509Certificate[])certAttrib)[0];
      }
    }
    if (cert != null)
    {
      ServiceProviderDto prov = config.findProviderForSSLCertificate(cert);
      if (prov == null)
      {
        LOG.error("can not identify client by cert " + cert.getSubjectDN());
      }
      return prov;
    }
    return null;
  }

  /**
   * Problem: Context wird von Metro irgendwann injiziert. In parallelen Threads gibt es aber nur eine
   * Referenz. Daher kann alles, was man aus dem Context liest, einem anderen Call angehören.
   */
  protected ServiceProviderDto identifyClient(WebServiceContext context, CoreConfigurationDto config)
  {
    try
    {
      if (!initialized)
      {
        throw new SecurityException("EIDImpl not initialized, probably reading of configured frontend certificate has failed. Look for previous log entries.");
      }

      MessageContext ctx = context.getMessageContext();

      // These Webservices are have to be called with SSL enabled
      HttpServletRequest httpRequest = ((HttpServletRequest)ctx.get(MessageContext.SERVLET_REQUEST));
      if (!httpRequest.isSecure())
      {
        throw new SOAPFaultException(SOAPFactory.newInstance()
                                                .createFault("access without SSL is not allowed",
                                                             SOAP12Constants.FAULT_CODE_CLIENT));
      }

      // if we are using the frontend the key has to be configrated
      boolean frontend = frontendCert != null;
      Object certAttrib = httpRequest.getAttribute("javax.servlet.request.X509Certificate");
      if (frontend && (certAttrib == null || !frontendCert.equals(((X509Certificate[])certAttrib)[0])))
      {
        throw new SecurityException("Certificate used for SSL client authentication does not equal configured frontend certificate.");
      }

      ServiceProviderDto provSsl = identifyClientBySslCert(httpRequest, config, frontend);
      ServiceProviderDto provXml = identifyClientByXmlSigCert(ctx, config);
      // If the SSL authentication is done with a different Service provide key than the XML signature abort,
      // there is something wrong.
      if (provSsl != null && provXml != null && !provSsl.equals(provXml))
      {
        throw new SOAPFaultException(SOAPFactory.newInstance()
                                                .createFault("The client identified as two different service provider",
                                                             SOAP12Constants.FAULT_CODE_CLIENT));
      }
      ServiceProviderDto prov = provXml != null ? provXml : provSsl;

      if (prov == null || prov.getEpaConnectorConfiguration() == null)
      {
        throw new SOAPFaultException(SOAPFactory.newInstance()
                                                .createFault("could not identify client",
                                                             SOAP12Constants.FAULT_CODE_CLIENT));
      }

      refId.set(httpRequest.getHeader(Constants.NAME_REFID));

      if (LOG.isDebugEnabled())
      {
        LOG.debug("got request with refId=" + refId.get() + " and service provider " + prov.getEntityID());
      }
      return prov;
    }
    catch (SOAPException | CertificateException e)
    {
      LOG.error("error in eID Webservice: " + e.getMessage());
      throw new RuntimeException(e.getMessage(), e);
    }
  }

}

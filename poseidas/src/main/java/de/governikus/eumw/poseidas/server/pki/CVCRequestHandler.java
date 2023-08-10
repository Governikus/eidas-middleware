/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;
import javax.xml.ws.WebServiceException;

import org.apache.commons.lang.ArrayUtils;

import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateDescription;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCPath;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECPublicKeyPath;
import de.governikus.eumw.poseidas.cardserver.certrequest.CertificateRequest;
import de.governikus.eumw.poseidas.cardserver.certrequest.CertificateRequestPath;
import de.governikus.eumw.poseidas.cardserver.certrequest.CvcRequestGenerator.CvcRequestData;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.KeyPair;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.DvcaCertDescriptionService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PKIServiceConnector;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthService;
import lombok.extern.slf4j.Slf4j;
import uri.eacbt._1.termAuth.dv.RequestCertificateReturnCodeType;


/**
 * Implementation of the CVC request process.
 *
 * @author tautenhahn
 */
@Slf4j
public class CVCRequestHandler extends BerCaRequestHandlerBase
{

  private static final Map<String, TerminalData> KNOWN_ROOT_CERTS = new HashMap<>();

  private static final String DETEST_EID00001 = "fyGCAbZ/ToIBbl8pAQBCDkRFVEVTVGVJRDAwMDAxf0mCAR0GCgQAfwAHAgICAgOBIKn7V9uh7qm8PmYKkJ2DjXJuO/Yj1SYgKCATSB0fblN3giB9Wgl1/CwwV+72dTBBev/n+4BVwSbcXGzpSktE8zC12YMgJtxcbOlKS0TzMLXZu9d8v5WEFilc9+HOa8zcGP+MB7aEQQSL0q65y35XyyxLSC/8gbevud4n4eO9I8I6RFO9ms4yYlR++DXD2sT9l/hGGhRhHcnCd0UTLe2OVFwdVMcvBGmXhSCp+1fboe6pvD5mCpCdg41xjDl6o7VhpveQHg6Cl0hWp4ZBBBhLtRn8Ko9S3A3HMRL6z+kU8qSbZ43VeZorHf6V4aZjWQFOIvqNZkOEE866bPDiFVdrZzN2v2F69N/pdh0ikBSHAQFfIA5ERVRFU1RlSUQwMDAwMX9MEgYJBAB/AAcDAQICUwX+DwH//18lBgEAAAgBA18kBgEDAAgBA183QJ8l6/r0uR5MYKFoN1TF3AdqMXl1Pvl9n4ywH+Hc07jIPnomYCqx80S+VwYAbXmp/2qXFkBNyDufMOEhOzkxKKI=";

  private static final String DETEST_EID00002 = "fyGCAbZ/ToIBbl8pAQBCDkRFVEVTVGVJRDAwMDAxf0mCAR0GCgQAfwAHAgICAgOBIKn7V9uh7qm8PmYKkJ2DjXJuO/Yj1SYgKCATSB0fblN3giB9Wgl1/CwwV+72dTBBev/n+4BVwSbcXGzpSktE8zC12YMgJtxcbOlKS0TzMLXZu9d8v5WEFilc9+HOa8zcGP+MB7aEQQSL0q65y35XyyxLSC/8gbevud4n4eO9I8I6RFO9ms4yYlR++DXD2sT9l/hGGhRhHcnCd0UTLe2OVFwdVMcvBGmXhSCp+1fboe6pvD5mCpCdg41xjDl6o7VhpveQHg6Cl0hWp4ZBBAlutYv9hiUiOOwmUhhcQ8OlbDIGgaIeN6jmndw4fAxfVROFbv4v3GVuYEiTIS4pRJs2XjBGBaxUE+db4x5kHxKHAQFfIA5ERVRFU1RlSUQwMDAwMn9MEgYJBAB/AAcDAQICUwX+DwH//18lBgEAAAkCAV8kBgEDAAkCAV83QBQRIKD9/AEaUvP3Kzh6PcesqItIaNWul0F4C2/4oLSeX1UWmi0pjvXPlZNdygw98+nULcRfdPIGYxcVSWHmx0Y=";

  private static final String DETEST_EID00004 = "fyGCAbZ/ToIBbl8pAQBCDkRFVEVTVGVJRDAwMDAyf0mCAR0GCgQAfwAHAgICAgOBIKn7V9uh7qm8PmYKkJ2DjXJuO/Yj1SYgKCATSB0fblN3giB9Wgl1/CwwV+72dTBBev/n+4BVwSbcXGzpSktE8zC12YMgJtxcbOlKS0TzMLXZu9d8v5WEFilc9+HOa8zcGP+MB7aEQQSL0q65y35XyyxLSC/8gbevud4n4eO9I8I6RFO9ms4yYlR++DXD2sT9l/hGGhRhHcnCd0UTLe2OVFwdVMcvBGmXhSCp+1fboe6pvD5mCpCdg41xjDl6o7VhpveQHg6Cl0hWp4ZBBHT/Y6uDjHPDA6wAPf7pXPi/Vfkej+vLc5XZQgNuR88YRex4bslbtFOqwoitAjtgZ5E8+bY/kI9JME5c/IswUN2HAQFfIA5ERVRFU1RlSUQwMDAwNH9MEgYJBAB/AAcDAQICUwX8DxP//18lBgECAAUBAV8kBgEFAAUBAV83QFwDWgYRtsWPC1Jh/dAJ3sq33Hp5SC1SSMyhGQWbfYKyFXzwxKSZvPRB79014pSljArxmjSgdiFZUzKFrPFwpQU=";

  private static final String DECVCA_EID00103 = "fyGCAbZ/ToIBbl8pAQBCDkRFQ1ZDQWVJRDAwMTAyf0mCAR0GCgQAfwAHAgICAgOBIKn7V9uh7qm8PmYKkJ2DjXJuO/Yj1SYgKCATSB0fblN3giB9Wgl1/CwwV+72dTBBev/n+4BVwSbcXGzpSktE8zC12YMgJtxcbOlKS0TzMLXZu9d8v5WEFilc9+HOa8zcGP+MB7aEQQSL0q65y35XyyxLSC/8gbevud4n4eO9I8I6RFO9ms4yYlR++DXD2sT9l/hGGhRhHcnCd0UTLe2OVFwdVMcvBGmXhSCp+1fboe6pvD5mCpCdg41xjDl6o7VhpveQHg6Cl0hWp4ZBBIklQZ/H8ZSSLPxrjdJa5qGcG1khbmzwYnDl11z9ZCBfVc+Ge7/v7v1uaA4f0ZfxiraESEkBNiVo78mttcYBjXKHAQFfIA5ERUNWQ0FlSUQwMDEwM39MEgYJBAB/AAcDAQICUwX8DxP//18lBgECAQIAA18kBgEFAQIAA183QE1vCKhqTxhAn2aFOH3Txqf/XWjqT3cUqGG7s7tyHQXTAUrfF2PJKS9xXY6U7ps+G3OrE4JBTr8537Ow+2wJ2+s=";

  private static final String DECVCA_EID00102 = "fyGCAbZ/ToIBbl8pAQBCDkRFQ1ZDQWVJRDAwMTAyf0mCAR0GCgQAfwAHAgICAgOBIKn7V9uh7qm8PmYKkJ2DjXJuO/Yj1SYgKCATSB0fblN3giB9Wgl1/CwwV+72dTBBev/n+4BVwSbcXGzpSktE8zC12YMgJtxcbOlKS0TzMLXZu9d8v5WEFilc9+HOa8zcGP+MB7aEQQSL0q65y35XyyxLSC/8gbevud4n4eO9I8I6RFO9ms4yYlR++DXD2sT9l/hGGhRhHcnCd0UTLe2OVFwdVMcvBGmXhSCp+1fboe6pvD5mCpCdg41xjDl6o7VhpveQHg6Cl0hWp4ZBBDNH7Plv+0vZuFVO+8z8fQskLxBx4ptMnGIseeM52ECvZ765uRJpImXZwWxiVz9Fef/U3i3pK6tAndXF1IJEqfeHAQFfIA5ERUNWQ0FlSUQwMDEwMn9MEgYJBAB/AAcDAQICUwX+DwH//18lBgEAAQABCF8kBgEDAQABCF83QFBnFFxoyulSD1uzSBfxypxDWT21ZAbGo7AGy/PzFOc0ms8Mxr/ry979ELTc8PIx2laXfYj5+QGC0ZkHalZQZFE=";
  static
  {
    // ref PKI
    addKnowRootCert(DETEST_EID00001);
    addKnowRootCert(DETEST_EID00002);
    addKnowRootCert(DETEST_EID00004);
    // prod PKI
    addKnowRootCert(DECVCA_EID00102);
    addKnowRootCert(DECVCA_EID00103);
  }

  /**
   * Create new Object which can be used for one service provider only as long as configuration is not changed.
   *
   * @param epaConfig The connection configuration for the terminal
   * @param facade The terminal configuration
   * @param hsmKeyStore HSM keystore
   */
  CVCRequestHandler(ServiceProviderType epaConfig,
                    TerminalPermissionAO facade,
                    KeyStore hsmKeyStore,
                    ConfigurationService configurationService,
                    PendingCertificateRequestRepository pendingCertificateRequestRepository)
    throws GovManagementException
  {
    super(epaConfig, facade, hsmKeyStore, configurationService);
  }

  private static void addKnowRootCert(String base64)
  {
    try
    {
      TerminalData cvc = new TerminalData(DatatypeConverter.parseBase64Binary(base64));
      KNOWN_ROOT_CERTS.put(cvc.getHolderReferenceString(), cvc);
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("unable to parse given cvc", e);
    }
  }

  private static void checkCVC(byte[] newCvcBytes,
                               byte[] oldCvcBytes,
                               byte[][] chain,
                               ASN1 publicKey,
                               ASN1 holderReference,
                               Date actualDate,
                               String cvcRefId)
    throws CertificateException, GovManagementException
  {
    try
    {
      TerminalData newCVC = new TerminalData(newCvcBytes);

      if (oldCvcBytes != null && oldCvcBytes.length > 1)
      {
        TerminalData oldCVC = new TerminalData(oldCvcBytes);

        // check if the new and old cvc are identical
        if (Arrays.equals(newCvcBytes, oldCvcBytes))
        {
          String detail = String.format("new cvc '%s' is identical with existing cvc '%s'", newCVC, oldCVC);
          throw new CertificateException(detail);
        }

        // check the holder reference
        if (holderReference == null)
        {
          // only if there is no holder reference from request data, check holder reference from old CVC
          byte[] newBasicHolderReference = getBasicHolderReference(newCVC);
          byte[] oldBasicHolderReference = getBasicHolderReference(oldCVC);
          if (!Arrays.equals(oldBasicHolderReference, newBasicHolderReference))
          {
            String detail = String.format("holder reference of new cvc '%s' does not match holder reference of existing cvc '%s'",
                                          newCVC,
                                          oldCVC);
            throw new CertificateException(detail);
          }
        }
        else
        {
          byte[] newBasicHolderReference = getBasicHolderReference(newCVC);
          byte[] requestedBasicHolderReference = getBasicHolderReference(holderReference);
          if (!Arrays.equals(requestedBasicHolderReference, newBasicHolderReference))
          {
            String detail = String.format("holder reference of new cvc '%s' does not match holder reference of certificate request",
                                          newCVC);
            throw new CertificateException(detail);
          }
        }
      }

      try
      {
        // check if chain is present
        if (chain == null)
        {
          log.warn("{}: no chain present to check new cvc: {}",
                   cvcRefId,
                   new String(newCVC.getCAReference(), StandardCharsets.UTF_8));
          String detail = String.format("no chain present to check new cvc '%s'", newCVC);
          throw new CertificateException(detail);
        }

        // check, if the CA reference of the new cvc is present in the chain
        boolean foundInChain = false;
        for ( byte[] cacert : chain )
        {
          TerminalData parsedCaCVC = new TerminalData(cacert);
          if (Arrays.equals(parsedCaCVC.getHolderReference(), newCVC.getCAReference()))
          {
            foundInChain = true;
            break;
          }
        }
        if (!foundInChain)
        {
          String detail = "ca reference of new cvc not found in chain: " + newCVC;
          throw new CertificateException(detail);
        }

        // check the dates
        if (newCVC.getEffectiveDate().after(actualDate))
        {
          String detail = String.format("effective date of new cvc '%s' is after actual date", newCVC);
          throw new CertificateException(detail);
        }
        if (newCVC.getExpirationDate().before(actualDate))
        {
          String detail = String.format("expiration date of new cvc '%s' is before actual date", newCVC);
          throw new CertificateException(detail);
        }

        // check the public key. it must be equal to the public key of the request
        ASN1 newCVCPublicKey = newCVC.getPublicKey();
        ASN1 newCVCPublicPoint = newCVCPublicKey.getChildElementByPath(ECPublicKeyPath.PUBLIC_POINT_Y);
        ASN1 requestPublicPoint = publicKey.getChildElementByPath(ECPublicKeyPath.PUBLIC_POINT_Y);
        if (!requestPublicPoint.equals(newCVCPublicPoint))
        {
          String detail = String.format("public key of new cvc '%s' does not match public key of pending request",
                                        newCVC);
          throw new CertificateException(detail);
        }

        // check the signatures
        List<TerminalData> formattedCVCList = formatCVCList(newCVC, Arrays.asList(chain), cvcRefId);
        try
        {
          if (!newCVC.verify(formattedCVCList))
          {
            String detail = String.format("mathematical signature check of new cvc '%s' failed", newCVC);
            throw new CertificateException(detail);
          }
        }
        catch (IOException e)
        {
          String detail = String.format("mathematical signature check of new cvc '%s' failed", newCVC);
          throw new CertificateException(detail, e);
        }
      }
      catch (IOException e)
      {
        throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, "IOException: " + e.getMessage());
      }
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("unable to parse given cvc", e);
    }
  }

  /**
   * @param newCVC
   * @return
   */
  private static byte[] getBasicHolderReference(TerminalData newCVC)
  {
    byte[] newHolderReference = new byte[newCVC.getHolderReference().length - 5];
    System.arraycopy(newCVC.getHolderReference(), 0, newHolderReference, 0, newHolderReference.length);
    return newHolderReference;
  }

  /**
   * @param holderReference
   * @return
   */
  private static byte[] getBasicHolderReference(ASN1 holderReference)
  {
    byte[] hrBytes = holderReference.getValue();
    byte[] newHolderReference = new byte[hrBytes.length - 5];
    System.arraycopy(hrBytes, 0, newHolderReference, 0, newHolderReference.length);
    return newHolderReference;
  }

  /**
   * Creates a sorted list from the given list
   *
   * @param terminalCertificate the terminal certificate to build the chain for
   * @param cvcChain the unsorted chain certificates
   * @param cvcRefId
   * @throws IllegalArgumentException if something illegal with the input
   * @return List with the chain certificates without the terminal and the root certificate
   */
  private static List<TerminalData> formatCVCList(TerminalData terminalCertificate,
                                                  List<byte[]> cvcChain,
                                                  String cvcRefId)
  {
    if (log.isDebugEnabled())
    {
      log.debug("{}: Parse session input CVC list with size: {}", cvcRefId, cvcChain.size());
    }
    List<TerminalData> formattedChain = new ArrayList<>();

    // Check the terminal CVC and add it to the list as first element
    if (terminalCertificate.isSelfSigned())
    {
      // FIXME: throw appropriate Exception
      throw new IllegalArgumentException("First CVC in list is self signed and not the terminal CVC");
    }
    TerminalData check = terminalCertificate;
    while (true)
    {
      if (log.isDebugEnabled())
      {
        log.debug("{}: Check CVC: {}/{}",
                  cvcRefId,
                  check.getHolderReferenceString(),
                  new String(check.getCAReference(), StandardCharsets.UTF_8));
      }
      TerminalData holderCVC = getReference(check, cvcChain);
      if (holderCVC == null)
      {
        break;
      }
      if (holderCVC.isSelfSigned())
      {
        formattedChain.add(holderCVC);
        break;
      }
      formattedChain.add(holderCVC);
      check = holderCVC;

    }
    if (log.isDebugEnabled())
    {
      log.debug("{}: Parsed session input and set new list with size: {}", cvcRefId, formattedChain.size());
    }
    return formattedChain;
  }

  private static TerminalData getReference(TerminalData toFind, List<byte[]> cvcChain)
  {
    for ( byte[] cvcBytes : cvcChain )
    {
      try
      {
        TerminalData cvc = new TerminalData(cvcBytes);
        if (Arrays.equals(cvc.getHolderReference(), toFind.getCAReference()))
        {
          return cvc;
        }
      }
      catch (IOException e)
      {
        throw new IllegalArgumentException("unable to parse given cvc", e);
      }
    }
    return null;
  }

  private static boolean canBeGivenToRequestGenerator(byte[] data)
  {
    try
    {
      ECCVCertificate cert = new ECCVCertificate(data);
      return cert.getChildElementByPath(ECCVCPath.PUBLIC_KEY_PRIME_MODULUS) != null;
    }
    catch (IOException e)
    {
      return false;
    }
  }

  /**
   * Create and send an initial certificate request.
   *
   * @param cvcDescription
   * @param countryCode
   * @param chrMnemonic
   * @param sequenceNumber
   */
  void makeInitialRequest(byte[] cvcDescription, String countryCode, String chrMnemonic, int sequenceNumber)
    throws GovManagementException
  {
    try
    {
      byte[][] encodedCvcs = getCACertificates(null);
      TerminalPermission tp = facade.getTerminalPermission(cvcRefId);
      if (tp == null)
      {
        facade.create(cvcRefId);
        tp = facade.getTerminalPermission(cvcRefId);
      }
      PoseidasCertificateRequestGenerator generator = new PoseidasCertificateRequestGenerator(cvcRefId, facade);
      generator.setDataForFirstRequest(selectRootCert(encodedCvcs),
                                       cvcDescription,
                                       countryCode,
                                       chrMnemonic,
                                       sequenceNumber);
      boolean withPendingRsc = false;
      if (facade.getPendingRscChrId(cvcRefId) != null
          && facade.getRequestSignerCertificate(cvcRefId, false).getNotAfter().after(new Date()))
      {
        log.info("{}: Make an initial request with the pending request signer certificate.", cvcRefId);
        withPendingRsc = true;
        generator.setRscAlias(buildAlias(cvcRefId, facade, false));
        generator.setRscPrivateKey(tp.getPendingRequestSignerCertificate().getPrivateKey());
      }
      else if (facade.getCurrentRscChrId(cvcRefId) != null
               && facade.getRequestSignerCertificate(cvcRefId, true).getNotAfter().after(new Date()))
      {
        log.info("{}: Make an initial request with the current request signer certificate.", cvcRefId);
        generator.setRscAlias(buildAlias(cvcRefId, facade, true));
        generator.setRscPrivateKey(tp.getCurrentRequestSignerCertificate().getPrivateKey());
      }
      CvcRequestData requestData = generator.create();
      String messageId = "#" + Utils.generateUniqueID();
      storeRequestData(cvcRefId,
                       messageId,
                       requestData.getCertificateRequest(),
                       requestData.getCertificateDescription(),
                       encodedCvcs,
                       requestData.getPkcs8PrivateKey());
      log.info("{}: Created and stored initial certificate request\n{}", cvcRefId, requestData.getCertificateRequest());

      byte[] cert;
      try
      {
        cert = sendCertificateRequest(requestData.getCertificateRequest().getEncoded());
        if (withPendingRsc)
        {
          facade.makePendingRscToCurrentRsc(cvcRefId);
        }
        installNewCertificate(cert);
      }
      catch (GovManagementException e)
      {
        if (withPendingRsc)
        {
          log.debug("Request with pending request signer certificate failed", e);
          log.info("{}: Could not make an initial request with pending request signer certificate.", cvcRefId);
          generator.setRscAlias(buildAlias(cvcRefId, facade, true));
          if (facade.getCurrentRscChrId(cvcRefId) == null)
          {
            log.info("{}: Fallback to initial request without request signer certificate.", cvcRefId);
          }
          else
          {
            log.info("{}: Fallback to initial request with the current request signer certificate.", cvcRefId);
            generator.setRscPrivateKey(tp.getCurrentRequestSignerCertificate().getPrivateKey());
          }
          requestData = generator.create();
          messageId = "#" + Utils.generateUniqueID();
          storeRequestData(cvcRefId,
                           messageId,
                           requestData.getCertificateRequest(),
                           requestData.getCertificateDescription(),
                           encodedCvcs,
                           requestData.getPkcs8PrivateKey());
          log.info("{}: Created and stored second initial certificate request\n{}",
                   cvcRefId,
                   requestData.getCertificateRequest());
          cert = sendCertificateRequest(requestData.getCertificateRequest().getEncoded());
          installNewCertificate(cert);
        }
        else
        {
          throw e;
        }
      }
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 0);

      // After storing the very first CVC, also request black, master and defect lists and public sector key
      // if needed
      requestBlackListAndPublicSectorKey(tp);
      requestMasterAndDefectList();
      CertificationRevocationListImpl.tryInitialize(configurationService, facade);
    }
    catch (GovManagementException e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 1);
      throw e;
    }
    catch (IOException | SignatureException e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 1);
      internalError("cannot create cert request", e);
    }
  }

  private void internalError(String msg, Exception e) throws GovManagementException
  {
    log.error("{}: {}", cvcRefId, msg, e);
    throw new GovManagementException(GlobalManagementCodes.INTERNAL_ERROR);
  }

  /**
   * create and send a subsequent request, store the obtained data in the persistence layer.
   *
   * @param tp terminal permission to be renewed
   * @return null if successful, technical error message otherwise
   */
  ManagementMessage makeSubsequentRequest(TerminalPermission tp)
  {
    if (tp.getCvc() == null)
    {
      // none present
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("cannot renew certificate as there is none for provider "
                                                                     + cvcRefId);
    }

    boolean expired = tp.getNotOnOrAfter().before(new Date());
    boolean hasPendingRsc = tp.getPendingRequestSignerCertificate() != null;
    boolean hasCurrentRsc = tp.getCurrentRequestSignerCertificate() != null;
    if (expired && !hasPendingRsc && !hasCurrentRsc)
    {
      // no recovery possible
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("cannot renew certificate as it is expired and no RSC available for provider "
                                                                     + cvcRefId);
    }

    try
    {
      String chr = new ECCVCertificate(tp.getCvc()).getHolderReferenceString();
      this.facade.archiveCVC(chr, tp.getCvc());
      log.debug("{}: CVC {} successfully archived", cvcRefId, chr);
    }
    catch (IOException e)
    {
      log.warn("{}: CVC could not be archived", cvcRefId);
    }

    return renewCvc(tp, hasPendingRsc);
  }

  private ManagementMessage renewCvc(TerminalPermission tp, boolean usePendingRsc)
  {
    byte[][] chain = null;
    try
    {
      chain = getCACertificates(null);
    }
    catch (GovManagementException e)
    {
      log.warn("{}: cannot download CA certificates, will keep old certificate chain", cvcRefId);
    }

    if (chain == null) // download failed
    {
      chain = new byte[tp.getChain().size()][];
      for ( CertInChain cin : tp.getChain() )
      {
        chain[cin.getKey().getPosInChain()] = cin.getData();
      }
    }

    try
    {
      CvcRequestData requestData = createRequest(tp, chain, usePendingRsc);
      storeRequestData(cvcRefId,
                       "s" + Utils.generateUniqueID(),
                       requestData.getCertificateRequest(),
                       requestData.getCertificateDescription(),
                       null,
                       requestData.getPkcs8PrivateKey());
      log.info("{}: Created and stored subsequent certificate request:\n{}",
               cvcRefId,
               requestData.getCertificateRequest());
      byte[] cvcRequestData = requestData.getCertificateRequest().getEncoded();
      byte[] newCert = sendCertificateRequest(cvcRequestData);
      if (usePendingRsc)
      {
        facade.makePendingRscToCurrentRsc(cvcRefId);
      }
      installNewCertificate(newCert);
      log.debug("{}: successfully finished makeSubsequentRequest", cvcRefId);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 0);
    }
    catch (Exception e)
    {
      if (usePendingRsc)
      {
        log.info("{}: subsequent request using pending RSC was not successful, will retry without", cvcRefId);
        if (log.isDebugEnabled())
        {
          log.debug(cvcRefId + ": Received exception for request with pending RSC", e);
        }
        return renewCvc(tp, false);
      }
      log.error("{}: cannot renew certificate", cvcRefId, e);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 1);
      if (e instanceof GovManagementException)
      {
        return ((GovManagementException)e).getManagementMessage();
      }
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage(e.getMessage());
    }
    return null;
  }

  public static String getHolderReferenceStringOfPendingRequest(PendingCertificateRequest pendingCertificateRequest)
  {
    try
    {
      if (pendingCertificateRequest == null)
      {
        return null;
      }
      // Get encoded certificate request
      byte[] requestData = pendingCertificateRequest.getRequestData();
      if (ArrayUtils.isEmpty(requestData))
      {
        return null;
      }
      // Encoded certificate request is wrapped in an application tag, that needs to be unwrapped (removed) for parsing
      ASN1 asn1 = new ASN1(requestData);
      byte[] value = asn1.getValue();
      if (value == null)
      {
        return null;
      }
      CertificateRequest certificateRequest = new CertificateRequest(value);
      return certificateRequest.getHolderReferenceString();
    }
    catch (IOException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Could not get holder reference from pending request {}", pendingCertificateRequest.getRefID(), e);
      }
      return "holder reference not found";
    }
  }

  private CvcRequestData createRequest(TerminalPermission tp, byte[][] chain, boolean usePendingRsc)
    throws IOException, SignatureException
  {
    PoseidasCertificateRequestGenerator generator = new PoseidasCertificateRequestGenerator(cvcRefId, facade);
    generator.prepareSubsequentRequest(selectRootCert(chain),
                                       tp.getCvc(),
                                       tp.getCvcPrivateKey(),
                                       tp.getCvcDescription(),
                                       tp.getNextCvcSequenceNumber());

    if (usePendingRsc)
    {
      log.info("{}: Make a subsequent request with the pending request signer certificate.", cvcRefId);
      generator.setRscPrivateKey(tp.getPendingRequestSignerCertificate().getPrivateKey());
      generator.setRscAlias(buildAlias(cvcRefId, facade, false));
    }
    else if (tp.getCurrentRequestSignerCertificate() != null
             && facade.getRequestSignerCertificate(cvcRefId, true).getNotAfter().after(new Date()))
    {
      log.info("{}: Make a subsequent request with the current request signer certificate.", cvcRefId);
      generator.setRscPrivateKey(tp.getCurrentRequestSignerCertificate().getPrivateKey());
      generator.setRscAlias(buildAlias(cvcRefId, facade, true));
    }
    else
    {
      log.info("{}: Make a subsequent request with the previous CVC.", cvcRefId);
    }

    return generator.create();
  }

  private static String buildAlias(String cvcRefId, TerminalPermissionAO facade, boolean useCurrent)
  {
    String requestSignerCertificateHolder = facade.getRequestSignerCertificateHolder(cvcRefId);
    if (requestSignerCertificateHolder == null)
    {
      return null;
    }
    Integer rscChrId = useCurrent ? facade.getCurrentRscChrId(cvcRefId) : facade.getPendingRscChrId(cvcRefId);
    if (rscChrId == null)
    {
      return null;
    }
    return requestSignerCertificateHolder + RequestSignerCertificateServiceImpl.getRscChrIdAsString(rscChrId);
  }

  /**
   * install an obtained CVCert.
   *
   * @param cert
   */
  private void installNewCertificate(byte[] cert) throws GovManagementException
  {

    byte[][] chain = null;
    byte[] certDescription = null;
    try
    {
      ECCVCertificate cvc = new ECCVCertificate(cert);
      String preferedCHR = cvc.getAuthorityReferenceString();
      chain = getCACertificates(preferedCHR);
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("unable to parse given cvc", e);
    }
    catch (GovManagementException e)
    {
      log.warn("{}: cannot download ca certificates, will keep old certificate chain", cvcRefId);
    }

    certDescription = getCertDescriptionIfNeeded(cert);


    TerminalPermission tp = facade.getTerminalPermission(cvcRefId);

    try
    {
      PendingCertificateRequest pendingCertificateRequest = tp.getPendingRequest();

      byte[][] chainForCheck = chain;
      if (chainForCheck == null) // download failed
      {
        chainForCheck = new byte[tp.getChain().size()][];
        for ( CertInChain cin : tp.getChain() )
        {
          chainForCheck[cin.getKey().getPosInChain()] = cin.getData();
        }
      }
      byte[] requestData = pendingCertificateRequest.getRequestData();
      CertificateRequest certificateRequest = new CertificateRequest(new ByteArrayInputStream(requestData), true);
      ASN1 publicKey = certificateRequest.getChildElementByPath(CertificateRequestPath.PUBLIC_KEY);
      if (publicKey == null)
      {
        ASN1[] bodies = certificateRequest.getChildElementsByTag(CertificateRequestPath.CV_CERTIFICATE_BODY.getTag());
        ASN1 body = bodies[0];
        ASN1[] publicKeys = body.getChildElementsByTag(CertificateRequestPath.PUBLIC_KEY.getTag());
        publicKey = publicKeys[0];
      }
      ASN1 holderReference = certificateRequest.getChildElementByPath(CertificateRequestPath.HOLDER_REFERENCE);
      checkCVC(cert, tp.getCvc(), chainForCheck, publicKey, holderReference, new Date(), cvcRefId);
    }
    catch (Exception e)
    {
      log.error("{}: check of new CVC failed. Reason: {}. CVC Data:\n{}",
                cvcRefId,
                e.getMessage(),
                Base64.getMimeEncoder().encodeToString(cert));
      facade.storeCVCObtainedError(cvcRefId, e.getMessage());
      throw new GovManagementException(GlobalManagementCodes.EC_INVALIDCERTIFICATEDATA);
    }

    facade.storeCVCObtained(cvcRefId, cert, chain, certDescription);
    log.debug("Stored new CVC for {}:\n{}", cvcRefId, Hex.dump(cert));
  }

  private void requestMasterAndDefectList() throws GovManagementException
  {
    MasterAndDefectListHandler mslHandler = new MasterAndDefectListHandler(serviceProvider, facade, hsmKeyStore,
                                                                           configurationService);
    mslHandler.updateLists();
  }

  private void requestBlackListAndPublicSectorKey(TerminalPermission tp) throws GovManagementException
  {
    RestrictedIdHandler riHandler = new RestrictedIdHandler(serviceProvider, facade, hsmKeyStore, configurationService);

    if (tp.getSectorID() == null)
    {
      if (BlackListLock.getINSTANCE().getBlackListUpdateLock().tryLock())
      {
        try
        {
          riHandler.requestBlackList(false, false);
        }
        catch (GovManagementException e)
        {
          log.error("{}: cannot fetch blacklist", cvcRefId, e);
        }
        finally
        {
          BlackListLock.getINSTANCE().getBlackListUpdateLock().unlock();
        }
      }
      else
      {
        log.debug("Black list is currently being updated, skipping this execution");
      }
    }
    try
    {
      riHandler.requestPublicSectorKeyIfNeeded();
    }
    catch (GovManagementException e)
    {
      log.error("{}: cannot fetch public sector key", cvcRefId, e);
    }
  }

  /**
   * Returns a new certificate Description if a new one if needed, because the old one does not match to one in the
   * database any more.
   */
  private byte[] getCertDescriptionIfNeeded(byte[] cert)
  {
    TerminalPermission tp = facade.getTerminalPermission(cvcRefId);
    try
    {
      if (tp.getCvcDescription() == null)
      {
        return fetchCertDescription(cert);
      }
      ECCVCertificate cvcWrapper = new ECCVCertificate(cert);
      CertificateDescription cvcDescription = new CertificateDescription(tp.getCvcDescription());
      if (!cvcWrapper.checkCVCDescriptionHash(cvcDescription))
      {
        return fetchCertDescription(cert);
      }
    }
    catch (Exception e)
    {
      log.error("{}: A problem occurred while parsing cvc or cvc description. This could cause problems later",
                cvcRefId,
                e);
    }
    return null;
  }

  private byte[] selectRootCert(byte[][] chain)
  {
    for ( byte[] c : chain )
    {
      if (canBeGivenToRequestGenerator(c))
      {
        return c;
      }
    }
    throw new IllegalArgumentException("no suitable certificate stored in chain");
  }

  private byte[] sendCertificateRequest(byte[] certReq) throws GovManagementException
  {
    byte[] obtainedCert = null;
    boolean increaseCounter = false;
    try
    {
      PKIServiceConnector.getContextLock();
      TermAuthService service = createService();
      obtainedCert = service.requestCertificate(certReq, null, null);
      increaseCounter = true;
    }
    catch (GovManagementException e)
    {
      if (e.getManagementMessage().toString().contains(RequestCertificateReturnCodeType.FAILURE_INNER_SIGNATURE.name()))
      {
        increaseCounter = true;
      }
      throw e;
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
      if (increaseCounter)
      {
        facade.increaseSequenceNumber(cvcRefId);
      }
    }
    facade.storeCVCRequestSent(cvcRefId);
    return obtainedCert;
  }

  /**
   * Fetches a new Certificate Description form the Service of the CA.
   */
  private byte[] fetchCertDescription(byte[] cvc) throws GovManagementException, IOException
  {
    byte[] obtainedCert = null;
    ECCVCertificate atcvc = new ECCVCertificate(cvc);
    byte[] certificateDescriptionHash = atcvc.getChildElementByPath(ECCVCPath.EXTENSIONS_DISCRETIONARY_DATA_CERTIFICATE_DESCRIPTION_HASH)
                                             .getValue();
    try
    {
      PKIServiceConnector.getContextLock();
      DvcaCertDescriptionService wrapper = createCertDescriptionService();
      obtainedCert = wrapper.getCertificateDescription(certificateDescriptionHash);
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
    }
    return obtainedCert;
  }

  private TermAuthService createService() throws GovManagementException
  {
    String serviceUrl = dvcaConfiguration.getTerminalAuthServiceUrl();
    X509Certificate dvcaCertificate = configurationService.getCertificate(dvcaConfiguration.getServerSSLCertificateName());

    try
    {
      PKIServiceConnector connector;
      if (hsmKeyStore == null)
      {
        KeyPair clientKeyPair = configurationService.getKeyPair(serviceProvider.getClientKeyPairName());
        List<X509Certificate> clientCertificate = List.of(clientKeyPair.getCertificate());
        connector = new PKIServiceConnector(600, dvcaCertificate, clientKeyPair.getKey(), clientCertificate, cvcRefId);

      }
      else
      {
        connector = new PKIServiceConnector(600, dvcaCertificate, hsmKeyStore, null, cvcRefId);
      }
      return new TermAuthService(connector, serviceUrl);
    }
    catch (GeneralSecurityException | NullPointerException e)
    {
      log.error("{}: problem with crypto data", cvcRefId, e);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }
    catch (URISyntaxException e)
    {
      log.error("{}: problem with crypto data", cvcRefId, e);
      throw new GovManagementException(IDManagementCodes.INVALID_URL, "ID.value.service.termAuth.url");
    }
  }

  private DvcaCertDescriptionService createCertDescriptionService() throws GovManagementException
  {
    String serviceUrl = dvcaConfiguration.getDvcaCertificateDescriptionServiceUrl();
    X509Certificate dvcaCertificate = configurationService.getCertificate(dvcaConfiguration.getServerSSLCertificateName());
    try
    {
      PKIServiceConnector connector;
      if (hsmKeyStore == null)
      {
        KeyPair clientKeyPair = configurationService.getKeyPair(serviceProvider.getClientKeyPairName());
        List<X509Certificate> clientCertificate = List.of(clientKeyPair.getCertificate());
        connector = new PKIServiceConnector(600, dvcaCertificate, clientKeyPair.getKey(), clientCertificate, cvcRefId);
      }
      else
      {
        connector = new PKIServiceConnector(600, dvcaCertificate, hsmKeyStore, null, cvcRefId);
      }
      return new DvcaCertDescriptionService(connector, serviceUrl);
    }
    catch (GeneralSecurityException | NullPointerException e)
    {
      log.error("{}: problem with crypto data", cvcRefId, e);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }
    catch (URISyntaxException e)
    {
      log.error("{}: problem with crypto data", cvcRefId, e);
      throw new GovManagementException(IDManagementCodes.INVALID_URL, "ID.value.service.termAuth.url");
    }
  }

  /**
   * This method returns an ordered chain with the DVCA certificate at position 0 and then the chain to the first root
   * certificate, we will remove any double certificates and add some missing certificates from the chain if it is
   * possible.
   *
   * @param preferedCHR The CHR which should be the DVCA, use null to get the most recent version
   * @return
   * @throws GovManagementException
   */
  private byte[][] getCACertificates(String preferedCHR) throws GovManagementException
  {
    byte[][] result;
    try
    {
      PKIServiceConnector.getContextLock();
      log.debug("{}: obtained lock on SSL context for downloading CACerts", cvcRefId);
      TermAuthService service = createService();
      result = service.getCACertificates();
    }
    catch (WebServiceException e)
    {
      log.error("{}: cannot get certificates", cvcRefId, e);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
    }
    // chain contains all the certificates we got, when we got one certificate more than once, take the one
    // which was not self singed. We will use that map later on to fetch the certificates we need.
    Map<String, TerminalData> chain = new HashMap<>();
    // signedBy contains all the CAR, so we cna find the certificate which did not sign anything, this is
    // probably the DVCA cert.
    Set<String> signedBy = new HashSet<>();
    for ( byte[] cert : result )
    {
      try
      {
        TerminalData cvc = new TerminalData(cert);
        TerminalData original = chain.get(cvc.getHolderReferenceString());
        if (original == null || (original.isSelfSigned() && !cvc.isSelfSigned()))
        {
          chain.put(cvc.getHolderReferenceString(), cvc);
          signedBy.add(cvc.getCAReferenceString());
        }
      }
      catch (IOException e)
      {
        throw new IllegalArgumentException("unable to parse given cvc", e);
      }
    }

    if (preferedCHR != null && chain.containsKey(preferedCHR))
    {
      return createOrderedCertChain(chain, preferedCHR);
    }
    Set<String> notSigningCVCs = new HashSet<>(chain.keySet());
    notSigningCVCs.removeAll(signedBy);
    if (notSigningCVCs.isEmpty())
    {

      log.error("{}: Can not find the DVCA certificate in the GetCACertificates output, we searched for a certificate which is not used to sign any other certificate.",
                cvcRefId);
      return result;
    }
    else if (notSigningCVCs.size() == 1)
    {
      return createOrderedCertChain(chain, notSigningCVCs.iterator().next());
    }
    else
    {
      log.info("{}: It looks like there is more than one DVCA certificate in the GetCACertificates output, use the newest one: {}",
               cvcRefId,
               notSigningCVCs);
      Date issued = new Date(0);
      String recentCHR = null;
      for ( String chr : notSigningCVCs )
      {
        TerminalData cvc = chain.get(chr);
        if (issued.before(cvc.getEffectiveDate()))
        {
          issued = cvc.getEffectiveDate();
          recentCHR = chr;
        }
      }
      return createOrderedCertChain(chain, recentCHR);
    }
  }

  /**
   * Return an array with the CVC with the CHR topCHR at position 0 and then all the following certs.
   *
   * @param chain All the certs we know so we can fetch them from this map.
   * @param topCHR the CVC to start with.
   * @return
   */
  private byte[][] createOrderedCertChain(Map<String, TerminalData> chain, String topCHR)
  {
    LinkedList<byte[]> cvcChain = new LinkedList<>();
    TerminalData cvc = null;
    String recentCHR = topCHR;
    do
    {
      cvc = chain.get(recentCHR);
      if (cvc == null)
      {
        cvc = KNOWN_ROOT_CERTS.get(recentCHR);
      }
      if (cvc == null)
      {
        log.error("{}: can not find CVC with CHR: {}", cvcRefId, recentCHR);
        break;
      }
      cvcChain.addLast(cvc.getEncoded());
      recentCHR = new String(cvc.getCAReference(), StandardCharsets.UTF_8);
    }
    while (!cvc.isSelfSigned());

    return cvcChain.toArray(new byte[cvcChain.size()][]);
  }

  private void storeRequestData(String primaryKey,
                                String messageId,
                                CertificateRequest certificateRequest,
                                CertificateDescription description,
                                byte[][] chain,
                                byte[] pkcs8PrivateKey)
  {
    facade.storeCVCRequestCreated(primaryKey,
                                  messageId,
                                  certificateRequest.getEncoded(),
                                  description == null ? null : description.getEncoded(),
                                  chain,
                                  pkcs8PrivateKey);
  }
}

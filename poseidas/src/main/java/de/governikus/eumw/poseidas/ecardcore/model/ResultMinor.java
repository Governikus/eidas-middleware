/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.model;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * ResultMinor This Enumeration contains all possible error Codes that are mentioned the eCard-API. Each
 * specified another source of a message.
 * <p>
 * Look for further information in OASIS DSS oasis-dss-core-spec-v1.0-os.pdf
 * </p>
 * Auto generated Java file - please do not edit (Bitte nicht editieren) Was build on Fri Mar 20 16:34:57 CET
 * 2015 by hauke
 *
 * @author XSD2Java
 */
public enum ResultMinor
{


  /**
   * CardInfo-File kann nicht hinzugefügt werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/CardInfo#addNotPossible
   */
  CARD_INFO_ADD_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/CardInfo#addNotPossible"),
  /**
   * CardInfo-File existiert nicht URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/CardInfo#notExisting
   */
  CARD_INFO_NOT_EXISTING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/CardInfo#notExisting"),
  /**
   * CardInfo-File kann nicht gelöscht werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/CardInfo#deleteNotPossible
   */
  CARD_INFO_DELETE_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/CardInfo#deleteNotPossible"),
  /**
   * CardInfo-File existiert bereits URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/CardInfo#alreadyExisting
   */
  CARD_INFO_ALREADY_EXISTING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/CardInfo#alreadyExisting"),
  /**
   * Fehlerhaftes CardInfo-File URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/CardInfo#incorrectFile
   */
  CARD_INFO_INCORRECT_FILE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/CardInfo#incorrectFile"),
  /**
   * No qualified certificate found. So the overall result of the verification interpreter is undetermined URI
   * value: http://www.bos-bremen.de/ecard/api/1.0/resultminor/vii/vii#not_qualified_certificate
   */
  VII_NOT_QUALIFIED("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vii/vii#not_qualified_certificate"),
  /**
   * Es konnte keine Inhaltsdaten für die Verifikation einer PKCS#7 Detached Datei gefunden werden. URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#no_content
   */
  VR_NO_CONTENT("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#no_content"),
  /**
   * Die Inhaltsdaten würden manipuliert. URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#content_manipulated
   */
  VR_CONTENT_MANIPULATED("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#content_manipulated"),
  /**
   * Zertifikat-Status unbekannt. URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_status_unknown
   */
  VR_CERTIFICATE_STATUS_UNKNOWN("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_status_unknown"),
  /**
   * INDETERMINATE Zertifikat URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_indeterminate_status
   */
  VR_CERTIFICATE_INDETERMINATE_STATUS("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_indeterminate_status"),
  /**
   * INVALID Zertifikat URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_invalid_status_validityinterval
   */
  VR_CERTIFICATE_INVALID_STATUS_VALIDITYINTERVAL("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_invalid_status_validityinterval"),
  /**
   * INVALID Zertifikat RevocationStatus URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_invalid_status_revocationstatus
   */
  VR_CERTIFICATE_INVALID_STATUS_REVOCATIONSTATUS("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_invalid_status_revocationstatus"),
  /**
   * INVALID Zertifikat IssuerTrust URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_invalid_status_issuertrust
   */
  VR_CERTIFICATE_INVALID_STATUS_ISSUERTRUST("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_invalid_status_issuertrust"),
  /**
   * INVALID Zertifikat Signature URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_invalid_status_signature
   */
  VR_CERTIFICATE_INVALID_STATUS_SIGNATURE("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#certificate_invalid_status_signature"),
  /**
   * Die Antwort des Verifikationsservers wurde verändert. Oder es ist ein falsches Server-Zertifikat
   * konfiguriert. URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#server_signature_invalid
   */
  VR_SERVER_SIGNATURE_INVALID("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#server_signature_invalid"),
  /**
   * Es wurde keine Signatur in der Antwort des Verifikationsservers gefunden URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#server_signature_not_found
   */
  VR_SERVER_SIGNATURE_NOT_FOUND("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#server_signature_not_found"),
  /**
   * Es wurde kein Server-Zertifikat in der Konfiguration gefunden URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#server_certificate_not_found
   */
  VR_SERVER_CERTIFICATE_NOT_FOUND("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#server_certificate_not_found"),
  /**
   * Der Verifikationszeitpunkt wurde verändert. URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#verifytime_modified
   */
  VR_VERIFYTIME_MODIFIED("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#verifytime_modified"),
  /**
   * Fehler vom Verifikationsserver URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#verifcationserver_error
   */
  VR_VERIFCATIONSERVER_ERROR("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#verifcationserver_error"),
  /**
   * Der Verifikationszeitpunkt wurde in der Zukunft gewählt. URI value:
   * http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#verifytime_wrongtimeinstance
   */
  VR_VERIFYTIME_WRONGTIMEINSTANCE("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#verifytime_wrongtimeinstance"),
  /**
   * Der Zustand des Zertifikats konnte nicht ermittelt werden, da die Online-Prüfung ausgeschaltet ist. URI
   * value: http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#cert_no_online_verify
   */
  VR_CERT_NO_ONLINE_VERIFY("http://www.bos-bremen.de/ecard/api/1.0/resultminor/vr/vr#cert_no_online_verify"),
  /**
   * Bei der Verifikation wurde kein Signaturzeitpunkt gefunden. Da man so nicht sagen kann, ob das Zertifikat
   * zum Signaturzeitpunkt gültig war, gibt es kein bestimmtes Prüfergebnis. URI value:
   * http://www.bos-bremen.de/ecard/api/1.1/resultminor/vr/vr#vr_no_signigtime_warning
   */
  VR_NO_SIGNINGTIME_WARNING("http://www.bos-bremen.de/ecard/api/1.1/resultminor/vr/vr#vr_no_signigtime_warning"),
  /**
   * There was some unknown error An unexpected error has occurred during processing which cannot be
   * represented by the standard codes or specific service error codes. The error and detail texts can
   * describe the error more closely. (API_UNKNOWN_ERROR) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#unknownError
   */
  COMMON_UNKNOWN_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#unknownError"),
  /**
   * Nutzung der Funktion durch die Client-Anwendung ist nicht erlaubt URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#noPermission
   */
  COMMON_NO_PERMISSION("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#noPermission"),
  /**
   * Interner Fehler Ein unerwarteter Fehler ist während der Verarbeitung aufgetreten, der nicht auf die
   * Standardfehlercodes bzw. auf die dienstspezifischen Fehlercodes abgebildet werden kann. Der Fehler- und
   * der Detailtext können den Fehler näher beschreiben. (API_UNKNOWN_ERROR) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError
   */
  COMMON_INTERNAL_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError"),
  /**
   * Parameter Fehler Falscher, fehlender oder nicht dem Format entsprechender Parameter.
   * (API_INCORRECT_PARAMETER) This was removed in TR-03112 version 1.1.5 Deprecated: use
   * common_incorrectParameter URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError
   */
  @Deprecated
  COMMON_PARAMETER_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError"),
  /**
   * Parameter Fehler Falscher, fehlender oder nicht dem Format entsprechender Parameter.
   * (API_INCORRECT_PARAMETER) This was added in TR-03112 version 1.1.5 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#incorrectParameter
   */
  COMMON_INCORRECT_PARAMETER("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#incorrectParameter"),
  /**
   * API-Funktion unbekannt URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#unknownAPIFunction
   */
  COMMON_UNKNOWN_API_FUNCTION("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#unknownAPIFunction"),
  /**
   * Framework nicht initialisiert URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#notInitialized
   */
  COMMON_NOT_INITIALIZED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#notInitialized"),
  /**
   * Warning indicating termination of an active session (API_WARNING_CONNECTION_DISCONNECTED) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#warningConnectionDisconnected
   */
  COMMON_WARNING_CONNECTION_DISCONNECTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#warningConnectionDisconnected"),
  /**
   * Warnung, da eine aktive Session beendet wurde URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#SessionTerminatedWarning
   */
  COMMON_SESSION_TERMINATED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#SessionTerminatedWarning"),
  /**
   * Update-Service ist nicht erreichbar URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#serviceNotAvailable
   */
  FRAMEWORK_UPDATE_SERVICE_NOT_AVAILABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#serviceNotAvailable"),
  /**
   * Unbekanntes Modulbt URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#unknownModule
   */
  FRAMEWORK_UPDATE_UNKNOWN_MODULE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#unknownModule"),
  /**
   * Ungültige Versionsnummer für Modul URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#invalidVersionNumber
   */
  FRAMEWORK_UPDATE_INVALID_VERSION_NUMBER("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#invalidVersionNumber"),
  /**
   * Nicht unterstütztes Betriebssystem URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#operationSystemNotSupported
   */
  FRAMEWORK_UPDATE_OPERATION_SYSTEM_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#operationSystemNotSupported"),
  /**
   * Kein Platz verfügbar URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#noSpaceAvailable
   */
  FRAMEWORK_UPDATE_NO_SPACE_AVAILABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#noSpaceAvailable"),
  /**
   * Zugriff verweigert URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#securityConditionsNotSatisfied
   */
  FRAMEWORK_UPDATE_SECURITY_CONDITIONS_NOT_SATISFIED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#securityConditionsNotSatisfied"),
  /**
   * Zugriff verweigert über AusweisApp URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#securityConditionNotSatisfied
   */
  FRAMEWORK_UPDATE_SECURITY_CONDITION_NOT_SATISFIED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/FrameworkUpdate#securityConditionNotSatisfied"),
  /**
   * Kartenterminalkonfiguration kann nicht geschrieben werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/IFD#writeConfigurationNotPossible
   */
  IFD_WRITE_CONFIGURATION_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/IFD#writeConfigurationNotPossible"),
  /**
   * Kartenterminal kann nicht hinzugefügt werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/IFD#couldNotAdd
   */
  IFD_COULD_NOT_ADD("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/IFD#couldNotAdd"),
  /**
   * Kartenterminal kann nicht gelöscht werdent URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/IFD#deleteNotPossible
   */
  IFD_DELETE_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/IFD#deleteNotPossible"),
  /**
   * Kartenterminal existiert bereits URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/IFD#addNotPossible
   */
  IFD_ADD_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/IFD#addNotPossible"),
  /**
   * Trusted Viewer kann nicht gelöscht werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TrustedViewer#deleteNotPossible
   */
  TRUSTED_VIEWER_DELETE_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TrustedViewer#deleteNotPossible"),
  /**
   * Ungültige TrustedViewerId URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TrustedViewer#invalidID
   */
  TRUSTED_VIEWER_INVALID_ID("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TrustedViewer#invalidID"),
  /**
   * Ungültige Konfigurationsinformationen für den URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TrustedViewer#invalidConfiguration
   */
  TRUSTED_VIEWER_INVALID_CONFIGURATION("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TrustedViewer#invalidConfiguration"),
  /**
   * Trusted Viewer mit angegebener ID existiert bereits URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TrustedViewer#alreadyExisting
   */
  TRUSTED_VIEWER_ALREADY_EXISTING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TrustedViewer#alreadyExisting"),
  /**
   * TSL kann nicht hinzugefügt werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TSL#deleteNotPossible
   */
  TSL_DELETE_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TSL#deleteNotPossible"),
  /**
   * TSL kann nicht entfernt werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TSL#exportNotPossible
   */
  TSL_EXPORT_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TSL#exportNotPossible"),
  /**
   * TSL kann nicht exportiert werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TSL#unknownTSL
   */
  TSL_UNKNOWN_TSL("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/TSL#unknownTSL"),
  /**
   * Der Knoten ist nicht erreichbar. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#nodeNotReachable
   */
  DP_NODE_NOT_REACHABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#nodeNotReachable"),
  /**
   * Zeitüberschreitung (Timeout) Die Operation wurde wegen Zeitüberschreitung abgebrochen. Deprecated: This
   * is not defined in TR-03112 URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp/dp#timeout
   */
  @Deprecated
  DP_TIMEOUT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp/dp#timeout"),
  /**
   * Zeitüberschreitung (Timeout) Die Operation wurde wegen Zeitüberschreitung abgebrochen. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#timeoutError
   */
  DP_TIMEOUT_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#timeoutError"),
  /**
   * Unbekanntes Channel Handle Deprecated: This was removed in TR-03112 Version 1.1.5 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#unknownChannelHandle
   */
  @Deprecated
  DP_UNKNOWN_CHANNEL_HANDLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#unknownChannelHandle"),
  /**
   * Unbekanntes Channel Handle Deprecated: This was added in TR-03112 Version 1.1.5 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#invalidChannelHandle
   */
  @Deprecated
  DP_INVALID_CHANNEL_HANDLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#invalidChannelHandle"),
  /**
   * Kommunikationsfehler (API_COMMUNICATIOPN_FAILURE) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#communicationError
   */
  DP_COMMUNICATION_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#communicationError"),
  /**
   * Aufbau eines vertrauenswürdigen Kanals gescheitert spelling error:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#trustedChannelEstablishmentFailed URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#trustedChannelEstabishmentFailed
   */
  DP_TRUSTED_CHANNEL_ESTABISHMENT_FAILED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#trustedChannelEstabishmentFailed"),
  /**
   * Unbekanntes Protokoll URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#unknownProtocol
   */
  DP_UNKNOWN_PROTOCOL("http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#unknownProtocol"),
  /**
   * Unbekannte Cipher-Suite URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#unknownCipherSuite
   */
  DP_UNKNOWN_CIPHER_SUITE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#unknownCipherSuite"),
  /**
   * Unbekanntes Web-Service-Binding URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#unknownWebserviceBinding
   */
  DP_UNKNOWN_WEBSERVICE_BINDING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#unknownWebserviceBinding"),
  /**
   * Angegebener Hashalgorithmus wird nicht unterstützt URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/algorithm#hashAlgorithmNotSupported
   */
  ALGORITHM_HASH_ALGORITHM_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/algorithm#hashAlgorithmNotSupported"),
  /**
   * Angegebener Signaturalgorithmus wird nicht unterstützt URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/algorithm#signatureAlgorithmNotSupported
   */
  ALGORITHM_SIGNATURE_ALGORITHM_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/algorithm#signatureAlgorithmNotSupported"),
  /**
   * Unbekanntes Attribut im Zertifikatsantrag URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#unknownAttribute
   */
  CERTIFICATE_REQUEST_UNKNOWN_ATTRIBUTE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#unknownAttribute"),
  /**
   * Einreichen des Zertifikatsantrages fehlgeschlagen URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#submissionFailed
   */
  CERTIFICATE_REQUEST_CREATION_FAILED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#submissionFailed"),
  /**
   * Unbekannter TransactionIdentifier URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#unknownTransactionID
   */
  CERTIFICATE_REQUEST_UNKNOWN_TRANSACTION_ID("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#unknownTransactionID"),
  /**
   * Zertifikat konnte nicht abgeholt werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#certificateDownloadFailed
   */
  CERTIFICATE_REQUEST_CERTIFICATE_DOWNLOAD_FAILED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#certificateDownloadFailed"),
  /**
   * If the subject is missing, a error message or warning is thrown. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#subjectMissing
   */
  CERTIFICATE_REQUEST_SUBJECT_MISSING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#subjectMissing"),
  /**
   * If during the creation of the certificate request the process failed. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#creationOfCertificateRequestFaild
   */
  CERTIFICATE_REQUEST_CREATION_OF_CERTIFICATE_REQUEST_FAILD("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#creationOfCertificateRequestFaild"),
  /**
   * If the submission failed. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#submissionFailed
   */
  CERTIFICATE_REQUEST_SUBMISSION_FAILED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/certificateRequest#submissionFailed"),
  /**
   * Bestimmte Knoten können nur bei einem XML-Dokument verschlüsselt werden URI value: http://www.bsi.bund
   * .de/ecard/api/1.1/resultminor/il/encryption#encryptionOfCertainNodesOnlyForXMLDocuments
   */
  ENCRYPTION_ENCRYPTION_OF_CERTAIN_NODES_ONLY_FOR_XML_DOCUMENTS("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/encryption#encryptionOfCertainNodesOnlyForXMLDocuments"),
  /**
   * Verschlüsselungsformat nicht unterstützt URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/encryption#encryptionFormatNotSupported
   */
  ENCRYPTION_ENCRYPTION_FORMAT_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/encryption#encryptionFormatNotSupported"),
  /**
   * Verschlüsselungszertifikat eines vorgesehenen Empfängers ist ungültig URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/encryption#invalidCertificate
   */
  ENCRYPTION_INVALID_CERTIFICATE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/encryption#invalidCertificate"),
  /**
   * Schlüsselerzeugung nicht möglich URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/key#keyGenerationNotPossible
   */
  KEY_KEY_GENERATION_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/key#keyGenerationNotPossible"),
  /**
   * Angegebener Verschlüsselungsalgorithmus wird nicht unterstützt URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/key#encryptionAlgorithmNotSupported
   */
  KEY_ENCRYPTION_ALGORITHM_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/key#encryptionAlgorithmNotSupported"),
  /**
   * OCSP-Responder nicht erreichbar URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/service#ocspResponderUnreachable
   */
  SERVICE_OCSP_RESPONDER_UNREACHABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/service#ocspResponderUnreachable"),
  /**
   * Verzeichnisdienst nicht erreichbar URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/service#directoryServiceUnreachable
   */
  SERVICE_DIRECTORY_SERVICE_UNREACHABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/service#directoryServiceUnreachable"),
  /**
   * Zeitstempeldienst nicht erreichbar URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/service#timeStampServiceUnreachable
   */
  SERVICE_TIME_STAMP_SERVICE_UNREACHABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/service#timeStampServiceUnreachable"),
  /**
   * Signaturformat nicht unterstützt Das angegebene Signatur- oder Zeitstempel-Format wird nicht unterstützt.
   * URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureFormatNotSupported
   */
  SIGNATURE_SIGNATURE_FORMAT_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureFormatNotSupported"),
  /**
   * PDF-Signatur für Nicht-PDF-Dokument angefordert URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#PDFSignatureForNonPDFDocument
   */
  SIGNATURE_PDF_SIGNATURE_FOR_NON_PDF_DOCUMENT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#PDFSignatureForNonPDFDocument"),
  /**
   * IncludeEContent nicht möglich Diese Warnung wird zurückgeliefert, wenn das IncludeEContent-Flag bei der
   * Erzeugung einer PDF-Signatur, eines Zeitstempels oder bei der übergabe eines Hashwertes zur Erzeugung
   * einer Signatur gesetzt wird. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#unableToIncludeEContentWarning
   */
  SIGNATURE_UNABLE_TO_INCLUDE_E_CONTENT_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#unableToIncludeEContentWarning"),
  /**
   * ignoredSignaturePlacementFlagWarning SignaturePlacement-Flag wurde ignoriert Diese Warnung wird
   * zurückgeliefert, wenn das SignaturePlacement-Flag bei einer Nicht-XML-basierten Signatur gesetzt wurde.
   * URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#ignoredSignaturePlacementFlagWarning
   */
  SIGNATURE_IGNORED_SIGNATURE_PLACEMENT_FLAG_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#ignoredSignaturePlacementFlagWarning"),
  /**
   * Zertifikat ist nicht verfügbar Das angegebene Zertifikat steht der Funktion nicht zur Verfügung. Die
   * Ursache könnte eine falscher Verweis oder ein gelöschtes Datenfeld sein. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateNotFound
   */
  SIGNATURE_CERTIFICATE_NOT_FOUND("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateNotFound"),
  /**
   * Zertifikat kann nicht interpretiert werden Das Format des angegebenen Zertifikates ist unbekannt und kann
   * nicht interpretiert werden. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateFormatNotCorrectWarning
   */
  SIGNATURE_CERTIFICATE_FORMAT_NOT_CORRECT_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateFormatNotCorrectWarning"),
  /**
   * Das Zertifikat wurde nicht ausreichend überprüft. Zum Beispiel weil es nicht geht, weil es zum Beispiel
   * nicht qualifiziert ist. Das ist eine Warnung, die bedeutet das das Verifikationsergebniss mit vorsicht zu
   * geniessen ist. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateStatusNotCheckedWarning
   */
  SIGNATURE_CERTIFICATE_STATUS_NOT_CHECKED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateStatusNotCheckedWarning"),
  /**
   * Ungültige Zertifikatsreferenz URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidCertificateReference
   */
  SIGNATURE_INVALID_CERTIFICATE_REFERENCE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidCertificateReference"),
  /**
   * Zertifikatskette ist unterbrochen Die angegebene Zertifikatskette ist unterbrochen. Somit kann eine
   * vollständige Prüfung bis zum Root-Zertifikat nicht erfolgen. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateChainInterrupted
   */
  SIGNATURE_CERTIFICATE_CHAIN_INTERRUPTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateChainInterrupted"),
  /**
   * Objektreferenz konnte nicht aufgelöst werden. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#resolutionOfObjectReferenceImpossible
   */
  SIGNATURE_RESOLUTION_OF_OBJECT_REFERENCE_IMPOSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#resolutionOfObjectReferenceImpossible"),
  /**
   * Transformationsalgorithmn not supported. The sign request contained a transformation that can not be
   * supported by the eCard-API. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#transformationAlgorithmNotSupported
   */
  SIGNATURE_TRANSFORMATION_ALGORITHM_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#transformationAlgorithmNotSupported"),
  /**
   * Viewer unbekannt oder nicht verfügbar URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#unknownViewer
   */
  SIGNATURE_UNKNOWN_VIEWER("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#unknownViewer"),
  /**
   * Zertifikatspfad wurde nicht geprüft Hierbei handelt es sich um eine Warnung. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificatePathNotValidatedWarning
   */
  SIGNATURE_CERTIFICATE_PATH_NOT_VALIDATED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificatePathNotValidatedWarning"),
  /**
   * Signaturmanifest wurde nicht geprüft Hierbei handelt es sich um eine Warnung. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureManifestNotCheckedWarning
   */
  SIGNATURE_SIGNATURE_MANIFEST_NOT_CHECKED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureManifestNotCheckedWarning"),
  /**
   * Eignung der Signatur- und Hashalgorithmen wurde nicht geprüft spellingerror in URI
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#suiteabilityOfAlgorithmsNotCheckedWarning
   * URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#suitabilityOfAlgorithmsNotCheckedWarning
   */
  SIGNATURE_SUITEABILITY_OF_ALGORITHMS_NOT_CHECKED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#suitabilityOfAlgorithmsNotCheckedWarning"),
  /**
   * Keine zur Signatur gehörigen Daten gefunden (detached signature without EContent) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#detachedSignatureWithoutEContent
   */
  SIGNATURE_DETACHED_SIGNATURE_WITHOUT_E_CONTENT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#detachedSignatureWithoutEContent"),
  /**
   * Sperrinformation kann nicht interpretiert werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#improperRevocationInformationWarning
   */
  SIGNATURE_IMPROPER_REVOCATION_INFORMATION_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#improperRevocationInformationWarning"),
  /**
   * Signaturformat fehlerhaft Das Format der übergebenen Signatur entspricht nicht der vorgesehenen
   * Spezifikation. Dieser Fehler tritt auf, wenn zwar ein unterstütztes Format (z.B. gemäß [RFC3275] oder
   * [RFC3369]) erkannt wurde, die Signatur aber nicht der vorgesehenen Form genügt. Wird bereits das
   * übergebene Format nicht erkannt, so wird Fehler 2801 zurück geliefert. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidSignatureFormat
   */
  SIGNATURE_INVALID_SIGNATURE_FORMAT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidSignatureFormat"),
  /**
   * Signaturalgorithmus besitzt zum relevanten Zeitpunkt keine Sicherheitseignung URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureAlgorithmNotSuitable
   */
  SIGNATURE_SIGNATURE_ALGORITHM_NOT_SUITABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureAlgorithmNotSuitable"),
  /**
   * Hashalgorithmus besitzt zum relevanten Zeitpunkt keine Sicherheitseignung URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#hashAlgorithmNotSuitable
   */
  SIGNATURE_HASH_ALGORITHM_NOT_SUITABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#hashAlgorithmNotSuitable"),
  /**
   * Zertifikatspfad ungültig URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidCertificatePath
   */
  SIGNATURE_INVALID_CERTIFICATE_PATH("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidCertificatePath"),
  /**
   * Zertifikat gesperrt URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateRevoked
   */
  SIGNATURE_CERTIFICATE_REVOKED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateRevoked"),
  /**
   * Referenzzeitpunkt außerhalb des Gültigkeitszeitraumes eines Zertifikates URI value: http://www.bsi.bund
   * .de/ecard/api/1.1/resultminor/il/signature#referenceTimeNotWithinCertificateValidityPeriod
   */
  SIGNATURE_REFERENCE_TIME_NOT_WITHIN_CERTIFICATE_VALIDITY_PERIOD("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#referenceTimeNotWithinCertificateValidityPeriod"),
  /**
   * Ungültige Erweiterungen in einem Zertifikat URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidCertificateExtension
   */
  SIGNATURE_INVALID_CERTIFICATE_EXTENSION("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidCertificateExtension"),
  /**
   * Prüfung eines Signaturmanifests schlug fehl URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureManifestNotCorrect
   */
  SIGNATURE_SIGNATURE_MANIFEST_NOT_CORRECT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureManifestNotCorrect"),
  /**
   * Angegebener SignatureType untersützt keine SignatureForm-Präzisierung URI value: http://www.bsi.bund.de
   * /ecard/api/1.1/resultminor/il/signature#signatureTypeDoesNotSupportSignatureFormClarificationWarning
   */
  SIGNATURE_SIGNATURE_TYPE_DOES_NOT_SUPPORT_SIGNATURE_FORM_CLARIFICATION_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureTypeDoesNotSupportSignatureFormClarificationWarning"),
  /**
   * Unbekannte SignatureForm URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#unknownSignatureForm
   */
  SIGNATURE_UNKNOWN_SIGNATURE_FORM("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#unknownSignatureForm"),
  /**
   * IncludeObject nur bei XML-Signaturen erlaubt URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il
   * /signature#includeObjectOnlyForXMLSignatureAllowedWarning
   */
  SIGNATURE_INCLUDE_OBJECT_ONLY_FOR_XML_SIGNATURE_ALLOWED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#includeObjectOnlyForXMLSignatureAllowedWarning"),
  /**
   * XPath-Ausdruck konnte nicht aufgelöst werden URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#xPathEvaluationError
   */
  SIGNATURE_XPATH_EVALUATION_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#xPathEvaluationError"),
  /**
   * Signature Policy unknown. ACHTUNG: Dieser Code wird zwar in der Dokumentation zum Sign Request erklärt
   * teil2.pdf, fehlt aber in der Liste der Fehlermeldungen im Teil1.pdf. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#unknownSignaturePolicy
   */
  SIGNATURE_UNKNOWN_SIGNATURE_POLICY("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#unknownSignaturePolicy"),
  /**
   * Ungeeignetes Stylesheet für übergebenes Dokument Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/viewer#unsuiteableSylesheetForDocument
   */
  @Deprecated
  VIEWER_UNSUITEABLE_SYLESHEET_FOR_DOCUMENT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/viewer#unsuiteableSylesheetForDocument"),
  /**
   * Ungeeignetes Stylesheet für übergebenes Dokument URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/viewer#unsuitableStylesheetForDocument
   */
  VIEWER_UNSUITABLE_STYLESHEET_FOR_DOCUMENT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/viewer#unsuitableStylesheetForDocument"),
  /**
   * Abbruch durch den Nutzer URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/viewer#cancelationByUser
   */
  VIEWER_CANCELATION_BY_USER("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/viewer#cancelationByUser"),
  /**
   * Zeitüberschreitung (Timeout) Die Operation wurde wegen Zeitüberschreitung abgebrochen. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/viewer#timeout
   */
  VIEWER_TIMEOUT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/viewer#timeout"),
  /**
   * ViewerMessage zu lang URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/viewer#viewerMessageTooLong
   */
  VIEWER_VIEWER_MESSAGE_TOO_LONG("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/viewer#viewerMessageTooLong"),
  /**
   * Codierung nicht möglich URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#encodingError
   */
  SUPPORT_ENCODING_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#encodingError"),
  /**
   * Decodierung nicht möglich URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#decodingError
   */
  SUPPORT_DECODING_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#decodingError"),
  /**
   * Schema-Validierung schlug fehl URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#schemaValidationError
   */
  SUPPORT_SCHEMA_VALIDATION_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#schemaValidationError"),
  /**
   * Bei der Schema-Validierung ist eine Warnung aufgetreten. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#schemaValidationWarning
   */
  SUPPORT_SCHEMA_VALIDATION_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#schemaValidationWarning"),
  /**
   * Kein geeignetes Schema verfügbar URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#noAppropriateSchema
   */
  SUPPORT_NO_APPROPRIATE_SCHEMA("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#noAppropriateSchema"),
  /**
   * CardInfo-Repository Server nicht erreichbar URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#cardInfoRepositoryUnreachable
   */
  SUPPORT_CARD_INFO_REPOSITORY_UNREACHABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/support#cardInfoRepositoryUnreachable"),
  /**
   * Zeitüberschreitung (Timeout) Die Operation wurde wegen Zeitüberschreitung abgebrochen.
   * (API_TIMEOUT_ERROR) Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#timeout
   */
  @Deprecated
  SAL_TIMEOUT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#timeout"),
  /**
   * Abbruch durch den Benutzer Eine notwendige Benutzerinteraktion (z. B. PIN-Eingabe oder Bestätigung der
   * Signaturerzeugung im Trusted Viewer) wurde durch Abbruch beendet (API_CANCELLATION_BY_USER) Deprecated:
   * This is spelled wrong URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#cancelationByUser
   */
  @Deprecated
  SAL_CANCELATION_BY_USER("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#cancelationByUser"),
  /**
   * Abbruch durch den Benutzer Eine notwendige Benutzerinteraktion (z. B. PIN-Eingabe oder Bestätigung der
   * Signaturerzeugung im Trusted Viewer) wurde durch Abbruch beendet (IFDL_CANCELLATION_BY_USER) This is the
   * ResultMinor the BuergerClient sends when in an ordinary desktop dialog "Abbrechen" is pushed. This is not
   * documented in part 1 of ecard-API1.1, it is in part 6 but there it is spelled cancellation, mind the
   * double-l. But there it is not documented for the DIDAuthenticate API-call. Deprecated: This is not
   * defined in TR-03112 URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl#cancelationByUser
   */
  @Deprecated
  IFDL_CANCELATION_BY_USER("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl#cancelationByUser"),
  /**
   * This is the ResultMinor the BuergerClient Testversion 4 sends when in an ordinary desktop dialog
   * "Abbrechen" is pushed. This is not documented for the DIDAuthenticate API-call. See ECA-495 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#cancellationByUser
   */
  SAL_CANCELLATION_BY_USER("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#cancellationByUser"),
  /**
   * Unbekanntes Connection Handle Deprecated: This is not specified by the BSI, do not use it URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#unknownConnectionHandle
   */
  @Deprecated
  SAL_UNKNOWN_CONNECTION_HANDLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#unknownConnectionHandle"),
  /**
   * Name existiert bereits (API_NAME_EXISTS) Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#nameAlreadyExisting
   */
  @Deprecated
  SAL_NAME_ALREADY_EXISTING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#nameAlreadyExisting"),
  /**
   * Name existiert bereits (API_NAME_EXISTS) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#nameExists
   */
  SAL_NAME_EXISTS("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#nameExists"),
  /**
   * Name existiert bereits (API_NAME_EXISTS) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#prerequisitesNotSatisfied
   */
  SAL_PREREQUISITES_NOT_SATISFIED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#prerequisitesNotSatisfied"),
  /**
   * Unbekanntes Protokoll (API_PROTOCOL_NOT_RECOGNIZED) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#unknownProtocol
   */
  SAL_UNKNOWN_PROTOCOL("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#unknownProtocol"),
  /**
   * Unknown protocol (API_PROTOCOL_NOT_RECOGNIZED) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#protocolNotRecognized
   */
  SAL_PROTOCOL_NOT_RECOGNIZED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#protocolNotRecognized"),
  /**
   * Ungeeignetes Protokoll für gewünschte Aktion (API_INAPPROPRIATE_PROTOCOL_FOR_ACTION) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#inappropriateProtocolForAction
   */
  SAL_INAPPROPRIATE_PROTOCOL_FOR_ACTION("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#inappropriateProtocolForAction"),
  /**
   * Unbekannter oder nicht erkannter Kartentyp URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#unknownCardType
   */
  SAL_UNKNOWN_CARD_TYPE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#unknownCardType"),
  /**
   * DID nicht vorhanden URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#unknownDIDName
   */
  SAL_UNKNOWN_DID_NAME("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#unknownDIDName"),
  /**
   * Data Set nicht vorhanden Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#unknownDataSetName
   */
  @Deprecated
  SAL_UNKNOWN_DATA_SET_NAME("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#unknownDataSetName"),
  /**
   * DSI nicht vorhanden Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal//sal#unknownDSIName
   */
  @Deprecated
  SAL_UNKNOWN_DSI_NAME("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal//sal#unknownDSIName"),
  /**
   * Fehler bei der Bildung eines CV-Zertifikatspfads Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#couldNotCreateCVCertificatePath
   */
  @Deprecated
  SAL_COULD_NOT_CREATE_CV_CERTIFICATE_PATH("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#couldNotCreateCVCertificatePath"),
  /**
   * Fehler bei der Prüfung von CV-Zertifikaten Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#cVCertificateNotValidated
   */
  @Deprecated
  SAL_CV_CERTIFICATE_NOT_VALIDATED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#cVCertificateNotValidated"),
  /**
   * Mathematische Prüfung der digitalen Signatur schlug fehl Deprecated: This is not specified in TR-03112
   * Version 1.1.5 URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#digitalSignatureNotCorrect
   */
  @Deprecated
  SAL_DIGITAL_SIGNATURE_NOT_CORRECT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#digitalSignatureNotCorrect"),
  /**
   * Warning - there is no active session This warning indicates that there is no active session, which can be
   * terminated with CardApplicationEndSession. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#noActiveSession
   */
  SAL_NO_ACTIVE_SESSION("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#noActiveSession"),
  /**
   * Entschlüsselung nicht möglich URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#decryptionNotPossible
   */
  SAL_DECRYPTION_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#decryptionNotPossible"),
  /**
   * The verified signature is not valid (API_INVALID_SIGNATURE) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidSignature
   */
  SAL_INVALID_SIGNATURE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidSignature"),
  /**
   * The selected key is not valid (API_INVALID_KEY) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidKey
   */
  SAL_INVALID_KEY("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidKey"),
  /**
   * Keine Initialisierung erfolgt Die verwendete Operation benötigt eine Initialisierung
   * (API_NOT_INITIALIZED) URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#notInitialized
   */
  SAL_NOT_INITIALIZED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#notInitialized"),
  /**
   * Ungültige Pfadangabe Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidPath
   */
  @Deprecated
  SAL_INVALID_PATH("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidPath"),
  /**
   * Zu viele Ergebnisse (API_TOO_MANY_RESULTS) Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#tooMuchResults
   */
  @Deprecated
  SAL_TOO_MUCH_RESULTS("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#tooMuchResults"),
  /**
   * Zu viele Ergebnisse (API_TOO_MANY_RESULTS) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#tooManyResults
   */
  SAL_TOO_MANY_RESULTS("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#tooManyResults"),
  /**
   * Warnung - Verbindung wurde getrennt (API_WARNING_CONNECTION_DISCONNECTED) Deprecated: This is not defined
   * in TR-03112 URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#connectionDisconnectedWarning
   */
  @Deprecated
  SAL_CONNECTION_DISCONNECTED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#connectionDisconnectedWarning"),
  /**
   * Warnung - Verbindung wurde getrennt (API_WARNING_CONNECTION_DISCONNECTED) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#warningConnectionDisconnected
   */
  SAL_WARNING_CONNECTION_DISCONNECTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#warningConnectionDisconnected"),
  /**
   * Warning ? An established session was terminated (API_WARNING_SESSION_ENDED) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#warningSessionEnded
   */
  SAL_WARNING_SESSION_ENDED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#warningSessionEnded"),
  /**
   * Service-Name existiert nicht Der angegebene Card Application Service - Name existiert nicht.
   * (API_NAMED_ENTITY_NOT_FOUND) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#namedEntityNotFound
   */
  SAL_NAMED_ENTITY_NOT_FOUND("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#namedEntityNotFound"),
  /**
   * Nicht genügend Ressourcen (API_INSUFFICIENT_RESOURCES) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#insufficientResources
   */
  SAL_INSUFFICIENT_RESOURCES("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#insufficientResources"),
  /**
   * Translation-Code oder Verweis fehlerhaft Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#proceduralElementNotCorrect
   */
  @Deprecated
  SAL_PROCEDURAL_ELEMENT_NOT_CORRECT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#proceduralElementNotCorrect"),
  /**
   * Zugriffskontrollinformation fehlerhaft URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidAccessControlInformation
   */
  SAL_INVALID_ACCESS_CONTROL_INFORMATION("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidAccessControlInformation"),
  /**
   * Kein Platz verfügbar Unter der angegebenen Referenz ist kein Speicherplatz verfügbar. Deprecated: This is
   * not defined in TR-03112 URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#noSpaceAvailable
   */
  @Deprecated
  SAL_NO_SPACE_AVAILABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#noSpaceAvailable"),
  /**
   * Warnung aktive Session (API_WARNING_SESSION_ENDED) Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#sessionTerminatedWarning
   */
  @Deprecated
  SAL_SESSION_TERMINATED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#sessionTerminatedWarning"),
  /**
   * Schlüsselerzeugung nicht möglich Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#keyCouldNotBeCreated
   */
  @Deprecated
  SAL_KEY_COULD_NOT_BE_CREATED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#keyCouldNotBeCreated"),
  /**
   * Identifikationsdaten fehlerhaft (x verbleibende Versuche) (EOP_RC) Deprecated: This is not specified by
   * the BSI, do not use it. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#wrongReferenceData
   */
  @Deprecated
  SAL_WRONG_REFERENCE_DATA("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#wrongReferenceData"),
  /**
   * Zugriff verweigert (SECURITY CONDITION) Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#securityConditionsNotSatisfied
   */
  @Deprecated
  SAL_SECURITY_CONDITIONS_NOT_SATISFIED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#securityConditionsNotSatisfied"),
  /**
   * Zugriff verweigert (SECURITY CONDITION) über AusweisApp URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#securityConditionNotSatisfied
   */
  SAL_SECURITY_CONDITION_NOT_SATISFIED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#securityConditionNotSatisfied"),
  /**
   * Identifikationsdaten blockiert (REFERENCE DATA BLOCKED) Deprecated: This is not defined in TR-03112 URI
   * value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#referenceDataBlocked
   */
  @Deprecated
  SAL_REFERENCE_DATA_BLOCKED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#referenceDataBlocked"),
  /**
   * Authentisierungsfunktion nicht freigeschaltet Die Authentisierungsfunktion kann noch nicht genutzt
   * werden, weil beispielsweise die Applikation noch nicht vollständig ist. Das kann bei einer SigG-Anwendung
   * ein fehlender Schlüssel oder ein noch nicht freigeschaltetes Zertifikat sein. Deprecated: This is not
   * defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#authenticationNotActivated
   */
  @Deprecated
  SAL_AUTHENTICATION_NOT_ACTIVATED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#authenticationNotActivated"),
  /**
   * Bedingungen für die Nutzung der Identifikationsdaten nicht erfällt Die Authentisierung mit Hilfe der
   * Identifikationsdaten kann nicht durchgeführt werden, weil sie nicht die notwendigen Anforderungen
   * erfüllt; beispielsweise muss eine Transport-PIN erst geändert werden. (Condition OF USE) Deprecated: This
   * is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#conditionOfUseNotSatisfied
   */
  @Deprecated
  SAL_CONDITION_OF_USE_NOT_SATISFIED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#conditionOfUseNotSatisfied"),
  /**
   * Funktion nicht unterstützt (FUNCTION NOT SUPPORTED) Deprecated: This is not defined in TR-03112 URI
   * value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#functionNotSupported
   */
  @Deprecated
  SAL_FUNCTION_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#functionNotSupported"),
  /**
   * Funktionalität wird von der aktuellen Version der API nicht unterstützt. Deprecated: This is not defined
   * in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/FunctionalityByCurrentProtocolVersionNotSupported
   */
  @Deprecated
  SAL_FUNCTIONALITY_BY_CURRENT_PROTOCOL_VERSION_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/FunctionalityByCurrentProtocolVersionNotSupported"),
  /**
   * Datei oder Applikation nicht gefunden (FILE NOT FOUND) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#fileNotFound
   */
  SAL_FILE_NOT_FOUND("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#fileNotFound"),
  /**
   * Angegebene Daten oder Referenzdaten nicht gefunden (DATA NOT FOUND) Deprecated: This is not defined in
   * TR-03112 URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#dataNotFound
   */
  @Deprecated
  SAL_DATA_NOT_FOUND("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#dataNotFound"),
  /**
   * Fehlender CardApplicationServiceName Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#missingCardApplicationServiceNameWarning
   */
  @Deprecated
  SAL_MISSING_CARD_APPLICATION_SERVICE_NAME_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#missingCardApplicationServiceNameWarning"),
  /**
   * Ungültiger Service Name Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidServiceName
   */
  @Deprecated
  SAL_INVALID_SERVICE_NAME("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidServiceName"),
  /**
   * Zertifikat kann nicht interpretiert werden. Das Format des angegebenen Zertifikates ist unbekannt und
   * kann nicht interpretiert werden. Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#certificateFormatNotCorrectWarning
   */
  @Deprecated
  SAL_CERTIFICATE_FORMAT_NOT_CORRECT_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#certificateFormatNotCorrectWarning"),
  /**
   * Zertifikatskette ist unterbrochen Die angegebene Zertifikatskette ist unterbrochen. Somit kann eine
   * vollständige Prüfung bis zum Root-Zertifikat nicht erfolgen. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#certificateChainInterrupted
   */
  SAL_CERTIFICATE_CHAIN_INTERRUPTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#certificateChainInterrupted"),
  /**
   * HashInfo wurde ignoriert Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#hashInfoIgnoredWarning
   */
  @Deprecated
  SAL_HASH_INFO_IGNORED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#hashInfoIgnoredWarning"),
  /**
   * The mandatory document validity check has failed. From the draft of part 7 from 20100922, special Minor
   * code for document validity failed. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/mEAC#DocumentValidityVerificationFailed
   */
  SAL_MEAC_DOCUMENT_VALIDITY_VERIFICATION_FAILED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/mEAC#DocumentValidityVerificationFailed"),
  /**
   * If the age verification process fails, a warining is returned in the AgeVerification element. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/mEAC#AgeVerificationFailedWarning
   */
  SAL_MEAC_AGE_VERIFICATION_FAILED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/mEAC#AgeVerificationFailedWarning"),
  /**
   * If the community affiliation process fails, a warning is returned in the CommunityVerification element.
   * URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/mEAC#CommunityVerificationFailedWarning
   */
  SAL_MEAC_COMMUNITY_VERIFICATION_FAILED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/mEAC#CommunityVerificationFailedWarning"),
  /**
   * In the case of a remote terminal any password transmitted in this element is ignored and this warning is
   * returned. URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/PACE#PasswordIgnoredWarning
   */
  SAL_PACE_PASSWORD_IGNORED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/PACE#PasswordIgnoredWarning"),
  /**
   * If the ReturnEFCardAccess is set true in PACEDIDAuthenticateInputType but no EF.CardAccess file is
   * available on the card, this warning is returned. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/PACE#EFCardAccessNotFoundWarning
   */
  SAL_PACE_EF_CARD_ACCESS_NOT_FOUND_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/PACE#EFCardAccessNotFoundWarning"),
  /**
   * See CADIDUpdateDataType in part 7 for more information. If the generateFlag alternative is selected in
   * the KeyInfo element and if the CAPublicKey element is also contained in the Marker, a warning is
   * returned. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/ChipAuth#PublicKeyIgnoredWarning
   */
  SAL_CHIPAUTH_PUBLIC_KEY_IGNORED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal/ChipAuth#PublicKeyIgnoredWarning"),
  /**
   * Zeitüberschreitung (Timeout) Die Operation wurde wegen Zeitüberschreitung abgebrochen.
   * (API_TIMEOUT_ERROR) Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#timeout
   */
  @Deprecated
  IFDL_COMMON_TIMEOUT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#timeout"),
  /**
   * Zeitüberschreitung (Timeout) Die Operation wurde wegen Zeitüberschreitung abgebrochen.
   * (API_TIMEOUT_ERROR) URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#timeoutError
   */
  IFDL_COMMON_TIMEOUT_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#timeoutError"),
  /**
   * Unbekanntes Context Handle (IFD_INVALID_CONTEXT_HANDLE) Deprecated: This is not defined in TR-03112 URI
   * value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#unknownContextHandle
   */
  @Deprecated
  IFDL_COMMON_UNKNOWN_CONTEXT_HANDLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#unknownContextHandle"),
  /**
   * Nicht valider Context Handle (IFD_INVALID_CONTEXT_HANDLE) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#invalidContextHandle
   */
  IFDL_COMMON_INVALID_CONTEXT_HANDLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#invalidContextHandle"),
  /**
   * Cancellation by the user A necessary user intervention (e.g. PIN entry) was terminated by cancellation.
   * (IFD_CANCELLATION_BY_USER) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#cancellationByUser
   */
  IFDL_COMMON_CANCELLATION_BY_USER("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#cancellationByUser"),
  /**
   * Unbekannter Session Identifier URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#unknownSessionIdentifier
   */
  IFDL_COMMON_UNKNOWN_SESSION_IDENTIFIER("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#unknownSessionIdentifier"),
  /**
   * Unbekanntes SLOT Handle (IFD_INVALID_SLOT_HANDLE) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#invalidSlotHandle
   */
  IFDL_COMMON_INVALID_SLOT_HANDLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/common#invalidSlotHandle"),
  /**
   * Unbekannte Eingabeeinheit (IFD_UNKNOWN_INPUT_UNIT) Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownInputDevice
   */
  @Deprecated
  IO_UNKNOWN_INPUT_DEVICE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownInputDevice"),
  /**
   * Newly recorded identification data do not correspond (IFD_REPEATED_DATA_MISMATCH) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#repeatedDataMismatch
   */
  IO_REPEATED_DATA_MISMATCH("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#repeatedDataMismatch"),
  /**
   * Unknown pin format (IFD_UNKNOWN_PIN_FORMAT URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownPINFormat
   */
  IO_UNKNOWN_PIN_FORMAT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownPINFormat"),
  /**
   * Unbekannte Ausgabeeinheit (IFD_UNKNOWN_DISPLAY_INDEX) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownOutputDevice
   */
  IO_UNKNOWN_OUTPUT_DEVICE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownOutputDevice"),
  /**
   * Abbruch des Kommandos nicht möglich (IFD_CANCEL_NOT_POSSIBLE) Deprecated: This is not defined in TR-03112
   * URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#cancelationNotPossibleWarning
   */
  @Deprecated
  IO_CANCELATION_NOT_POSSIBLE_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#cancelationNotPossibleWarning"),
  /**
   * Keine Chipkartentransaktion gestartet (IFD_NO_TRANSACTION_STARTED) Deprecated: This is not defined in
   * TR-03112 URI value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#noTransactionStartedWarning
   */
  @Deprecated
  IO_NO_TRANSACTION_STARTED_WARNING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#noTransactionStartedWarning"),
  /**
   * Keine Chipkartentransaktion gestartet (IFD_NO_TRANSACTION_STARTED) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#noTransactionStarted
   */
  IO_NO_TRANSACTION_STARTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#noTransactionStarted"),
  /**
   * Erneut erfasste Identifikationsdaten stimmen nicht überein (IFD_REPEATED_DATA_MISMATCH) Deprecated: This
   * is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#repeatedIdentificationDataMismatch
   */
  @Deprecated
  IO_REPEATED_IDENTIFICATION_DATA_MISMATCH("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#repeatedIdentificationDataMismatch"),
  /**
   * Unbekannter biometrischer Subtyp (IFD_UNKNOWN_BOIMETRIC_SUBTYPE) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownBiometricSubtype
   */
  IO_UNKNOWN_BIOMETRIC_SUBTYPE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownBiometricSubtype"),
  /**
   * Unknown input unit (IFD_UNKNOWN_INPUT_UNIT) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownInputUnit
   */
  IO_UNKNOWN_INPUT_UNIT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownInputUnit"),
  /**
   * Unknown display index (IFD_UNKNOWN_DISPLAY_INDEX) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownDisplayIndex
   */
  IO_UNKNOWN_DISPLAY_INDEX("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#unknownDisplayIndex"),
  /**
   * Abbruch des Kommandos nicht möglich (IFD_CANCEL_NOT_POSSIBLE) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#cancelNotPossible
   */
  IO_CANCEL_NOT_POSSIBLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/IO#cancelNotPossible"),
  /**
   * Exklusive Reservierung nicht möglich Die exklusive Reservierung der eCard ist nicht möglich. Mögliche
   * Ursachen sind, dass weitere Anwendungen auf die eCard zugreifen oder die Rechte für die exklusive
   * Reservierung der eCard nicht vorhanden sind (API_EXCLUSIVE_NOT_AVAILABLE) Deprecated: This is not defined
   * in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#exclusiveNotAvailable
   */
  @Deprecated
  TERMINAL_EXCLUSIVE_NOT_AVAILABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#exclusiveNotAvailable"),
  /**
   * Exklusive Reservierung nicht möglich Die exklusive Reservierung der eCard ist nicht möglich. Mögliche
   * Ursachen sind, dass weitere Anwendungen auf die eCard zugreifen oder die Rechte für die exklusive
   * Reservierung der eCard nicht vorhanden sind (API_EXCLUSIVE_NOT_AVAILABLE) Deprecated: This is not
   * avaliable in TR-03112 version 1.1.5 any more URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#exclusiveNotAvailable
   */
  @Deprecated
  SAL_EXCLUSIVE_NOT_AVAILABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#exclusiveNotAvailable"),
  /**
   * Kartenterminal existiert nicht Das adressierte Kartenterminal (IFDName) ist unbekannt. (IFD_UNKNOWN_IFD)
   * Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#unknownIFDName
   */
  @Deprecated
  TERMINAL_UNKNOWN_IFD_NAME("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#unknownIFDName"),
  /**
   * Unknown Action The requested action to be performed is unknown. (IFD_UNKNOWN_ACTION) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#unknownAction
   */
  TERMINAL_UNKNOWN_ACTION("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#unknownAction"),
  /**
   * Kartenterminal existiert nicht Das adressierte Kartenterminal (IFD) ist unbekannt. (IFD_UNKNOWN_IFD) URI
   * value: http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#unknownIFD
   */
  TERMINAL_UNKNOWN_IFD("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#unknownIFD"),
  /**
   * Kartenterminalslot existiert nicht Der adressierte Kartenterminalslot (Slot) ist unbekannt. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#unknownSlot
   */
  TERMINAL_UNKNOWN_SLOT("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#unknownSlot"),
  /**
   * The request was not successful, because the card is already used by another process
   * (IFD_SHARING_VIOLATION)) URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#IFDSharingVolation
   */
  TERMINAL_IFD_SHARING_VOLATION("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#IFDSharingVolation"),
  /**
   * Fehler beim Zugriff auf das Kartenterminal Beim Zugriff auf das Kartenterminal ist ein Fehler
   * aufgetreten. Die Ursache kann ein Kommunikationsfehler oder ein Protokollfehler sein. URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#accessError
   */
  TERMINAL_ACCESS_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#accessError"),
  /**
   * Kartenterminalslot existiert nicht Der in der Operation adressierte Slot des Kartenterminals existiert
   * nicht. (IFD_UNKNOWN_SLOT) Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#slotIndexNotExisting
   */
  @Deprecated
  TERMINAL_SLOT_INDEX_NOT_EXISTING("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#slotIndexNotExisting"),
  /**
   * Keine eCard vorhanden Die eCard wurde manuell entfernt und ist durch das System nicht mehr erfassbar
   * (IFD_NO_CARD) Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#noCard
   */
  @Deprecated
  TERMINAL_NO_CARD("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#noCard"),
  /**
   * Kartenterminal unterstützt die gewünschte mechanische Funktionalität nicht Deprecated: This is not
   * defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#mechanicalFunctionNotSupported
   */
  @Deprecated
  TERMINAL_MECHANICAL_FUNCTION_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#mechanicalFunctionNotSupported"),
  /**
   * Kartenterminal beschäftigt (IFD_SHARING_VIOLATION) Deprecated: This is not defined in TR-03112 URI value:
   * http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#IFDBusy
   */
  @Deprecated
  TERMINAL_IFD_BUSY("http://www.bsi.bund.de/ecard/api/1.1/resultminor/ifdl/terminal#IFDBusy");

  private static final Log LOGGER = LogFactory.getLog(ResultMinor.class.getName());

  private final String uri;

  ResultMinor(String uri)
  {
    this.uri = uri;
  }

  @Override
  public String toString()
  {
    return uri;
  }

  /**
   * Converts a URI to an Enumeration element
   */
  public static ResultMinor valueOfEnum(String uri)
  {
    for ( ResultMinor item : values() )
    {
      if (item.toString().equals(uri))
      {
        return item;
      }
    }
    for ( ResultMinor item : values() )
    {
      if (item.toString().endsWith(uri))
      {
        // TesVersion 3 (Look in EnumeratonTemplate.vm)
        LOGGER.debug("BC quircks mode. identify " + uri + " as " + item.toString());
        return item;
      }
    }
    throw new IllegalArgumentException("not a valid value of ResultMinor: " + uri);
  }

}

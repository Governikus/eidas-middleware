/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.gov2server.constants.admin;

/**
 * This is the set of all error codes which may produced by the Governikus Identity Manager in addition to global codes.
 * WebAdmin should be able to display a nice text for each messages created by one of these codes.
 * <p>
 *
 * @author tt
 */
public final class IDManagementCodes
{

  private IDManagementCodes()
  {
    // no instances needed
  }

  private static final String PREFIX_ERROR = "ID.msg.error.";

  /**
   * Some uploaded field has incorrect format. Detail is label of that field.
   */
  public static final Code1 INVALID_INPUT_DATA = new Code1(PREFIX_ERROR + "invalidInputData");

  /**
   * Some provider uses nPA but has no terminal certificate available. Detail is providers entityID.
   */
  public static final Code1 MISSING_TERMINAL_CERTIFICATE = new Code1(PREFIX_ERROR + "missingTerminalCertificate");

  /**
   * The terminal certificate data for some provider is present but not complete or (partly) incorrect. Detail is
   * providers entityID.
   */
  public static final Code1 INCOMPLETE_TERMINAL_CERTIFICATE = new Code1(PREFIX_ERROR + "incompleteTerminalCertificate");

  /**
   * There is no master list for the given service provider. First parameter is providers entityID, second parameter is
   * list type.
   */
  public static final Code2 NO_LIST_AVAILABLE = new Code2(PREFIX_ERROR + "noListAvailable");

  /**
   * The sector public hash in the CVC does not match the sector public hash from the CVC. Detail is providers entityID.
   */
  public static final Code1 SECTOR_HASH_DOES_NOT_MATCH = new Code1(PREFIX_ERROR + "sectorHashDoesNotMatch");

  /**
   * The CVC description does not match the hash in the CVC. Detail is providers entityID.
   */
  public static final Code1 CVC_DESCRIPTION_NOT_MATCH = new Code1(PREFIX_ERROR + "cvcDescriptionNotMatch");

  /**
   * entered URL value has wrong format. Detail is label.
   */
  public static final Code1 INVALID_URL = new Code1(PREFIX_ERROR + "invalidURL");

  /**
   * The option in the second argument must be configured for provider in first argument.
   */
  public static final Code2 MISSING_OPTION_FOR_PROVIDER = new Code2(PREFIX_ERROR + "missingOptionForProvider");

  /**
   * A configuration field for a service provider contains an invalid value. Details: provider name, field name
   */
  public static final Code2 INVALID_OPTION_FOR_PROVIDER = new Code2(PREFIX_ERROR + "invalidOptionForProvider");

  /**
   * You cannot perform that operation because input in field {0} is missing.
   */
  public static final Code1 MISSING_INPUT_VALUE = new Code1(PREFIX_ERROR + "missingInputValue");

  /**
   * A database entry with that primary key already exists
   */
  public static final Code1 DATABASE_ENTRY_EXISTS = new Code1(PREFIX_ERROR + "databaseEntryExists");

  /**
   * The service provider configuration must be saved before performing this operation.
   */
  public static final Code0 SERVICE_PROVIDER_NOT_SAVED = new Code0(PREFIX_ERROR + "serviceProviderNotSaved");

  /**
   * The CVC is currently being updated by another process
   */
  public static final Code0 CVC_UPDATE_LOCKED = new Code0(PREFIX_ERROR + "cvcUpdateLocked");

  /**
   * The format of the given CVC is invalid
   */
  public static final Code0 INVALID_CERTIFICATE = new Code0(PREFIX_ERROR + "invalidCertificate");

}

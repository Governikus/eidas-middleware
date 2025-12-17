/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.ecardcore.utilities;

import de.governikus.eumw.poseidas.ecardcore.core.ECardErrorCode;
import de.governikus.eumw.poseidas.ecardcore.core.ECardErrorCodeParam;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;


/**
 * ECardCommonErrorCodes Error codes that can appear in any framework independent of module configuration.
 *
 * @author Alexander Funk
 */
public enum ECardCommonErrorCodes implements ECardErrorCode
{

  /** if the file size is 0 */
  @ECardErrorCodeParam(params = {"file"})
  FILE_IS_EMPTY("file.is_empty", startCode() + 1, ResultMinor.COMMON_INCORRECT_PARAMETER),
  /** if the file object is a directory and not a regular file */
  @ECardErrorCodeParam(params = {"file"})
  FILE_IS_A_DIR("file.is_a_dir", startCode() + 2, ResultMinor.COMMON_INCORRECT_PARAMETER),
  /** if the file could not be read */
  @ECardErrorCodeParam(params = {"file"})
  FILE_CANT_READ("file.cant_read", startCode() + 3, ResultMinor.COMMON_INCORRECT_PARAMETER),
  /** if the file could not be write */
  @ECardErrorCodeParam(params = {"file"})
  FILE_CANT_WRITE("file.cant_write", startCode() + 4),
  /** if the file object is null */
  FILE_IS_NULL("file.is_null", startCode() + 5, ResultMinor.COMMON_INCORRECT_PARAMETER),
  /** if the file could not be found on the volume */
  @ECardErrorCodeParam(params = {"file"})
  FILE_NOT_FOUND("file.not_found", startCode() + 6, ResultMinor.COMMON_INCORRECT_PARAMETER),
  /** if the file could not be deleted */
  @ECardErrorCodeParam(params = {"file"})
  FILE_CANT_DELETE("file.cant_delete", startCode() + 7),
  /** if the file can't be parsed, it is invalid */
  @ECardErrorCodeParam(params = {"file"})
  FILE_INVALID("file.invalid", startCode() + 8, ResultMinor.COMMON_INCORRECT_PARAMETER),
  /** if the security manager denied the file access */
  @ECardErrorCodeParam(params = {"file"})
  FILE_PERMISSION_DENIED("file.permission_denied", startCode() + 9, ResultMinor.COMMON_INCORRECT_PARAMETER),
  /** if the file is to large for an enveloped signature */
  @ECardErrorCodeParam(params = {"file"})
  FILE_TOO_LARGE_FOR_ENVELOPED_SIGNATURE("file.too_large_for_enveloped_signature",
                                         startCode() + 10,
                                         ResultMinor.SAL_INSUFFICIENT_RESOURCES),
  /** if the InputDocument hash does not match the deposited file */
  @ECardErrorCodeParam(params = {"FileSource"})
  INPUTDOCUMENT_HASH_MANIPULATED("inputdocument.hash_manipulated",
                                 startCode() + 11,
                                 ResultMinor.COMMON_NOT_INITIALIZED),
  /** if the hash algorithm could not be found or is not supported */
  @ECardErrorCodeParam(params = {"HashAlgo"})
  UNSUPPORTED_HASH_ALGORITHM("algorithm.unsupported.hash",
                             startCode() + 12,
                             ResultMinor.ALGORITHM_HASH_ALGORITHM_NOT_SUPPORTED),
  /** if the crypto provider isn't supported because missing registration */
  @ECardErrorCodeParam(params = {"provider_name"})
  UNSUPPORTED_CRYPTO_PROVIDER("cryptoprovider.unsupported", startCode() + 13),
  /** if a unknown error occurred. */
  UNKNOWN_ERROR("unknown.error", startCode() + 14, ResultMinor.COMMON_INTERNAL_ERROR),
  /**
   * If a required parameter is missing on an API call.
   */
  COMMON_PARAMETERMISSING("common.requiredparametersmissing", startCode() + 15, ResultMinor.COMMON_INCORRECT_PARAMETER),
  /**
   * If a parameter has a wrong value or a wrong format, so that the request can not be fulfilled.
   */
  COMMON_WRONGPARAMETERS("common.wrongparameter", startCode() + 16, ResultMinor.COMMON_INCORRECT_PARAMETER),

  /**
   * Some requirement by the eCard-API on the Classpath or the JDK is not met. A hint is given what configuration is
   * missing.
   */
  @ECardErrorCodeParam(params = {"Hint"})
  COMMON_CONFIGURATIONERROR("common.configurationError", startCode() + 17, ResultMinor.COMMON_INTERNAL_ERROR),

  /**
   * Some requirement by the eCard-API on the Classpath or the JDK is not met. A hint is given what configuration is
   * missing.
   */
  @ECardErrorCodeParam(params = {"provider_name"})
  NO_SUCH_PROVIDER("common.no_such_provider", startCode() + 18, ResultMinor.COMMON_INTERNAL_ERROR),


  // Proxy
  /** if the http transport proxy settings are invalid */
  INVALID_PROXY_SETTINGS("common.invalid_proxy_settings", startCode() + 19, ResultMinor.DP_COMMUNICATION_ERROR),

  /** if the http transport configuration is invalid */
  INVALID_TRANSPORT_CONFIGURATION("common.invalid_transport_configuratin",
                                  startCode() + 20,
                                  ResultMinor.COMMON_INTERNAL_ERROR),

  // END
  ;

  /**
   * the first eCardModule, error codes start with 1000
   */
  private static final int STARTCODE = 1000;

  private static int startCode()
  {
    return STARTCODE;
  }



  private final String messageKey;

  private final int errno;

  private final ResultMinor minor;

  private ECardCommonErrorCodes(String returnCode, int i)
  {
    messageKey = returnCode;
    errno = i;
    minor = null;
  }

  private ECardCommonErrorCodes(String returnCode, int i, ResultMinor minor)
  {
    messageKey = returnCode;
    errno = i;
    this.minor = minor;
  }



  @Override
  public int getMessageCode()
  {
    return errno;
  }

  @Override
  public String getMessageKey()
  {
    return messageKey;
  }

  @Override
  public ResultMinor getResultMinor()
  {
    return minor;
  }

}

/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.impl;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionParameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.Read;
import de.governikus.eumw.poseidas.cardserver.eac.functions.read.ReadResult;


/**
 * Implementation of file parameter for application selection, file selection and reading.
 *
 * @see Read
 * @see FileSelect
 * @see ApplicationSelect
 * @see ReadResult
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class FileParameter implements FunctionParameter
{

  private byte[] efid = null;

  private byte[] dfid = null;

  private byte[] aid = null;

  private boolean withFCP = false;

  /**
   * Constructor.
   *
   * @param file_id if of file (EF)
   * @param dfid id of DF or <code>null</code>
   * @param aid id of application or <code>null</code>
   * @throws IllegalArgumentException if id of file <code>null</code> or empty
   */
  private FileParameter(byte[] file_id, byte[] dfid, byte[] aid, boolean withFCP)
  {
    super();
    AssertUtil.notNullOrEmpty(file_id, "id of file");
    this.efid = file_id;
    this.dfid = dfid;
    this.aid = aid;
    this.withFCP = withFCP;
  }

  /**
   * Constructor.
   *
   * @param path_id ID of path according to FID of DF or AID, <code>null</code> for no select of path required
   * @param file_id id of file
   * @param path_id_is_aid <code>true</code> for path is an AID, <code>false</code> for FID of a DF
   * @throws IllegalArgumentException if id of file <code>null</code> or empty
   */
  public FileParameter(byte[] path_id, byte[] file_id, boolean path_id_is_aid)
  {
    this(file_id, path_id_is_aid ? null : path_id, !path_id_is_aid ? null : path_id, false);
  }

  /**
   * Constructor.
   *
   * @param path_id ID of path according to FID of DF or AID, <code>null</code> for no select of path required
   * @param file_id id of file
   * @param path_id_is_aid <code>true</code> for path is an AID, <code>false</code> for FID of a DF
   * @param useFCP <code>true</code> for requesting FCP to be returned on selection
   * @throws IllegalArgumentException if id of file <code>null</code> or empty
   */
  public FileParameter(byte[] path_id, byte[] file_id, boolean path_id_is_aid, boolean useFCP)
  {
    this(file_id, path_id_is_aid ? null : path_id, !path_id_is_aid ? null : path_id, useFCP);
  }

  /**
   * Gets FID of EF.
   *
   * @return FID of EF
   */
  public byte[] getEFID()
  {
    return efid;
  }


  /**
   * Gets FID of DF.
   *
   * @return FID of DF, maybe <code>null</code>
   */
  public byte[] getDFID()
  {
    return dfid;
  }

  /**
   * Gets AID.
   *
   * @return AID, maybe <code>null</code>
   */
  public byte[] getAID()
  {
    return aid;
  }

  /**
   * Indicates whether to request FCP when selecting file.
   *
   * @return <code>true</code> for request FCP
   */
  public boolean useFCP()
  {
    return this.withFCP;
  }
}

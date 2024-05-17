package de.governikus.eumw.poseidas.server.pki;

import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.Code0;


/**
 * Exception for {@link MasterOrDefectList} which stores the information, which list throws this exception.
 */
public class MasterAndDefectListException extends GovManagementException
{

  public enum MasterOrDefectList
  {
    MASTER_LIST, DEFECT_LIST;
  }

  private final MasterOrDefectList masterOrDefectList;

  public MasterAndDefectListException(Code0 code, MasterOrDefectList masterOrDefectList)
  {
    super(code);
    this.masterOrDefectList = masterOrDefectList;
  }

  public MasterOrDefectList getMasterOrDefectList()
  {
    return masterOrDefectList;
  }
}

package de.governikus.eumw.poseidas.eidserver.convenience;

import java.io.Serializable;


/**
 * Data has been deselected by the ID card holder.
 */
public class EIDInfoResultDeselected implements EIDInfoResult, Serializable
{

  private static final long serialVersionUID = 2L;

  @Override
  public String toString()
  {
    return "Deselected";
  }
}

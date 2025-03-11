package de.governikus.eumw.poseidas.server.pki.blocklist;

import java.io.Serial;

import lombok.NoArgsConstructor;


/**
 * Exception for errors when a delta update has been found to cause an inconsistent state.
 */
@NoArgsConstructor
public class BlockListConsistencyException extends Exception
{

  @Serial
  private static final long serialVersionUID = 1L;
}

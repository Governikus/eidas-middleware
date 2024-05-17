package de.governikus.eumw.poseidas.server.pki.blocklist;

import java.io.Serial;


/**
 * Exception for errors when a Block List can not be processed and saved in a file.
 */
public class BlockListStorageException extends Exception
{

  @Serial
  private static final long serialVersionUID = 1L;

  /**
   * Constructs a BlockListStorageException with the specified error message.
   *
   * @param message the error message to describe the exception.
   */
  public BlockListStorageException(String message)
  {
    super(message);
  }

  /**
   * Constructs a BlockListStorageException with the specified error message and the cause of the error.
   *
   * @param message the error message to describe the exception.
   * @param cause the cause of the error.
   */
  public BlockListStorageException(String message, Throwable cause)
  {
    super(message, cause);
  }
}

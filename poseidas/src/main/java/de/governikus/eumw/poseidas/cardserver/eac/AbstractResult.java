/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac;




/**
 * Abstract result.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public abstract class AbstractResult<T extends Object> implements Result<T>
{

  private T data = null;

  private Throwable throwable = null;

  /**
   * Constructor.
   */
  public AbstractResult()
  {
    this(null, null);
  }

  /**
   * Copy-Constructor.
   *
   * @param toBeCopied result to be copied
   * @throws NullPointerException if result to be copied <code>null</code>
   */
  AbstractResult(Result<T> toBeCopied)
  {
    this(toBeCopied.getData(), toBeCopied.getThrowable());
  }

  /**
   * Constructor.
   *
   * @param throwable throwable
   */
  public AbstractResult(Throwable throwable)
  {
    this(null, throwable);
  }

  /**
   * Constructor.
   *
   * @param data data
   * @param throwable throwable
   */
  public AbstractResult(T data, Throwable throwable)
  {
    this.data = data;
    this.throwable = throwable;
  }

  /**
   * Constructor.
   *
   * @param data data
   */
  public AbstractResult(T data)
  {
    this(data, null);
  }

  /**
   * Gets throwable of result.
   *
   * @return throwable if error occured, otherwise <code>null</code>
   */
  @Override
  public final Throwable getThrowable()
  {
    return this.throwable;
  }

  /**
   * Gets data.
   *
   * @return data, maybe <code>null</code>
   */
  @Override
  public final T getData()
  {
    return this.data;
  }

  /** {@inheritDoc} */
  @Override
  public final boolean hasFailed()
  {
    return this.throwable != null;
  }

  /** {@inheritDoc} */
  @Override
  public final boolean wasSuccessful()
  {
    return !hasFailed();
  }
}

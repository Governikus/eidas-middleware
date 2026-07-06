package de.governikus.eumw.eidasstarterkit;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import lombok.Getter;
import lombok.ToString;


@Getter
@ToString
public final class EncryptionAlgorithmInfo
{

  @NonNull
  private final String algorithm;

  @Nullable
  private Integer keySize;

  @Nullable
  private String digestAlgorithm;

  @Nullable
  private String mgfAlgorithm;

  @Nullable
  private KdfParams kdfParams;

  @Nullable
  private String kaNonceValue;



  public record KdfParams(@Nullable String algorithm, @Nullable String digest)
  {}

  public EncryptionAlgorithmInfo(@NonNull String algorithm)
  {
    this.algorithm = algorithm;
  }

  public EncryptionAlgorithmInfo setKeySize(@Nullable Integer keySize)
  {
    this.keySize = keySize;
    return this;
  }

  public EncryptionAlgorithmInfo setDigestAlgorithm(@Nullable String digestAlgorithm)
  {
    this.digestAlgorithm = digestAlgorithm;
    return this;
  }

  public EncryptionAlgorithmInfo setMgfAlgorithm(@Nullable String mgfAlgorithm)
  {
    this.mgfAlgorithm = mgfAlgorithm;
    return this;
  }

  public EncryptionAlgorithmInfo setKdfParams(@Nullable KdfParams kdfParams)
  {
    this.kdfParams = kdfParams;
    return this;
  }

  public EncryptionAlgorithmInfo setKaNonce(String kaNonceValue)
  {
    this.kaNonceValue = kaNonceValue;
    return this;
  }
}

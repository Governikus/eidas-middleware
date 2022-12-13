package de.governikus.eumw.poseidas.config.model;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class KeystoreInfoHolder
{

  String name;

  String keyStoreType;

  List<String> possibleCertificateAlias;

  List<String> possibleKeyPairAlias;
}

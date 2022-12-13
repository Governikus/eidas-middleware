package de.governikus.eumw.poseidas.config.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class CertificateInfoHolder
{

  String name;

  String subject;

  String issuer;

  String serialnumber;

  String validUntil;

  boolean valid;

  String keystore;

  String alias;
}

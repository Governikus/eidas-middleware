package de.governikus.eumw.poseidas.config.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class KeystoreUploadModel
{

  String password;

  @NotBlank(message = "May not be empty")
  String name;

  @NotNull
  String keyStoreType;
}

package de.governikus.eumw.poseidas.config.model.forms;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Model to hold the new password
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class NewPasswordModel
{
    private String oldPassword;

    private String newPassword;

    private String newPasswordRepeat;
}

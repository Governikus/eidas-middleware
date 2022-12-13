package de.governikus.eumw.poseidas.config;

import java.io.IOException;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.model.forms.NewPasswordModel;
import de.governikus.eumw.poseidas.service.PasswordHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Controller
@RequestMapping(ContextPaths.ADMIN_CONTEXT_PATH)
@RequiredArgsConstructor
public class LoginController
{

  public static final String LOGIN_FORM = "pages/loginForm";

  public static final String SET_NEW_PASSWORD = "pages/setNewPassword";

  public static final String ERROR = "error";

  private final PasswordHandler passwordHandler;

  @GetMapping("/login")
  public String index(Model model)
  {
    if (passwordHandler.isPasswordSet())
    {
      return LOGIN_FORM;
    }
    model.addAttribute(new NewPasswordModel());
    model.addAttribute("passwordAction", ContextPaths.ADMIN_CONTEXT_PATH + "/setNewPassword");
    return SET_NEW_PASSWORD;
  }

  @PostMapping({"/setNewPassword"})
  public String updatePassword(Model model, @ModelAttribute NewPasswordModel newPasswordModel)
  {
    if (passwordHandler.isPasswordSet())
    {
      model.addAttribute(ERROR, "A password is already set.");
      return LOGIN_FORM;
    }
    if (!checkNewPassword(model, newPasswordModel))
    {
      return SET_NEW_PASSWORD;
    }
    try
    {
      passwordHandler.updatePassword(newPasswordModel.getNewPassword(), false);
      model.addAttribute("msg", "New password set");
      return LOGIN_FORM;
    }
    catch (IOException e)
    {
      log.error("Could not set password!", e);

      model.addAttribute(newPasswordModel);
      model.addAttribute(ERROR, "Could not set password! Please check logs for more info.");
      return SET_NEW_PASSWORD;
    }
  }


  @GetMapping("/changePassword")
  public String changePasswordForm(Model model)
  {
    model.addAttribute(new NewPasswordModel());
    model.addAttribute("passwordAction", ContextPaths.ADMIN_CONTEXT_PATH + "/changePassword");
    return SET_NEW_PASSWORD;
  }

  @PostMapping("/changePassword")
  public String changePassword(Model model, @ModelAttribute NewPasswordModel newPasswordModel)
  {
    if (checkNewPassword(model, newPasswordModel))
    {
      try
      {
        passwordHandler.updatePassword(newPasswordModel.getNewPassword(), false);
        model.addAttribute("msg", "Password changed successfully");
      }
      catch (IOException e)
      {
        log.error("Could not set password!", e);

        model.addAttribute(newPasswordModel);
        model.addAttribute(ERROR, "Could not set password! Please check logs for more info.");

      }
    }
    return SET_NEW_PASSWORD;
  }

  private boolean checkNewPassword(Model model, NewPasswordModel newPasswordModel)
  {

    if (passwordHandler.getHashedPassword() != null && !passwordHandler.verifyOldPassword(newPasswordModel.getOldPassword()))
    {
      model.addAttribute(newPasswordModel);
      model.addAttribute(ERROR, "The old password is not correct.");
      return false;
    }

    if ("Pleasechangeme!".equals(newPasswordModel.getNewPassword()))
    {
      model.addAttribute(newPasswordModel);
      model.addAttribute(ERROR, "The new password can not be the default password from previous versions");
      return false;
    }
    if (newPasswordModel.getNewPassword().isBlank())
    {
      model.addAttribute(newPasswordModel);
      model.addAttribute(ERROR, "Password must not be empty!");
      return false;
    }
    if (!newPasswordModel.getNewPassword().equals(newPasswordModel.getNewPasswordRepeat()))
    {
      model.addAttribute(newPasswordModel);
      model.addAttribute(ERROR, "Passwords don't match");
      return false;
    }
    return true;
  }
}

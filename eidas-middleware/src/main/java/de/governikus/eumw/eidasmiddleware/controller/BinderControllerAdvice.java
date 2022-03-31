package de.governikus.eumw.eidasmiddleware.controller;

import org.springframework.core.annotation.Order;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.InitBinder;

@ControllerAdvice
@Order(10000)
public class BinderControllerAdvice {
  @InitBinder
  public void setAllowedFields(WebDataBinder dataBinder) {
    // This code protects Spring Core from a "Remote Code Execution" attack (dubbed "Spring4Shell").
    // By applying this mitigation, you prevent the "Class Loader Manipulation" attack vector from firing.
    // For more details, see this post: https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/
    String[] denylist = new String[]{"class.*", "Class.*", "*.class.*", "*.Class.*"};
    dataBinder.setDisallowedFields(denylist);
  }
}
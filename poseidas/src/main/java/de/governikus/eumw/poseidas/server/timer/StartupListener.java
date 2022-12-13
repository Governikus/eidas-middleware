package de.governikus.eumw.poseidas.server.timer;

import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import lombok.AllArgsConstructor;


@Component
@AllArgsConstructor
public class StartupListener
{

  private final PermissionDataHandling permissionDataHandling;

  private final TerminalPermissionAO facade;

  private final CvcTlsCheck cvcTlsCheck;

  private final ConfigurationService configurationService;

  @EventListener
  public void onApplicationEvent(WebServerInitializedEvent event)
  {
    initCRL();
    cvcTlsCheck.check();
  }

  private void initCRL()
  {
    permissionDataHandling.renewMasterAndDefectList();
    CertificationRevocationListImpl.tryInitialize(configurationService, facade);
  }
}

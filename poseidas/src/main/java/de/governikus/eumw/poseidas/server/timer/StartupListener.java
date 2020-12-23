package de.governikus.eumw.poseidas.server.timer;

import java.util.HashSet;

import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.MasterList;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import de.governikus.eumw.poseidas.server.pki.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import lombok.extern.slf4j.Slf4j;


@Component
@Slf4j
public class StartupListener
{

  private final PermissionDataHandling permissionDataHandling;

  private final TerminalPermissionAO facade;

  private final CvcTlsCheck cvcTlsCheck;

  public StartupListener(PermissionDataHandling permissionDataHandling,
                         TerminalPermissionAO facade,
                         CvcTlsCheck cvcTlsCheck)
  {
    this.permissionDataHandling = permissionDataHandling;
    this.facade = facade;
    this.cvcTlsCheck = cvcTlsCheck;
  }

  @EventListener
  public void onApplicationEvent(WebServerInitializedEvent event)
  {
    initCRL();
    cvcTlsCheck.check();
  }

  private void initCRL()
  {
    permissionDataHandling.renewMasterAndDefectList();
    String cvcRefID = PoseidasConfigurator.getInstance()
                                          .getCurrentConfig()
                                          .getServiceProvider()
                                          .entrySet()
                                          .iterator()
                                          .next()
                                          .getValue()
                                          .getEpaConnectorConfiguration()
                                          .getCVCRefID();
    TerminalPermission terminalPermission = facade.getTerminalPermission(cvcRefID);
    if (terminalPermission == null || ArrayUtil.isNullOrEmpty(terminalPermission.getMasterList()))
    {
      log.warn("No terminal permission for cvcRefId: {}. Can not initialize CRL", cvcRefID);
      return;
    }
    MasterList ml = new MasterList(terminalPermission.getMasterList());
    CertificationRevocationListImpl.initialize(new HashSet<>(ml.getCertificates()));
  }
}

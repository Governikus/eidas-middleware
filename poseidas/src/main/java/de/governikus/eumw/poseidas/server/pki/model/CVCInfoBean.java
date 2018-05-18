/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.model;

import java.io.Serializable;
import java.text.DateFormat;
import java.util.Date;
import java.util.Map;

import de.governikus.eumw.poseidas.gov2server.constants.admin.AdminPoseidasConstants;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandlingMBean;

/**
 * This class represents a single service provider entity. It provides methods
 * for setting and getting entity details as well as CVC operations and renewing
 * the three lists.
 * 
 * @author bpr
 *
 */
public class CVCInfoBean implements Serializable {

	private static final long serialVersionUID = 1L;

	private PermissionDataHandlingMBean data;

	private ServiceProviderDto entry;

	private Map<String, Object> info;

	private String entityID;

	private String countryCode;

	private String chrMnemonic;

	private int sequenceNumber;

	public CVCInfoBean() {
		super();
	}

	public CVCInfoBean(ServiceProviderDto entry, PermissionDataHandlingMBean data) {
		this();
		this.entry = entry;
		entityID = entry.getEntityID();
		this.data = data;
		fetchInfo();
	}

	public void fetchInfo() {
		if (entry == null) {
			CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
			entry = config.getServiceProvider().get(entityID);
		}
		info = data.getPermissionDataInfo(entry.getEpaConnectorConfiguration().getCVCRefID(), true);
	}

	public void setEntityID(String entityID) {
		this.entityID = entityID;
	}

	public String getEntityID() {
		return entityID;
	}

	public String getCountryCode() {
		return countryCode;
	}

	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}

	public String getChrMnemonic() {
		return chrMnemonic;
	}

	public void setChrMnemonic(String chrMnemonic) {
		this.chrMnemonic = chrMnemonic;
	}

	public int getSequenceNumber() {
		return sequenceNumber;
	}

	public void setSequenceNumber(int sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}

	public String getCVCRefID() {
		return entry.getEpaConnectorConfiguration().getCVCRefID();
	}

	public boolean isInfo() {
		return info != null;
	}

	public String getCHR() {
		try {
			return (String) info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_HOLDERREFERENCE);
		} catch (NullPointerException e) {
			return "";
		}
	}

	public String getSubjectName() {
		try {
			return (String) info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_SUBJECT_NAME);
		} catch (NullPointerException e) {
			return "";
		}
	}

	public String getSubjectURL() {
		try {
			return (String) info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_SUBJECT_URL);
		} catch (NullPointerException e) {
			return "";
		}
	}

	public String getCAR() {
		try {
			return (String) info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_CA_REFERENCE);
		} catch (NullPointerException e) {
			return "";
		}
	}

	private String dateToString(Date date) {
		if (date == null) {
			return null;
		}
		DateFormat formater = DateFormat.getDateInstance(DateFormat.SHORT);
		return formater.format(date);
	}

	public String getValidFrom() {
		try {
			return dateToString((Date) info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EFFECTIVE_DATE));
		} catch (NullPointerException e) {
			return "";
		}
	}

	public String getInvalidOn() {
		try {
			return dateToString((Date) info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EXPIRATION_DATE));
		} catch (NullPointerException e) {
			return "";
		}
	}

	public String getIssuerName() {
		try {
			return (String) info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ISSUER_NAME);
		} catch (NullPointerException e) {
			return "";
		}
	}

	public String getIssuerURL() {
		try {
			return (String) info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ISSUER_URL);
		} catch (NullPointerException e) {
			return "";
		}
	}

	public String getRedirectURL() {
		try {
			return (String) info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_REDIRECT_URL);
		} catch (NullPointerException e) {
			return "";
		}
	}

	public String getTermsOfUsagePlanText() {
		try {
			return (String) info.get(AdminPoseidasConstants.VALUE_PERMISSION_DATA_TERMS_OF_USAGE_PLAIN_TEXT);
		} catch (NullPointerException e) {
			return "";
		}
	}

	public String checkReadyForFirstRequest() {
		ManagementMessage result = data.checkReadyForFirstRequest(entityID);
		return result.toString();
	}

	public String initRequest() {
		ManagementMessage result = data.requestFirstTerminalCertificate(entityID, countryCode, chrMnemonic,
				sequenceNumber);
		return result.toString();
	}

	public String renewBlackList() {
		ManagementMessage result = data.renewBlackList(entityID);
		return result.toString();
	}

	public String renewMasterAndDefectList() {
		ManagementMessage result = data.renewMasterAndDefectList(entityID);
		return result.toString();
	}

	public String triggerCertRenewal() {
		ManagementMessage result = data.triggerCertRenewal(entityID);
		return result.toString();
	}
}

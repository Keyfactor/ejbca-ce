/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.configuration;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Backing bean for edit EST alias view.
 *
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class EditEstConfigMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;

    @ManagedProperty(value = "#{estConfigMBean}")
    private EstConfigMBean estConfigMBean;
    EstAliasGui estAliasGui = null;

    public class EstAliasGui {
        private String name;
        private String caId;
        private String endEntityProfileId;
        private String certificateProfileId;
        private Boolean certificateRequired;
        private String userName;
        private String password;
        private Boolean allowSameKey;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getCaId() {
            return caId;
        }

        public void setCaId(String caId) {
            this.caId = caId;
        }

        public String getEndEntityProfileId() {
            return endEntityProfileId;
        }

        public void setEndEntityProfileId(String endEntityProfileId) {
            this.endEntityProfileId = endEntityProfileId;
        }

        public String getCertificateProfileId() {
            return certificateProfileId;
        }

        public void setCertificateProfileId(String certificateProfileId) {
            this.certificateProfileId = certificateProfileId;
        }

        public Boolean getCertificateRequired() {
            return certificateRequired;
        }

        public void setCertificateRequired(Boolean certificateRequired) {
            this.certificateRequired = certificateRequired;
        }

        public String getUserName() {
            return userName;
        }

        public void setUserName(String userName) {
            this.userName = userName;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public Boolean getAllowSameKey() {
            return allowSameKey;
        }

        public void setAllowSameKey(Boolean allowSameKey) {
            this.allowSameKey = allowSameKey;
        }
    }

    public EstAliasGui getEstAlias() {
        if (estAliasGui == null) {
            EstAliasGui estAliasGui = new EstAliasGui();
            String aliasName = estConfigMBean.getSelectedAlias();
            estAliasGui.setName(aliasName);
            EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfiguration();
            estAliasGui.setCaId(estConfiguration.getDefaultCAID(aliasName));
            estAliasGui.setEndEntityProfileId(String.valueOf(estConfiguration.getEndEntityProfileID(aliasName)));
            String certProfileID = estConfiguration.getCertProfileID(aliasName);
            // If we had the old type, EJBCA 6.11 of CP, which is the name, convert it to ID
            if (!NumberUtils.isNumber(certProfileID)) {
                Map<String, Integer> certificateProfiles = getEjbcaWebBean().getCertificateProfilesNoKeyId(estAliasGui.getEndEntityProfileId());
                if (certificateProfiles.get(certProfileID) != null) {
                    certProfileID = String.valueOf(certificateProfiles.get(certProfileID));
                }
            }
            estAliasGui.setCertificateProfileId(certProfileID);
            estAliasGui.setCertificateRequired(estConfiguration.getCert(aliasName));
            estAliasGui.setUserName(estConfiguration.getUsername(aliasName));
            estAliasGui.setPassword(estConfiguration.getPassword(aliasName));
            estAliasGui.setAllowSameKey(estConfiguration.getKurAllowSameKey(aliasName));
            this.estAliasGui = estAliasGui;
        }
        return estAliasGui;
    }


    public boolean isViewOnly() {
        return estConfigMBean.isViewOnly();
    }

    public List<SelectItem> getCaItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        if (StringUtils.isEmpty(getEstAlias().getCaId())) {
            ret.add(new SelectItem("", EjbcaJSFHelper.getBean().getText().get("ESTDEFAULTCA_DISABLED")));
        }
        Map<String, Integer> canames = getEjbcaWebBean().getCANames();
        for (String caname : canames.keySet()) {
            final Integer cadi = canames.get(caname);
            ret.add(new SelectItem(cadi, caname));
        }
        return ret;
    }

    public List<SelectItem> getEndEntityProfileItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        Map<String, String> nameToIdMap = getEjbcaWebBean().getAuthorizedEEProfilesAndIdsNoKeyId(AccessRulesConstants.CREATE_END_ENTITY);
        for (String endEntityProfileName : nameToIdMap.keySet()) {
            String endEntityProfileId = nameToIdMap.get(endEntityProfileName);
            ret.add(new SelectItem(endEntityProfileId, endEntityProfileName));
        }
        return ret;
    }

    public List<SelectItem> getCertificateProfileItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        if (estAliasGui.getEndEntityProfileId() != null) {
            Map<String, Integer> certificateProfiles = getEjbcaWebBean().getCertificateProfilesNoKeyId(estAliasGui.getEndEntityProfileId());
            for (String certificateProfileName : certificateProfiles.keySet()) {
                int certificateProfileId = certificateProfiles.get(certificateProfileName);
                ret.add(new SelectItem(certificateProfileId, certificateProfileName));
            }
        }
        return ret;
    }

    public String cancel() {
        reset();
        return "done";
    }

    public String save() throws AuthorizationDeniedException {
        String alias = estAliasGui.getName();
        EstConfiguration estConfiguration = getEjbcaWebBean().getEstConfigForEdit(alias);
        if (StringUtils.isEmpty(estAliasGui.getCaId())) {
            estConfiguration.setDefaultCAID(alias, 0);
        } else {
            estConfiguration.setDefaultCAID(alias, Integer.valueOf(estAliasGui.getCaId()));
        }
        if (estAliasGui.getEndEntityProfileId() != null) {
            estConfiguration.setEndEntityProfileID(alias, Integer.valueOf(estAliasGui.getEndEntityProfileId()));
        }
        if (estAliasGui.getCertificateProfileId() != null) {
            estConfiguration.setCertProfileID(alias, Integer.valueOf(estAliasGui.getCertificateProfileId()));
        }
        estConfiguration.setCert(alias, estAliasGui.getCertificateRequired());
        estConfiguration.setUsername(alias, estAliasGui.getUserName());
        estConfiguration.setPassword(alias, estAliasGui.getPassword());
        estConfiguration.setKurAllowSameKey(alias, estAliasGui.getAllowSameKey());
        getEjbcaWebBean().updateEstConfigFromClone(alias);
        reset();
        return "done";
    }

    private void reset() {
        estAliasGui = null;
        getEjbcaWebBean().clearEstConfigClone();
        estConfigMBean.actionCancel();
    }

    public EstConfigMBean getEstConfigMBean() {
        return estConfigMBean;
    }

    public void setEstConfigMBean(EstConfigMBean estConfigMBean) {
        this.estConfigMBean = estConfigMBean;
    }
}

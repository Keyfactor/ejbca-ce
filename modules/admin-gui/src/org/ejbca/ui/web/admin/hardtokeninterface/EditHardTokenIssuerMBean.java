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

package org.ejbca.ui.web.admin.hardtokeninterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.faces.model.SelectItem;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * @version $Id$
 */
public class EditHardTokenIssuerMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;

    private HardTokenIssuerMBean hardTokenIssuerMBean;
    private IssuerGui issuerGui;

    public class IssuerGui {
        private String name;
        private String roleLabel;
        private String description;
        private ArrayList<Integer> availableHardTokenProfiles;

        public IssuerGui(String name, String roleLabel, String description, ArrayList<Integer> availableHardTokenProfiles) {
            this.name = name;
            this.roleLabel = roleLabel;
            this.description = description;
            this.availableHardTokenProfiles = availableHardTokenProfiles;
        }

        public String getRoleLabel() {
            return roleLabel;
        }

        public void setRoleLabel(String roleLabel) {
            this.roleLabel = roleLabel;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public ArrayList<Integer> getAvailableHardTokenProfiles() {
            return availableHardTokenProfiles;
        }

        public void setAvailableHardTokenProfiles(ArrayList<String> availableHardTokenProfiles) {
            ArrayList<Integer> ap = new ArrayList<>();
            for (String profile : availableHardTokenProfiles) {
                ap.add(Integer.valueOf(profile));
            }
            this.availableHardTokenProfiles = ap;
        }
    }

    public IssuerGui getIssuerGui() {
        if (issuerGui == null) {
            final HardTokenIssuerInformation issuerInformation = hardTokenIssuerMBean.getTokenbean().getHardTokenIssuerInformation(hardTokenIssuerMBean.getSelectedHardTokenIssuer());
            final String roleLabel = hardTokenIssuerMBean.getTokenbean().getRoleIdToNameMap().get(issuerInformation.getRoleDataId());
            final String description = issuerInformation.getHardTokenIssuer().getDescription();
            final ArrayList<Integer> availableHardTokenProfiles = issuerInformation.getHardTokenIssuer().getAvailableHardTokenProfiles();
            issuerGui = new IssuerGui(issuerInformation.getAlias(), roleLabel, description, availableHardTokenProfiles);
        }
        return issuerGui;
    }


    public List<SelectItem> getAvailableHardTokenProfilesSelectItemList() {
        final TreeMap<String, Integer> hardTokenProfiles = getEjbcaWebBean().getHardTokenProfiles();
        final List<SelectItem> ret = new ArrayList<>();
        for (Map.Entry<String, Integer> hardTokenProfile : hardTokenProfiles.entrySet()) {
            ret.add(new SelectItem(hardTokenProfile.getValue(), hardTokenProfile.getKey()));
        }
        return ret;
    }

    public String save() throws AuthorizationDeniedException {
        HardTokenIssuer issuer = hardTokenIssuerMBean.getTokenbean().getHardTokenIssuerInformation(issuerGui.name).getHardTokenIssuer();
        issuer.setDescription(issuerGui.getDescription());
        issuer.setAvailableHardTokenProfiles(issuerGui.getAvailableHardTokenProfiles());
        try {
            hardTokenIssuerMBean.getTokenbean().changeHardTokenIssuer(issuerGui.name, issuer);
        } catch (HardTokenIssuerDoesntExistsException e) {
            addErrorMessage("HARDTOKENDOESNTEXIST");
        }
        reset();
        return "done";
    }

    public String cancel() {
        reset();
        return "done";
    }

    private void reset() {
        issuerGui = null;
        hardTokenIssuerMBean.reset();
    }

    public HardTokenIssuerMBean getHardTokenIssuerMBean() {
        return hardTokenIssuerMBean;
    }

    public void setHardTokenIssuerMBean(HardTokenIssuerMBean hardTokenIssuerMBean) {
        this.hardTokenIssuerMBean = hardTokenIssuerMBean;
    }
}

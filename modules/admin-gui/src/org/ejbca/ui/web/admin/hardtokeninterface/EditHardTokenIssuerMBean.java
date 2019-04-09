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

        public IssuerGui(String name, String roleLabel, String description) {
            this.name = name;
            this.roleLabel = roleLabel;
            this.description = description;
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
    }

    public IssuerGui getIssuerGui() {
        if (issuerGui == null) {
            final HardTokenIssuerInformation issuerInformation = hardTokenIssuerMBean.getTokenbean().getHardTokenIssuerInformation(hardTokenIssuerMBean.getSelectedHardTokenIssuer());
            final String roleLabel = hardTokenIssuerMBean.getTokenbean().getRoleIdToNameMap().get(issuerInformation.getRoleDataId());
            final String description = issuerInformation.getHardTokenIssuer().getDescription();
            issuerGui = new IssuerGui(issuerInformation.getAlias(), roleLabel, description);
        }
        return issuerGui;
    }

    public String save() throws AuthorizationDeniedException {
        HardTokenIssuer issuer = hardTokenIssuerMBean.getTokenbean().getHardTokenIssuerInformation(issuerGui.name).getHardTokenIssuer();
        issuer.setDescription(issuerGui.getDescription());
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

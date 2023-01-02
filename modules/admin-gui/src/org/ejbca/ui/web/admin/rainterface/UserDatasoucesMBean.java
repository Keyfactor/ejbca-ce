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
package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.ejb.EJB;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 */
//@Named("userDatasoucesMBean")
//@SessionScoped
public class UserDatasoucesMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(UserDatasoucesMBean.class);

    @EJB
    private UserDataSourceSessionLocal userdatasourcesession = null;

    private String selectedUserDataSource;
    private String newUserDatasource = "";

    /**
     * Indicates a delete action in progress to render its view.
     */
    private boolean deleteInProgress = false;

    public UserDatasoucesMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_EDITUSERDATASOURCES);
    }

    public List<SelectItem> getUserDatasourceSeletItemList() {
        TreeMap<String, Integer> userdatasourcenames = getAuthorizedUserDataSourceNames();
        final List<SelectItem> ret = new ArrayList<>();
        for (Map.Entry<String, Integer> userDatasource : userdatasourcenames.entrySet()) {
            ret.add(new SelectItem(userDatasource.getKey(), userDatasource.getKey()));
        }
        return ret;
    }

    private TreeMap<String, Integer> getAuthorizedUserDataSourceNames() {
        TreeMap<String, Integer> retval = new TreeMap<>();

        Collection<Integer> authorizedsources = userdatasourcesession.getAuthorizedUserDataSourceIds(getAdmin(), false);
        for (Integer id : authorizedsources) {
            retval.put(userdatasourcesession.getUserDataSourceName(getAdmin(), id), id);
        }

        return retval;
    }

    public void addDatasource() throws AuthorizationDeniedException {
        if (newUserDatasource != null) {
            if (!newUserDatasource.trim().equals("")) {
                if (!StringTools.checkFieldForLegalChars(newUserDatasource)) {
                    addErrorMessage("ONLYCHARACTERS");
                } else {
                    try {
                        userdatasourcesession.addUserDataSource(getAdmin(), newUserDatasource.trim(), new CustomUserDataSourceContainer());
                    } catch (UserDataSourceExistsException e) {
                        addErrorMessage("USERDATASOURCEALREADY");
                        newUserDatasource = null;
                    }
                }
            }
        }
    }

    public void renameDatasource() throws AuthorizationDeniedException {
        if (selectedUserDataSource != null && newUserDatasource != null) {
            selectedUserDataSource = selectedUserDataSource.trim();
            newUserDatasource = newUserDatasource.trim();
            if (StringUtils.isNotEmpty(newUserDatasource) && StringUtils.isNotEmpty(selectedUserDataSource)) {
                if (!StringTools.checkFieldForLegalChars(newUserDatasource)) {
                    addErrorMessage("ONLYCHARACTERS");
                } else {
                    try {
                        userdatasourcesession.renameUserDataSource(getAdmin(), selectedUserDataSource, newUserDatasource);
                        newUserDatasource = null;
                    } catch (UserDataSourceExistsException e) {
                        addErrorMessage("USERDATASOURCEALREADY");
                    }
                }
            }
        }
    }

    public void cloneDatasource() throws AuthorizationDeniedException {
        if (selectedUserDataSource != null && newUserDatasource != null) {
            selectedUserDataSource = selectedUserDataSource.trim();
            newUserDatasource = newUserDatasource.trim();
            if (StringUtils.isNotEmpty(newUserDatasource) && StringUtils.isNotEmpty(selectedUserDataSource)) {
                if (!StringTools.checkFieldForLegalChars(newUserDatasource)) {
                    addErrorMessage("ONLYCHARACTERS");
                } else {
                    try {
                        userdatasourcesession.cloneUserDataSource(getAdmin(), selectedUserDataSource, newUserDatasource);
                        newUserDatasource = null;
                    } catch (UserDataSourceExistsException e) {
                        addErrorMessage("USERDATASOURCEALREADY");
                    }
                }
            }
        }
    }

    public void deleteDatasource() throws AuthorizationDeniedException {
        if (selectedUserDataSource != null) {
            if (!selectedUserDataSource.trim().equals("")) {
                boolean result = userdatasourcesession.removeUserDataSource(getAdmin(), selectedUserDataSource);
                if (!result) {
                    addErrorMessage("COULDNTDELETEUSERDATASOURCE");
                }
            }
        }
        actionCancel();
    }

    /**
     * Delete action.
     */
    public void actionDelete() {
        if (StringUtils.isNotEmpty(selectedUserDataSource)) {
            deleteInProgress = true;
        }
    }

    /**
     * Cancel action.
     */
    public void actionCancel() {
        deleteInProgress = false;
        selectedUserDataSource = null;
        newUserDatasource = null;
    }

    /**
     * Edit action.
     *
     * @return the navigation outcome defined in faces-config.xml.
     */
    public String actionEdit() {
        if (StringUtils.isNotEmpty(selectedUserDataSource)) {
            return "edit";
        } else {
            addErrorMessage("USERDATASOURCESELECT");
        }
        return "";
    }

    public boolean isAuthorizedToEdit() {
        return isAuthorizedTo(StandardRules.CERTIFICATEPROFILEEDIT.resource());
    }

    public String getSelectedUserDataSource() {
        return selectedUserDataSource;
    }

    public void setSelectedUserDataSource(String selectedUserDataSource) {
        this.selectedUserDataSource = selectedUserDataSource;
    }

    public String getNewUserDatasource() {
        return newUserDatasource;
    }

    public void setNewUserDatasource(String newUserDatasource) {
        this.newUserDatasource = newUserDatasource;
    }

    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }
}
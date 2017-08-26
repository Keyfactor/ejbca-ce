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

package org.ejbca.ui.web.admin.keys.validation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.ejb.EJB;
import javax.faces.model.ListDataModel;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.keys.validation.CouldNotRemoveKeyValidatorException;
import org.cesecore.keys.validation.KeyValidatorDoesntExistsException;
import org.cesecore.keys.validation.KeyValidatorExistsException;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.keys.validation.RsaKeyValidator;
import org.cesecore.keys.validation.Validator;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Managed bean for edit validators page (editvalidators.xhtml).
 *
 * @version $Id$
 */
public class ValidatorsBean extends BaseManagedBean {

    private static final long serialVersionUID = 1969611638716145216L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ValidatorsBean.class);

    /** Selected key validator id. */
    private Integer selectedKeyValidatorId = null;

    /** Selected key validator name. */
    private String keyValidatorName = StringUtils.EMPTY;

    private boolean renameInProgress = false;
    private boolean deleteInProgress = false;
    private boolean addFromTemplateInProgress = false;

    /** View only flag for view action. */
    private boolean viewOnly = true;

    /** Backing object for key validator list. */
    private ListDataModel<ValidatorItem> validatorItems = null;

    @EJB
    private CaSessionLocal caSession;

    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;

    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;

    /**
     * Gets the selected key validator id.
     * @return the id.
     */
    public Integer getSelectedKeyValidatorId() {
        return selectedKeyValidatorId;
    }

    /**
     * Sets the selected key validator id.
     * @param id the id
     */
    public void setSelectedKeyValidatorId(final Integer id) {
        selectedKeyValidatorId = id;
    }

    /**
     * Gets the selected key validator name.
     * @return the name
     */
    public String getSelectedKeyValidatorName() {
        final Integer id = getSelectedKeyValidatorId();
        if (id != null) {
            return keyValidatorSession.getKeyValidatorName(id.intValue());
        }
        return null;
    }

    /**
     * Force a shorter scope (than session scoped) for the ListDataModel by always resetting it before it is rendered
     * @return
     */
    public String getResetKeyValidatorsTrigger() {
        validatorItems = null;
        return StringUtils.EMPTY;
    }

    /**
     * Internal class for key validator items rendered as table.
     */
    public class ValidatorItem {

        private final int id;
        private final String name;
        private final String implementationLabel;

        /**
         * Creates a new instance.
         * @param id the id
         * @param name the name
         * @param implementationLabel the label of the imlementation
         */
        public ValidatorItem(final int id, final String name, final String implementationLabel) {
            this.id = id;
            this.implementationLabel = implementationLabel;
            this.name = name;
        }

        public int getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public String getLabel() {
            return implementationLabel;
        }
    }

    /**
     * Gets the available key validators taking into account access rules. The admin need access to view vlidators, and to all certificate profiles
     * referenced by the Validator.
     * @return ListDataModel<ValidatorItem>
     */
    public ListDataModel<ValidatorItem> getAvailableValidators() {
        if (validatorItems == null) {
            final List<ValidatorItem> items = new ArrayList<ValidatorItem>();
            final Collection<Integer> validatorIds = keyValidatorSession.getAuthorizedKeyValidatorIds(getAdmin(), AccessRulesConstants.REGULAR_VIEWVALIDATOR);
            for (Integer id : validatorIds) {
            	final Validator validator = keyValidatorSession.getValidator(id);
                final String accessRule = StandardRules.VALIDATORACCESS.resource() + validator.getProfileId();
                if (isAuthorizedTo(accessRule)) {
                    items.add(new ValidatorItem(id, validator.getProfileName() + " (" + validator.getLabel() + ")", validator.getLabel()));
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("User with token " + getAdmin().getUniqueId() + " is not authorized to access rule "
                                + StandardRules.VALIDATORACCESS.resource() + validator.getProfileName() + " ("+validator.getProfileId()+").");
                    }
                }
            }
            Collections.sort(items, new Comparator<ValidatorItem>() {
                @Override
                public int compare(ValidatorItem o1, ValidatorItem o2) {
                    return o1.getName().compareToIgnoreCase(o2.getName());
                }
            });
            validatorItems = new ListDataModel<ValidatorItem>(items);
           
        }

        return validatorItems;
    }

    /**
     * Checks if the administrator is authorized to view.
     * @return true if authorized.
     */
    public boolean isAuthorizedToView() {
        return isAuthorizedTo(StandardRules.VALIDATORVIEW.resource());
    }

    /**
     * Checks if the administrator is authorized to edit.
     * @return true if authorized.
     */
    public boolean isAuthorizedToEdit() {
        return isAuthorizedTo(StandardRules.VALIDATOREDIT.resource());
    }

    /**
     * Gets the view only flag.
     * @return true if view only.
     */
    public boolean getViewOnly() {
        return viewOnly;
    }

    /**
     * Edit action.
     * @return the navigation outcome defined in faces-config.xml.
     */
    public String actionEdit() {
        selectCurrentRowData();
        viewOnly = false;
        return "edit";
    }

    /**
     * View action.
     * @return the navigation outcome defined in faces-config.xml.
     */
    public String actionView() {
        selectCurrentRowData();
        viewOnly = true;
        return "view";
    }

    /**
     * Add action. Adds a new key validator.
     */
    public void actionAdd() {
        final String name = getKeyValidatorName();
        if (StringUtils.isNotBlank(name)) {
            try {
                keyValidatorSession.addKeyValidator(getAdmin(), new RsaKeyValidator(name));
                getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
                actionCancel();
            } catch (KeyValidatorExistsException e) {
                addErrorMessage("VALIDATORALREADY", name);
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        validatorItems = null;
    }

    /**
     * Selection changed event.
     */
    private void selectCurrentRowData() {
        final ValidatorItem item = (ValidatorItem) getAvailableValidators().getRowData();
        setSelectedKeyValidatorId(item.getId());
    }

    /**
     * Checks if a rename, delete or addFromTemplate action is in Progress.
     * @return true if action is in progress.
     */
    public boolean isOperationInProgress() {
        return isRenameInProgress() || isDeleteInProgress() || isAddFromTemplateInProgress();
    }

    /**
     * Checks if a addFromTemplate action is in Progress.
     * @return true if action is in progress.
     */
    public boolean isAddFromTemplateInProgress() {
        return addFromTemplateInProgress;
    }

    /**
     * AddFromTemplate action. 
     */
    public void actionAddFromTemplate() {
        selectCurrentRowData();
        addFromTemplateInProgress = true;
    }

    /**
     * AddFromTemplate confirm action. 
     */
    public void actionAddFromTemplateConfirm() {
        final String name = getKeyValidatorName();
        if (name.length() > 0) {
            try {
                keyValidatorSession.cloneKeyValidator(getAdmin(), getSelectedKeyValidatorId(), name);
                getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
                setKeyValidatorName(StringUtils.EMPTY);
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            } catch (KeyValidatorExistsException e) {
                addErrorMessage("VALIDATORALREADY", name);
            } catch (KeyValidatorDoesntExistsException e) {
                // NOPMD: ignore do nothing
            }
        }
        actionCancel();
    }

    /**
     * Checks if a delete action is in Progress.
     * @return true if action is in progress.
     */
    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }

    /**
     * Delete action.
     */
    public void actionDelete() {
        selectCurrentRowData();
        deleteInProgress = true;
    }

    /**
     * Delete confirm action.
     */
    public void actionDeleteConfirm() throws AuthorizationDeniedException, CouldNotRemoveKeyValidatorException {
        try {
            keyValidatorSession.removeKeyValidator(getAdmin(), getSelectedKeyValidatorId());
            keyValidatorSession.flushKeyValidatorCache();
            getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to remove key validator.");
        } catch (CouldNotRemoveKeyValidatorException e) {
            addErrorMessage("COULDNTDELETEVALIDATOR");
        }
        actionCancel();
    }

    /**
     * Checks if a rename action is in Progress.
     * @return true if action is in progress.
     */
    public boolean isRenameInProgress() {
        return renameInProgress;
    }

    /**
     * Rename action.
     */
    public void actionRename() {
        selectCurrentRowData();
        renameInProgress = true;
    }

    /**
     * Rename confirm action.
     */
    public void actionRenameConfirm() throws AuthorizationDeniedException {
        final String name = getKeyValidatorName();
        if (name.length() > 0) {
            try {
                keyValidatorSession.renameKeyValidator(getAdmin(), getSelectedKeyValidatorId(), name);
                getEjbcaWebBean().getInformationMemory().keyValidatorsEdited();
                setKeyValidatorName(StringUtils.EMPTY);
            } catch (KeyValidatorDoesntExistsException e) {
                addErrorMessage("VALIDATORDOESNOTEXIST", name);
            } catch (KeyValidatorExistsException e) {
                addErrorMessage("VALIDATORALREADY", name);
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage("Not authorized to rename key validator.");
            }
        }
        actionCancel();
    }

    /**
     * Cancel action.
     */
    public void actionCancel() {
        addFromTemplateInProgress = false;
        deleteInProgress = false;
        renameInProgress = false;
        validatorItems = null;
        selectedKeyValidatorId = null;
        keyValidatorName = null;
    }
    
    /**
     * Gets the selected key validator name.
     * @return the name.
     */
    public String getKeyValidatorName() {
        return keyValidatorName;
    }

    /**
     * Sets the selected key validator name.
     * @param name the name
     */
    public void setKeyValidatorName(String name) {
        name = name.trim();
        if (StringTools.checkFieldForLegalChars(name)) {
            addErrorMessage("ONLYCHARACTERS");
        } else {
            this.keyValidatorName = name;
        }
    }

}

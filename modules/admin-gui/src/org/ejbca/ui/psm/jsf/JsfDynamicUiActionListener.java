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
package org.ejbca.ui.psm.jsf;

import java.io.Serializable;

import javax.faces.application.FacesMessage;
import javax.faces.component.html.HtmlCommandButton;
import javax.faces.context.FacesContext;
import javax.faces.event.AbortProcessingException;
import javax.faces.event.ActionEvent;
import javax.faces.event.ActionListener;

import org.apache.log4j.Logger;
import org.cesecore.util.ui.DynamicUiActionCallback;
import org.cesecore.util.ui.DynamicUiCallbackException;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiModelException;
import org.cesecore.util.ui.DynamicUiProperty;

import com.keyfactor.CesecoreException;

/**
 * This MyFaces ActionListener implementation for {@link DynamicUiModel} delegates the event to 
 * the {@link DynamicUiActionCallback} associated with the dynamic UI property and renders the 
 * outcome on the view.
 * 
 * @version $Id$
 */
public class JsfDynamicUiActionListener implements Serializable, ActionListener {

    private static final long serialVersionUID = -1L;

	/** Class logger. */
    private static final Logger log = Logger.getLogger(JsfDynamicUiActionListener.class);

    /** DynamicUIProperty reference. */
    private DynamicUiProperty<?> dynamicUiProperty;

    /** Required by java.lang.Serializable */
    public JsfDynamicUiActionListener() {
    }

    /** 
     * Constructor with DynamicUiProperty reference.
     */
    public JsfDynamicUiActionListener(final DynamicUiProperty<?> dynamicUiProperty) {
        this.dynamicUiProperty = dynamicUiProperty;
    }

    @Override
    public void processAction(final ActionEvent event) throws AbortProcessingException {
        final HtmlCommandButton button = (HtmlCommandButton) event.getSource();
        if (log.isDebugEnabled()) {
            log.debug("Dynamic UI model action called: " + event + " by component " + button);
        }
        if (dynamicUiProperty.getActionCallback() != null) {
            try {
                dynamicUiProperty.getActionCallback().action(button.getValue());
                FacesContext.getCurrentInstance().renderResponse();
            } catch (DynamicUiCallbackException e) {
                log.info("Could not process dynamic UI model action callback: " + e.getMessage());
                FacesContext.getCurrentInstance().addMessage("error", new FacesMessage(FacesMessage.SEVERITY_INFO, e.getMessage(), e.getMessage()));
                // throw new AbortProcessingException(e);
                // -> Renders the message (no stack trace) on UI.
            } catch (CesecoreException e) {
                log.info("Could not process dynamic UI model action callback: " + e.getMessage());
                FacesContext.getCurrentInstance().addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), e.getMessage()));
            }
        } else {
            throw new AbortProcessingException(new DynamicUiModelException(
                    "Registered dynamic UI model action " + dynamicUiProperty.getName() + " does not have an action callback."));
        }
    }
}

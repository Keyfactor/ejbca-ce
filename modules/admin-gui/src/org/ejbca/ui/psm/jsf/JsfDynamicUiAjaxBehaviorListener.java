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

import javax.faces.component.UIInput;
import javax.faces.event.AbortProcessingException;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.event.AjaxBehaviorListener;

import org.apache.log4j.Logger;
import org.cesecore.util.ui.DynamicUiActionCallback;
import org.cesecore.util.ui.DynamicUiCallbackException;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiProperty;

import com.keyfactor.CesecoreException;

/**
 * This MyFaces AjaxBehaviorListener implementation for {@link DynamicUiModel} delegates the event to 
 * the {@link DynamicUiActionCallback} associated with the dynamic UI property and renders the 
 * outcome on the view.
 * 
 * @version $Id$
 */
public class JsfDynamicUiAjaxBehaviorListener implements Serializable, AjaxBehaviorListener {

    private static final long serialVersionUID = -1L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(JsfDynamicUiHtmlInputText.class);

    /** DynamicUIProperty reference. */
    private DynamicUiProperty<?> dynamicUiProperty;
    
    /** UI component reference. */
    private UIInput component;

    /** 
     * Constructor with DynamicUiProperty and UI component reference.
     */
    public JsfDynamicUiAjaxBehaviorListener(final DynamicUiProperty<?> dynamicUiProperty, final UIInput component) {
        this.dynamicUiProperty = dynamicUiProperty;
        this.component = component;
    }

    @Override
    public void processAjaxBehavior(AjaxBehaviorEvent event) throws AbortProcessingException {
    	if (log.isTraceEnabled()) {
            log.trace( "Call dynamic UI property AJAX action event: " + event);
        }
        try {
            dynamicUiProperty.getActionCallback().action(((UIInput) event.getSource()).getSubmittedValue());
        } catch (DynamicUiCallbackException | CesecoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not perform dynamic UI property action callback: " + component.getSubmittedValue(), e);
            }
        }
    }
}
/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util.ui;

import java.util.List;

import com.keyfactor.CesecoreException;

/**
 * Action callback from the PSM (may be JSF 2 (JsfDynamicUiPsmFactory) back to the PIM {@link DynamicUiModel}.
 * 
 * @version $Id$
 */
public interface DynamicUiActionCallback {

    /**
     * Action callback method.
     * @param paramter the given (in case of UIInput components)
     * @throws DynamicUiCallbackException any exception containing a message which has to be rendered on UI.
     * @throws CesecoreException 
     */
    void action(Object parameter) throws DynamicUiCallbackException, CesecoreException;
    
    /**
     * Gets the list of components of the same dialog to be updated.
     * @return the list of components to be updated or null if all components has to be updated.
     */
    List<String> getRender();
}

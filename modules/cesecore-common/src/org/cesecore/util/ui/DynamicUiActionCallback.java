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

/**
 * Action callback from the PSM (may be JSF 2 (JsfDynamicUiPsmFactory) back to the PIM {@link DynamicUiModel}.
 * 
 * @version $Id: DynamicUiActionCallback.java 25000 2017-12-25 12:28:24Z anjakobs $
 */
public interface DynamicUiActionCallback {

    /**
     * Action callback method.
     * @param paramter the given (in case of UIInput components)
     * @throws DynamicUiCallbackException any exception containing a message which has to be rendered on UI.
     */
    void action(Object parameter) throws DynamicUiCallbackException;
}

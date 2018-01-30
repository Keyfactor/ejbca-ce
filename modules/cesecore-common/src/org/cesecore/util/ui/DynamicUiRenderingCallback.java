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
 * Rendering callback from PIM to PSM (may be JSF 2 (JsfDynamicUiPsmFactory).
 * 
 * @version $Id: DynamicUiRenderingCallback.java 25500 2018-01-07 09:28:24Z anjakobs $
 */
public interface DynamicUiRenderingCallback {

    /**
     * The rendering callback method sets the components value to be rendered on UI.
     * @param value the given value (in case of UIOutput components).
     */
    void setValue(Object value);
}

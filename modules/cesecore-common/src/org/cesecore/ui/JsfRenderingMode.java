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

package org.cesecore.ui;

/**
 * Constants defining how a dynamic JSF component should be rendered.
 * Not all rendering modes are necessarily implemented by all components, 
 * meaning some components may render themselves in the same way in different
 * rendering modes.
 * @version $Id$
 */
public enum JsfRenderingMode {
    /**
     * The component is not visible in the UI.
     */
    Hidden,
    /**
     * The component is visible in the UI but the user cannot interact 
     * with it.
     */
    Disabled,
    /**
     * The component is visible and the user can change the data
     * encapsulated by the component.
     */
    Enabled,
    /**
     * The component is visible and the user can change the data
     * encapsulated by the component. Additionally, if such 
     * functionality is supported, it may render additional
     * JSF controls which allows the user to edit the component
     * itself, such as adding new radio buttons or change the way 
     * user input is validated.
     */
    Editable,
}

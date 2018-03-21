/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util.ui;

/**
 * Interface type for PSM components like check boxes, text fields, etc. for dynamic UI model.
 * 
 * @version $Id$
 *
 */
public interface DynamicUiComponent {

	/**
	 * Enables or disables the component.
	 * @param disabled
	 */
    void setDisabled(final boolean disabled);
}

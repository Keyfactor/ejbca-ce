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
 * Interface type for index dynamic UI model (i.e. to be rendered in a list).
 */
public interface IndexedDynamicUiModel {

    /**
     * Initializes the dynamic UI model for this domain object.
     * Sets the index (used as ID post fix appended with a hyphen '-').
     * 
     * @param index the index.
     */
    void initDynamicUiModel(int index);
    
}

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
 * Interface type for domain objects (or other objects) with dynamic UI model.
 * 
 * @version $Id: DynamicUiModelAware.java 26390 2017-11-04 15:20:58Z anjakobs $
 *
 */
public interface DynamicUiModelAware {

    /**
     * Initializes the dynamic UI model for this domain object.
     */
    void initDynamicUiModel();
    
    /**
     * Gets the dynamic UI model.
     * @return the object.
     */
    DynamicUiModel getDynamicUiModel();
}

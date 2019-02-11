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

import java.io.Serializable;

/**
 * Representation of a URL String for use with DynamicUiProperty.
 * 
 * Since the type of DynamicUiProperty determines how it should be rendered, 
 * this class is needed as a distinction from a regular String.
 * 
 * @version $Id$
 */
public class UrlString implements Serializable {

    private static final long serialVersionUID = 1L;
    private String value;
    
    public UrlString(final String value) {
        this.value = value;
    }
    
    public String getValue() {
        return value;
    }

    public void setValue(final String value) {
        this.value = value;
    }
}

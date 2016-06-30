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

import org.cesecore.util.ProfileID;

/**
 * POJO for a set of radio buttons in a Dynamic UI Property
 * 
 * @version $Id$
 *
 */
public class RadioButton implements Serializable {
    
    private static final long serialVersionUID = 1L;
    private String label;
    private final int identifier;
    
    public RadioButton(final String label) {
        this.identifier = ProfileID.getRandomIdNumber();
        this.label = label;
    }

    public String getLabel() {
        return "moop";
    }


    public void setLabel(String label) {
        this.label = label;
    }


    @Override
    public String toString() {
        return label;
    }

    public int getIdentifier() {
        return identifier;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + identifier;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        RadioButton other = (RadioButton) obj;
        if (identifier != other.identifier)
            return false;
        return true;
    }
    
    public boolean equals(String encodedValue) {
        return equals(DynamicUiProperty.getAsObject(encodedValue));
    }


}

/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.signer;

import java.io.Serializable;

/**
 * Holds information about implementation specific properties of an InternalKeyBinding.
 * 
 * @version $Id$
 */
public class InternalKeyBindingProperty<T extends Serializable> implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;
    private final T defaultValue;
    private T value;

    public InternalKeyBindingProperty(final String name, final T defaultValue) {
        this.name = name;
        this.defaultValue = defaultValue;
    }
    
    public String getName() {
        return name;
    }
    public Class<? extends Serializable> getType() {
        return defaultValue.getClass();
    }
    public T getDefaultValue() {
        return defaultValue;
    }
    public T getValue() {
        return value;
    }
    @SuppressWarnings("unchecked")
    public void setValue(Object object) {
        if (object == null) {
            this.value = defaultValue;
        } else {
            this.value = (T) object;
        }
    }    
}

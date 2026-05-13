/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.approval;

import java.io.Serial;
import java.io.Serializable;

public abstract class DummyAllowedSerializableClass implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private long someValue;

    public DummyAllowedSerializableClass() {
        someValue = System.currentTimeMillis();
    }

    public long getSomeValue() {
        return someValue;
    }

    public void setSomeValue(long someValue) {
        this.someValue = someValue;
    }

    public boolean equals(Object obj) {
        return obj != null &&
                obj.getClass().equals(getClass()) &&
                someValue == ((DummyAllowedSerializableClass)obj).someValue;
    }

    public int hashCode() {
        return (int)someValue;
    }

    public String toString() {
        return "DummyAllowedSerializableClass: " + someValue;
    }
}

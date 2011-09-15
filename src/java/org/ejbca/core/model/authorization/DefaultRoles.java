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
package org.ejbca.core.model.authorization;


/**
 * Represents a set of predefined roles.
 * 
 * 
 * @version $Id$
 * 
 */
public enum DefaultRoles {
    SUPERADMINISTRATOR(1, "SUPERADMINISTRATOR"), 
    CAADMINISTRATOR(2, "CAADMINISTRATOR"), 
    RAADMINISTRATOR(3, "RAADMINISTRATOR"), 
    SUPERVISOR(4, "SUPERVISOR"), 
    HARDTOKENISSUER(5, "HARDTOKENISSUER");

    private int numericalValue;
    private String name;

    private DefaultRoles(int numericalValue, String name) {
        this.numericalValue = numericalValue;
        this.name = name;
    }

    public int getNumericalValue() {
        return numericalValue;
    }

    public String getName() {
        return name;
    }
    
}

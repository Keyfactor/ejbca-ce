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

/**
 * Authorization Rules for InternalKeyBindings.
 * 
 * @version $Id$
 */
public enum InternalKeyBindingRules {
    BASE("/internalkeybinding"),
    DELETE(BASE.resource() + "/delete"),
    MODIFY(BASE.resource() + "/modify"),
    VIEW(BASE.resource() + "/view"),
    ;

    private final String resource;
    
    private InternalKeyBindingRules(String resource) {
        this.resource = resource;
    }

    public String resource() {
        return this.resource;
    }

    public String toString() {
        return this.resource;
    }
}

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
package org.cesecore.authorization.control;

/**
 * CryptoToken related access rules.
 * 
 * @version $Id$
 */
public enum CryptoTokenRules {
    BASE("/cryptotoken"),
    MODIFY_CRYPTOTOKEN(BASE.resource() + "/modify"),
    DELETE_CRYPTOTOKEN(BASE.resource() + "/delete"),
    VIEW(BASE.resource() + "/view"),
    USE(BASE.resource() + "/use"),
    ACTIVATE(BASE.resource() + "/activate"),
    DEACTIVATE(BASE.resource() + "/deactivate"),
    GENERATE_KEYS(BASE.resource() + "/keys/generate"),
    REMOVE_KEYS(BASE.resource() + "/keys/remove"),
    TEST_KEYS(BASE.resource() + "/keys/test"),
    ;

    private final String resource;
    
    private CryptoTokenRules(String resource) {
        this.resource = resource;
    }

    public String resource() {
        return this.resource;
    }

    public String toString() {
        return this.resource;
    }
}

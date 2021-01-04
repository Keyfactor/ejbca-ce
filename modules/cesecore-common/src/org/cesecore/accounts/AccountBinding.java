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
package org.cesecore.accounts;

import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.profiles.Profile;

/**
 * Base interface for all account bindings. 
 */
public interface AccountBinding extends Profile, Cloneable {

    static final String TYPE_NAME = "ACCOUNT_BINDING";
    
    /**
     * Initializes the account binding. Called from the constructor.
     */
    void init();
    
    /**
     * Verifies the external account identifier.
     * 
     * @return true if the account binding identifier could be verified (i.e. with symmetric encryption or asymmetric signature).
     * @throws AccountBindingException if the verification fails.
     */
    boolean verify() throws AccountBindingException;
    
    /**
     * Returns the backing data hash map.
     * @return the map.
     */
    UpgradeableDataHashMap getUpgradableHashmap();
    
    /**
     * Returns the sub type of this account binding
     * @return the sub type or null.
     */
    Class<? extends AccountBinding> getAccountBindingSubType();
    
    /**
     * Returns the account binding identifier type.
     * @return type of account binding, e.g. "ACME_EAB_RFC_COMPLIANT"
     */
    String getAccountBindingTypeIdentifier();
    
    /**
     * @return the type as a human readable name.
     */
    String getLabel();
}

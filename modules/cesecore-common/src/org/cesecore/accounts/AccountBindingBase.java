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

import java.io.Serializable;

import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.profiles.ProfileBase;

/**
 * Base class for all account binding strategy objects. 
 */
public abstract class AccountBindingBase extends ProfileBase implements Serializable, Cloneable, AccountBinding {

    private static final long serialVersionUID = -971069235766052280L;
    
    /** Class logger. */
    private static final Logger log = Logger.getLogger(AccountBindingBase.class);

    /** Message resources. */
    protected static final InternalResources intres = InternalResources.getInstance();

    /**
     * Default constructor.
     */
    public AccountBindingBase() {
        super();
        init();
    }
    
    @Override
    public String getProfileType() {
        return AccountBinding.TYPE_NAME;
    }
    
    @Override
    public void initialize() {
        data.put(PROFILE_TYPE, getImplementationClass().getName()); 
    }
    
    @Override
    public void init() {
        initialize();
        if (null == data.get(VERSION)) {
            data.put(VERSION, LATEST_VERSION);
        }
    }
    
    @Override
    public abstract boolean verify() throws AccountBindingException;
    
    @Override
    public float getLatestVersion(){
        return LATEST_VERSION;
    }
    
    @Override
    public void upgrade() {
        if (log.isTraceEnabled()) {
            log.trace(">upgrade: " + getLatestVersion() + ", " + getVersion());
        }
        super.upgrade();
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade.
            log.info(intres.getLocalizedMessage("accountbinding.upgrade", getVersion()));
            init();
            // Finished upgrade, set new version
            data.put(VERSION, LATEST_VERSION);
        }
    }
    
    @Override
    protected void saveTransientObjects() {
    }

    @Override
    protected void loadTransientObjects() {
    }
    
    @Override
    public UpgradeableDataHashMap getUpgradableHashmap() {
        return this;
    }

}

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
 
package org.ejbca.core.model.hardtoken.types;

import java.io.Serializable;

import org.ejbca.core.model.UpgradeableDataHashMap;



/**
 * HardToken is a base class that all HardToken classes is supposed to inherit.  It function is to
 * define the data the token is supposed contain.
 *
 * @author TomSelleck
 * @version $Id: HardToken.java,v 1.1 2006-01-17 20:31:52 anatom Exp $
 */
public abstract class HardToken extends UpgradeableDataHashMap implements Serializable, Cloneable {
    // Default Values
    public static final float LATEST_VERSION = 0;
    public static final String TOKENTYPE = "TOKENTYPE";

    
    public static final String TOKENPROFILE = "TOKENPROFILE";
    // Protexted Constants, must be overloaded by all deriving classes.
    public String[] FIELDS;
    public int[] DATATYPES;
    public String[] FIELDTEXTS;

    // Public Constants.

    /* Constants used to define how the stored data should be represented in the web-gui.*/
    public static final int INTEGER = 0;
    public static final int LONG = 1;
    public static final int STRING = 2;
    public static final int BOOLEAN = 3;
    public static final int DATE = 4;
    public static final int EMPTYROW = 5;
    public static final String EMPTYROW_FIELD = "EMTPYROW";



    
    // Public Methods
    public Object getField(String field) {
        return data.get(field);
    }
    	
	public abstract int getNumberOfFields() ;

	public abstract String getFieldText(int index); 

	public abstract String getFieldPointer(int index);

	public abstract int getFieldDataType(int index);

    public void setField(String field, Object value) {
        data.put(field, value);
    }

    
    public int getTokenProfileId() {
    	if(data.get(HardToken.TOKENPROFILE) == null)
    		return 0;
    	
        return ((Integer) data.get(HardToken.TOKENPROFILE)).intValue();
    }
    
	public void setTokenProfileId(int hardtokenprofileid) {
	  data.put(HardToken.TOKENPROFILE, new Integer(hardtokenprofileid));
	}


    /**
     * Implemtation of UpgradableDataHashMap function getLatestVersion
     *
     */
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /**
     * Implemtation of UpgradableDataHashMap function upgrade.
     */
    public void upgrade() {
    }
}

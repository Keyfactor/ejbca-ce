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
 
package org.ejbca.core.model.hardtoken.types;

import java.io.Serializable;

import org.cesecore.internal.UpgradeableDataHashMap;
import org.ejbca.core.model.hardtoken.HardTokenConstants;



/**
 * HardToken is a base class that all HardToken classes is supposed to inherit.  It function is to
 * define the data the token is supposed contain.
 *
 * @author TomSelleck
 * @version $Id$
 */
public abstract class HardToken extends UpgradeableDataHashMap implements Serializable, Cloneable {
    private static final long serialVersionUID = 3354480892183271060L;
    // Default Values
    public static final float LATEST_VERSION = 0;
    public static final String TOKENTYPE = "TOKENTYPE";
    
	public static final String LABEL_REGULARCARD   = HardTokenConstants.LABEL_REGULARCARD;	//"LABEL_REGULARCARD";
	public static final String LABEL_TEMPORARYCARD = HardTokenConstants.LABEL_TEMPORARYCARD;	//"LABEL_TEMPORARYCARD";
	public static final String LABEL_PROJECTCARD   = HardTokenConstants.LABEL_PROJECTCARD;	//"LABEL_PROJECTCARD";

    
    public static final String TOKENPROFILE = "TOKENPROFILE";
    public static final String LABEL        = "LABEL";

    protected boolean includePUK = true;
    
    // Public Constants.

    /* Constants used to define how the stored data should be represented in the web-gui.*/
    public static final int INTEGER = 0;
    public static final int LONG = 1;
    public static final int STRING = 2;
    public static final int BOOLEAN = 3;
    public static final int DATE = 4;
    public static final int EMPTYROW = 5;
    public static final String EMPTYROW_FIELD = "EMTPYROW";

    public HardToken(boolean includePUK){
    	this.includePUK = includePUK;
    }
    
    // Public Methods
    public Object getField(String field) {
        return data.get(field);
    }
    	
    public abstract String[] getFields(boolean includePUK);
    public abstract int[] getDataTypes(boolean includePUK);
    public abstract String[] getFieldTexts(boolean includePUK);
    
    public int getNumberOfFields() {
    	return getFields(includePUK).length;
    }

    public String getFieldText(int index) {
    	return getFieldTexts(includePUK)[index];
    }

    public String getFieldPointer(int index) {
    	return getFields(includePUK)[index];
    }


    public int getFieldDataType(int index) {
    	return getDataTypes(includePUK)[index];
    }
		

    public void setField(String field, Object value) {
        data.put(field, value);
    }

    
    public int getTokenProfileId() {
    	if(data.get(HardToken.TOKENPROFILE) == null) {
    		return 0;
    	}
        return ((Integer) data.get(HardToken.TOKENPROFILE)).intValue();
    }
    
	public void setTokenProfileId(int hardtokenprofileid) {
	  data.put(HardToken.TOKENPROFILE, Integer.valueOf(hardtokenprofileid));
	}
	
	/**
	 * 
	 * @return one of the LABEL_ constants or null of no label is set.
	 */
    public String getLabel() {    	
        return (String) data.get(HardToken.LABEL);
    }

    /**
     * 
     * @param hardTokenLabel should be one of the LABEL_ constants
     */
	public void setLabel(String hardTokenLabel) {
		  data.put(HardToken.LABEL, hardTokenLabel);
	}

    /**
     * Implementation of UpgradableDataHashMap function getLatestVersion
     *
     */
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /**
     * Implementation of UpgradableDataHashMap function upgrade.
     */
    public void upgrade() {
    }
    

}

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

import org.ejbca.core.model.SecConst;



/**
 * TurkishEIDHardToken is a class defining data stored in database for a Turkish EID token.
 *
 * @version $Id$
 */
public class TurkishEIDHardToken extends HardToken {
    private static final long serialVersionUID = -8771180471734319021L;

    // Public Constants
	public static final int THIS_TOKENTYPE = SecConst.TOKEN_TURKISHEID;
	
    public static final String INITIALPIN   = "INITIALPIN";
    public static final String PUK           = "PUK";
       
    
    public static final String[] FIELDSWITHPUK = {
    	INITIALPIN, PUK, EMPTYROW_FIELD
    };
    public static final int[] DATATYPESWITHPUK = { STRING, STRING, EMPTYROW};
    public static final String[] FIELDTEXTSWITHPUK = {
        INITIALPIN, PUK, EMPTYROW_FIELD
    };
    public static final String[] FIELDSWITHOUTPUK =new String[] {};
    public static final int[] DATATYPESWITHOUTPUK = new int[] {};
    public static final String[] FIELDTEXTSWITHOUTPUK = new String[] {};

    // Public Methods
    /** Constructor to use. */
    public TurkishEIDHardToken(String initialpin,
                               String puk,
                               int hardtokenprofileid) {
    	super(true);
        setInitialPIN(initialpin);
        setPUK(puk);

        setTokenProfileId(hardtokenprofileid);        
        
        data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
    } 
    
    /** Constructor only to be used internally. */
    public TurkishEIDHardToken(boolean includePUK) {
    	super(includePUK);
    	if(!includePUK){
      	  setInitialPIN("");
      	  setPUK("");
      	}
    	data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
    }



    
    // Public Methods.
    public String getInitialPIN() {
        return (String) data.get(INITIALPIN);
    }

    public void setInitialPIN(String initialpin) {
        data.put(INITIALPIN, initialpin);
    }
    

    public String getPUK() {
        return (String) data.get(PUK);
    }

    public void setPUK(String puk) {
        data.put(PUK, puk);
    }



	public int[] getDataTypes(boolean includePUK) {
		if(includePUK){
			return DATATYPESWITHPUK;	
		}
		return DATATYPESWITHOUTPUK;
	}

	public String[] getFieldTexts(boolean includePUK) {
		if(includePUK){
			return FIELDTEXTSWITHPUK;	
		}
		return FIELDTEXTSWITHOUTPUK;
	}

	public String[] getFields(boolean includePUK) {
		if(includePUK){
			return FIELDSWITHPUK;	
		}
		return FIELDSWITHOUTPUK;
	}
    

 
}

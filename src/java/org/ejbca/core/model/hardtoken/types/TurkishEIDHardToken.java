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

import org.ejbca.core.model.SecConst;



/**
 * TurkishEIDHardToken is a class defining data stored in database for a Turkish EID token.
 *
 * @version $Id: TurkishEIDHardToken.java,v 1.2 2006-11-11 12:46:04 herrvendil Exp $
 */
public class TurkishEIDHardToken extends HardToken {
    // Public Constants
	public static final int THIS_TOKENTYPE = SecConst.TOKEN_TURKISHEID;
	
    public static final String INITIALPIN   = "INITIALPIN";
    public static final String PUK           = "PUK";
       
    
    public static final String[] FIELDS = {
    	INITIALPIN, PUK, EMPTYROW_FIELD
    };
    public static final int[] DATATYPES = { STRING, STRING, EMPTYROW};
    public static final String[] FIELDTEXTS = {
        INITIALPIN, PUK, EMPTYROW_FIELD
    };

    // Public Methods
    /** Constructor to use. */
    public TurkishEIDHardToken(String initialpin,
                               String puk,
                               int hardtokenprofileid) {
        setInitialPIN(initialpin);
        setPUK(puk);

        setTokenProfileId(hardtokenprofileid);        
        
        data.put(TOKENTYPE, new Integer(THIS_TOKENTYPE));
    } 
    
    /** Constructor only to be used internally. */
    public TurkishEIDHardToken() {    	
    	data.put(TOKENTYPE, new Integer(THIS_TOKENTYPE));
    }


    public int getNumberOfFields() {
    	return TurkishEIDHardToken.FIELDS.length;
    }

    public String getFieldText(int index) {
    	return TurkishEIDHardToken.FIELDTEXTS[index];
    }

    public String getFieldPointer(int index) {
    	return TurkishEIDHardToken.FIELDS[index];
    }


    public int getFieldDataType(int index) {
    	return TurkishEIDHardToken.DATATYPES[index];
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
    

 
}

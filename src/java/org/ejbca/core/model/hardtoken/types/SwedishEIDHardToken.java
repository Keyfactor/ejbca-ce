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
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;



/**
 * SwedishEIDHardToken is a class defining data stored in database for a Swedish EID token.
 *
 * @version $Id: SwedishEIDHardToken.java,v 1.2 2006-09-17 23:02:22 herrvendil Exp $
 */
public class SwedishEIDHardToken extends HardToken {
    // Public Constants
	public static final int THIS_TOKENTYPE = SecConst.TOKEN_SWEDISHEID;
	
    public static final String INITIALAUTHENCPIN   = "INITIALAUTHENCPIN";
    public static final String AUTHENCPUK          = "AUTHENCPUK";
    public static final String INITIALSIGNATUREPIN = "INITIALSIGNATUREPIN";
    public static final String SIGNATUREPUK        = "SIGNATUREPUK";   
    
    public static String[] FIELDS = null;
    public static int[] DATATYPES = null;
    public static String[] FIELDTEXTS = null;
    
    static {
    	if(GlobalConfiguration.HARDTOKEN_DIPLAYSENSITIVEINFO){
    		FIELDS = new String[] {INITIALAUTHENCPIN, AUTHENCPUK, EMPTYROW_FIELD, INITIALSIGNATUREPIN, SIGNATUREPUK};
    		DATATYPES = new int[] { STRING, STRING, EMPTYROW, STRING, STRING };
    		FIELDTEXTS = new String[] { INITIALAUTHENCPIN, AUTHENCPUK, EMPTYROW_FIELD, INITIALSIGNATUREPIN, SIGNATUREPUK};   
    	}else{
    		FIELDS = new String[] {};
    		DATATYPES = new int[] {};
    	    FIELDTEXTS = new String[] {};    	 
    	}
    }


    // Public Methods
    /** Constructor to use. */
    public SwedishEIDHardToken(String initialauthencpin,
                               String authencpuk,
                               String initialsignaturepin,
                               String signaturepuk,
                               int hardtokenprofileid) {
        setInitialAuthEncPIN(initialauthencpin);
        setAuthEncPUK(authencpuk);
        setInitialSignaturePIN(initialsignaturepin);
        setSignaturePUK(signaturepuk);
        setTokenProfileId(hardtokenprofileid);        
        
        data.put(TOKENTYPE, new Integer(THIS_TOKENTYPE));
    } 
    
    /** Constructor only to be used internally. */
    public SwedishEIDHardToken() {    	
    	data.put(TOKENTYPE, new Integer(THIS_TOKENTYPE));
    }


    public int getNumberOfFields() {
    	return SwedishEIDHardToken.FIELDS.length;
    }

    public String getFieldText(int index) {
    	return SwedishEIDHardToken.FIELDTEXTS[index];
    }

    public String getFieldPointer(int index) {
    	return SwedishEIDHardToken.FIELDS[index];
    }


    public int getFieldDataType(int index) {
    	return SwedishEIDHardToken.DATATYPES[index];
    }
    
    // Public Methods.
    public String getInitialAuthEncPIN() {
        return (String) data.get(INITIALAUTHENCPIN);
    }

    public void setInitialAuthEncPIN(String initialbasicpin) {
        data.put(INITIALAUTHENCPIN, initialbasicpin);
    }
    

    public String getAuthEncPUK() {
        return (String) data.get(AUTHENCPUK);
    }

    public void setAuthEncPUK(String basicpuk) {
        data.put(AUTHENCPUK, basicpuk);
    }
    

    public String getInitialSignaturePIN() {
        return (String) data.get(INITIALSIGNATUREPIN);
    }

    public void setInitialSignaturePIN(String initialsignaturepin) {
        data.put(INITIALSIGNATUREPIN, initialsignaturepin);
    }
    


    public String getSignaturePUK() {
        return (String) data.get(SIGNATUREPUK);
    }

    public void setSignaturePUK(String signaturepuk) {
        data.put(SIGNATUREPUK, signaturepuk);
    }

    // Private fields.
}

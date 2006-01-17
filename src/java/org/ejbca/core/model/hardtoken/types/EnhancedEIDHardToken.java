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
 * EnhancedEIDHardToken is a class defining data stored in database for a Enhanced EID token.
 *
 * @version $Id: EnhancedEIDHardToken.java,v 1.1 2006-01-17 20:31:52 anatom Exp $
 */
public class EnhancedEIDHardToken extends HardToken {
    // Public Constants
	public static final int THIS_TOKENTYPE  = SecConst.TOKEN_ENHANCEDEID;
    public static final String INITIALSIGNATUREPIN = "INITIALSIGNATUREPIN";
    public static final String SIGNATUREPUK        = "SIGNATUREPUK";
	public static final String INITIALAUTHPIN      = "INITIALAUTHPIN";
	public static final String AUTHPUK             = "AUTHPUK";
	public static final String INITIALENCPIN       = "INITIALENCPIN";
	public static final String ENCPUK              = "ENCPUK";
	public static final String ENCKEYRECOVERABLE   = "ENCKEYRECOVERABLE";
		    
    public static final String[] FIELDS = {
		INITIALSIGNATUREPIN, SIGNATUREPUK, EMPTYROW_FIELD, INITIALAUTHPIN, AUTHPUK, 
		EMPTYROW_FIELD, INITIALENCPIN, ENCPUK, ENCKEYRECOVERABLE 
    };
    public static final int[] DATATYPES = { STRING, STRING, EMPTYROW, 
    	                                    STRING, STRING, EMPTYROW, 
    	                                    STRING, STRING, BOOLEAN };
    public static final String[] FIELDTEXTS = {
		INITIALSIGNATUREPIN, SIGNATUREPUK, EMPTYROW_FIELD, 
		INITIALAUTHPIN, AUTHPUK, EMPTYROW_FIELD,
		INITIALENCPIN, ENCPUK, ENCKEYRECOVERABLE 
    };

    // Public Methods
   /** Constructor to use. */
    public EnhancedEIDHardToken(String initialsignaturepin,
                                String signaturepuk,
	                            String initialauthpin,
								String authpuk,
	                            String initialencpin,
								String encpuk,
								boolean enckeyrecoverable, 
                                int hardtokenprofileid) {
        setInitialSignaturePIN(initialsignaturepin);
		setSignaturePUK(signaturepuk);
        setInitialAuthPIN(initialauthpin);
        setAuthPUK(authpuk);
		setInitialEncPIN(initialencpin);
		setEncPUK(encpuk);
		setEncKeyRecoverable(enckeyrecoverable);
        setTokenProfileId(hardtokenprofileid);     
        
        data.put(TOKENTYPE, new Integer(THIS_TOKENTYPE));
    }

    /** Constructor only to be used internally. */
    public EnhancedEIDHardToken() {    	
    	data.put(TOKENTYPE, new Integer(THIS_TOKENTYPE));
    }

    public int getNumberOfFields() {
    	return EnhancedEIDHardToken.FIELDS.length;
    }

    public String getFieldText(int index) {
    	return EnhancedEIDHardToken.FIELDTEXTS[index];
    }

    public String getFieldPointer(int index) {
    	return EnhancedEIDHardToken.FIELDS[index];
    }


    public int getFieldDataType(int index) {
    	return EnhancedEIDHardToken.DATATYPES[index];
    }    
    
    // Public Methods.
    
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
    
	public String getInitialAuthPIN() {
		return (String) data.get(INITIALAUTHPIN);
	}

	public void setInitialAuthPIN(String initialauthpin) {
		data.put(INITIALAUTHPIN, initialauthpin);
	}
    

	public String getAuthPUK() {
		return (String) data.get(AUTHPUK);
	}

	public void setAuthPUK(String authpuk) {
		data.put(AUTHPUK, authpuk);
	}

	public String getInitialEncPIN() {
		return (String) data.get(INITIALENCPIN);
	}

	public void setInitialEncPIN(String initialencpin) {
		data.put(INITIALENCPIN, initialencpin);
	}
    

	public String getEncPUK() {
		return (String) data.get(ENCPUK);
	}

	public void setEncPUK(String encpuk) {
		data.put(ENCPUK, encpuk);
	}
	
	public boolean getEncKeyRecoverable() {
		return ((Boolean) data.get(ENCKEYRECOVERABLE)).booleanValue();
	}

	public void setEncKeyRecoverable(boolean enckeyrecoverable) {
		data.put(ENCKEYRECOVERABLE, new Boolean(enckeyrecoverable));
	}
	   
    // Private fields.
}

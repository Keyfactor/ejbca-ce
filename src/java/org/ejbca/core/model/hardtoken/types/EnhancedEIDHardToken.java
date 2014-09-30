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
 * EnhancedEIDHardToken is a class defining data stored in database for a Enhanced EID token.
 *
 * @version $Id$
 */
public class EnhancedEIDHardToken extends HardToken {
    private static final long serialVersionUID = 9043768992711957547L;
    // Public Constants
	public static final int THIS_TOKENTYPE  = SecConst.TOKEN_ENHANCEDEID;
    public static final String INITIALSIGNATUREPIN = "INITIALSIGNATUREPIN";
    public static final String SIGNATUREPUK        = "SIGNATUREPUK";
	public static final String INITIALAUTHPIN      = "INITIALAUTHPIN";
	public static final String AUTHPUK             = "AUTHPUK";
	public static final String ENCKEYRECOVERABLE   = "ENCKEYRECOVERABLE";
		        
    public static final String[] FIELDSWITHPUK = new String[] {
		INITIALSIGNATUREPIN, SIGNATUREPUK, EMPTYROW_FIELD, INITIALAUTHPIN, AUTHPUK, 
		EMPTYROW_FIELD, ENCKEYRECOVERABLE};
    public static final int[] DATATYPESWITHPUK = new int[] { STRING, STRING, EMPTYROW, 
                                                             STRING, STRING, EMPTYROW, BOOLEAN };
    public static final String[] FIELDTEXTSWITHPUK = new String[] {
		"INITIALSIGNATUREPIN", "SIGNATUREPUK", EMPTYROW_FIELD, 
		"INITIALAUTHENCPIN", "AUTHENCPUK", EMPTYROW_FIELD, ENCKEYRECOVERABLE 
    };
    
    public static final String[] FIELDSWITHOUTPUK = new String[] {ENCKEYRECOVERABLE};
    public static final int[] DATATYPESWITHOUTPUK = new int[] {BOOLEAN};
    public static final String[] FIELDTEXTSWITHOUTPUK = new String[] {ENCKEYRECOVERABLE}; 
        
    // Public Methods
   /** Constructor to use. */
    public EnhancedEIDHardToken(String initialsignaturepin,
                                String signaturepuk,
	                            String initialauthencpin,
								String authencpuk,
								boolean enckeyrecoverable, 
                                int hardtokenprofileid) {
    	super(true);
        setInitialSignaturePIN(initialsignaturepin);
		setSignaturePUK(signaturepuk);
        setInitialAuthPIN(initialauthencpin);
        setAuthPUK(authencpuk);
		setEncKeyRecoverable(enckeyrecoverable);
        setTokenProfileId(hardtokenprofileid);     
        
        data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
    }

    /** Constructor only to be used internally. */
    public EnhancedEIDHardToken(boolean includePUK) {
    	super(includePUK);   	
    	data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
    	if(!includePUK){
      	  setInitialAuthPIN("");
      	  setAuthPUK("");
      	  setInitialSignaturePIN("");
      	  setSignaturePUK("");
      	}
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

	
	public boolean getEncKeyRecoverable() {
		return ((Boolean) data.get(ENCKEYRECOVERABLE)).booleanValue();
	}

	public void setEncKeyRecoverable(boolean enckeyrecoverable) {
		data.put(ENCKEYRECOVERABLE, Boolean.valueOf(enckeyrecoverable));
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
	   
    // Private fields.
}

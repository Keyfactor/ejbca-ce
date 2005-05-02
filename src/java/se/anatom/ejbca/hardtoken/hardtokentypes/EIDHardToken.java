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
 
package se.anatom.ejbca.hardtoken.hardtokentypes;

import se.anatom.ejbca.SecConst;


/**
 *  EIDHardToken is a class defining data stored in database for a EID token.
 *  
 *  OBSERVE This class should only be used for backward compability with EJBCA 2.0 
 * @version $Id$
 */
public class EIDHardToken extends HardToken {
    // Public Constants
    public static final String INITIALBASICPIN = "INITIALBASICPIN";
    public static final String BASICPUK = "BASICPUK";
    public static final String INITIALSIGNATUREPIN = "INITIALSIGNATUREPIN";
    public static final String SIGNATUREPUK = "SIGNATUREPUK";
    public static final int THIS_TOKENTYPE = SecConst.TOKEN_EID;
    public static final String[] FIELDS = {
        INITIALBASICPIN, BASICPUK, EMPTYROW_FIELD, INITIALSIGNATUREPIN, SIGNATUREPUK
    };
    public static final int[] DATATYPES = { STRING, STRING, EMPTYROW, STRING, STRING };
    public static final String[] FIELDTEXTS = {
        INITIALBASICPIN, BASICPUK, EMPTYROW_FIELD, INITIALSIGNATUREPIN, SIGNATUREPUK
    };

    // Public Methods

    /**
     * Creates a certificate with the characteristics of an end user.
     */
    public EIDHardToken() {
        setInitialBasicPIN("");
        setBasicPUK("");
        setInitialSignaturePIN("");
        setSignaturePUK("");

        data.put(TOKENTYPE, new Integer(THIS_TOKENTYPE));
    }

    // Public Overloaded Methods.
    public int getNumberOfFields() {
        return EIDHardToken.FIELDS.length;
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getFieldText(int index) {
        return EIDHardToken.FIELDTEXTS[index];
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getFieldPointer(int index) {
        return EIDHardToken.FIELDS[index];
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getFieldDataType(int index) {
        return EIDHardToken.DATATYPES[index];
    }

    // Public Methods.
    public String getInitialBasicPIN() {
        return (String) data.get(INITIALBASICPIN);
    }

    /**
     * DOCUMENT ME!
     *
     * @param initialbasicpin DOCUMENT ME!
     */
    public void setInitialBasicPIN(String initialbasicpin) {
        data.put(INITIALBASICPIN, initialbasicpin);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getBasicPUK() {
        return (String) data.get(BASICPUK);
    }

    /**
     * DOCUMENT ME!
     *
     * @param basicpuk DOCUMENT ME!
     */
    public void setBasicPUK(String basicpuk) {
        data.put(BASICPUK, basicpuk);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getInitialSignaturePIN() {
        return (String) data.get(INITIALSIGNATUREPIN);
    }

    /**
     * DOCUMENT ME!
     *
     * @param initialsignaturepin DOCUMENT ME!
     */
    public void setInitialSignaturePIN(String initialsignaturepin) {
        data.put(INITIALSIGNATUREPIN, initialsignaturepin);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSignaturePUK() {
        return (String) data.get(SIGNATUREPUK);
    }

    /**
     * DOCUMENT ME!
     *
     * @param signaturepuk DOCUMENT ME!
     */
    public void setSignaturePUK(String signaturepuk) {
        data.put(SIGNATUREPUK, signaturepuk);
    }

    // Private fields.
}

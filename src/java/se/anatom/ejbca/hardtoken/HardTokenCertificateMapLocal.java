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
 
package se.anatom.ejbca.hardtoken;


/**
 * For docs, see HardTokenCertificateMapBean
 *
 * @version $Id: HardTokenCertificateMapLocal.java,v 1.6 2004-04-16 07:38:56 anatom Exp $
 **/

public interface HardTokenCertificateMapLocal extends javax.ejb.EJBLocalObject {

    // Public methods
    public String getCertificateFingerprint();    
    public String getTokenSN();
    public void setTokenSN(String tokenSN);
}


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

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing certificates placed on a token.
 * Information stored:
 * <pre>
 *  certificatefingerprint 
 *  tokensn 
 * </pre>
 *
 * @version $Id: HardTokenCertificateMapBean.java,v 1.11 2004-04-16 07:38:56 anatom Exp $
 */
public abstract class HardTokenCertificateMapBean extends BaseEntityBean {

    private static Logger log = Logger.getLogger(HardTokenCertificateMapBean.class);

    public abstract String getCertificateFingerprint();
    public abstract void setCertificateFingerprint(String certificateFingerprint);   
        
    public abstract String getTokenSN();
    public abstract void setTokenSN(String tokenSN);

     
    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of a certificate to hard token relation.
     *
     * @return null
     *
     **/

    public String ejbCreate(String certificateFingerprint, String tokenSN) throws CreateException {        
        setCertificateFingerprint(certificateFingerprint);   
        setTokenSN(tokenSN);
        
        log.debug("Created HardTokenCertificateMap for token SN: "+ tokenSN );
        return certificateFingerprint;
    }

    public void ejbPostCreate(String certificateFingerprint, String tokenSN) {
        // Do nothing. Required.
    }
}

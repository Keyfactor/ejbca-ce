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
 
package org.ejbca.core.ejb.ca.store;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;



/**
 * Entity Bean representing a CRL. Information stored:
 * <pre>
 * CRL (base64Crl)
 * IssuerDN (issuerDN)
 * CRLNumber (CRLNumber)
 * SHA1 fingerprint (fingerprint)
 * CA SHA1 fingerprint (cAFingerprint)
 * thisUpdate (thisUpdate)
 * nextUpdate (nextUpdate)
 * </pre>
 *
 * @version $Id$
 *
 * @ejb.bean description="This enterprise bean entity represents a CRL with accompanying data"
 * display-name="CRLDataEB"
 * name="CRLData"
 * jndi-name="CRLData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="CRLDataBean"
 *
 * @ejb.transaction type="Required"
 *
 * @ejb.pk class="org.ejbca.core.ejb.ca.store.CRLDataPK"
 * extends="java.lang.Object"
 * implements="java.io.Serializable"
 *
 * @ejb.persistence table-name = "CRLData"

 * @ejb.home
 * generate="local"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="org.ejbca.core.ejb.ca.store.CRLDataLocalHome"
 *
 * @ejb.interface
 * generate="local"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="org.ejbca.core.ejb.ca.store.CRLDataLocal"
 *
 * @ejb.finder description="findByIssuerDNAndCRLNumber"
 *   signature="org.ejbca.core.ejb.ca.store.CRLDataLocal findByIssuerDNAndCRLNumber(java.lang.String issuerdn, int cRLNumber)"
 *   query="SELECT OBJECT(a) from CRLDataBean a WHERE a.issuerDN=?1 AND a.crlNumber=?2"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class CRLDataBean extends BaseEntityBean {
    private static final Logger log = Logger.getLogger(CRLDataBean.class);

    /**
     * @ejb.persistence column-name="cRLNumber"
     * @ejb.interface-method
     */
    public abstract int getCrlNumber();

    /**
     * @ejb.interface-method
     */
    public abstract void setCrlNumber(int crlNumber);

    /** -1 for a normal CRL and 1 for a deltaCRL
     * @ejb.persistence column-name="deltaCRLIndicator"
     * @ejb.interface-method
     */
    public abstract int getDeltaCRLIndicator();

    /**
     * @ejb.interface-method
     */
    public abstract void setDeltaCRLIndicator(int deltaCRLIndicator);
    
    /**
     * @ejb.persistence column-name="issuerDN"
     * @ejb.interface-method
     */
    public abstract String getIssuerDN();

    /**
     * Use setIssuer instead
     *
     * @see #setIssuer(String)
     */
    public abstract void setIssuerDN(String issuerDN);

    /**
     * @ejb.pk-field
     * @ejb.persistence column-name="fingerprint"
     * @ejb.interface-method
     */
    public abstract String getFingerprint();

    /**
     */
    public abstract void setFingerprint(String fingerprint);

    /**
     * @ejb.persistence column-name="cAFingerprint"
     * @ejb.interface-method
     */
    public abstract String getCaFingerprint();

    /**
     * @ejb.interface-method
     */
    public abstract void setCaFingerprint(String caFingerprint);

    /**
     * @ejb.persistence column-name="thisUpdate"
     * @ejb.interface-method
     */
    public abstract long getThisUpdate();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     * @ejb.interface-method
     */
    public abstract void setThisUpdate(long thisUpdate);

    /**
     * @ejb.persistence column-name="nextUpdate"
     * @ejb.interface-method
     */
    public abstract long getNextUpdate();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     * @ejb.interface-method
     */
    public abstract void setNextUpdate(long nextUpdate);

    /**
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="base64Crl"
     * @ejb.interface-method
     */
    public abstract String getBase64Crl();

    /**
     * @ejb.interface-method
     */
    public abstract void setBase64Crl(String base64Crl);

    //
    // Public methods used to help us manage CRLs
    //
    /**
     * @ejb.interface-method
     */
    public X509CRL getCRL() {
        X509CRL crl = null;
        try {
            String b64Crl = getBase64Crl();
            crl = CertTools.getCRLfromByteArray(Base64.decode(b64Crl.getBytes()));
        } catch (CRLException ce) {
            log.error("Can't decode CRL.", ce);
            return null;
        } 
        return crl;
    }
    /**
     * @ejb.interface-method
     */
    public byte[] getCRLBytes() {
    	byte[] crl = null;
    	String b64Crl = getBase64Crl();
    	crl = Base64.decode(b64Crl.getBytes());
    	return crl;
    }

    /**
     * @ejb.interface-method
     */
    public void setCRL(X509CRL incrl) {
        try {
            String b64Crl = new String(Base64.encode((incrl).getEncoded()));
            setBase64Crl(b64Crl);
        } catch (CRLException ce) {
            log.error("Can't extract DER encoded CRL.", ce);
        }
    }

    /**
     * @ejb.interface-method
     */
    public void setIssuer(String dn) {
        setIssuerDN(CertTools.stringToBCDNString(dn));
    }

    /**
     * @ejb.interface-method
     */
    public void setThisUpdate(Date thisUpdate) {
        if (thisUpdate == null) {
            setThisUpdate(-1L);
        }

        setThisUpdate(thisUpdate.getTime());
    }

    /**
     * @ejb.interface-method
     */
    public void setNextUpdate(Date nextUpdate) {
        if (nextUpdate == null) {
            setNextUpdate(-1L);
        }

        setNextUpdate(nextUpdate.getTime());
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a CRL. Create by sending in the CRL, which extracts (from the
     * crl) fingerprint (primary key), CRLNumber, issuerDN, thisUpdate, nextUpdate. CAFingerprint
     * are set to default values (null) and should be set using the respective set-methods.
     *
     * @param incrl the asn.1 form of the (X509)CRL to be stored in the database.
     * @param number monotonically increasnig CRL number
     * @param issuerDN the issuer of the CRL
     * @param thisUpdate thisUpdate field in CRL
     * @param nextUpdate nextUpdate field in CRL
     * @param cafingerprint fingerprint of the CA certificate issuing the CRL
     *
     * @ejb.create-method
     */
    public CRLDataPK ejbCreate(byte[] incrl, int number, String issuerDN, Date thisUpdate, Date nextUpdate, String cafingerprint, int deltaCRLIndicator) throws CreateException {
    	String b64Crl = new String(Base64.encode(incrl));
    	setBase64Crl(b64Crl);
    	String fp = CertTools.getFingerprintAsString(incrl);
    	setFingerprint(fp);

    	// Make sure names are always looking the same
    	String issuer = CertTools.stringToBCDNString(issuerDN);
    	setIssuerDN(issuer);
    	if (log.isDebugEnabled()) {
    		log.debug("Creating crldata, fp="+fp+", issuer=" + issuer+", crlNumber="+number+", deltaCRLIndicator="+deltaCRLIndicator);
    	}

    	setCaFingerprint(cafingerprint);
    	setCrlNumber(number);
    	setThisUpdate(thisUpdate);
    	setNextUpdate(nextUpdate);
    	setDeltaCRLIndicator(deltaCRLIndicator);

    	CRLDataPK pk = new CRLDataPK(fp);

        return pk;
    }

    /**
     * DOCUMENT ME!
     *
     * @param incrl DOCUMENT ME!
     * @param number DOCUMENT ME!
     */
    public void ejbPostCreate(byte[] incrl, int number, String issuerDN, Date thisUpdate, Date nextUpdate, String cafingerprint, int deltaCRLIndicator) {
        // Do nothing. Required.
    }
}

/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.certificates.crl;

import org.cesecore.certificates.certificate.CertificateConstants;

import java.io.Serializable;
import java.security.cert.X509CRL;
import java.util.Date;

/**
 * Holds information about a CRL stored in the database.
 *
 */
public final class CRLInfo implements Serializable {
    private static final long serialVersionUID = 4942836797714142516L;
    private final String subjectDn;
    private final int crlPartitionIndex;
    private final int crlNumber;
    private final Date thisUpdate;
    private final Date nextUpdate;
    private final CRLData crlData;

    /**
     * Create information about a CRL stored in the database. The CRL itself is read lazily.
     * 
     * @param crlData ORM data object representing a CRL.
     */
    public CRLInfo(final CRLData crlData) {
        this.subjectDn = crlData.getIssuerDN();
        this.crlPartitionIndex = crlData.getCrlPartitionIndex() == -1
                ? CertificateConstants.NO_CRL_PARTITION
                : crlData.getCrlPartitionIndex();
        this.crlNumber = crlData.getCrlNumber();
        this.thisUpdate = new Date(crlData.getThisUpdate());
        this.nextUpdate = new Date(crlData.getNextUpdate());
        this.crlData = crlData;
    }
    
    /**
     * This constructor is used as a helper to show GUI data, skipping the crl which could be heavy hence speed up GUI load.
     *  
     * @param subjectDN
     * @param crlPartitionIndex
     * @param crlNumber
     * @param thisUpdate
     * @param nextUpdate
     */
    public CRLInfo(final String subjectDN, final int crlPartitionIndex, final int crlNumber, final long thisUpdate, final long nextUpdate) {
        this.subjectDn = subjectDN;
        this.crlPartitionIndex = crlPartitionIndex == -1 ? CertificateConstants.NO_CRL_PARTITION : crlPartitionIndex;
        this.crlNumber = crlNumber;
        this.thisUpdate = new Date(thisUpdate);
        this.nextUpdate = new Date(nextUpdate);
        this.crlData = null;
    }

    /**
     * Get the subject DN of the CA who signed the CRL.
     * 
     * @return the subject DN of the CA who signed the CRL.
     */
    public String getSubjectDN() {
        return subjectDn;
    }

    /** 
     * Get the CRL partition index or {@link CertificateConstants#NO_CRL_PARTITION} if this object holds the main CRL.
     * 
     * @return the CRL partition index.
     */
    public int getCrlPartitionIndex() {
        return crlPartitionIndex;
    }

    /**
     * Get the CRL number.
     * 
     * @return the CRL number.
     */
    public int getLastCRLNumber() {
        return crlNumber;
    }

    /**
     * Get the date when the CRL was signed.
     * 
     * @return the creation date of the CRL.
     */
    public Date getCreateDate() {
        return thisUpdate;
    }

    /**
     * Get the date when the CRL expires.
     * 
     * @return the expiration date of the CRL.
     */
    public Date getExpireDate() {
        return nextUpdate;
    }

    /**
     * Get the actual CRL as a {@link X509CRL} object.
     * 
     * @return the CRL itself.
     */
    public X509CRL getCrl() {
        return crlData.getCRL();
    }
}

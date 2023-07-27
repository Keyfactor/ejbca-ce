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
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Date;
import java.util.LinkedHashMap;

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.internal.UpgradeableDataHashMap;

import com.keyfactor.util.CertTools;

/**
 * Information about a certificate that is being issued, but which issuance could be aborted
 * in a half-issued state (e.g. rolled back internally, but published externally).
 */
public class IncompletelyIssuedCertificateInfo extends UpgradeableDataHashMap {

    private static final long serialVersionUID = 1L;
    private static final float LATEST_VERSION = 0;

    private static final String KEY_CERTBYTES = "certBytes";
    private static final String KEY_USERNAME = "username";
    private static final String KEY_CAFINGERPRINT = "caFingerprint";
    private static final String KEY_CERTPROFILEID = "certProfileId";
    private static final String KEY_ENDENTITYPROFILEID = "endEntityProfileId";
    private static final String KEY_CRLPARTITIONINDEX = "crlPartitionIndex";
    private static final String KEY_ACCOUNTBINDINGID = "accountBindingId";

    private int caId;
    private BigInteger serialNumber;
    private Date startTime;

    /** Constructor for loading from database */
    public IncompletelyIssuedCertificateInfo(final int caId, final BigInteger serialNumber, final long startTime, final LinkedHashMap<?,?> dataMap) {
        super();
        this.caId = caId;
        this.serialNumber = serialNumber;
        this.startTime = new Date(startTime);
        loadData(dataMap);
    }

    /** Constructor that is called after generating a certificate that needs to be "journaled" */
    public IncompletelyIssuedCertificateInfo(final int caId, final BigInteger serialNumber, final Date startTime, final EndEntityInformation endEntity,
            final Certificate cert, final Certificate cacert, final int crlPartitionIndex) {
        super();
        this.caId = caId;
        this.serialNumber = serialNumber;
        this.startTime = startTime;
        initDataFromEndEntityInformation(endEntity, cert, cacert, crlPartitionIndex);
    }

    private void initDataFromEndEntityInformation(final EndEntityInformation endEntity, final Certificate cert, final Certificate cacert, final int crlPartitionIndex) {
        try {
            data.put(KEY_CERTBYTES, cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Failed to encode newly created certificate");
        }
        data.put(KEY_USERNAME, endEntity.getUsername());
        data.put(KEY_CAFINGERPRINT, CertTools.getFingerprintAsString(cacert));
        data.put(KEY_CERTPROFILEID, endEntity.getCertificateProfileId());
        data.put(KEY_ENDENTITYPROFILEID, endEntity.getEndEntityProfileId());
        data.put(KEY_CRLPARTITIONINDEX, crlPartitionIndex);
        final ExtendedInformation extInfo = endEntity.getExtendedInformation();
        data.put(KEY_ACCOUNTBINDINGID, extInfo != null ? extInfo.getAccountBindingId() : null);
    }

    /** ID of CA that issued the certificate */
    public int getCaId() {
        return caId;
    }

    public void setCaId(int caId) {
        this.caId = caId;
    }

    /** Certificate serial number */
    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    /** Start time of issuance. Used to find certificates where issuance has been aborted. */
    public Date getStartTime() {
        return startTime;
    }

    public void setStartTime(Date startTime) {
        this.startTime = startTime;
    }

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        // Do nothing
    }

    public byte[] getCertBytes() {
        return (byte[]) data.get(KEY_CERTBYTES);
    }

    public String getUsername() {
        return (String) data.get(KEY_USERNAME);
    }

    public String getCaFingerprint() {
        return (String) data.get(KEY_CAFINGERPRINT);
    }

    public int getCertificateProfileId() {
        return (int) data.get(KEY_CERTPROFILEID);
    }

    public int getEndEntityProfileId() {
        return (int) data.get(KEY_ENDENTITYPROFILEID);
    }

    public int getCrlPartitionIndex() {
        return (int) data.get(KEY_CRLPARTITIONINDEX);
    }

    public String getAccountBindingId() {
        return (String) data.get(KEY_ACCOUNTBINDINGID);
    }

}

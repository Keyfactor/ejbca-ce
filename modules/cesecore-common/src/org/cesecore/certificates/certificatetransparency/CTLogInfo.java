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
package org.cesecore.certificates.certificatetransparency;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.TimeZone;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;

import com.keyfactor.util.keys.KeyTools;

/**
 * Represents a Certificate Transparency log
 *
 * @version $Id$
 */
public final class CTLogInfo implements Serializable {

    private static final Logger log = Logger.getLogger(CTLogInfo.class);
    private static final long serialVersionUID = 1L;

    private final int logId;
    private byte[] publicKeyBytes;
    private String url; // base URL, without "add-chain" or "add-pre-chain"
    private int timeout = 5000; // milliseconds
    private String label;
    @Deprecated
    private boolean isMandatory;
    private Integer expirationYearRequired;
    private Date intervalStart;
    private Date intervalEnd;

    private transient PublicKey publicKey;
    
    private static final Random random = new Random();

    /**
     * Creates a CT log info object, but does not parse the public key yet
     * (so it can be created from static blocks etc.)
     *
     * @param url  Base URL to the log. The CT log library will automatically append
     *        the strings "add-chain" or "add-pre-chain" depending on whether
     *        EJBCA is submitting a pre-certificate or a regular certificate.
     * @param publicKeyBytes  The ASN1 encoded public key of the log.
     * @param label to place CT log under.
     * @param timeout of SCT response in ms.
     */
    public CTLogInfo(final String url, final byte[] publicKeyBytes, final String label, final int timeout) {
        if (!url.endsWith("/")) {
            log.error("CT Log URL must end with a slash. URL: "+url); // EJBCA 6.4 didn't enforce this due to a regression
        }
        if (!url.endsWith("/ct/v1/")) {
            log.warn("CT Log URL should end with /ct/v1/. URL: "+url);
        }
        this.logId = random.nextInt();
        this.url = url;
        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("publicKeyBytes is null");
        }
        this.publicKeyBytes = publicKeyBytes.clone();
        if (label != null && label.isEmpty()) {
            this.label = "Unlabeled";
        } else {
            this.label = label;
        }
        this.timeout = timeout;
    }

    private void ensureParsed() {
        if (publicKey == null) {
            publicKey = KeyTools.getPublicKeyFromBytes(publicKeyBytes);
            if (publicKey == null) {
                throw new IllegalStateException("Failed to parse key");
            }
        }
    }

    /** @return Internal Id consisting of the hashcode of the URL */
    public int getLogId() {
        return logId;
    }

    public PublicKey getLogPublicKey() {
        ensureParsed();
        return publicKey;
    }

    public byte[] getPublicKeyBytes() {
        return publicKeyBytes;
    }

    public void setLogPublicKey(final byte[] publicKeyBytes) {
        this.publicKey = null;
        this.publicKeyBytes = publicKeyBytes;
    }

    /** @return Log Key ID as specified by the RFC, in human-readable format */
    public String getLogKeyIdString() {
        try {
            ensureParsed();
            final MessageDigest md = MessageDigest.getInstance("SHA256");
            final byte[] keyId = md.digest(publicKey.getEncoded());
            return Base64.toBase64String(keyId);
        } catch (NoSuchAlgorithmException e) {
            // Should not happen, but not critical.
            return "";
        } catch (Exception e) {
            return e.getLocalizedMessage();
        }
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(final String url) {
        this.url = url;
    }

    public int getTimeout() {
        return timeout;
    }

    /**
     * Determine whether this certificate transparency log belongs to the group of certificate
     * transparency logs to which it is mandatory to publish.
     * @return true if this is a mandatory log, or false otherwise
     */
    public boolean isMandatory() {
        return isMandatory;
    }

    /** Sets the timeout in milliseconds when sending a request to the log server */
    public void setTimeout(final int timeout) {
        if (timeout < 0) {
            throw new IllegalArgumentException("Timeout value is negative");
        }
        this.timeout = timeout;
    }

    /** Makes sure that a URL ends with /ct/v1/ */
    public static String fixUrl(String urlToFix) {
        urlToFix = urlToFix.replaceAll("\\s","");
        String url = (urlToFix.endsWith("/") ? urlToFix : urlToFix + "/");
        if (!url.endsWith("/ct/v1/")) {
            if (!url.endsWith("/ct/")) {
                url = url + "ct/v1/";
            } else {
                url = url + "v1/";
            }
        }
        return url;
    }

    public String getLabel() {
        return label == null ? "Unlabeled" : label;
    }

    public void setLabel(final String label) {
        this.label = label;
    }

    /**
     * Returns the expiration year which certificates published to this CT log must
     * have in order to be accepted, or null if there is no such requirement. For
     * example, if this method returns "2019" then you should only try to publish
     * certificates to this CT log expiring in 2019, since all other certificates
     * will be rejected.
     * @return the expiration year required for all certificates being published to
     * this log or null if there is no such requirement
     */
    public Integer getExpirationYearRequired() {
        return expirationYearRequired;
    }

    /**
     * Returns the expiration year which certificates published to this CT log must
     * have in order to be accepted, or null if there is no such requirement. See
     * {@link #getExpirationYearRequired()}.
     * @param expirationYearRequired the expiration year required for new certificates
     * being published to this CT log, or null if no such requirement
     */
    public void setExpirationYearRequired(final Integer expirationYearRequired) {
        this.expirationYearRequired = expirationYearRequired;
    }

    /**
     * Returns a {@link Date} object defining the start date of the validity period, which all certificates
     * published to this CT log must fulfill in order to be accepted, or null if there is no such requirement.
     *
     * <p>For example, if this method returns "20.01.2019" then you should only try to publish
     * certificates to this CT log expiring after this date, since all other certificates
     * will be rejected.
     *
     * @return the validity period start date for sharding or null if there is no such requirement.
     */
    public Date getIntervalStart() {
        return intervalStart;
    }

    /**
     * Sets a {@link Date} object defining the start date of the validity period, which all certificates
     * published to this CT log must fulfill. See also {@link #getIntervalStart()}.
     *
     * @param intervalStart the new validity start date for sharding or null to disable.
     */
    public void setIntervalStart(final Date intervalStart) {
        this.intervalStart = intervalStart != null ? getStartOfTheDay(intervalStart) : null;
    }

    /**
     * Returns a {@link Date} object defining the end date of the validity period, which all certificates
     * published to this CT log must fulfill in order to be accepted, or null if there is no such requirement.
     *
     * <p>For example, if this method returns "20.01.2020" then you should only try to publish
     * certificates to this CT log expiring before this date, since all other certificates
     * will be rejected.
     *
     * @return the validity period end date for sharding or null if there is no such requirement.
     */
    public Date getIntervalEnd() {
        return intervalEnd;
    }

    /**
     * Sets a {@link Date} object defining the end date of the validity period, which all certificates
     * published to this CT log must fulfill. See also {@link #getIntervalEnd()}.
     *
     * @param intervalEnd the new validity end date for sharding or null to disable.
     */
    public void setIntervalEnd(final Date intervalEnd) {
        this.intervalEnd = intervalEnd != null ? getEndOfTheDay(intervalEnd) : null;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || o.getClass() != CTLogInfo.class) {
            return false;
        }

        final CTLogInfo ctLogInfo = (CTLogInfo) o;
        return logId == ctLogInfo.getLogId() &&
                url.equals(ctLogInfo.getUrl());
    }

    @Override
    public int hashCode() {
        return logId + (url.hashCode() * 4711);
    }

    @Override
    public String toString() {
        return getUrl();
    }

    private Date getStartOfTheDay(final Date date) {
        final Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.setTime(date);
        int year = calendar.get(Calendar.YEAR);
        int month = calendar.get(Calendar.MONTH);
        int day = calendar.get(Calendar.DATE);
        calendar.set(year, month, day, 0, 0, 0);
        return calendar.getTime();
    }

    private Date getEndOfTheDay(final Date date) {
        final Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.setTime(date);
        int year = calendar.get(Calendar.YEAR);
        int month = calendar.get(Calendar.MONTH);
        int day = calendar.get(Calendar.DATE);
        calendar.set(year, month, day, 23, 59, 59);
        return calendar.getTime();
    }
}

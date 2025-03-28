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

package org.ejbca.core.ejb.ca.store;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

import jakarta.persistence.Entity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import jakarta.persistence.TypedQuery;

import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.LogRedactionUtils;
import org.cesecore.util.SecureXMLDecoder;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.FixEndOfBrokenXML;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;

/**
 * Representation of historical information about the data user to create a certificate.
 * 
 * the information is currently used to:
 * - list request history for a user
 * - find issuing User DN (EndEntityInformation) when republishing a certificate (in case the userDN for the user changed)
 */ 
@SuppressWarnings("deprecation")
@Entity
@Table(name="CertReqHistoryData")
public class CertReqHistoryData extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(CertReqHistoryData.class);

	private String issuerDN;
	private String fingerprint;
	private String serialNumber;
	private long timestamp;
	private String userDataVO;
	private String username;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity Bean holding info about a request data at the time the certificate was issued.
	 * 
	 * @param incert the certificate issued
	 * @param issuerDN should be the same as CertTools.getIssuerDN(incert)
	 * @param endEntityInformation the data used to issue the certificate. 
	 */
	public CertReqHistoryData(Certificate incert, String issuerDN, EndEntityInformation endEntityInformation) {
		// Exctract fields to store with the certificate.
		setFingerprint(CertTools.getFingerprintAsString(incert));
        setIssuerDN(issuerDN);
        if (log.isDebugEnabled()) {
        	log.debug("Creating certreqhistory data, serial=" + CertTools.getSerialNumberAsString(incert) + ", issuer=" + getIssuerDN());
        }
        setSerialNumber(CertTools.getSerialNumber(incert).toString());
        setTimestamp(new Date().getTime());
		setUsername(endEntityInformation.getUsername());
		storeEndEntityInformation(endEntityInformation);
	}
	private void storeEndEntityInformation(EndEntityInformation endEntityInformation) {
		try {
			// Save the user admin data in xml encoding.
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			try (final XMLEncoder encoder = new XMLEncoder(baos)) {
			    encoder.writeObject(endEntityInformation);
			}
			if (log.isDebugEnabled()) {
			    log.debug(printEndEntityInformationXML("endEntityInformation:", endEntityInformation));
			}
			setUserDataVO(baos.toString("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			log.error("", e);
			throw new RuntimeException(e);    	                                              
		} 
	}

	public CertReqHistoryData() { }
	
	/**
	 * DN of issuer of certificate
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return issuer dn
	 */
	//@Column
	public String getIssuerDN() { return issuerDN; }
	/**
	 * Use setIssuer instead
	 * @param issuerDN issuer dn
	 */
	public void setIssuerDN(String issuerDN) { this.issuerDN =issuerDN; }

	/**
	 * Fingerprint of certificate
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return fingerprint
	 */
	//@Id @Column
	public String getFingerprint() { return fingerprint; }
	/**
	 * Fingerprint of certificate
	 * Shouldn't be set after creation.
	 * @param fingerprint fingerprint
	 */
	public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }

	/**
	 * Serialnumber formated as BigInteger.toString()
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return serial number
	 */
	//@Column
	public String getSerialNumber() { return serialNumber; }

	/**
	 * Serialnumber formated as BigInteger.toString()
	 * Shouldn't be set after creation.
	 * @param serialNumber serial number
	 */
	public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

	/**
	 * Date formated as seconds since 1970 (== Date.getTime())
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return timestamp 
	 */
	//@Column
	public long getTimestamp() { return timestamp; }

	/**
	 * Date formated as seconds since 1970 (== Date.getTime())
	 * Shouldn't be set after creation.
	 * @param timestamp when certificate request info was stored
	 */
	public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

	/**
     * UserDataVO in xmlencoded String format
     * Should not be used outside of entity bean, use getCertReqHistory instead
     * @return  xmlencoded encoded UserDataVO
     */
    //@Column @Lob
    public String getUserDataVO() { return userDataVO; }

    /**
     * UserDataVO in  xmlencoded String format
     * Shouldn't be set after creation.
     * @param userDataVO xmlencoded encoded UserDataVO
     */
    public void setUserDataVO(String userDataVO) { this.userDataVO = userDataVO; }

	/**
	 * username in database
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return username
	 */
	//@Column
	public String getUsername() { return username; }

	/**
	 * username
	 * Shouldn't be set after creation.
	 * @param username username
	 */
	public void setUsername(String username) { this.username = StringTools.stripUsername(username); }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	@Override
	public String getRowProtection() { return rowProtection; }
	@Override
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

	//
	// Public business methods used to help us manage certificates
	//

	/**
	 * Returns the value object containing the information of the entity bean.
	 * This is the method that should be used to retreive cert req history 
	 * correctly.
	 * 
	 * NOTE: This method will try to repair broken XML and will in that case
	 * update the database. This means that this method must always run in a
	 * transaction! 
	 * 
	 * @return certificate request history object
	 */
	@Transient
    public CertReqHistory getCertReqHistory() {

		return new CertReqHistory(this.getFingerprint(),this.getSerialNumber(),
		                          this.getIssuerDN(),this.getUsername(),new Date(this.getTimestamp()),
		                          decodeXML(getUserDataVO(), false));
	}
	
	/** just used internally in the this class to indicate that the XML can not be fixed.
	 */
	private class NotPossibleToFixXML extends Exception {
		private static final long serialVersionUID = 3690860390706539637L;

        // just used internally in the this class to indicate that the XML can not be fixed.
		public NotPossibleToFixXML() {
			// do nothing
		}
	}
	
	/** decode objects that have been serialized to xml.
	 * This method tries to fix xml that has been broken by some characters missing in the end.
	 * This has been found in some older DB during upgrade from EJBCA 3.4, and seemed to be due to 
	 * internationalized characters. This seemed to truncate the XML somehow, and here we try to handle that
	 * in a nice way.  
	 */
    private EndEntityInformation decodeXML(final String sXML, final boolean lastTry) {
		final byte baXML[] = sXML.getBytes(StandardCharsets.UTF_8);
		EndEntityInformation endEntityInformation = null;
		// The EndEntityInformation object is not fully serializable by XMLEncoder/Decoder
		// (the "type" field is not serialized correctly), so we set ignoreErrors to true
		try (final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(baXML), true)) {
            final Object o = decoder.readObject();
            if (o instanceof EndEntityInformation) {
                endEntityInformation  = (EndEntityInformation)o;
            } else if (o instanceof UserDataVO) {
                // It is probably an older object of type UserDataVO
                log.debug("Trying to decode old type of CertReqHistoryData with UserDataVO");
                UserDataVO olddata = (UserDataVO)o;
                endEntityInformation = olddata.toEndEntityInformation();
            } else if (o instanceof Base64PutHashMap) {
                // Base64PutHashMap has been seen in some cases (from old EJBCA versions? or a bug?)
                // This will not be accessible in the GUI, since the end entity profile ID is missing.
                log.debug("Trying to decode old type of CertReqHistoryData with Base64PutHashMap. Entry will not be viewable in GUI");
                final ExtendedInformation extinfo = new ExtendedInformation();
                extinfo.loadData(o);
                endEntityInformation = new EndEntityInformation();
                endEntityInformation.setExtendedInformation(extinfo);
            } else {
                throw new IllegalStateException("Decoded CertReqHistoryData with unexpected class: " + (o != null ? o.getClass() : null));
            }
        } catch (Exception t) { // NOPMD: catch all to try to repair
			// try to repair the end of the XML string.
			// this will only succeed if a limited number of chars is lost in the end of the string
			// note that this code will not make anything worse and that it will not be run if the XML can be encoded.
			// 
			try {
				if ( lastTry ) {
				    if (t instanceof IOException) {
				        final String msg = "Failed to parse data map for certificate request history for '" + getFingerprint() + "': " + t.getMessage();
			            if (log.isDebugEnabled()) {
			                log.debug(msg + ". Data:\n" + sXML);
			            }
			            throw new IllegalStateException(msg, t);
				    } else if (t instanceof RuntimeException) {
				        throw (RuntimeException) t;
				    }
					return null;
				}
				final String sFixedXML = FixEndOfBrokenXML.fixXML(sXML, "string", "</void></object></java>");
				if ( sFixedXML==null ) {
					throw new NotPossibleToFixXML();					
				}
				endEntityInformation = decodeXML(sFixedXML, true);
				if ( endEntityInformation==null ) {
					throw new NotPossibleToFixXML();
				}
				storeEndEntityInformation(endEntityInformation); // store it right so it does not have to be repaired again.
				// Old and most probably unused code. Do not redact here. 
				log.warn(printEndEntityInformationXML("XML has been repaired. Trailing tags fixed. DB updated with correct XML.", sXML));
				return endEntityInformation;
			} catch ( NotPossibleToFixXML e ) {
			    // Old and most probably unused code. Do not redact here.
				log.error(printEndEntityInformationXML("Not possible to decode EndEntityInformation. No way to fix the XML.", sXML), t);
				return null;
			}
		}
		if (log.isTraceEnabled() ) {
			log.trace(printEndEntityInformationXML("Successfully decoded EndEntityInformation XML.",sXML));
		}
		/* Code that fixes broken XML that has actually been parsed. It seems that the decoder is not checking for the java end tag.
		 * Currently this is left out in order to not mess with working but broken XML.
		if ( sXML.indexOf("<java")>0 && sXML.indexOf("</java>")<0 ) {
			storeEndEntityInformation(endEntityInformation); // store it right				
		}
		 */
		return endEntityInformation;
	}
    
	private String printEndEntityInformationXML(String sComment, String sXML) {
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new PrintWriter(sw);
		pw.println(sComment);
		pw.println("XMLDATA start on next line:");
		// Nothing to redact in the XML data.
		pw.print(sXML);
		pw.println("| end of XMLDATA. The char before '|' was the last XML.");
		pw.println();
		pw.println("Issuer DN: "+getIssuerDN());
		pw.println("Serial #"+getSerialNumber());
		pw.println("User name: "+getUsername());
		pw.println("Certificate fingerprint: "+getFingerprint());
		pw.println();
		return sw.toString();
	}
	
	private String printEndEntityInformationXML(final String sComment, final EndEntityInformation endEntityInformation) throws UnsupportedEncodingException {
        
        final EndEntityInformation eeiToLog;
        if (LogRedactionUtils.isRedactPii(endEntityInformation.getEndEntityProfileId())) {
            eeiToLog = new EndEntityInformation(endEntityInformation);
            // Set to null, for <redacted> an IndexOutOfBoundsException is thrown.
            eeiToLog.setDN(null);
            eeiToLog.setSubjectAltName(LogRedactionUtils.REDACTED_CONTENT);
            if (eeiToLog.getExtendedInformation() != null) {
                eeiToLog.getExtendedInformation().setCertificateRequest(new byte[] {});
            }
        } else {
            eeiToLog = endEntityInformation;
        }
        
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(eeiToLog);
        }
        
        return printEndEntityInformationXML(sComment, baos.toString("UTF-8"));
    }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getFingerprint()).append(getIssuerDN()).append(getSerialNumber()).append(getTimestamp()).append(getUserDataVO()).append(getUsername());
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() throws DatabaseProtectionException {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() throws DatabaseProtectionException {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return getFingerprint();
    }

    //
    // End Database integrity protection methods
    //

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static CertReqHistoryData findById(EntityManager entityManager, String fingerprint) {
		return entityManager.find(CertReqHistoryData.class, fingerprint);
	}
	
	/** @return return the query results as a List. */
    public static List<CertReqHistoryData> findByIssuerDNSerialNumber(EntityManager entityManager, String issuerDN, String serialNumber) {
		final TypedQuery<CertReqHistoryData> query = entityManager.createQuery("SELECT a FROM CertReqHistoryData a WHERE a.issuerDN=:issuerDN AND a.serialNumber=:serialNumber", CertReqHistoryData.class);
		query.setParameter("issuerDN", issuerDN);
		query.setParameter("serialNumber", serialNumber);
		return query.getResultList();
	}

	/** @return return the query results as a List. */
    public static List<CertReqHistoryData> findByUsername(EntityManager entityManager, String username) {
	    final TypedQuery<CertReqHistoryData> query = entityManager.createQuery("SELECT a FROM CertReqHistoryData a WHERE a.username=:username", CertReqHistoryData.class);
		query.setParameter("username", username);
		return query.getResultList();
	}
}

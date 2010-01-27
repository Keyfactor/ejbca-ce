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
package org.ejbca.core.model.log;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;

/**
 * Represents a protected log event with all its context information.
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogEventRow {

	private static final Logger log = Logger.getLogger(ProtectedLogEventRow.class);

	private int adminType;
	private String admindata;
	private int caid;
	private int module;
	private long eventTime;
	private String username;
	private String certificateSerialNumber;
	private String certificateIssuerDN;
	private int eventId;
	private String eventComment;
	private ProtectedLogEventIdentifier eventIdentifier;
	private String nodeIP;
	private ProtectedLogEventIdentifier[] linkedInEventIdentifiers;
	private byte[] linkedInEventsHash;
	private String currentHashAlgorithm;
	private int protectionKeyIdentifier;
	private String protectionKeyAlgorithm;
	private byte[] protection;
	
	public ProtectedLogEventRow(int adminType, String admindata, int caid, int module, long eventTime, String username, String certificateSerialNumber,
			String certificateIssuerDN, int eventId, String eventComment, ProtectedLogEventIdentifier eventIdentifier, String nodeIP,
			ProtectedLogEventIdentifier[] linkedInEventIdentifiers, byte[] linkedInEventsHash, String currentHashAlgorithm, int protectionKeyIdentifier, String protectionKeyAlgorithm, byte[] protection) {
		this.adminType = adminType;
		this.admindata = admindata;
		this.caid = caid;
		this.module = module;
		this.eventTime = eventTime;
		this.username = username;
		this.certificateSerialNumber = certificateSerialNumber;
		this.certificateIssuerDN = certificateIssuerDN;
		this.eventId = eventId;
		this.eventComment = eventComment;
		this.eventIdentifier = eventIdentifier;
		this.nodeIP = nodeIP;
		this.linkedInEventIdentifiers = linkedInEventIdentifiers;
		this.linkedInEventsHash = linkedInEventsHash;
		this.currentHashAlgorithm = currentHashAlgorithm;
		this.protectionKeyIdentifier = protectionKeyIdentifier;
		this.protectionKeyAlgorithm = protectionKeyAlgorithm;
		this.protection = protection;
	}
	
	/*  Dependency in the wrong direction..
	public ProtectedLogEventRow(ProtectedLogDataLocal protectedLogDataLocal) {
		this.adminType = protectedLogDataLocal.getAdminType();
		this.admindata = protectedLogDataLocal.getAdminData();
		this.caid = protectedLogDataLocal.getCaId();
		this.module = protectedLogDataLocal.getModule();
		this.eventTime = protectedLogDataLocal.getEventTime();
		this.username = protectedLogDataLocal.getUsername();
		this.certificateSerialNumber = protectedLogDataLocal.getCertificateSerialNumber();
		this.certificateIssuerDN = protectedLogDataLocal.getCertificateIssuerDN();
		this.eventId = protectedLogDataLocal.getEventId();
		this.eventComment = protectedLogDataLocal.getEventComment();
		this.eventIdentifier = new ProtectedLogEventIdentifier(protectedLogDataLocal.getNodeGUID(), protectedLogDataLocal.getCounter());
		this.nodeIP = protectedLogDataLocal.getNodeIP();
		this.linkedInEventIdentifiers = protectedLogDataLocal.getLinkedInEventIdentifiers();
		this.linkedInEventsHash = protectedLogDataLocal.getLinkedInEventsHash();
		this.currentHashAlgorithm = protectedLogDataLocal.getCurrentHashAlgorithm();
		this.protectionKeyIdentifier = protectedLogDataLocal.getProtectionKeyIdentifier();
		this.protectionKeyAlgorithm = protectedLogDataLocal.getProtectionKeyAlgorithm();
		this.protection = protectedLogDataLocal.getProtection();
	}
	*/
	
	public ProtectedLogEventRow(ResultSet rs) throws SQLException {
		// Ignore pk
		this.adminType = rs.getInt(2);
		this.admindata = rs.getString(3);
		this.caid = rs.getInt(4);
		this.module = rs.getInt(5);
		this.eventTime = rs.getLong(6);
		this.username = rs.getString(7);
		this.certificateSerialNumber = rs.getString(8);
		this.certificateIssuerDN = rs.getString(9);
		this.eventId = rs.getInt(10);
		this.eventComment = rs.getString(11);
		this.eventIdentifier = new ProtectedLogEventIdentifier(rs.getInt(12), rs.getLong(13));
		this.nodeIP = rs.getString(14);
    	String b64LinkedInEventIdentifiers = rs.getString(15);
    	ProtectedLogEventIdentifier[] protectedLogEventIdentifiers = null;
    	if (b64LinkedInEventIdentifiers != null) {
        	String[] b64LinkedInEventIdentifierArray = b64LinkedInEventIdentifiers.split(";");
        	protectedLogEventIdentifiers = new ProtectedLogEventIdentifier[b64LinkedInEventIdentifierArray.length];
    		for (int i=0; i<b64LinkedInEventIdentifierArray.length; i++) {
    			protectedLogEventIdentifiers[i] = new ProtectedLogEventIdentifier(b64LinkedInEventIdentifierArray[i]);
    		}
    	}
		this.linkedInEventIdentifiers = protectedLogEventIdentifiers;
		if (rs.getString(16) == null) {
			this.linkedInEventsHash = null;
		} else {
			this.linkedInEventsHash = Base64.decode(rs.getString(16).getBytes());
		}
		this.currentHashAlgorithm = rs.getString(17);
		this.protectionKeyIdentifier = rs.getInt(18);
		this.protectionKeyAlgorithm = rs.getString(19);
		if (rs.getString(20) == null) {
			this.protection = null;
		} else {
			this.protection = Base64.decode(rs.getString(20).getBytes());
		}
	}
	
	public int getAdminType() { return adminType; }
	public String getAdmindata() {return admindata; }
	public int getCaid() { return caid; }
	public int getModule() { return module; }
	public long getEventTime() { return eventTime; }
	public String getUsername() { return username; }
	public String getCertificateSerialNumber() { return certificateSerialNumber; }
	public String getCertificateIssuerDN() { return certificateIssuerDN; }
	public int getEventId() { return eventId; }
	public String getEventComment() { return eventComment; }
	public ProtectedLogEventIdentifier getEventIdentifier() { return eventIdentifier; }
	public String getNodeIP() { return nodeIP; }
	public ProtectedLogEventIdentifier[] getLinkedInEventIdentifiers() { return linkedInEventIdentifiers; }
	public byte[] getLinkedInEventsHash() { return linkedInEventsHash; }
	public String getCurrentHashAlgorithm() { return currentHashAlgorithm; }
	public int getProtectionKeyIdentifier() { return protectionKeyIdentifier; }
	public String getProtectionKeyAlgorithm() { return protectionKeyAlgorithm; }

	public byte[] getProtection() { return protection; }
	public void setProtection(byte[] protection) { this.protection = protection; }

    /**
     * @param includeProtection is true if the protection field should be included.
     */
	public byte[] getAsByteArray(boolean includeProtection) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos;
		try {
			dos = new DataOutputStream(baos);
			dos.writeInt(adminType);
			if (admindata != null) {
				dos.writeUTF(admindata);
			}
			dos.writeInt(caid);
			dos.writeInt(module);
			dos.writeLong(eventTime);
			if (username != null) {
				dos.writeUTF(username);
			}
			if (certificateSerialNumber != null) {
				dos.writeUTF(certificateSerialNumber);
			}
			if (certificateIssuerDN != null) {
				dos.writeUTF(certificateIssuerDN);
			}
			dos.writeInt(eventId);
			if (eventComment != null) {
				dos.writeUTF(eventComment);
			}
			if (eventIdentifier != null) {
				dos.writeInt(eventIdentifier.getNodeGUID());
				dos.writeLong(eventIdentifier.getCounter());
			}
			if (nodeIP != null) {
				dos.writeUTF(nodeIP);
			}
			if (linkedInEventIdentifiers != null) {
				for (int i=0; i<linkedInEventIdentifiers.length; i++) {
					if (linkedInEventIdentifiers[i] != null) {
						dos.writeInt(linkedInEventIdentifiers[i].getNodeGUID());
						dos.writeLong(linkedInEventIdentifiers[i].getCounter());
					}
					
				}
			}
			if (linkedInEventsHash != null) {
				dos.write(linkedInEventsHash);
			}
			if (currentHashAlgorithm != null) {
				dos.writeUTF(currentHashAlgorithm);
			}
			dos.writeInt(protectionKeyIdentifier);
			if (protectionKeyAlgorithm != null) {
				dos.writeUTF(protectionKeyAlgorithm);
			}
			if (includeProtection && protection != null) {
				dos.write(protection);
			}
			dos.flush();
		} catch (IOException e) {
			log.error(e);
			throw new EJBException(e);
		} 
		return baos.toByteArray();
	}

	/**
	 * Only return a byte array of the elements that are actual log-data.
	 * @return
	 */
	public byte[] getLogDataAsByteArray() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos;
		try {
			dos = new DataOutputStream(baos);
			dos.writeInt(adminType);
			if (admindata != null) {
				dos.writeUTF(admindata);
			}
			dos.writeInt(caid);
			dos.writeInt(module);
			dos.writeLong(eventTime);
			if (username != null) {
				dos.writeUTF(username);
			}
			if (certificateSerialNumber != null) {
				dos.writeUTF(certificateSerialNumber);
			}
			if (certificateIssuerDN != null) {
				dos.writeUTF(certificateIssuerDN);
			}
			dos.writeInt(eventId);
			if (eventComment != null) {
				dos.writeUTF(eventComment);
			}
			if (eventIdentifier != null) {
				dos.writeInt(eventIdentifier.getNodeGUID());
				dos.writeLong(eventIdentifier.getCounter());
			}
			dos.flush();
		} catch (IOException e) {
			throw new EJBException(e);
		} 
		return baos.toByteArray();
	}

	/**
	 * Calculates the hash of this function using  this objects "getCurrentHashAlgorithm()" and "getAsByteArray()"
	 */
	public byte[] calculateHash() {
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(currentHashAlgorithm, "BC");
		} catch (NoSuchAlgorithmException e) {
			throw new EJBException(e);
		} catch (NoSuchProviderException e) {
			throw new EJBException(e);
		}
		return messageDigest.digest(getAsByteArray(true));
	}

	public int hashCode() {
		return getEventIdentifier().hashCode();
	}

	public boolean equals(Object o) {
		return o instanceof ProtectedLogEventRow && equals((ProtectedLogEventRow) o);
	}

	/**
	 * Return true if both have the same (NodeId,count) value and same hash.
	 */
	public boolean equals(ProtectedLogEventRow row) {
		if (this.getEventIdentifier().equals(row.getEventIdentifier())) {
			if (Arrays.equals(this.calculateHash(), row.calculateHash())) {
				return true;
			}
		}
		return false;
	}
}

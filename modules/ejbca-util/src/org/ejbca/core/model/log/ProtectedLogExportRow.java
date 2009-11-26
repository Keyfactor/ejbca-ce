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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * Represents an export.
 * @version $Id$
 */
public class ProtectedLogExportRow {
	
	private static final Logger log = Logger.getLogger(ProtectedLogExportRow.class);
	
	private long timeOfExport;
	private long exportEndTime;
	private long exportStartTime;
	private byte[] logDataHash;
	private byte[] previousExportHash;
	private String currentHashAlgorithm;
	private byte[] signatureCertificate;
	private boolean deleted;
	private byte[] signature;
	
	public ProtectedLogExportRow(long timeOfExport, long exportEndTime, long exportStartTime, byte[] logDataHash, byte[] previousExportHash, String currentHashAlgorithm,
			byte[] signatureCertificate, boolean deleted, byte[] signature) {
		this.timeOfExport = timeOfExport;
		this.exportEndTime = exportEndTime;
		this.exportStartTime = exportStartTime;
		this.logDataHash = logDataHash;
		this.previousExportHash = previousExportHash;
		this.currentHashAlgorithm = currentHashAlgorithm;
		this.signatureCertificate = signatureCertificate;
		this.deleted = deleted;
		this.signature = signature;
	}

	public ProtectedLogExportRow(long timeOfExport, long exportEndTime, long exportStartTime, byte[] logDataHash, byte[] previousExportHash, String currentHashAlgorithm,
			Certificate signatureCertificate, boolean deleted, byte[] signature) {
		this.timeOfExport = timeOfExport;
		this.exportEndTime = exportEndTime;
		this.exportStartTime = exportStartTime;
		this.logDataHash = logDataHash;
		this.previousExportHash = previousExportHash;
		this.currentHashAlgorithm = currentHashAlgorithm;
		this.signatureCertificate = null;
		if (signatureCertificate != null) {
			try {
				this.signatureCertificate = signatureCertificate.getEncoded();
			} catch (CertificateEncodingException e) {
				log.error(e);
			}
		}
		this.deleted = deleted;
		this.signature = signature;
	}

    public ProtectedLogExportRow(ResultSet rs) {
		try {
	    	// Ignore pk
			this.timeOfExport = rs.getLong(2);
			this.exportEndTime = rs.getLong(3);
			this.exportStartTime = rs.getLong(4);
			if (rs.getString(5) == null) {
				this.logDataHash =null;
			} else {
				this.logDataHash = Base64.decode(rs.getString(5).getBytes());
			}
			if (rs.getString(6) == null) {
				this.previousExportHash =null;
			} else {
				this.previousExportHash = Base64.decode(rs.getString(6).getBytes());
			}
			this.currentHashAlgorithm = rs.getString(7);
			if (rs.getString(8) == null) {
				this.signatureCertificate =null;
			} else {
				this.signatureCertificate = Base64.decode(rs.getString(8).getBytes());
			}
			this.deleted = rs.getBoolean(9);
			if (rs.getString(10) == null) {
				this.signature = null;
			} else {
				this.signature = Base64.decode(rs.getString(10).getBytes());
			}
		} catch (SQLException e) {
    		log.error(e);
		}
	}
    
    public boolean equals(ProtectedLogExportRow p) {
    	return p != null && exportStartTime == p.getExportStartTime() && exportEndTime == p.getExportEndTime() && timeOfExport == p.getTimeOfExport();
    }

	public long getTimeOfExport() { return timeOfExport; }
    public long getExportEndTime() { return exportEndTime; }
    public long getExportStartTime() { return exportStartTime; }
    public byte[] getLogDataHash() {  return logDataHash; }
    public byte[] getPreviosExportHash() { return previousExportHash; }
    public String getCurrentHashAlgorithm() { return currentHashAlgorithm; }
    public byte[] getSignatureCertificateAsByteArray() { return signatureCertificate; }
    public Certificate getSignatureCertificate() {
    	try {
    		return CertTools.getCertfromByteArray(signatureCertificate);
    	} catch (CertificateException e) {
    		log.error(e);
    		return null;
    	}
    }
    public boolean getDeleted() { return deleted; }
    public byte[] getSignature() { return signature; }

    public void setSignature(byte[] signature) {
		this.signature = signature;
	}

    /**
     * @param includeProtection is true if the protection field should be included.
     */
	public byte[] getAsByteArray(boolean includeProtection) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos;
		try {
			dos = new DataOutputStream(baos);
			dos.writeLong(timeOfExport);
			dos.writeLong(exportEndTime);
			dos.writeLong(exportStartTime);
			if (logDataHash != null) {
				dos.write(logDataHash);
			}
			if (previousExportHash != null) {
				dos.write(previousExportHash);
			}
			if (currentHashAlgorithm != null) {
				dos.writeUTF(currentHashAlgorithm);
			}
			if (signatureCertificate != null) {
				dos.write(signatureCertificate);
			}
			dos.writeBoolean(deleted);
			if (includeProtection && signature != null) {
				dos.write(signature);
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

}

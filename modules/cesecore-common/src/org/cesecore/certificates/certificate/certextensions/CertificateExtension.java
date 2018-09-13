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
package org.cesecore.certificates.certificate.certextensions;

import java.io.IOException;
import java.io.Serializable;
import java.security.PublicKey;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Base class for a certificate extension.
 * All extensions should inherit this class.
 * 
 * The methods that need implementation is getValue
 * 
 * @version $Id$
 */
public abstract class CertificateExtension implements Serializable {
	
	private static final long serialVersionUID = -7708267512352607118L;
	
	// This attribute should be removed when support for EJBCA 6.4.0 is dropped. This attribute has been replaced by OID as an extension's identifying attribute.
	// By the time we dropped support for Ejbca 6.4.0, this attribute will not be significant in any way and any references to it can be removed without replacement.
	@Deprecated
    private int id;
	private String oID;
	private String displayName;
	private boolean criticalFlag;
	private boolean requiredFlag;
	private Properties properties;
	
	/**
	 * Constructor for creating a Certificate Extension. 
	 */
	public CertificateExtension() {
		super();
	}

	/**
	 * @return the unique id of the extension
	 */
	public int getId() {
		return id;
	}

	/**
	 * @return The unique OID of the extension
	 */
	public String getOID() {
		return oID;
	}
	
	/**
	 * @param The unique OID of the extension
	 */
	public void setOID(String oID) {
		this.oID = oID.trim();
	}
	
	/**
	 * @return This extension's readable name
	 */
	public String getDisplayName() {
	    return displayName;
	}
	
	/**
	 * @param The extension's readable name
	 */
	public void setDisplayName(String displayName) {
	    this.displayName = displayName;
	}
	/**
	 * @return flag indicating if the extension should be marked as critical or not.
	 */
	public boolean isCriticalFlag() {
		return criticalFlag;
	}

	/**
	 * @param flag indicating if the extension should be marked as critical or not.
	 */
	public void setCriticalFlag(boolean criticalFlag) {
		this.criticalFlag = criticalFlag;
	}
	
	/**
     * @return flag indicating if the extension should be marked as required or not.
     */
    public boolean isRequiredFlag() {
        return requiredFlag;
    }

    /**
     * @param flag indicating if the extension should be marked as required or not.
     */
    public void setRequiredFlag(final boolean requiredFlag) {
        this.requiredFlag = requiredFlag;
    }
	

	/**
	 * The properties configured for this extension. The properties are stripped
	 * of the beginning "idX.property.". So searching for the property
	 * "id1.property.value" only the key "value" should be used in the returned property.
	 * 
	 * @return the properties configured for this certificate extension.
	 */
	public Properties getProperties() {
		return properties;
	}
	
	/**
	 * Method that initializes the CertificateExtension
	 * 
	 * @param id, the uniqueID of the extension
	 * @param oID, the OID 
	 * @param criticalFlag if the extension should be marked as critical or not.
	 * @param requiredFlag if the extension should be marked as required or not. 
	 * @param config the complete configuration property file.
	 */
	public void init(int id, String oID, String displayName, boolean criticalFlag, final boolean requiredFlag, Properties extensionProperties){
		this.id = id;
		this.oID = oID.trim();
		this.displayName = displayName;
		this.criticalFlag = criticalFlag;
		this.requiredFlag = requiredFlag;
		this.properties = extensionProperties;
	}
	
	/**
	 * Method that should return the ASN1Encodable value used in the extension
	 * this is the method at all implementors must implement.
	 * 
	 * @param userData the userdata of the issued certificate.
	 * @param ca the CA data with access to all the keys etc. For CA certificates, this is the CA itself.
	 * @param certProfile the certificate profile
	 * @param userPublicKey public key of the user, or null if not available
	 * @param caPublicKey public key of the CA, or null if not available
	 * @param val validity of certificate where the extension will be added
	 * @return a ASN1Encodable or null, if this extension should not be used, which was determined from the values somehow.
	 * @throws CertificateExtensionException if there was an error constructing the certificate extension
	 * 
     * @deprecated Callers should use the getValueEncoded method as this method might not be supported by all implementations. Implementors can
     * still implement this method if they prefer as it gets called from getValueEncoded.
	 */
    public abstract ASN1Encodable getValue(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException;

	/**
	 * Method that should return the byte[] value used in the extension. 
	 * 
	 * The default implementation of this method first calls the getValue() 
	 * method and then encodes the result as an byte array. 
	 * CertificateExtension implementors has the choice of overriding this 
	 * method if they want to include byte[] data in the certificate that
	 * is not necessarily an ASN.1 structure otherwise the getValue method 
	 * can be implemented as before.
	 * 
	 * @param userData the userdata of the issued certificate.
	 * @param ca the CA data with access to all the keys etc
	 * @param certProfile the certificate profile
	 * @param userPublicKey public key of the user, or null if not available
	 * @param caPublicKey public key of the CA, or null if not available
     * @param val validity of certificate where the extension will be added
	 * @return a byte[] or null, if this extension should not be used, which was determined from the values somehow.
	 * @throws CertificateExtensionException if there was an error constructing the certificate extensio
     *
	 */
    public byte[] getValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException {
		final byte[] result;
		final ASN1Encodable value = getValue(userData, ca, certProfile, userPublicKey, caPublicKey, val);
		if (value == null) {
			result = null;
		} else {
		    try {
		        result = value.toASN1Primitive().getEncoded();
		    } catch (IOException ioe) {
		        throw new CertificateExtensionException(ioe.getMessage(), ioe);
		    }
		}
		return result;
	}
	
}

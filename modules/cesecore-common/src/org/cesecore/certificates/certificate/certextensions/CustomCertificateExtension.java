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

import java.security.PublicKey;
import java.util.Map;
import java.util.Properties;

import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Interface for custom certificate extensions.
 * 
 * @version $Id$
 *
 */
public interface CustomCertificateExtension {

    String[] BOOLEAN = {"true", "false"};
    
    
    /**
     * @return the unique id of the extension
     */
    int getId();
    
    /**
     * @return The unique OID of the extension
     */
    String getOID();
    
    /**
     * 
     * @return a map containing available extension properties as keys, along with possible values. 
     */
    Map<String, String[]> getAvailableProperties();
    

    /**
     * @return This extension's readable name
     */
    String getDisplayName();
    
    /**
     * @return flag indicating if the extension should be marked as critical or not.
     */
    boolean isCriticalFlag();
    
    /**
     * @return flag indicating if the extension should be marked as required or not.
     */
    boolean isRequiredFlag();
    
    /**
     * The propertes configured for this extension. The properties are stripped
     * of the beginning "idX.property.". So searching for the property
     * "id1.property.value" only the key "value" should be used in the returned property.
     * 
     * @return the properties configured for this certificate extension.
     */
    Properties getProperties();
    
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
    byte[] getValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
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
     * @param oid OID used to fetch extension data value from the request, in case of dynamic extension.
     * @return a byte[] or null, if this extension should not be used, which was determined from the values somehow.
     * @throws CertificateExtensionException if there was an error constructing the certificate extension.
     *
     */
    byte[] getValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val, String oid) throws CertificateExtensionException;
}

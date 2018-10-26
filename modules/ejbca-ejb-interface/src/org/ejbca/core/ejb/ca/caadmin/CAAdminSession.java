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
package org.ejbca.core.ejb.ca.caadmin;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.ejb.EJBException;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CesecoreException;
import org.cesecore.audit.enums.EventType;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CANameChangeRenewalException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;

/**
 * Administrates and manages CAs in EJBCA system.
 * 
 * @version $Id$
 */
public interface CAAdminSession {

    /**
     * Creates a certificate request that should be sent to External CA for
     * processing. This command will not affect the current issuing key or
     * certificate.
     * 
     * @param authenticationToken
     *            the administrator performing the action
     * @param caid
     *            id of the CA that should create the request
     * @param cachain
     *            A Collection of CA-certificates, can be either a collection
     *            of Certificate or byte[], or even empty collection or null.
     * @param nextSignKeyAlias
     *            The next key alias to use for this request.
     *            If null, then a new key pair will be generated named using
     *            the key sequence.
     * @return request message in binary format, can be a PKCS10 or CVC request
     */
    byte[] makeRequest(AuthenticationToken authenticationToken, int caid, Collection<?> certChain, String nextSignKeyAlias)
            throws AuthorizationDeniedException, CertPathValidatorException, CryptoTokenOfflineException;

    /**
     * If the CA can do so, this method signs another entity's CSR, for
     * authentication. Prime example of for EU EAC ePassports where the DVs
     * initial certificate request is signed by the CVCA. The signature
     * algorithm used to sign the request will be whatever algorithm the CA uses
     * to sign certificates.
     * 
     * @param caid the CA that should sign the request
     * @param request
     *            binary certificate request, the format should be understood by
     *            the CA
     * @return binary certificate request, which is the same as passed in except
     *         also signed by the CA, or it might be the exact same if the CA
     *         does not support request signing
     */
    byte[] createAuthCertSignRequest(AuthenticationToken authenticationToken, int caid, byte[] certSignRequest)
            throws AuthorizationDeniedException, CADoesntExistsException, CryptoTokenOfflineException;

    /**
     * Receives a certificate response from an external CA and sets the newly
     * created CAs status to active.
     * 
     * @param admin
     *            The administrator performing the action
     * @param caid
     *            The caid (DN.hashCode()) of the CA that is receiving this
     *            response
     * @param responsemessage
     *            X509ResponseMessage with the certificate issued to this CA
     * @param chain
     *            an optional collection with the CA certificate(s), or null. If
     *            given the complete chain (except this CAs own certificate must
     *            be given). The contents can be either Certificate objects, or byte[]'s with DER encoded certificates.
     * @param nextKeyAlias compare received certificate to this alias's public key
     * @throws EjbcaException
     */
    void receiveResponse(AuthenticationToken authenticationToken, int caid, ResponseMessage responsemessage, Collection<?> cachain,
            String nextKeyAlias) throws AuthorizationDeniedException, CertPathValidatorException, EjbcaException, CesecoreException;

    /**
     * Receives a certificate response from an external CA and sets the newly
     * created CAs status to active.
     * 
     * @param admin
     *            The administrator performing the action
     * @param caid
     *            The caid (DN.hashCode()) of the CA that is receiving this
     *            response
     * @param responsemessage
     *            X509ResponseMessage with the certificate issued to this CA
     * @param chain
     *            an optional collection with the CA certificate(s), or null. If
     *            given the complete chain (except this CAs own certificate must
     *            be given). The contents can be either Certificate objects, or byte[]'s with DER encoded certificates.
     * @param nextKeyAlias compare received certificate to this alias's public key
     * @param futureRollover
     *            If the request is for a certificate that will have a
     *            validity start date in the future. Issued certificates will
     *            use the existing CA certificiate/key until it expires.
     * @throws EjbcaException
     */
    void receiveResponse(AuthenticationToken authenticationToken, int caid, ResponseMessage responsemessage, Collection<?> cachain,
            String nextKeyAlias, boolean futureRollover) throws AuthorizationDeniedException, CertPathValidatorException, EjbcaException, CesecoreException;
    
    /**
     * Processes a Certificate Request from an external CA.
     * 
     * @param cainfo
     *            the info for the CA that should be created, or already exists.
     *            Don't forget to set signedBy in the info.
     */
    ResponseMessage processRequest(AuthenticationToken admin, CAInfo cainfo, RequestMessage requestmessage) throws CAExistsException,
            CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException;
    
    /**
     * Add an external CA's certificate as a CA.
     * 
     * @param certificates contains the full certificate chain down to the leaf CA to be imported. Use {@link org.cesecore.util.EJBTools#wrapCertCollection} to convert to the wrapper type.
     * @throws CertificateImportException in the case the certificate was already imported or the provided certificates could not be used.
     */
    void importCACertificate(AuthenticationToken authenticationToken, String caName, Collection<CertificateWrapper> wrappedCerts)
            throws AuthorizationDeniedException, CAExistsException, IllegalCryptoTokenException, CertificateImportException;
    
    /**
     * Update an existing external CA's certificate chain.
     * 
     * We allow the same leaf CA certificate to be re-imported in the case where the chain has changed.
     * 
     * @param certificates contains the full certificate chain down to the leaf CA to be imported. Use {@link org.cesecore.util.EJBTools#wrapCertCollection} to convert to the wrapper type.
     * @throws CertificateImportException in the case the certificate was already imported or the provided certificates could not be used.
     */
    void updateCACertificate(final AuthenticationToken authenticationToken, final int caId, final Collection<CertificateWrapper> wrappedCerts)
            throws CADoesntExistsException, AuthorizationDeniedException, CertificateImportException;

    /**
     * Inits an external CA service. this means that a new key and certificate
     * will be generated for this service, if it exists before. If it does not
     * exist before it will be created.
     */
    void initExternalCAService(AuthenticationToken admin, int caid, ExtendedCAServiceInfo info) throws CADoesntExistsException,
            AuthorizationDeniedException, CAOfflineException;

    /**
     * Unlike the similarly named method initializeAndUpgradeCAs(), this method initializes a
     * previously uninitialized CA by setting its status to active and generating certificate chains
     * for it. 
     * 
     * @param authenticationToken an authentication token
     * @param caInfo representing the CA
     * @throws AuthorizationDeniedException if user was denied authorization to edit CAs
     * @throws CryptoTokenOfflineException if the keystore defined by the cryptotoken in caInfo has no keys
     * @throws InvalidAlgorithmException if the CA signature algorithm is invalid
     */
    void initializeCa(AuthenticationToken authenticationToken, CAInfo caInfo) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, InvalidAlgorithmException;

    /**
     * Renews a existing CA certificate using the requested keys or by
     * generating new keys. The specified notBefore date will be used. 
     * Other data about the new CA is taken from database. This
     * method is used for renewing CAs internally in EJBCA. For renewing CAs
     * signed by external CAs, makeRequest is used to generate a certificate
     * request.
     * 
     * @param caid the caid of the CA that will be renewed
     * @param nextSignKeyAlias
     *            The cryptoTokenAlias to use for the next keys or null to
     *            generate a new key pair using the CA key sequence.
     * @param customNotBefore 
     *            date to use as notBefore date in the new certificate
     *            or null if not custom date should be used which means 
     *            that the current time will be used (normal case).
     * @param createLinkCertificate
     *            generates an additional certificate stored in the CA object
     *            with the next keys signed by the current keys. 
     * @throws AuthorizationDeniedException 
     * @throws CryptoTokenOfflineException 
     * @throws CryptoTokenAuthenticationFailedException
     */
    void renewCA(AuthenticationToken administrator, int caid, String nextSignKeyAlias, Date customNotBefore, boolean createLinkCertificate)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

    /**
     * Replaces the certificate chain and key in a CA with the roll over chain and key.
     * Intended to be called after a roll over chain/key, created with {@link CAAdminSession#makeRequest(AuthenticationToken, int, Collection, String, boolean)}
     * with futureRollover=true, has became valid.
     *
     * @param caid The CAId of the CA.
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenOfflineException
     */
    void rolloverCA(AuthenticationToken administrator, int caid) throws AuthorizationDeniedException, CryptoTokenOfflineException;

    /**
     * Renews a existing CA certificate using the requested keys or by
     * generating new keys. The specified notBefore date will be used. 
     * Other data about the new CA is taken from database. This
     * method is used for renewing CAs internally in EJBCA. For renewing CAs
     * signed by external CAs, makeRequest is used to generate a certificate
     * request.
     * 
     * @param caid the caid of the CA that will be renewed
     * @param regenerateKeys
     *            if true and the CA have a soft CAToken the keys are
     *            regenerated before the certificate request.
     * @param customNotBefore 
     *            date to use as notBefore date in the new certificate
     *            or null if not custom date should be used which means 
     *            that the current time will be used (normal case).
     * @param createLinkCertificate
     *            generates an additional certificate stored in the CA object
     *            with the new keys signed by the current keys.
     *            For CVC CAs this is ignored and the link certificate is always generated.
     * @throws AuthorizationDeniedException if admin was not authorized to this CA
     * @throws CADoesntExistsException if CA with ID caid didn't exist.
     * @throws CryptoTokenOfflineException
     */
    void renewCA(AuthenticationToken admin, int caid, boolean regenerateKeys, Date customNotBefore, boolean createLinkCertificate)
            throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException;
    
    /**
     * Renews an existing CA certificate using the requested keys or by generating new keys. After renewal CA certificate will have
     * new name (subjectDN) specified with newCAName. CA name change operation is not part of RFC 5280 and is introduced with ICAO 9303 7th edition.
     * If generated, linked certificates will have IssuerDN of old-named and SubjectDN of new-named CA certificate
     * and will be signed by old-named CA certificate. This operation is intended to be used with ICAO CSCA,
     * although it should work with every X509 CA. This operation is not supported for CVC CA.
     * The specified notBefore date and newCAName will be used. Other data about the new CA is taken from database. 
     * This method is used for renewing CAs internally in EJBCA. For renewing CAs
     * signed by external CAs, makeRequest is used to generate a certificate request.
     * 
     * @param caid the caid of the CA that will be renewed
     * @param regenerateKeys
     *            if true and the CA have a soft CAToken the keys are
     *            regenerated before the certificate request.
     * @param customNotBefore 
     *            date to use as notBefore date in the new certificate
     *            or null if not custom date should be used which means 
     *            that the current time will be used (normal case).
     * @param createLinkCertificate
     *            generates an additional certificate stored in the CA object
     *            with the new keys signed by the current keys.
     *            For CVC CAs this is ignored and the link certificate is always generated.
     * @param newSubjectDN 
     *            new SubjectDN/IssuerDN of CA certificate (new CA Name will be Common Name value)
     * @throws AuthorizationDeniedException if admin was not authorized to this CA
     * @throws CADoesntExistsException if CA with ID caid didn't exist.
     * @throws CryptoTokenOfflineException 
     * @throws CANameChangeRenewalException if the specified newSubjectDN is not valid for some reason
     * (same as the current one, does not contain the Common Name or CA Name already exists under this name)
     */
    void renewCANewSubjectDn(AuthenticationToken admin, int caid, boolean regenerateKeys, Date customNotBefore, boolean createLinkCertificate, String newSubjectDN)
            throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CANameChangeRenewalException;
    
    /**
     * Renews an existing CA certificate using the requested keys or by generating new keys. After renewal CA certificate will have
     * new name (subjectDN) specified with newCAName. CA name change operation is not part of RFC 5280 and is introduced with ICAO 9303 7th edition.
     * If generated, linked certificates will have IssuerDN of old-named and SubjectDN of new-named CA certificate
     * and will be signed by old-named CA certificate. This operation is intended to be used with ICAO CSCA,
     * although it should work with every X509 CA. This operation is not supported for CVC CA.
     * The specified notBefore date and newCAName will be used. Other data about the new CA is taken from database. 
     * This method is used for renewing CAs internally in EJBCA. For renewing CAs
     * signed by external CAs, makeRequest is used to generate a certificate request.
     * 
     * @param caid the caid of the CA that will be renewed
     * @param nextSignKeyAlias
     *            The cryptoTokenAlias to use for the next keys or null to
     *            generate a new key pair using the CA key sequence.
     * @param customNotBefore 
     *            date to use as notBefore date in the new certificate
     *            or null if not custom date should be used which means 
     *            that the current time will be used (normal case).
     * @param createLinkCertificate
     *            generates an additional certificate stored in the CA object
     *            with the new keys signed by the current keys.
     *            For CVC CAs this is ignored and the link certificate is always generated.
     * @param newSubjectDN 
     *            new SubjectDN/IssuerDN of CA certificate (new CA Name will be Common Name value)
     * @throws AuthorizationDeniedException if admin was not authorized to this CA
     * @throws CADoesntExistsException if CA with ID caid didn't exist.
     * @throws CryptoTokenOfflineException 
     * @throws CANameChangeRenewalException if the specified newSubjectDN is not valid for some reason
     * (same as the current one, does not contain the Common Name or CA Name already exists under this name) 
     */
    void renewCANewSubjectDn(AuthenticationToken admin, int caid, String nextSignKeyAlias, Date customNotBefore, boolean createLinkCertificate, String newSubjectDN)
            throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CANameChangeRenewalException;

    /**
     * Method that revokes the CA. After this is all certificates created by
     * this CA revoked and a final CRL is created.
     * 
     * @param admin the administrator requesting the revocation
     * @param caid the ID of the CA
     * @param reason one of RevokedCertInfo.REVOCATION_REASON values.
     */
    void revokeCA(AuthenticationToken admin, int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Method that is used to create a new CA from an imported keystore from
     * another type of CA, for example OpenSSL.
     * 
     * @param admin Administrator
     * @param caname
     *            the CA-name (human readable) the newly created CA will get
     * @param p12file a byte array of old server p12 file.
     * @param keystorepass used to unlock the keystore.
     * @param privkeypass used to unlock the private key.
     * @param privateSignatureKeyAlias
     *            the alias for the private key in the keystore.
     * @param privateEncryptionKeyAlias
     *            the alias for the private encryption key in the keystore
     */
    void importCAFromKeyStore(AuthenticationToken admin, String caname, byte[] p12file, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias);

    /**
     * Method that is used to create a new CA from keys and certificates.
     * 
     * @param caname The name the new CA will have
     * @param keystorepass The keystore password the CA will have
     * @param signatureCertChain The CA certificate(s)
     * @param p12PublicSignatureKey CA public signature key
     * @param p12PrivateSignatureKey CA private signature key
     * @param p12PrivateEncryptionKey
     *            CA private encryption key, or null to generate a new
     *            encryption key
     * @param p12PublicEncryptionKey
     *            CA public encryption key, or null to generate a new
     *            encryption key
     * @throws CAOfflineException if CRLs can not be generated because imported CA did not manage to get online
     */
    void importCAFromKeys(AuthenticationToken admin, String caname, String keystorepass, java.security.cert.Certificate[] signatureCertChain,
            java.security.PublicKey p12PublicSignatureKey, java.security.PrivateKey p12PrivateSignatureKey,
            java.security.PrivateKey p12PrivateEncryptionKey, java.security.PublicKey p12PublicEncryptionKey)
            throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, IllegalCryptoTokenException,
            CAExistsException, AuthorizationDeniedException, CAOfflineException;

    /**
     * Method that is used to create a new CA from keys on an HSM and
     * certificates in a file.
     * 
     * @param admin
     *            Administrator
     * @param caname
     *            the CA-name (human readable) the newly created CA will get
     * @param signatureCertChain
     *            chain of certificates, this CAs certificate first.
     * @param catokenpassword
     *            used to unlock the HSM keys.
     * @param catokenclasspath
     *            classpath to one of the HardToken classes, for example
     *            org.cesecore.keys.token.PKCS11CryptoToken.
     * @param catokenproperties
     *            the catoken properties, same as usually entered in the
     *            adminGUI for hard token CAs.
     * 
     * @throws AuthorizationDeniedException if imported CA was signed by a CA user does not have authorization to.
     * @throws CAExistsException if the CA already exists
     * @throws CAOfflineException if CRLs can not be generated because imported CA did not manage to get online
     * @throws CryptoTokenAuthenticationFailedException if authentication to the crypto token failed.
     * @throws CryptoTokenOfflineException if crypto token is unavailable.
     * @throws NoSuchSlotException if no slot as defined by the label in catokenproperties could be found
     * @throws IllegalCryptoTokenException the certificate chain is incomplete
     */
    void importCAFromHSM(AuthenticationToken admin, String caname, Certificate[] signatureCertChain, String catokenpassword,
            String catokenclasspath, String catokenproperties) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            IllegalCryptoTokenException, CAExistsException, AuthorizationDeniedException, CAOfflineException,
            NoSuchSlotException;

    /**
     * Exports a CA to file. The method only works for soft tokens.
     * 
     * @param admin Administrator
     * @param caname the CA-name (human readable) the CA
     * @param keystorepass used to lock the keystore.
     * @param privkeypass used to lock the private key.
     * @param privateSignatureKeyAlias
     *            the alias for the private signature key in the keystore.
     * @param privateEncryptionKeyAlias
     *            the alias for the private encryption key in teh keystore
     * @return A byte array of the CAs p12 in case of X509 CA and pkcs8 private
     *         certificate signing key in case of CVC CA.
     */
    byte[] exportCAKeyStore(AuthenticationToken admin, String caname, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias);

    /**
     * Method returning a Collection of Certificate of all CA certificates known
     * to the system. Certificates for External CAs or CAs that are awaiting
     * certificate response are not returned, because we don't have certificates
     * for them. Uses getAvailableCAs to list CAs.
     */
    Collection<Certificate> getAllCACertificates();

    /**
     * Activates an 'Offline' CA Token and sets the CA status to active and
     * ready for use again. The admin must be authorized to
     * "/ca_functionality/basic_functions/activate_ca" in order to
     * activate/deactivate.
     * 
     * @param admin the administrator calling the method
     * @param caid the is of the CA to activate
     * @param authorizationcode the authorization code used to unlock the CA tokens private keys.
     * @throws AuthorizationDeniedException
     *             it the administrator isn't authorized to activate the CA.
     * @throws ApprovalException
     *             if an approval already is waiting for specified action
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     */
    void activateCAService(AuthenticationToken admin, int caid) throws AuthorizationDeniedException, ApprovalException,
            WaitingForApprovalException, CADoesntExistsException;

    /**
     * Deactivates an 'active' CA token and sets the CA status to offline. The
     * admin must be authorized to
     * "/ca_functionality/basic_functions/activate_ca" in order to
     * activate/deactivate.
     * 
     * @param admin the administrator calling the method
     * @param caid the is of the CA to activate.
     * @throws AuthorizationDeniedException
     *             it the administrator isn't authorized to activate the CA.
     * @throws EjbcaException
     *             if the given caid couldn't be found or its status is wrong.
     */
    void deactivateCAService(AuthenticationToken admin, int caid) throws AuthorizationDeniedException, CADoesntExistsException;

    /**
     * Removes the catoken keystore from the database and sets its status to
     * {@link CryptoToken#STATUS_OFFLINE}.
     * 
     * The signature algorithm, encryption algorithm, key algorithm and other
     * properties are not removed so that the keystore can later by restored by
     * using

     * {@link CAAdminSession#restoreCAKeyStore(AuthenticationToken, String, byte[], String, String, String, String)}
     * .
     * 
     * 
     * @param admin Administrator
     * @param caname Name (human readable) of CA for which the keystore should be removed
     * @throws EJBException in case if the catoken is not a soft catoken
     * 

     * @see CAAdminSession#exportCAKeyStore(AuthenticationToken, String, String, String, String, String)
     */
    void removeCAKeyStore(AuthenticationToken admin, String caname) throws EJBException;

    /**
     * Restores the keys for the CAToken from a KeyStore.
     * 
     * @param admin Administrator
     * @param caname
     *            Name (human readable) of the CA for which the keystore should
     *            be restored
     * @param p12file The KeyStore to read keys from
     * @param keystorepass Password for the KeyStore
     * @param privkeypass Password for the private key
     * @param privateSignatureKeyAlias
     *            Alias of the signature key in the KeyStore
     * @param privateEncryptionKeyAlias
     *            Alias of the encryption key in the KeyStore
     * @throws EJBException
     *             in case of the CAToken is not a soft CAToken or if the CA
     *             already has an active CAToken or if any of the aliases can
     *             not be found or if the KeyStore does not contain the right
     *             private key
     */
    void restoreCAKeyStore(AuthenticationToken admin, String caname, byte[] p12file, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias) throws EJBException;

    /**
     * Method used to edit the data of a CA.
     * 
     * Not all of the CAs data can be edited after the creation, therefore will
     * only the values from CAInfo that is possible be updated.
     * But if the CA is in uninitialized state then the Subject DN (and CA ID)
     * may in fact be changed, which is not possible otherwise. 
     * 
     * @param cainfo CAInfo object containing values that will be updated
     * 
     * @see org.ejbca.core.model.ca.caadmin.CAInfo
     * @see org.ejbca.core.model.ca.caadmin.X509CAInfo
     */
    void editCA(AuthenticationToken admin, CAInfo cainfo) throws AuthorizationDeniedException;

    /**
     * Method used to check if certificate profile id exists in any CA.
     * 
     * @param admin The admin performing the action 
     * @param certificateprofileid the ID of the sought certificate profile
     * @return a list of names of the CAs using the certificate profile 
     */
    List<String> getCAsUsingCertificateProfile(int certificateprofileid);

    /**
     * Method used to check if publishers id exists in any CAs CRLPublishers
     * Collection.
     */
    boolean exitsPublisherInCAs(int publisherid);

    /**
     * Method that publishes the given CA certificate chain to the list of
     * publishers. Is mainly used when CA is created.
     * 
     * @param admin Information about the administrator performing the event.
     * @param certificatechain Certificate chain to publish
     * @param usedpublishers
     *            a collection if publisher id's (Integer) indicating which
     *            publisher that should be used.
     * @param caDataDN
     *            DN from CA data. If a the CA certificate does not have a DN
     *            object to be used by the publisher this DN could be searched
     *            for the object.
     */
    void publishCACertificate(AuthenticationToken admin, Collection<Certificate> certificatechain, Collection<Integer> usedpublishers,
            String caDataDN) throws AuthorizationDeniedException;

    /**
     * (Re-)Publish the last CRLs for a CA.
     *
     * @param admin            Information about the administrator performing the event.
     * @param caCert           The certificate for the CA to publish CRLs for
     * @param usedpublishers   a collection if publisher id's (Integer) indicating which publisher that should be used.
     * @param caDataDN         DN from CA data. If a the CA certificate does not have a DN object to be used by the publisher this DN could be searched for the object.
     * @param doPublishDeltaCRL should delta CRLs be published?
     * @throws AuthorizationDeniedException 
     */
    void publishCRL(AuthenticationToken admin, Certificate caCert, Collection<Integer> usedpublishers, String caDataDN,
            boolean doPublishDeltaCRL) throws AuthorizationDeniedException;

    /** 
     * This method returns a set containing IDs of all authorized publishers. This set will be the sum of the following:
     * 
     * * Unassigned publishers
     * * Publishers assigned to CAs that the admin has access to
     * * Publishers assigned to Certificate Profiles that the admin has access to
     * * Publishers assigned to Peers (if Enterprise mode) that the admin has access to 
     * 
     * @return a Set of IDs of authorized publishers. 
     */
    Set<Integer> getAuthorizedPublisherIds(AuthenticationToken admin);

    /**
     * This method returns a set containing IDs of authorized publishers, except publishers of excluded types. This set will be the sum of the following:
     *
     * * Unassigned publishers
     * * Publishers assigned to CAs that the admin has access to
     * * Publishers assigned to Certificate Profiles that the admin has access to
     * * Publishers assigned to Peers (if Enterprise mode) that the admin has access to
     *
     * @return a Set of IDs of authorized publishers.
     */
    Set<Integer> getAuthorizedPublisherIds(AuthenticationToken admin, List<Integer> excludedTypes);
    
    /**
     * Method used to create a new CA.
     * 
     * The cainfo parameter should at least contain the following information.
     * SubjectDN Name (if null then is subjectDN used).
     * Description (optional) Status (SecConst.CA_ACTIVE or
     * SecConst.CA_WAITING_CERTIFICATE_RESPONSE) SignedBy (CAInfo.SELFSIGNED,
     * CAInfo.SIGNEDBYEXTERNALCA or CAId of internal CA)
     * 
     * @throws CAExistsException if CA defined by cainfo already exists.
     * @throws CryptoTokenOfflineException if crypto token was not available.
     * @throws InvalidAlgorithmException if the CA signature algorithm is invalid
     * 
     * For other optional values see:
     * @see org.ejbca.core.model.ca.caadmin.CAInfo
     * @see org.ejbca.core.model.ca.caadmin.X509CAInfo
     */
    void createCA(AuthenticationToken admin, CAInfo cainfo) throws CAExistsException, AuthorizationDeniedException,
            CryptoTokenOfflineException, InvalidAlgorithmException;

    /**
     * Method used to perform a extended CA Service, like OCSP CA Service.
     *
     * @param admin   Information about the administrator or admin performing the event.
     * @param caid    the CA that should perform the service
     * @param request a service request.
     * @return A corresponding response.
     * @throws IllegalExtendedCAServiceRequestException
     *                                 if the request was invalid.
     * @throws ExtendedCAServiceNotActiveException
     *                                 thrown when the service for the given CA isn't activated
     * @throws CADoesntExistsException The given caid does not exist.
     * @throws OperatorCreationException 
     * @throws CertificateException 
     * @throws CertificateEncodingException 
     */
    ExtendedCAServiceResponse extendedService(AuthenticationToken admin, int caid, ExtendedCAServiceRequest request)
            throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException,
            CADoesntExistsException, AuthorizationDeniedException, CertificateEncodingException, CertificateException, OperatorCreationException;

    /**
     * Makes sure that no CAs are cached to ensure that we read from database
     * next time we try to access it.
     * Present in remote interface so we can call it from CLI.
     */
    void flushCACache();

    /** @return the latest link certificate (if any) */
    byte[] getLatestLinkCertificate(int caId) throws CADoesntExistsException;

    /**
     * Updates all references to the given CAId/SubjectDN in the database.
     * This method must be called when the Subject DN of a CA is changed.
     * 
     * @param authenticationToken Authentication token
     * @param fromId CA Id to change from.
     * @param toId CA Id to change to.
     * @param toDN Subject DN to change to.
     */
    void updateCAIds(AuthenticationToken authenticationToken, int fromId, int toId, String toDN) throws AuthorizationDeniedException;
    
    /**
     * Writes a custom audit log into the database.
     *
     * Authorization requirements: <pre>
     * - /administrator
     * - /secureaudit/log_custom_events (must be configured in advanced mode when editing access rules)
     * </pre>
     *
     * @param authenticationToken the authentication token.
     * @param type a user defined string used as a prefix in the log comment.
     * @param caName the name of the CA related to the event or null for the administrators CA to be used.
     * @param username the name of the related user or null if no related user exists.
     * @param certificateSn the certificates SN related to the log event or null if no certificate is related to this log event.
     * @param msg the message data used in the log comment. The log comment will have a syntax of 'type : msg'.
     * @param event the event type (log level) of the log entry ({@link org.ejbca.core.ejb.audit.enums.EjbcaEventTypes}).
     * @throws AuthorizationDeniedException if the administrators isn't authorized to log.
     * @throws CADoesntExistsException if a referenced CA does not exist.
     */
    void customLog(AuthenticationToken authenticationToken, String type, String caName, String username, String certificateSn, String msg, EventType event) 
            throws AuthorizationDeniedException, CADoesntExistsException;
}

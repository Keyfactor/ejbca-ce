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

package org.ejbca.core.ejb.ca.sign;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.CADataLocal;
import org.ejbca.core.ejb.ca.caadmin.CADataLocalHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.catoken.CATokenContainer;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Creates and signs certificates.
 *
 * @ejb.bean description="Session bean handling core CA function,signing certificates"
 *   display-name="RSASignSessionSB"
 *   name="RSASignSession"
 *   jndi-name="RSASignSession"
 *   local-jndi-name="SignSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry description="Name of PRNG algorithm used for random source - refer to Appendix A in the
 * Java Cryptography Architecture API Specification And Reference for
 * information about standard PRNG algorithm names"
 *   name="randomAlgorithm"
 *   type="java.lang.String"
 *   value="SHA1PRNG"
 *
 * @ejb.ejb-external-ref description="The CA entity bean"
 *   view-type="local"
 *   ref-name="ejb/CADataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ca.caadmin.CADataLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.CADataLocal"
 *   link="CAData"
 *
 * @ejb.ejb-external-ref description="The CRL Create bean"
 *   view-type="local"
 *   ref-name="ejb/CreateCRLSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal"
 *   link="CreateCRLSession"
 *   
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref description="The Certificate store used to store and fetch certificates"
 *   view-type="local"
 *   ref-name="ejb/CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 * @ejb.ejb-external-ref description="The Authentication session used to authenticate users when issuing certificates.
 * Alter this to enable a custom made authentication session implementing the
 * IAuthenticationSessionLocal interface"
 *   view-type="local"
 *   ref-name="ejb/AuthenticationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocal"
 *   link="AuthenticationSession"
 *
 * @ejb.ejb-external-ref description="Publishers are configured to store certificates and CRLs in additional places
 * from the main database. Publishers runs as local beans"
 *   view-type="local"
 *   ref-name="ejb/PublisherSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal"
 *   link="PublisherSession"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   remote-class="org.ejbca.core.ejb.ca.sign.ISignSessionHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   remote-class="org.ejbca.core.ejb.ca.sign.ISignSessionRemote"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.sign.ISignSessionLocal"
 *   
 * @jboss.method-attributes
 *   pattern = "verify*"
 *   read-only = "true"
 *   
 *   @version $Id$
 */
public class RSASignSessionBean extends BaseSessionBean {


    /**
     * Local interfacte to ca admin store
     */
    private CADataLocalHome cadatahome;

    /**
     * Home interface to certificate store
     */
    private ICertificateStoreSessionLocalHome storeHome = null;

    /* Home interface to Authentication session */
    private IAuthenticationSessionLocalHome authHome = null;

    /* Home interface to Publisher session */
    private IPublisherSessionLocalHome publishHome = null;

    /** The local interface of the job runner session bean used to create crls.*/
    private ICreateCRLSessionLocal crlSession;

    /**
     * The local interface of the log session bean
     */
    private ILogSessionLocal logsession;

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    

    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     * @ejb.create-method 
     */
    public void ejbCreate() throws CreateException {
        trace(">ejbCreate()");

        try {
            // Install BouncyCastle provider
            CertTools.installBCProvider();

            // get home interfaces to other session beans used
            storeHome = (ICertificateStoreSessionLocalHome) getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
            authHome = (IAuthenticationSessionLocalHome) getLocator().getLocalHome(IAuthenticationSessionLocalHome.COMP_NAME);

            cadatahome = (CADataLocalHome) getLocator().getLocalHome(CADataLocalHome.COMP_NAME);

            publishHome = (IPublisherSessionLocalHome) getLocator().getLocalHome(IPublisherSessionLocalHome.COMP_NAME);

            // Set up the serial number generator for Certificate Serial numbers
            // The serial number generator is a Singleton, so it can be initialized here and 
            // used by X509CA
            String randomAlgorithm = getLocator().getString("java:comp/env/randomAlgorithm");
            if (randomAlgorithm != null) {
                SernoGenerator.instance().setAlgorithm(randomAlgorithm);
            }
            SernoGenerator.instance().setSernoOctetSize(EjbcaConfiguration.getCaSerialNumberOctetSize());            	
        } catch (Exception e) {
            debug("Caught exception in ejbCreate(): ", e);
            throw new EJBException(e);
        }

        trace("<ejbCreate()");
    }


    /**
     * Gets connection to log session bean
     */
    private ILogSessionLocal getLogSession() {
        if (logsession == null) {
            try {
                ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
                logsession = logsessionhome.create();
            } catch (Exception e) {
                throw new EJBException(e);
            }
        }
        return logsession;
    } //getLogSession

    private ICreateCRLSessionLocal getCRLCreateSession() {
    	if(crlSession == null){
    		try{
    			ICreateCRLSessionLocalHome home = (ICreateCRLSessionLocalHome) getLocator().getLocalHome(ICreateCRLSessionLocalHome.COMP_NAME);
    			crlSession = home.create();
    		}catch(Exception e){
    			throw new EJBException(e);
    		}
    	}
    	return crlSession;
    }

    /**
     * Retrieves the certificate chain for the signer. The returned certificate chain MUST have the
     * RootCA certificate in the last position.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param caid  is the issuerdn.hashCode()
     * @return Collection of Certificate, the certificate chain, never null.
     * @ejb.permission unchecked="true"
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public Collection getCertificateChain(Admin admin, int caid) {
        // get CA
        CADataLocal cadata = null;
        try {
            cadata = cadatahome.findByPrimaryKey(new Integer(caid));
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }

        CA ca = null;
        try {
            ca = cadata.getCA();
        } catch (java.io.UnsupportedEncodingException uee) {
            throw new EJBException(uee);
        } catch(IllegalKeyStoreException e){
            throw new EJBException(e);
        }

        return ca.getCertificateChain();
    }  // getCertificateChain


    /**
     * Creates a signed PKCS7 message containing the whole certificate chain, including the
     * provided client certificate.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param cert  client certificate which we want encapsulated in a PKCS7 together with
     *              certificate chain.
     * @return The DER-encoded PKCS7 message.
     * @throws CADoesntExistsException       if the CA does not exist or is expired, or has an invalid cert
     * @throws SignRequestSignatureException if the certificate is not signed by the CA
     * @ejb.interface-method view-type="both"
     */
    public byte[] createPKCS7(Admin admin, Certificate cert, boolean includeChain) throws CADoesntExistsException, SignRequestSignatureException {
        Integer caid = new Integer(CertTools.getIssuerDN(cert).hashCode());
        return createPKCS7(caid.intValue(), cert, includeChain);
    } // createPKCS7

    /**
     * Creates a signed PKCS7 message containing the whole certificate chain of the specified CA.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param caId  CA for which we want a PKCS7 certificate chain.
     * @return The DER-encoded PKCS7 message.
     * @throws CADoesntExistsException if the CA does not exist or is expired, or has an invalid cert
     * @ejb.interface-method view-type="both"
     */
    public byte[] createPKCS7(Admin admin, int caId, boolean includeChain) throws CADoesntExistsException {
        try {
            return createPKCS7(caId, null, includeChain);
        } catch (SignRequestSignatureException e) {
        	String msg = intres.getLocalizedMessage("error.unknown");
            error(msg, e);
            throw new EJBException(e);
        }
    } // createPKCS7

    /**
     * Internal helper method
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param caId  CA for which we want a PKCS7 certificate chain.
     * @param cert  client certificate which we want ancapsulated in a PKCS7 together with
     *              certificate chain, or null
     * @return The DER-encoded PKCS7 message.
     * @throws CADoesntExistsException if the CA does not exist or is expired, or has an invalid cert
     */
    private byte[] createPKCS7(int caId, Certificate cert, boolean includeChain) throws CADoesntExistsException, SignRequestSignatureException {
    	if (log.isTraceEnabled()) {
            log.trace(">createPKCS7(" + caId + ", " + CertTools.getIssuerDN(cert) + ")");
    	}
        byte[] returnval = null;
        // get CA
        CADataLocal cadata = null;
        try {
            cadata = cadatahome.findByPrimaryKey(new Integer(caId));
        } catch (javax.ejb.FinderException fe) {
            throw new CADoesntExistsException(fe);
        }

        CA ca = null;
        try {
            ca = cadata.getCA();
        } catch (java.io.UnsupportedEncodingException uee) {
            throw new CADoesntExistsException(uee);
        } catch(IllegalKeyStoreException e){
            throw new EJBException(e);
        }

        // Check that CA hasn't expired.
        Certificate cacert = ca.getCACertificate();
        try {
            CertTools.checkValidity(cacert, new Date());
        } catch (CertificateExpiredException e) {
            // Signers Certificate has expired.
            cadata.setStatus(SecConst.CA_EXPIRED);
            ca.setStatus(SecConst.CA_EXPIRED);
        	String msg = intres.getLocalizedMessage("signsession.caexpired", cadata.getSubjectDN());
            throw new CADoesntExistsException(msg);
        } catch (CertificateNotYetValidException cve) {
            throw new CADoesntExistsException(cve);
        }

        returnval = ca.createPKCS7(cert, includeChain);
        log.trace("<createPKCS7()");
        return returnval;
    } // createPKCS7

    /**
     * Requests for a certificate to be created for the passed public key with default key usage
     * The method queries the user database for authorization of the user.
     *
     * @param admin    Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk       the public key to be put in the created certificate.
     * @return The newly created certificate or null.
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws IllegalKeyException     if the public key is of wrong type.
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     */
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException {
        // Default key usage is defined in certificate profiles
        return createCertificate(admin, username, password, pk, -1);
    } // createCertificate

    /**
     * Requests for a certificate to be created for the passed public key with the passed key
     * usage. The method queries the user database for authorization of the user. CAs are only
     * allowed to have certificateSign and CRLSign set.
     *
     * @param admin    Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk       the public key to be put in the created certificate.
     * @param keyusage integer with mask describing desired key usage in format specified by
     *                 X509Certificate.getKeyUsage(). id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
     *                 KeyUsage ::= BIT STRING { digitalSignature        (0), nonRepudiation          (1),
     *                 keyEncipherment         (2), dataEncipherment        (3), keyAgreement (4),
     *                 keyCertSign             (5), cRLSign                 (6), encipherOnly (7),
     *                 decipherOnly            (8) }
     * @return The newly created certificate or null.
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws IllegalKeyException     if the public key is of wrong type.
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     */
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, boolean[] keyusage) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException {
        return createCertificate(admin, username, password, pk, CertTools.sunKeyUsageToBC(keyusage));
    }

    /**
     * Requests for a certificate to be created for the passed public key with the passed key
     * usage. The method queries the user database for authorization of the user. CAs are only
     * allowed to have certificateSign and CRLSign set.
     *
     * @param admin    Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk       the public key to be put in the created certificate.
     * @param keyusage integer with bit mask describing desired keys usage, overrides keyUsage from
     *                 CertificateProfiles if allowed. Bit mask is packed in in integer using constants
     *                 from CertificateData. -1 means use default keyUsage from CertificateProfile. ex. int
     *                 keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *                 digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *                 | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @return The newly created certificate or null.
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws IllegalKeyException     if the public key is of wrong type.
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     */
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, int keyusage) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException {
        return createCertificate(admin, username, password, pk, keyusage, null, null, SecConst.PROFILE_NO_PROFILE, SecConst.CAID_USEUSERDEFINED);
    }

    /**
     * Requests for a certificate to be created for the passed public key with the passed key
     * usage. The method queries the user database for authorization of the user. CAs are only
     * allowed to have certificateSign and CRLSign set.
     *
     * @param admin    Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk       the public key to be put in the created certificate.
     * @param keyusage integer with bit mask describing desired keys usage, overrides keyUsage from
     *                 CertificateProfiles if allowed. Bit mask is packed in in integer using constants
     *                 from CertificateData. -1 means use default keyUsage from CertificateProfile. ex. int
     *                 keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *                 digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *                 | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @param notAfter an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
     * @return The newly created certificate or null.
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws IllegalKeyException     if the public key is of wrong type.
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     */
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, int keyusage, Date notBefore, Date notAfter) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException {
        return createCertificate(admin, username, password, pk, keyusage, notBefore, notAfter, SecConst.PROFILE_NO_PROFILE, SecConst.CAID_USEUSERDEFINED);
    }

    /**
     * Requests for a certificate of the specified type to be created for the passed public key.
     * The method queries the user database for authorization of the user.
     *
     * @param admin    Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param certType integer type of certificate taken from CertificateData.CERT_TYPE_XXX. the
     *                 type CertificateData.CERT_TYPE_ENCRYPTION gives keyUsage keyEncipherment,
     *                 dataEncipherment. the type CertificateData.CERT_TYPE_SIGNATURE gives keyUsage
     *                 digitalSignature, non-repudiation. all other CERT_TYPES gives the default keyUsage
     *                 digitalSignature, keyEncipherment
     * @param pk       the public key to be put in the created certificate.
     * @return The newly created certificate or null.
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws IllegalKeyException     if the public key is of wrong type.
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     */
    public Certificate createCertificate(Admin admin, String username, String password, int certType, PublicKey pk) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException {
        trace(">createCertificate(pk, certType)");
        // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
        boolean[] keyusage = new boolean[9];
        Arrays.fill(keyusage, false);
        switch (certType) {
            case SecConst.CERT_TYPE_ENCRYPTION:
                // keyEncipherment
                keyusage[2] = true;
                // dataEncipherment
                keyusage[3] = true;
                break;
            case SecConst.CERT_TYPE_SIGNATURE:
                // digitalSignature
                keyusage[0] = true;
                // non-repudiation
                keyusage[1] = true;
                break;
            default:
                // digitalSignature
                keyusage[0] = true;
                // keyEncipherment
                keyusage[2] = true;
                break;
        }

        Certificate ret = createCertificate(admin, username, password, pk, keyusage);
        trace("<createCertificate(pk, certType)");
        return ret;
    } // createCertificate

    /**
     * Requests for a certificate to be created for the passed public key wrapped in a self-signed
     * certificate. Verification of the signature (proof-of-possesion) on the request is
     * performed, and an exception thrown if verification fails. The method queries the user
     * database for authorization of the user.
     *
     * @param admin    Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param incert   a certificate containing the public key to be put in the created certificate.
     *                 Other (requested) parameters in the passed certificate can be used, such as DN,
     *                 Validity, KeyUsage etc. Currently only KeyUsage is considered!
     * @return The newly created certificate or null.
     * @throws ObjectNotFoundException       if the user does not exist.
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws IllegalKeyException           if the public key is of wrong type.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *                                       the CA.
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     */
    public Certificate createCertificate(Admin admin, String username, String password, Certificate incert) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, SignRequestSignatureException, CADoesntExistsException {
        trace(">createCertificate(cert)");
        X509Certificate cert = (X509Certificate) incert;
        try {
            // Convert the certificate to a BC certificate. SUN does not handle verifying RSASha256WithMGF1 for example 
            Certificate bccert = CertTools.getCertfromByteArray(incert.getEncoded());
            bccert.verify(cert.getPublicKey());
        } catch (Exception e) {
        	log.debug("Exception verify POPO: ", e);
        	String msg = intres.getLocalizedMessage("signsession.popverificationfailed");
            throw new SignRequestSignatureException(msg);
        }
        Certificate ret = createCertificate(admin, username, password, cert.getPublicKey(), cert.getKeyUsage());
        trace("<createCertificate(cert)");
        return ret;
    } // createCertificate

    /**
     * Requests for a certificate to be created for the passed public key wrapped in a
     * certification request message (ex PKCS10). Verification of the signature
     * (proof-of-possesion) on the request is performed, and an exception thrown if verification
     * fails. The method queries the user database for authorization of the user.
     *
     * @param admin         Information about the administrator or admin preforming the event.
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     *                      Currently no additional parameters in the PKCS10 request is considered!
     * @param responseClass The implementation class that will be used as the response message.
     * @return The newly created response message or null.
     * @throws ObjectNotFoundException       if the user does not exist.
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws IllegalKeyException           if the public key is of wrong type.
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *                                       the CA.
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     */
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, Class responseClass) throws NotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException {
        return createCertificate(admin, req, -1, responseClass);
    }

    /**
     * Requests for a certificate to be created for the passed public key with the passed key
     * usage and using the given certificate profile. This method is primarily intended to be used when
     * issueing hardtokens having multiple certificates per user.
     * The method queries the user database for authorization of the user. CAs are only
     * allowed to have certificateSign and CRLSign set.
     *
     * @param admin                Information about the administrator or admin preforming the event.
     * @param username             unique username within the instance.
     * @param password             password for the user.
     * @param pk                   the public key to be put in the created certificate.
     * @param keyusage             integer with bit mask describing desired keys usage, overrides keyUsage from
     *                             CertificateProfiles if allowed. Bit mask is packed in in integer using constants
     *                             from CertificateData. -1 means use default keyUsage from CertificateProfile. ex. int
     *                             keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *                             digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *                             | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @param certificateprofileid used to override the one set in userdata.
     *                             Should be set to SecConst.PROFILE_NO_PROFILE if the usedata certificateprofileid should be used
     * @param caid                 used to override the one set in userdata.�
     *                             Should be set to SecConst.CAID_USEUSERDEFINED if the regular certificateprofileid should be used
     * 
     * 
     * @return The newly created certificate or null.
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws IllegalKeyException     if the public key is of wrong type.
     * 
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     */
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, int keyusage, int certificateprofileid, int caid) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException {
    	return createCertificate(admin, username, password, pk, keyusage, null, null, certificateprofileid, caid);
    }
    
    /**
     * Requests for a certificate to be created for the passed public key wrapped in a
     * certification request message (ex PKCS10).  The username and password used to authorize is
     * taken from the request message. Verification of the signature (proof-of-possesion) on the
     * request is performed, and an exception thrown if verification fails. The method queries the
     * user database for authorization of the user.
     *
     * @param admin         Information about the administrator or admin preforming the event.
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     * @param keyUsage      integer with bit mask describing desired keys usage. Bit mask is packed in
     *                      in integer using contants from CertificateDataBean. ex. int keyusage =
     *                      CertificateDataBean.digitalSignature | CertificateDataBean.nonRepudiation; gives
     *                      digitalSignature and nonRepudiation. ex. int keyusage = CertificateDataBean.keyCertSign
     *                      | CertificateDataBean.cRLSign; gives keyCertSign and cRLSign. Keyusage < 0 means that default
     *                      keyUsage should be used, or should be taken from extensions in the request.
     * @param responseClass The implementation class that will be used as the response message.
     * @return The newly created response or null.
     * @throws ObjectNotFoundException       if the user does not exist.
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws IllegalKeyException           if the public key is of wrong type.
     * @throws CADoesntExistsException       if the targeted CA does not exist
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *                                       the CA.
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.ejb.ca.store.CertificateDataBean
     * @see org.ejbca.core.protocol.IRequestMessage
     * @see org.ejbca.core.protocol.IResponseMessage
     * @see org.ejbca.core.protocol.X509ResponseMessage
     */
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, int keyUsage, Class responseClass) throws AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException, NotFoundException {
        trace(">createCertificate(IRequestMessage)");
        // Get CA that will receive request
        CADataLocal cadata = null;
        UserDataVO data = null;
        IResponseMessage ret = null;            
        try {
        	cadata = getCAFromRequest(admin, req);
            CA ca = cadata.getCA();
            CATokenContainer catoken = ca.getCAToken();
            
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getJCEProvider());
            }
            // Verify the request
            if (req.verify() == false) {
            	String msg = intres.getLocalizedMessage("signsession.popverificationfailed");
                getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new SignRequestSignatureException(msg);
            }
            
            if (req.getUsername() == null) {
            	String msg = intres.getLocalizedMessage("signsession.nouserinrequest", req.getRequestDN());
                getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new SignRequestException(msg);
                //ret.setFailInfo(FailInfo.BAD_REQUEST);
                //ret.setStatus(ResponseStatus.FAILURE);
            } else if (req.getPassword() == null) {
            	String msg = intres.getLocalizedMessage("signsession.nopasswordinrequest");
                getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new SignRequestException(msg);
            } else {        
            	ResponseStatus status = ResponseStatus.SUCCESS;
            	FailInfo failInfo = null;
            	String failText = null;
                Certificate cert = null;
            	try {
    				// If we haven't done so yet, authenticate user
            		data = authUser(admin, req.getUsername(), req.getPassword());
                    PublicKey reqpk = req.getRequestPublicKey();
                    if (reqpk == null) {
                        getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, intres.getLocalizedMessage("signsession.nokeyinrequest"));
                        throw new InvalidKeyException("Key is null!");
                    }
                    // We need to make sure we use the users registered CA here
                    if (data.getCAId() != ca.getCAId()) {
                    	failText = intres.getLocalizedMessage("signsession.wrongauthority", new Integer(ca.getCAId()), new Integer(data.getCAId()));
                        status = ResponseStatus.FAILURE;
                        failInfo = FailInfo.WRONG_AUTHORITY;
                        getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, failText);
                    }

                    if (status.equals(ResponseStatus.SUCCESS)) {
                    	Date notBefore = req.getRequestValidityNotBefore(); // Optionally requested validity
                    	Date notAfter = req.getRequestValidityNotAfter(); // Optionally requested validity
                    	X509Extensions exts = req.getRequestExtensions(); // Optionally requested extensions
                    	int ku = keyUsage;
                    	if (ku < 0) {
                    		debug("KeyUsage < 0, see if we can override KeyUsage");
                        	if (exts != null) {
                            	X509Extension ext = exts.getExtension(X509Extensions.KeyUsage);
                            	if (ext != null) {
                                    ASN1OctetString os = ext.getValue();
                                    ByteArrayInputStream bIs = new ByteArrayInputStream(os.getOctets());
                                    ASN1InputStream dIs = new ASN1InputStream(bIs);
                                    DERObject dob = dIs.readObject();
                                	DERBitString bs = DERBitString.getInstance(dob);
                                	ku = bs.intValue();                        		                            		
                            		debug("We have a key usage request extension: "+ku);
                            	}
                        	}
                    	}
    					String sequence = null;
    					byte[] ki = req.getRequestKeyInfo();
    					if ( (ki != null) && (ki.length > 0) ) {
        					sequence = new String(ki);    						
    					}
                    	cert = createCertificate(admin, data, req.getRequestX509Name(), ca, reqpk, ku, notBefore, notAfter, exts, sequence);
                    }
            	} catch (ObjectNotFoundException oe) {
            		// If we didn't find the entity return error message
            		log.error("User not found: ", oe);
                	failText = intres.getLocalizedMessage("signsession.nosuchuser", req.getUsername());
                    status = ResponseStatus.FAILURE;
                    failInfo = FailInfo.INCORRECT_DATA;
                    getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, failText);
            	}
                
                //Create the response message with all nonces and checks etc
                ret = req.createResponseMessage(responseClass, req, ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT), catoken.getProvider());
				
				if ( (cert == null) && (status == ResponseStatus.SUCCESS) ) {
					status = ResponseStatus.FAILURE;
					failInfo = FailInfo.BAD_REQUEST;
                } else {
                    ret.setCertificate(cert);
                }
                ret.setStatus(status);
                if (failInfo != null) {
                    ret.setFailInfo(failInfo); 
                    ret.setFailText(failText);
                }
            }
            ret.create();
            // Call authentication session and tell that we are finished with this user
            if (ca.getFinishUser() == true) {
            	finishUser(admin, req.getUsername(), req.getPassword());
            }            	
        } catch (NotFoundException oe) {
            throw oe;
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (IllegalKeyException ke) {
            log.error("Key is of unknown type: ", ke);
            throw ke;
        } catch (IllegalKeyStoreException e) {
            throw new IllegalKeyException(e);
        } catch (UnsupportedEncodingException e) {
            throw new CADoesntExistsException(e);
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (IOException e) {
            log.error("Cannot create response message: ", e);
        } catch (CATokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", cadata.getSubjectDN());
            log.error(msg, ctoe);
            getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, ctoe);
            throw new CADoesntExistsException(msg);
        }
        trace("<createCertificate(IRequestMessage)");
        return ret;
    }
    
    /**
     * Method that generates a request failed response message. The request
     * should already have been decrypted and verified.
     *
     * @param admin         Information about the administrator or admin preforming the event.
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!

     * @param responseClass The implementation class that will be used as the response message.
     * 
     * @return A decrypted and verified IReqeust message
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws CADoesntExistsException       if the targeted CA does not exist
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the the request couldn't be verified.
     * @throws IllegalKeyException 
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     * @see se.anatom.ejbca.protocol.IRequestMessage
     * @see se.anatom.ejbca.protocol.IResponseMessage
     * @see se.anatom.ejbca.protocol.X509ResponseMessage
     */
    public IResponseMessage createRequestFailedResponse(Admin admin, IRequestMessage req,  Class responseClass) throws  AuthLoginException, AuthStatusException, IllegalKeyException, CADoesntExistsException, SignRequestSignatureException, SignRequestException {
        trace(">createRequestFailedResponse(IRequestMessage)");
        IResponseMessage ret = null;            
        CADataLocal cadata = null;
        try {
        	cadata = getCAFromRequest(admin, req);
            CA ca = cadata.getCA();
            CATokenContainer catoken = ca.getCAToken();
         
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            }
            // Verify the request
            if (req.verify() == false) {
            	String msg = intres.getLocalizedMessage("signsession.popverificationfailed");
                getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, intres.getLocalizedMessage("signsession.popverificationfailed"));
                throw new SignRequestSignatureException(msg);
            }
            
            //Create the response message with all nonces and checks etc
            ret = req.createResponseMessage(responseClass, req, ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT), catoken.getProvider());
            
            ret.setStatus(ResponseStatus.FAILURE);
            ret.setFailInfo(FailInfo.BAD_REQUEST);
            ret.create();
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (IllegalKeyStoreException e) {
            throw new IllegalKeyException(e);
        } catch (NotFoundException e) {
        	// This can actually not happen here?
            throw new CADoesntExistsException(e);
        } catch (UnsupportedEncodingException e) {
            throw new CADoesntExistsException(e);
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (IOException e) {
            log.error("Cannot create response message: ", e);
        } catch (CATokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", cadata.getSubjectDN());
            log.error(msg, ctoe);
            getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, ctoe);
            throw new CADoesntExistsException(msg);
        }
        trace("<createRequestFailedResponse(IRequestMessage)");
        return ret;
    }

    /**
     * Method that just decrypts and verifies a request and should be used in those cases
     * a when encrypted information needs to be extracted and presented to an RA for approval.
     *
     * @param admin         Information about the administrator or admin preforming the event.
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     * 
     * @return A decrypted and verified IReqeust message
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws IllegalKeyException           if the public key is of wrong type.
     * @throws CADoesntExistsException       if the targeted CA does not exist
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the the request couldn't be verified.
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     * @see se.anatom.ejbca.protocol.IRequestMessage
     * @see se.anatom.ejbca.protocol.IResponseMessage
     * @see se.anatom.ejbca.protocol.X509ResponseMessage
     */
    public IRequestMessage decryptAndVerifyRequest(Admin admin, IRequestMessage req) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException {
        trace(">decryptAndVerifyRequest(IRequestMessage)");
        // Get CA that will receive request
        CADataLocal cadata = null;
            
        try {
        	cadata = getCAFromRequest(admin, req);
            CA ca = cadata.getCA();
            CATokenContainer catoken = ca.getCAToken();
            
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            }
            // Verify the request
            if (req.verify() == false) {
            	String msg = intres.getLocalizedMessage("signsession.popverificationfailed");
            	getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new SignRequestSignatureException(msg);
            }
  
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (IllegalKeyStoreException e) {
            throw new IllegalKeyException(e);
        } catch (UnsupportedEncodingException e) {
            throw new CADoesntExistsException(e);
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        }  catch (CATokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", cadata.getSubjectDN());
            log.error(msg, ctoe);
            getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, ctoe);
            throw new CADoesntExistsException(msg);
        }
        trace("<decryptAndVerifyRequest(IRequestMessage)");
        return req;
    }
    
    /**
     * Implements ISignSession::getCRL
     *
     * @param admin         Information about the administrator or admin preforming the event.
     * @param req           a CRL Request message
     * @param responseClass the implementation class of the desired response
     * @return The newly created certificate or null.
     * @throws IllegalKeyException           if the public key is of wrong type.
     * @throws CADoesntExistsException       if the targeted CA does not exist
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *                                       the CA.
     * @ejb.interface-method view-type="both"
     */
    public IResponseMessage getCRL(Admin admin, IRequestMessage req, Class responseClass) throws AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException, UnsupportedEncodingException {
        trace(">getCRL(IRequestMessage)");
        IResponseMessage ret = null;
        ICertificateStoreSessionLocal certificateStore = null;
        try {
            certificateStore = storeHome.create();
        } catch (CreateException e) {
            error("Can not create certificate store session: ", e);
            throw new EJBException(e);
        }
        // Get CA that will receive request
        CADataLocal cadata = getCAFromRequest(admin, req);
        try {
            CA ca = cadata.getCA();
            CATokenContainer catoken = ca.getCAToken();

            if (ca.getStatus() != SecConst.CA_ACTIVE) {
            	String msg = intres.getLocalizedMessage("signsession.canotactive", cadata.getSubjectDN());
            	getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
                throw new EJBException(msg);
            }

            // Check that CA hasn't expired.
            Certificate cacert = ca.getCACertificate();
            try {
                CertTools.checkValidity(cacert, new Date());
            } catch (CertificateExpiredException cee) {
                // Signers Certificate has expired.
                cadata.setStatus(SecConst.CA_EXPIRED);
                ca.setStatus(SecConst.CA_EXPIRED);
                String msg = intres.getLocalizedMessage("signsession.caexpired", cadata.getSubjectDN());
                getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg, cee);
                throw new CADoesntExistsException(msg);
            } catch (CertificateNotYetValidException cve) {
                throw new CADoesntExistsException(cve);
            }

            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            }
            //Create the response message with all nonces and checks etc
            ret = req.createResponseMessage(responseClass, req, ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT), catoken.getProvider());
            
            // Get the Full CRL, don't even bother digging into the encrypted CRLIssuerDN...since we already
            // know that we are the CA (SCEP is soooo stupid!)
            final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
            byte[] crl = getCRLCreateSession().getLastCRL(admin, certSubjectDN, false);
            if (crl != null) {
                ret.setCrl(CertTools.getCRLfromByteArray(crl));
                ret.setStatus(ResponseStatus.SUCCESS);
            } else {
                ret.setStatus(ResponseStatus.FAILURE);
                ret.setFailInfo(FailInfo.BAD_REQUEST);
            }
            ret.create();
            // TODO: handle returning errors as response message,
            // javax.ejb.ObjectNotFoundException and the others thrown...
        } catch (NotFoundException e) {
        	// This actually can not happen here
            throw new CADoesntExistsException(e);
        } catch (IllegalKeyStoreException e) {
            throw new IllegalKeyException(e);
        } catch (UnsupportedEncodingException e) {
            throw new CADoesntExistsException(e);
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (CRLException e) {
            log.error("Cannot create response message: ", e);
        } catch (IOException e) {
            log.error("Cannot create response message: ", e);
        } catch (CATokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", cadata.getSubjectDN());
        	log.error(msg, ctoe);
            getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg, ctoe);
            throw new CADoesntExistsException(msg);
        }
        trace("<getCRL(IRequestMessage)");
        return ret;
    }
    
    /**
     * Help Method that extracts the CA specified in the request.
     * 
     */
    private CADataLocal getCAFromRequest(Admin admin, IRequestMessage req) throws AuthStatusException, AuthLoginException, CADoesntExistsException, UnsupportedEncodingException{
    	CADataLocal cadata = null;
        try {
            // See if we can get issuerDN directly from request
            if (req.getIssuerDN() != null) {
            	String dn = req.getIssuerDN();
            	debug("Got an issuerDN: "+dn);
            	// If we have issuer and serialNo, we must find the CA certificate, to get the CAs subject name
            	// If we don't have a serialNumber, we take a chance that it was actually the subjectDN (for example a RootCA)
            	BigInteger serno = req.getSerialNo();
            	if (serno != null) {
            		debug("Got a serialNumber: "+serno.toString(16));
                    ICertificateStoreSessionLocal certificateStore = storeHome.create();
            		Certificate cert = certificateStore.findCertificateByIssuerAndSerno(admin, dn, serno);
            		if (cert != null) {
            			dn = CertTools.getSubjectDN(cert);
            		}
            	}
            	debug("Using DN: "+dn);
            	try {
                    cadata = cadatahome.findByPrimaryKey(new Integer(dn.hashCode()));            		
                    debug("Using CA (from issuerDN) with id: " + cadata.getCaId() + " and DN: " + cadata.getSubjectDN());
            	} catch (Exception e) {
            		// We could not find a CA from that DN, so it might not be a CA. Try to get from username instead
            		if (req.getUsername() != null) {
            			cadata = getCAFromUsername(admin, req);
                    } else {
                        String msg = intres.getLocalizedMessage("signsession.canotfoundissuerusername", dn, "null");        	
                        throw new CADoesntExistsException(msg);
                    }
            	}
            } else if (req.getUsername() != null) {
                cadata = getCAFromUsername(admin, req);
            } else {
                throw new CADoesntExistsException();
            }
        } catch (javax.ejb.FinderException fe) {
            String msg = intres.getLocalizedMessage("signsession.canotfoundissuerusername", req.getIssuerDN(), req.getUsername());        	
            error(msg);
            getLogSession().log(admin, -1, LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, fe);
            throw new CADoesntExistsException(fe);
        } catch (CreateException ce) {
        	// Really fatal error
            String msg = intres.getLocalizedMessage("signsession.canotfoundissuerusername", req.getIssuerDN(), req.getUsername());        	
            error(msg, ce);        	
            getLogSession().log(admin, -1, LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, ce);
            throw new EJBException(ce);
        }
        
        CA ca = null;
        try {
        	ca = cadata.getCA();
        	
        	if (ca.getStatus() != SecConst.CA_ACTIVE) {
                String msg = intres.getLocalizedMessage("signsession.canotactive", cadata.getSubjectDN());
        		getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
        		throw new EJBException(msg);
        	}
        	
        	// Check that CA hasn't expired.
        	Certificate cacert = ca.getCACertificate();
        	CertTools.checkValidity(cacert, new Date());
        } catch (CertificateExpiredException cee) {
            // Signers Certificate has expired.
            cadata.setStatus(SecConst.CA_EXPIRED);
            ca.setStatus(SecConst.CA_EXPIRED);
            String msg = intres.getLocalizedMessage("signsession.caexpired", cadata.getSubjectDN());
            getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, cee);
            throw new CADoesntExistsException(msg);
        } catch (CertificateNotYetValidException cve) {
            throw new CADoesntExistsException(cve);
        } catch (IllegalKeyStoreException e) {
        	throw new EJBException(e);
        }
        
        return cadata;
    }

	private CADataLocal getCAFromUsername(Admin admin, IRequestMessage req)
			throws ObjectNotFoundException, AuthStatusException, AuthLoginException, FinderException {
		// See if we can get username and password directly from request
		String username = req.getUsername();
		String password = req.getPassword();
		UserDataVO data = authUser(admin, username, password);
		CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(data.getCAId()));
		debug("Using CA (from username) with id: " + cadata.getCaId() + " and DN: " + cadata.getSubjectDN());
		return cadata;
	}

    /**
     * Requests for a CRL to be created with the passed (revoked) certificates.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param caid Id of the CA which CRL should be created.
     * @param certs collection of RevokedCertInfo object.
     * @param basecrlnumber the CRL number of the Case CRL to generate a deltaCRL, -1 to generate a full CRL
     * @return The newly created CRL in DER encoded byte form or null, use CertTools.getCRLfromByteArray to convert to X509CRL.
     * @throws CATokenOfflineException 
     * @ejb.interface-method view-type="both"
     */
    public byte[] createCRL(Admin admin, int caid, Collection certs, int basecrlnumber) throws CATokenOfflineException {
        trace(">createCRL()");
        byte[] crlBytes = null; // return value
        CADataLocal cadata = null;
        try {
            // get CA
            try {
                cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            } catch (javax.ejb.FinderException fe) {
                String msg = intres.getLocalizedMessage("signsession.canotfoundcaid", new Integer(caid));        	
                getLogSession().log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECRL, msg, fe);
                throw new EJBException(fe);
            }

            final CA ca;
            try {
                ca = cadata.getCA();
            } catch (java.io.UnsupportedEncodingException uee) {
                throw new EJBException(uee);
            }
            if ( (ca.getStatus() != SecConst.CA_ACTIVE) && (ca.getStatus() != SecConst.CA_WAITING_CERTIFICATE_RESPONSE) ) {
                String msg = intres.getLocalizedMessage("signsession.canotactive", cadata.getSubjectDN());
                getLogSession().log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new CATokenOfflineException(msg);
            }

            // Check that CA hasn't expired.
            Certificate cacert = ca.getCACertificate();
            try {
                CertTools.checkValidity(cacert, new Date());
            } catch (CertificateExpiredException e) {
                // Signers Certificate has expired.
                cadata.setStatus(SecConst.CA_EXPIRED);
                ca.setStatus(SecConst.CA_EXPIRED);
                String msg = intres.getLocalizedMessage("signsession.caexpired", cadata.getSubjectDN());
                getLogSession().log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECRL, msg, e);
                throw new EJBException(msg);
            } catch (CertificateNotYetValidException e) {
                throw new EJBException(e);
            }

            ICertificateStoreSessionLocal certificateStore = storeHome.create();
            // Get highest number of last CRL (full or delta) and increase by 1, both full CRLs and deltaCRLs share the same 
            // series of CRL Number
            final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
            int fullnumber = getCRLCreateSession().getLastCRLNumber(admin, certSubjectDN, false);
            int deltanumber = getCRLCreateSession().getLastCRLNumber(admin, certSubjectDN, true);
            int number = ( (fullnumber > deltanumber) ? fullnumber : deltanumber ) +1; 
            final X509CRL crl;
            boolean deltaCRL = (basecrlnumber > -1);
            if (deltaCRL) {
            	// Workaround if transaction handling fails so that crlNumber for deltaCRL would happen to be the same
            	if (number == basecrlnumber) {
            		number++;
            	}
            	crl = (X509CRL) ca.generateDeltaCRL(certs, number, basecrlnumber);	
            } else {
            	crl = (X509CRL) ca.generateCRL(certs, number);
            }
            if (crl != null) {
                String msg = intres.getLocalizedMessage("signsession.createdcrl", new Integer(number), cadata.getName(), cadata.getSubjectDN());
                getLogSession().log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CREATECRL, msg);

                // Store CRL in the database
                String fingerprint = CertTools.getFingerprintAsString(cacert);
                crlBytes = crl.getEncoded();            	
                log.debug("Storing CRL in certificate store.");
                getCRLCreateSession().storeCRL(admin, crlBytes, fingerprint, number, crl.getIssuerDN().getName(), crl.getThisUpdate(), crl.getNextUpdate(), (deltaCRL ? 1 : -1));
                // Store crl in ca CRL publishers.
                log.debug("Storing CRL in publishers");
                IPublisherSessionLocal pub = publishHome.create();
                pub.storeCRL(admin, ca.getCRLPublishers(), crlBytes, fingerprint, number, ca.getSubjectDN());
            }
        } catch (CATokenOfflineException ctoe) {
            String cadn = null;
            if (cadata != null) {
                cadn = cadata.getSubjectDN();
            }
            String msg = intres.getLocalizedMessage("error.catokenoffline", cadn);
            log.error(msg, ctoe);
            getLogSession().log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECRL, msg, ctoe);
            throw ctoe;
        } catch (Exception e) {
            getLogSession().log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECRL, intres.getLocalizedMessage("signsession.errorcreatecrl"), e);
            throw new EJBException(intres.getLocalizedMessage("signsession.errorcreatecrl"), e);
        }
        trace("<createCRL()");
        return crlBytes;
    } // createCRL

    /**
     * Method that publishes the given CA certificate chain to the list of publishers.
     * Is mainly used by CAAdminSessionBean when CA is created.
     *
     * @param admin            Information about the administrator or admin preforming the event.
     * @param certificatechain certchain of certificate to publish
     * @param usedpublishers   a collection if publisher id's (Integer) indicating which publisher that should be used.
     * @param caDataDN         DN from CA data. If a the CA certificate does not have a DN object to be used by the publisher this DN could be searched for the object.
     * @ejb.interface-method view-type="both"
     */
    public void publishCACertificate(Admin admin, Collection certificatechain, Collection usedpublishers, String caDataDN) {
        try {
            ICertificateStoreSessionLocal certificateStore = storeHome.create();

            Object[] certs = certificatechain.toArray();
            for (int i = 0; i < certs.length; i++) {
				Certificate cert = (Certificate)certs[i];
                String fingerprint = CertTools.getFingerprintAsString(cert);
                // CA fingerprint, figure out the value if this is not a root CA
                String cafp = fingerprint;
                // Calculate the certtype
                boolean isSelfSigned = CertTools.isSelfSigned(cert);
                int type = SecConst.CERTTYPE_ENDENTITY;
                if (CertTools.isCA(cert))  {
                	// this is a CA
                	if (isSelfSigned) {
                		type = SecConst.CERTTYPE_ROOTCA;
                	} else {
                		type = SecConst.CERTTYPE_SUBCA;
                		// If not a root CA, the next certificate in the chain should be the CA of this CA
                		if ((i+1) < certs.length) {
                			Certificate cacert = (Certificate)certs[i+1]; 
                			cafp = CertTools.getFingerprintAsString(cacert);
                		}
                	}                		
                } else if (isSelfSigned) {
                	// If we don't have basic constraints, but is self signed, we are still a CA, just a stupid CA
                	type = SecConst.CERTTYPE_ROOTCA;
                } else {
            		// If and end entity, the next certificate in the chain should be the CA of this end entity
            		if ((i+1) < certs.length) {
            			Certificate cacert = (Certificate)certs[i+1]; 
            			cafp = CertTools.getFingerprintAsString(cacert);
            		}
                }
                
                String name = "SYSTEMCERT";
                if (type != SecConst.CERTTYPE_ENDENTITY) {
                	name = "SYSTEMCA";
                }
                // Store CA certificate in the database if it does not exist
                long updateTime = new Date().getTime();
                int profileId = 0;
                String tag = null;
                CertificateInfo ci = certificateStore.getCertificateInfo(admin, fingerprint);
                if (ci == null) {
                	// If we don't have it in the database, store it setting certificateProfileId = 0 and tag = null
                    certificateStore.storeCertificate(admin, cert, name, cafp, SecConst.CERT_ACTIVE, type, profileId, tag, updateTime);
                } else {
                	updateTime = ci.getUpdateTime().getTime();
                	profileId = ci.getCertificateProfileId();
                	tag = ci.getTag();
                }
                // Store cert in ca cert publishers.
                IPublisherSessionLocal pub = publishHome.create();
                if (usedpublishers != null) {
                    pub.storeCertificate(admin, usedpublishers, cert, cafp, null, caDataDN, fingerprint, SecConst.CERT_ACTIVE, type, -1, RevokedCertInfo.NOT_REVOKED, tag, profileId, updateTime, null);
                    if ( type != SecConst.CERTTYPE_ENDENTITY ) {
                        final String issuerDN = CertTools.getSubjectDN(cert);
                        final byte crl[] = getCRLCreateSession().getLastCRL(admin, issuerDN, false);
                        if ( crl!=null ) {
                            final int nr = getCRLCreateSession().getLastCRLNumber(admin, issuerDN, false);
                            pub.storeCRL(admin, usedpublishers, crl, cafp, nr, caDataDN);
                        }
                        final byte deltaCrl[] = getCRLCreateSession().getLastCRL(admin, issuerDN, true);
                        if ( deltaCrl!=null ) {
                            final int nr = getCRLCreateSession().getLastCRLNumber(admin, issuerDN, true);
                            pub.storeCRL(admin, usedpublishers, deltaCrl, cafp, nr, caDataDN);
                        }
                    }
                }
            }
        } catch (javax.ejb.CreateException ce) {
            throw new EJBException(ce);
        }
    }

    private UserDataVO authUser(Admin admin, String username, String password) throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        // Authorize user and get DN
        try {
            IAuthenticationSessionLocal authSession = authHome.create();
            return authSession.authenticateUser(admin, username, password);
        } catch (CreateException e) {
            log.error(e);
            throw new EJBException(e);
        }

    } // authUser

    /** Finishes user, i.e. set status to generated, if it should do so.
     * The authentication session is responsible for determining if this should be done or not */ 
    private void finishUser(Admin admin, String username, String password) {
        // Finnish user and set new status
        try {
            IAuthenticationSessionLocal authSession = authHome.create();
            authSession.finishUser(admin, username, password);
        } catch (CreateException e) {
            log.error(e);
            throw new EJBException(e);
        } catch (ObjectNotFoundException e) {
            String msg = intres.getLocalizedMessage("signsession.finishnouser", username);        	
        	log.info(msg);
        }
    } // finishUser

    /**
     * Requests for a certificate to be created for the passed public key with the passed key
     * usage and using the given certificate profile. This method is primarily intended to be used when
     * issueing hardtokens having multiple certificates per user.
     * The method queries the user database for authorization of the user. CAs are only
     * allowed to have certificateSign and CRLSign set.
     *
     * @param admin                Information about the administrator or admin preforming the event.
     * @param username             unique username within the instance.
     * @param password             password for the user.
     * @param pk                   the public key to be put in the created certificate.
     * @param keyusage             integer with bit mask describing desired keys usage, overrides keyUsage from
     *                             CertificateProfiles if allowed. Bit mask is packed in in integer using constants
     *                             from CertificateData. -1 means use default keyUsage from CertificateProfile. ex. int
     *                             keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *                             digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *                             | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @param notAfter an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
     * @param certificateprofileid used to override the one set in userdata.
     *                             Should be set to SecConst.PROFILE_NO_PROFILE if the usedata certificateprofileid should be used
     * @param caid                 used to override the one set in userdata.
     *                             Should be set to SecConst.CAID_USEUSERDEFINED if the regular certificateprofileid should be used
     * 
     * 
     * @return The newly created certificate or null.
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws IllegalKeyException     if the public key is of wrong type.
     * 
     */
    private Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, int keyusage, Date notBefore, Date notAfter, int certificateprofileid, int caid) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException {
        trace(">createCertificate(pk, ku, date)");
        try {
            // Authorize user and get DN
            UserDataVO data = authUser(admin, username, password);
            debug("Authorized user " + username + " with DN='" + data.getDN() + "'." + " with CA=" + data.getCAId());
            if (certificateprofileid != SecConst.PROFILE_NO_PROFILE) {
                debug("Overriding user certificate profile with :" + certificateprofileid);
                data.setCertificateProfileId(certificateprofileid);
            }
            
            if (caid != SecConst.CAID_USEUSERDEFINED) {
                debug("Overriding user caid with :" + caid);
                data.setCAId(caid);
            }


            debug("User type=" + data.getType());
            // get CA
            CADataLocal cadata = null;
            try {
                cadata = cadatahome.findByPrimaryKey(new Integer(data.getCAId()));
            } catch (javax.ejb.FinderException fe) {
                String msg = intres.getLocalizedMessage("signsession.canotfoundcaid", new Integer(data.getCAId()));        	
                getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, fe);
                throw new CADoesntExistsException(msg);
            }
            CA ca = null;
            try {
                ca = cadata.getCA();
            } catch (java.io.UnsupportedEncodingException uee) {
                throw new EJBException(uee);
            } catch(IllegalKeyStoreException e){
                throw new EJBException(e);
            }

            if (ca.getStatus() != SecConst.CA_ACTIVE) {
            	String msg = intres.getLocalizedMessage("signsession.canotactive", cadata.getSubjectDN());
                getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new EJBException(msg);
            }

            // Check that CA hasn't expired.
            Certificate cacert = ca.getCACertificate();
            try {
                CertTools.checkValidity(cacert, new Date());
            } catch (CertificateExpiredException cee) {
                // Signers Certificate has expired.
                cadata.setStatus(SecConst.CA_EXPIRED);
                ca.setStatus(SecConst.CA_EXPIRED);
            	String msg = intres.getLocalizedMessage("signsession.caexpired", cadata.getSubjectDN());
                getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, cee);
                throw new EJBException(msg);
            } catch (CertificateNotYetValidException cve) {
                throw new EJBException(cve);
            }


            // Now finally after all these checks, get the certificate, we don't have any sequence number or extensions available here
            Certificate cert = createCertificate(admin, data, null, ca, pk, keyusage, notBefore, notAfter, null, null);
            // Call authentication session and tell that we are finished with this user
            if (ca.getFinishUser() == true) {
                finishUser(admin, username, password);
            }
            trace("<createCertificate(pk, ku, date)");
            return cert;
        } catch (ObjectNotFoundException oe) {
            throw oe;
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (IllegalKeyException ke) {
            throw ke;
        }
    } // createCertificate

    /**
     * Creates the certificate, does NOT check any authorization on user, profiles or CA!
     * This must be done earlier
     *
     * @param admin    administrator performing this task
     * @param data     auth data for user to get the certificate
     * @param ca       the CA that will sign the certificate
     * @param pk       ther users public key to be put in the certificate
     * @param keyusage requested key usage for the certificate, may be ignored by the CA
     * @param notBefore an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
     * @param notAfter an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
     * @param extensions an optional set of extensions to set in the created certificate, if the profile allows extension override, null if the profile default extensions should be used.
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by CVC CAs for sequence field. Can be set to null.
     * @return Certificate that has been generated and signed by the CA
     * @throws IllegalKeyException if the public key given is invalid
     */
    private Certificate createCertificate(Admin admin, UserDataVO data, X509Name requestX509Name, CA ca, PublicKey pk, int keyusage, Date notBefore, Date notAfter, X509Extensions extensions, String sequence) throws IllegalKeyException {
        trace(">createCertificate(pk, ku, notAfter)");
        try {
            getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_INFO_REQUESTCERTIFICATE, intres.getLocalizedMessage("signsession.requestcert", data.getUsername(), new Integer(data.getCAId()), new Integer(data.getCertificateProfileId())));
            // If the user is of type USER_INVALID, it cannot have any other type (in the mask)
            if (data.getType() == SecConst.USER_INVALID) {
            	String msg = intres.getLocalizedMessage("signsession.usertypeinvalid");
            	getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
            } else {
                ICertificateStoreSessionLocal certificateStore = storeHome.create();
                // Retrieve the certificate profile this user should have
                int certProfileId = data.getCertificateProfileId();
                CertificateProfile certProfile = certificateStore.getCertificateProfile(admin, certProfileId);
                // What if certProfile == null?
                if (certProfile == null) {
                    certProfileId = SecConst.CERTPROFILE_FIXED_ENDUSER;
                    certProfile = certificateStore.getCertificateProfile(admin, certProfileId);
                }

                // Check that CAid is among available CAs
                boolean caauthorized = false;
                Iterator iter = certProfile.getAvailableCAs().iterator();
                while (iter.hasNext()) {
                    int next = ((Integer) iter.next()).intValue();
                    if (next == data.getCAId() || next == CertificateProfile.ANYCA) {
                        caauthorized = true;
                    }
                }

                // Sign Session bean is only able to issue certificates with a End Entity or SubCA type certificate profile.
                if ( (certProfile.getType() != CertificateProfile.TYPE_ENDENTITY) && (certProfile.getType() != CertificateProfile.TYPE_SUBCA) ) {
                	String msg = intres.getLocalizedMessage("signsession.errorcertprofiletype", new Integer(certProfile.getType()));
                    getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                    throw new EJBException(msg);
                }

                if (!caauthorized) {
                	String msg = intres.getLocalizedMessage("signsession.errorcertprofilenotauthorized", new Integer(data.getCAId()), new Integer(certProfile.getType()));
                	getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                    throw new EJBException(msg);
                }

                log.debug("Using certificate profile with id " + certProfileId);
                int keyLength = KeyTools.getKeyLength(pk);
                if (keyLength == -1) {
                	String text = intres.getLocalizedMessage("signsession.unsupportedkeytype", pk.getClass().getName()); 
                    getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_INFO_CREATECERTIFICATE, text);
                    throw new IllegalKeyException(text);
                }
                log.debug("Keylength = " + keyLength); 
                if ((keyLength < (certProfile.getMinimumAvailableBitLength() - 1))
                        || (keyLength > (certProfile.getMaximumAvailableBitLength()))) {
                	String text = intres.getLocalizedMessage("signsession.illegalkeylength", new Integer(keyLength)); 
                    getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_INFO_CREATECERTIFICATE, text);
                    throw new IllegalKeyException(text);
                }

                // Below we have a small loop if it would happen that we generate the same serial number twice
                int retrycounter = 0;
                boolean stored = false;
                Exception storeEx = null; // this will not be null if stored == false after the below passage
                Certificate cert = null;
                String cafingerprint = null;
                String serialNo = "unknown";
                long updateTime = new Date().getTime();
                String tag = null;
                while (!stored && retrycounter < 5) {
                    cert = ca.generateCertificate(data, requestX509Name, pk, keyusage, notBefore, notAfter, certProfile, extensions, sequence);
                    serialNo = CertTools.getSerialNumberAsString(cert);
                    // Store certificate in the database
                    Certificate cacert = ca.getCACertificate();
                    cafingerprint = CertTools.getFingerprintAsString(cacert);
                    try {
                        certificateStore.storeCertificate(admin, cert, data.getUsername(), cafingerprint, SecConst.CERT_ACTIVE, certProfile.getType(), certProfileId, tag, updateTime);                        
                        stored = true;
                    } catch (CreateException e) {
                    	// If we have created a unique index on (issuerDN,serialNumber) on table CertificateData we can 
                    	// get a CreateException here if we would happen to generate a certificate with the same serialNumber
                    	// as one already existing certificate.
                    	log.info("Can not store certificate with serNo ("+serialNo+"), will retry (retrycounter="+retrycounter+") with a new certificate with new serialNo: "+e.getMessage());
                    	storeEx = e;
                    }
                    retrycounter++;
                }
                if (!stored) {
                	log.error("Can not store certificate in database in 5 tries, aborting: ", storeEx);
                	throw storeEx;
                }
                
                getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), cert, LogConstants.EVENT_INFO_CREATECERTIFICATE, intres.getLocalizedMessage("signsession.certificateissued", data.getUsername()));
                if (log.isDebugEnabled()) {
                    debug("Generated certificate with SerialNumber '" + serialNo + "' for user '" + data.getUsername() + "'.");
                    debug(cert.toString());                	
                }

                // Store the request data in history table.
                certificateStore.addCertReqHistoryData(admin,cert,data);
                // Store certificate in certificate profiles publishers.
                IPublisherSessionLocal pub = publishHome.create();
                Collection publishers = certProfile.getPublisherList();
                if (publishers != null) {
                    pub.storeCertificate(admin, publishers, cert, data.getUsername(), data.getPassword(), data.getDN(), cafingerprint, SecConst.CERT_ACTIVE, certProfile.getType(), -1, RevokedCertInfo.NOT_REVOKED, tag, certProfileId, updateTime, data.getExtendedinformation());
                }
                
                // Finally we check if this certificate should not be issued as active, but revoked directly upon issuance 
                int revreason = getIssuanceRevocationReason(data);
                if (revreason != RevokedCertInfo.NOT_REVOKED) {
                	certificateStore.revokeCertificate(admin, cert, publishers, revreason, data.getDN());
                }                

                trace("<createCertificate(pk, ku, notAfter)");
                return cert;
            }
        } catch (IllegalKeyException ke) {
            throw ke;
        } catch (CATokenOfflineException ctoe) {
        	// This method should actually throw CATokenOfflineException instead of wrpping this in an EJBException
        	String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            getLogSession().log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, ctoe);
            throw new EJBException(msg, ctoe);
        } catch (Exception e) {
            log.error(e);
            throw new EJBException(e);
        }
        trace("<createCertificate(pk, ku)");
        log.error("Invalid user type for user " + data.getUsername());
        throw new EJBException("Invalid user type for user " + data.getUsername());
    } // createCertificate

    
    /**
     * Sign an array of bytes with CA.
     * 
     * @param keyPupose one of SecConst.CAKEYPURPOSE_...
     * @ejb.interface-method view-type="both"
     */
    public byte[] signData(byte[] data, int caId, int keyPurpose) throws NoSuchAlgorithmException, CATokenOfflineException, IllegalKeyStoreException, UnsupportedEncodingException,
    		FinderException, InvalidKeyException, SignatureException {
        CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caId));
        CATokenContainer caToken = cadata.getCA().getCAToken(); 
        PrivateKey pk = caToken.getPrivateKey(keyPurpose);
    	Signature signer = Signature.getInstance(caToken.getCATokenInfo().getSignatureAlgorithm());
        signer.initSign(pk);
        signer.update(data);
        return (signer.sign());
    }
    
    /**
     * Verify an array of bytes with a signature
     * @param keyPupose one of SecConst.CAKEYPURPOSE_...
     * @ejb.interface-method view-type="both"
     */
    public boolean verifySignedData(byte[] data, int caId, int keyPurpose, byte[] signature) throws FinderException, IllegalKeyStoreException, UnsupportedEncodingException,
    		CATokenOfflineException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caId));
        CATokenContainer caToken = cadata.getCA().getCAToken();
        PublicKey pk = caToken.getPublicKey(keyPurpose);
        Signature signer = Signature.getInstance(caToken.getCATokenInfo().getSignatureAlgorithm());
        signer.initVerify(pk);
        signer.update(data);
        return (signer.verify(signature));    	
    }
    
    /**
     * Method used to perform a extended CA Service, like OCSP CA Service.
     *
     * @param admin   Information about the administrator or admin preforming the event.
     * @param caid    the ca that should perform the service
     * @param request a service request.
     * @return A corresponding response.
     * @throws IllegalExtendedCAServiceRequestException
     *                                 if the request was invalid.
     * @throws ExtendedCAServiceNotActiveException
     *                                 thrown when the service for the given CA isn't activated
     * @throws CADoesntExistsException The given caid doesn't exists.
     * @ejb.interface-method view-type="both"
     */
    public ExtendedCAServiceResponse extendedService(Admin admin, int caid, ExtendedCAServiceRequest request)
            throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, CADoesntExistsException {

        // Get CA that will process request
        CADataLocal cadata = null;
        ExtendedCAServiceResponse returnval = null;
        try {
            cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            if (log.isDebugEnabled()) {
                debug("Exteneded service with request class '"+request.getClass().getName()+"' called for CA '"+cadata.getName()+"'");            	
            }
            returnval = cadata.getCA().extendedService(request);
        } catch (javax.ejb.FinderException fe) {
            throw new CADoesntExistsException(fe);
        } catch (UnsupportedEncodingException ue) {
            throw new EJBException(ue);
        } catch(IllegalKeyStoreException e){
            throw new EJBException(e);
        }


        return returnval;

    }

    /**
     * Returns the issuance revocation code configured on the end entity extended information.
     *
     * @param data user data
     * @return issuance revocation code configured on the end entity extended information, a constant from RevokedCertInfo. Default RevokedCertInfo.NOT_REVOKED. 
     */
    private int getIssuanceRevocationReason(UserDataVO data) {
    	int ret = RevokedCertInfo.NOT_REVOKED;
    	ExtendedInformation ei = data.getExtendedinformation();
        if ( ei != null ) {
            String revocationReason = ei.getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
            if (revocationReason != null) {
                ret = Integer.valueOf(revocationReason);            	
            }
        }
        if (log.isDebugEnabled()) {
            debug("User revocation reason: "+ret);        	
        }
        return ret;
    }


} //RSASignSessionBean

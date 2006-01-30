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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.ObjectNotFoundException;

import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.CADataLocal;
import org.ejbca.core.ejb.ca.caadmin.CADataLocalHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
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
import org.ejbca.core.model.ca.catoken.CAToken;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

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
 * @ejb.env-entry description="Used internally to keystores in database"
 *   name="keyStorePass"
 *   type="java.lang.String"
 *   value="${ca.keystorepass}"

 * @ejb.env-entry description="Password for OCSP keystores"
 *   name="OCSPKeyStorePass"
 *   type="java.lang.String"
 *   value="${ca.ocspkeystorepass}"
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
 *   ejb-name="CADataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICADataLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICADataLocal"
 *   link="CAData"
 *
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ejb-name="LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref description="The Certificate store used to store and fetch certificates"
 *   view-type="local"
 *   ejb-name="CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 * @ejb.ejb-external-ref description="The Authentication session used to authenticate users when issuing certificates.
 * Alter this to enable a custom made authentication session implementing the
 * IAuthenticationSessionLocal interface"
 *   view-type="local"
 *   ejb-name="AuthenticationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocal"
 *   link="AuthenticationSession"
 *
 * @ejb.ejb-external-ref description="Publishers are configured to store certificates and CRLs in additional places
 * from the main database. Publishers runs as local beans"
 *   view-type="local"
 *   ejb-name="PublisherSessionLocal"
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

    /**
     * The local interface of the log session bean
     */
    private ILogSessionLocal logsession;
    /**
     * Source of good random data
     */
    SecureRandom randomSource = null;
    


    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     * @ejb.create-method 
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");

        try {
            // Install BouncyCastle provider
            CertTools.installBCProvider();

            // get home interfaces to other session beans used
            storeHome = (ICertificateStoreSessionLocalHome) getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
            authHome = (IAuthenticationSessionLocalHome) getLocator().getLocalHome(IAuthenticationSessionLocalHome.COMP_NAME);

            cadatahome = (CADataLocalHome) getLocator().getLocalHome(CADataLocalHome.COMP_NAME);

            publishHome = (IPublisherSessionLocalHome) getLocator().getLocalHome(IPublisherSessionLocalHome.COMP_NAME);

            // Get a decent source of random data
            String randomAlgorithm = getLocator().getString("java:comp/env/randomAlgorithm");
            randomSource = SecureRandom.getInstance(randomAlgorithm);
            SernoGenerator.setAlgorithm(randomAlgorithm);


        } catch (Exception e) {
            debug("Caught exception in ejbCreate(): ", e);
            throw new EJBException(e);
        }

        debug("<ejbCreate()");
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


    /**
     * Retrieves the certificate chain for the signer. The returned certificate chain MUST have the
     * RootCA certificate in the last position.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param caid  is the issuerdn.hashCode()
     * @return The certificate chain, never null.
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
        Integer caid = new Integer(CertTools.getIssuerDN((X509Certificate) cert).hashCode());
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
            error("Unknown error, strange?", e);
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
        debug(">createPKCS7(" + caId + ", " + CertTools.getIssuerDN((X509Certificate) cert) + ")");
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
        }

        // Check that CA hasn't expired.
        X509Certificate cacert = (X509Certificate) ca.getCACertificate();
        try {
            cacert.checkValidity();
        } catch (CertificateExpiredException e) {
            // Signers Certificate has expired.
            cadata.setStatus(SecConst.CA_EXPIRED);
            throw new CADoesntExistsException("Signing CA " + cadata.getSubjectDN() + " has expired");
        } catch (CertificateNotYetValidException cve) {
            throw new CADoesntExistsException(cve);
        }

        returnval = ca.createPKCS7(cert, includeChain);
        debug("<createPKCS7()");
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
        debug(">createCertificate(pk)");
        // Default key usage is defined in certificate profiles
        debug("<createCertificate(pk)");
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
        return createCertificate(admin, username, password, pk, keyusage, SecConst.PROFILE_NO_PROFILE, SecConst.CAID_USEUSERDEFINED);
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
     * @param caid                 used to override the one set in userdata.¨
     *                             Should be set to SecConst.CAID_USEUSERDEFINED if the regular certificateprofileid should be used
     * 
     * 
     * @return The newly created certificate or null.
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws IllegalKeyException     if the public key is of wrong type.
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     */
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, int keyusage, int certificateprofileid, int caid) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException {
        debug(">createCertificate(pk, ku)");
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


            debug("type=" + data.getType());
            // get CA
            CADataLocal cadata = null;
            try {
                cadata = cadatahome.findByPrimaryKey(new Integer(data.getCAId()));
            } catch (javax.ejb.FinderException fe) {
                getLogSession().log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Invalid CA Id", fe);
                throw new CADoesntExistsException();
            }
            CA ca = null;
            try {
                ca = cadata.getCA();
            } catch (java.io.UnsupportedEncodingException uee) {
                throw new EJBException(uee);
            }
            // Check that CA hasn't expired.
            X509Certificate cacert = (X509Certificate) ca.getCACertificate();

            if (ca.getStatus() != SecConst.CA_ACTIVE) {
                getLogSession().log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Signing CA " + cadata.getSubjectDN() + " isn't active.");
                throw new EJBException("Signing CA " + cadata.getSubjectDN() + " isn't active.");
            }

            try {
                cacert.checkValidity();
            } catch (CertificateExpiredException cee) {
                // Signers Certificate has expired.
                cadata.setStatus(SecConst.CA_EXPIRED);
                getLogSession().log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Signing CA " + cadata.getSubjectDN() + " has expired", cee);
                throw new EJBException("Signing CA " + cadata.getSubjectDN() + " has expired");
            } catch (CertificateNotYetValidException cve) {
                throw new EJBException(cve);
            }


            // Now finally after all these checks, get the certificate
            Certificate cert = createCertificate(admin, data, ca, pk, keyusage);
            // Call authentication session and tell that we are finished with this user
            if (ca.getFinishUser() == true) {
                finishUser(admin, username, password);
            }
            debug("<createCertificate(pk, ku)");
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
        debug(">createCertificate(pk, certType)");
        // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
        boolean[] keyusage = new boolean[9];
        Arrays.fill(keyusage, false);
        switch (certType) {
            case CertificateDataBean.CERT_TYPE_ENCRYPTION:
                // keyEncipherment
                keyusage[2] = true;
                // dataEncipherment
                keyusage[3] = true;
                break;
            case CertificateDataBean.CERT_TYPE_SIGNATURE:
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
        debug("<createCertificate(pk, certType)");
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
        debug(">createCertificate(cert)");
        X509Certificate cert = (X509Certificate) incert;
        try {
            cert.verify(cert.getPublicKey());
        } catch (Exception e) {
            throw new SignRequestSignatureException("Verification of signature (popo) on certificate failed.");
        }
        Certificate ret = createCertificate(admin, username, password, cert.getPublicKey(), cert.getKeyUsage());
        debug("<createCertificate(cert)");
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
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, Class responseClass) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException {
        return createCertificate(admin, req, -1, responseClass);
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
     *                      keyUsage should be used.
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
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, int keyUsage, Class responseClass) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException {
        debug(">createCertificate(IRequestMessage)");
        // Get CA that will receive request
        CADataLocal cadata = null;
        UserDataVO data = null;
        IResponseMessage ret = null;            
        try {
        	cadata = getCAFromRequest(admin, req);
            CA ca = cadata.getCA();
            CAToken catoken = ca.getCAToken();
            
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo((X509Certificate)ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            }
            // Verify the request
            if (req.verify() == false) {
                getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "POPO verification failed.");
                throw new SignRequestSignatureException("Verification of signature (popo) on request failed.");
            }
            
            if (req.getUsername() == null) {
                log.error("No username in request, request DN: "+req.getRequestDN());
                throw new SignRequestException("No username in request, request DN: "+req.getRequestDN());
                //ret.setFailInfo(FailInfo.BAD_REQUEST);
                //ret.setStatus(ResponseStatus.FAILURE);
            } else if (req.getPassword() == null) {
                log.error("No password in request");
                throw new SignRequestException("No password in request!");
            } else {              
				// If we haven't done so yet, authenticate user
                if (data == null) {
                    data = authUser(admin, req.getUsername(), req.getPassword());
                }
                PublicKey reqpk = req.getRequestPublicKey();
                if (reqpk == null) {
                    throw new InvalidKeyException("Key is null!");
                }
                Certificate cert = null;
                cert = createCertificate(admin, data, ca, reqpk, keyUsage);
                
                //Create the response message with all nonces and checks etc
                ret = createResponseMessage(responseClass, req, ca, catoken);
				
				if (cert != null) {
                    ret.setCertificate(cert);
                    ret.setStatus(ResponseStatus.SUCCESS);
                } else {
                    ret.setStatus(ResponseStatus.FAILURE);
                    ret.setFailInfo(FailInfo.BAD_REQUEST);
                }
            }
            ret.create();
            // Call authentication session and tell that we are finished with this user
            if (ca.getFinishUser() == true) {
                finishUser(admin, req.getUsername(), req.getPassword());
            }
            // TODO: handle returning errors as response message,
            // javax.ejb.ObjectNotFoundException and the others thrown...
        } catch (ObjectNotFoundException oe) {
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
            log.error("CA Token is Offline: ", ctoe);
            cadata.setStatus(SecConst.CA_OFFLINE);
            getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Signing CA " + cadata.getSubjectDN() + " is offline.", ctoe);
            throw new CADoesntExistsException("Signing CA " + cadata.getSubjectDN() + " is offline.");
        }
        debug("<createCertificate(IRequestMessage)");
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
        debug(">decryptAndVerifyRequest(IRequestMessage)");
        // Get CA that will receive request
        CADataLocal cadata = null;
            
        try {
        	cadata = getCAFromRequest(admin, req);
            CA ca = cadata.getCA();
            CAToken catoken = ca.getCAToken();
            
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo((X509Certificate)ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            }
            // Verify the request
            if (req.verify() == false) {
                getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "POPO verification failed.");
                throw new SignRequestSignatureException("Verification of signature (popo) on request failed.");
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
            log.error("CA Token is Offline: ", ctoe);
            cadata.setStatus(SecConst.CA_OFFLINE);
            getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Signing CA " + cadata.getSubjectDN() + " is offline.", ctoe);
            throw new CADoesntExistsException("Signing CA " + cadata.getSubjectDN() + " is offline.");
        }
        debug("<decryptAndVerifyRequest(IRequestMessage)");
        return req;
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
     * @throws AuthLoginException 
     * @throws AuthStatusException 
     * @throws IllegalKeyException 
     * @throws CADoesntExistsException 
     * @throws SignRequestSignatureException 
     * @ejb.permission unchecked="true"
     * @ejb.interface-method view-type="both"
     * @see se.anatom.ejbca.protocol.IRequestMessage
     * @see se.anatom.ejbca.protocol.IResponseMessage
     * @see se.anatom.ejbca.protocol.X509ResponseMessage
     */
    public IResponseMessage createRequestFailedResponse(Admin admin, IRequestMessage req,  Class responseClass) throws  AuthLoginException, AuthStatusException, IllegalKeyException, CADoesntExistsException, SignRequestSignatureException {
        debug(">createRequestFailedResponse(IRequestMessage)");
        IResponseMessage ret = null;            
        CADataLocal cadata = null;
        try {
        	cadata = getCAFromRequest(admin, req);
            CA ca = cadata.getCA();
            CAToken catoken = ca.getCAToken();
         
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo((X509Certificate)ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            }
            // Verify the request
            if (req.verify() == false) {
                getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "POPO verification failed.");
                throw new SignRequestSignatureException("Verification of signature (popo) on request failed.");
            }
            
            //Create the response message with all nonces and checks etc
            ret = createResponseMessage(responseClass, req, ca, catoken);
            
            ret.setStatus(ResponseStatus.FAILURE);
            ret.setFailInfo(FailInfo.BAD_REQUEST);
            ret.create();
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
        } catch (IOException e) {
            log.error("Cannot create response message: ", e);
        } catch (CATokenOfflineException ctoe) {
            log.error("CA Token is Offline: ", ctoe);
            cadata.setStatus(SecConst.CA_OFFLINE);
            getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Signing CA " + cadata.getSubjectDN() + " is offline.", ctoe);
            throw new CADoesntExistsException("Signing CA " + cadata.getSubjectDN() + " is offline.");
        }
        debug("<createRequestFailedResponse(IRequestMessage)");
        return ret;
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
    public IResponseMessage getCRL(Admin admin, IRequestMessage req, Class responseClass) throws IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException {
        debug(">getCRL(IRequestMessage)");
        IResponseMessage ret = null;
        ICertificateStoreSessionLocal certificateStore = null;
        try {
            certificateStore = storeHome.create();
        } catch (CreateException e) {
            error("Can not create certificate store session: ", e);
            throw new EJBException(e);
        }
        // Get CA that will receive request
        CADataLocal cadata = null;
        try {
            // See if we can get issuerDN directly from request
            if (req.getIssuerDN() != null) {
                cadata = cadatahome.findByPrimaryKey(new Integer(req.getIssuerDN().hashCode()));
                debug("Using CA (from issuerDN) with id: " + cadata.getCaId() + " and DN: " + cadata.getSubjectDN());
            } else {
                throw new CADoesntExistsException();
            }
        } catch (javax.ejb.FinderException fe) {
            error("Can not find CA Id from issuerDN: " + req.getIssuerDN() + " or username: " + req.getUsername());
            getLogSession().log(admin, -1, LogEntry.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogEntry.EVENT_ERROR_GETLASTCRL, "Invalid CA Id", fe);
            throw new CADoesntExistsException(fe);
        }
        try {
            CA ca = cadata.getCA();
            CAToken catoken = ca.getCAToken();

            if (ca.getStatus() != SecConst.CA_ACTIVE) {
                getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_GETLASTCRL, "Signing CA " + cadata.getSubjectDN() + " isn't active.");
                throw new EJBException("Signing CA " + cadata.getSubjectDN() + " isn't active.");
            }

            // Check that CA hasn't expired.
            X509Certificate cacert = (X509Certificate) ca.getCACertificate();
            try {
                cacert.checkValidity();
            } catch (CertificateExpiredException cee) {
                // Signers Certificate has expired.
                cadata.setStatus(SecConst.CA_EXPIRED);
                getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_GETLASTCRL, "Signing CA " + cadata.getSubjectDN() + " has expired", cee);
                throw new CADoesntExistsException("Signing CA " + cadata.getSubjectDN() + " has expired");
            } catch (CertificateNotYetValidException cve) {
                throw new CADoesntExistsException(cve);
            }

            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo((X509Certificate)ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            }
            //Create the response message with all nonces and checks etc
            ret = createResponseMessage(responseClass, req, ca, catoken);
            
            // Get the CRL, don't even bother digging into the encrypted CRLIssuerDN...since we already
            // know that we are the CA (SCEP is soooo stupid!)
            byte[] crl = certificateStore.getLastCRL(admin, req.getIssuerDN());
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
            log.error("CA Token is Offline: ", ctoe);
            cadata.setStatus(SecConst.CA_OFFLINE);
            getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_GETLASTCRL, "Signing CA " + cadata.getSubjectDN() + " is offline.", ctoe);
            throw new CADoesntExistsException("Signing CA " + cadata.getSubjectDN() + " is offline.");
        }
        debug("<getCRL(IRequestMessage)");
        return ret;
    }
    
    /**
     * Help Method that extracts the CA specified in the request.
     * 
     */
    private CADataLocal getCAFromRequest(Admin admin, IRequestMessage req) throws AuthStatusException, AuthLoginException, CADoesntExistsException, UnsupportedEncodingException{
    	CADataLocal cadata = null;
    	UserDataVO data = null;
        try {
            // See if we can get issuerDN directly from request
            if (req.getIssuerDN() != null) {
                cadata = cadatahome.findByPrimaryKey(new Integer(req.getIssuerDN().hashCode()));
                debug("Using CA (from issuerDN) with id: " + cadata.getCaId() + " and DN: " + cadata.getSubjectDN());
            } else if (req.getUsername() != null) {
                // See if we can get username and password directly from request
                String username = req.getUsername();
                String password = req.getPassword();
                data = authUser(admin, username, password);
                cadata = cadatahome.findByPrimaryKey(new Integer(data.getCAId()));
                debug("Using CA (from username) with id: " + cadata.getCaId() + " and DN: " + cadata.getSubjectDN());
            } else {
                throw new CADoesntExistsException();
            }
        } catch (javax.ejb.FinderException fe) {
            error("Can not find CA Id from issuerDN: " + req.getIssuerDN() + " or username: " + req.getUsername());
            getLogSession().log(admin, -1, LogEntry.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Invalid CA Id", fe);
            throw new CADoesntExistsException(fe);
        }
        
        CA ca = cadata.getCA();

        if (ca.getStatus() != SecConst.CA_ACTIVE) {
            getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Signing CA " + cadata.getSubjectDN() + " isn't active.");
            throw new EJBException("Signing CA " + cadata.getSubjectDN() + " isn't active.");
        }

        // Check that CA hasn't expired.
        X509Certificate cacert = (X509Certificate) ca.getCACertificate();
        try {
            cacert.checkValidity();
        } catch (CertificateExpiredException cee) {
            // Signers Certificate has expired.
            cadata.setStatus(SecConst.CA_EXPIRED);
            getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Signing CA " + cadata.getSubjectDN() + " has expired", cee);
            throw new CADoesntExistsException("Signing CA " + cadata.getSubjectDN() + " has expired");
        } catch (CertificateNotYetValidException cve) {
            throw new CADoesntExistsException(cve);
        }
        
        return cadata;
    }

    private IResponseMessage createResponseMessage(Class responseClass, IRequestMessage req, CA ca, CAToken catoken) throws CATokenOfflineException {
    	IResponseMessage ret = null;
    	// Create the response message and set all required fields
    	try {
    		ret = (IResponseMessage) responseClass.newInstance();
    	} catch (InstantiationException e) {
    		//TODO : do something with these exceptions
    		log.error("Error creating response message", e);
    		return null;
    	} catch (IllegalAccessException e) {
    		log.error("Error creating response message", e);
    		return null;
    	}
    	if (ret.requireSignKeyInfo()) {
    		ret.setSignKeyInfo((X509Certificate) ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
    	}
    	if (ret.requireEncKeyInfo()) {
    		ret.setEncKeyInfo((X509Certificate) ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT), catoken.getProvider());
    	}
    	if (req.getSenderNonce() != null) {
    		ret.setRecipientNonce(req.getSenderNonce());
    	}
    	if (req.getTransactionId() != null) {
    		ret.setTransactionId(req.getTransactionId());
    	}
    	// Sendernonce is a random number
    	byte[] senderNonce = new byte[16];
    	randomSource.nextBytes(senderNonce);
    	ret.setSenderNonce(new String(Base64.encode(senderNonce)));
    	// If we have a specified request key info, use it in the reply
    	if (req.getRequestKeyInfo() != null) {
    		ret.setRecipientKeyInfo(req.getRequestKeyInfo());
    	}
    	// Which digest algorithm to use to create the response, if applicable
    	ret.setPreferredDigestAlg(req.getPreferredDigestAlg());
    	// Include the CA cert or not in the response, if applicable for the response type
    	ret.setIncludeCACert(req.includeCACert());
    	return ret;
    }
    /**
     * Requests for a CRL to be created with the passed (revoked) certificates.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param caid Id of the CA which CRL should be created.
     * @param certs vector of RevokedCertInfo object.
     * @return The newly created CRL in DER encoded byte form or null, use CerlTools.getCRLfromByteArray to convert to X509CRL.
     * @ejb.interface-method view-type="both"
     */
    public byte[] createCRL(Admin admin, int caid, Vector certs) {
        debug(">createCRL()");
        byte[] crlBytes;
        try {
            // get CA
            CADataLocal cadata = null;
            try {
                cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            } catch (javax.ejb.FinderException fe) {
                getLogSession().log(admin, caid, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECRL, "Invalid CA Id", fe);
                throw new EJBException(fe);
            }

            CA ca = null;
            try {
                ca = cadata.getCA();
            } catch (java.io.UnsupportedEncodingException uee) {
                throw new EJBException(uee);
            }
            if (ca.getStatus() != SecConst.CA_ACTIVE) {
                getLogSession().log(admin, caid, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Signing CA " + cadata.getSubjectDN() + " isn't active.");
                throw new EJBException("Signing CA " + cadata.getSubjectDN() + " isn't active.");
            }

            // Check that CA hasn't expired.
            X509Certificate cacert = (X509Certificate) ca.getCACertificate();
            try {
                cacert.checkValidity();
            } catch (CertificateExpiredException e) {
                // Signers Certificate has expired.
                cadata.setStatus(SecConst.CA_EXPIRED);
                getLogSession().log(admin, caid, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECRL, "Signing CA " + cadata.getSubjectDN() + " has expired", e);
                throw new EJBException("Signing CA " + cadata.getSubjectDN() + " has expired");
            } catch (CertificateNotYetValidException e) {
                throw new EJBException(e);
            }

            ICertificateStoreSessionLocal certificateStore = storeHome.create();
            // Get number of last CRL and increase by 1
            int number = certificateStore.getLastCRLNumber(admin, ca.getSubjectDN()) + 1;
            X509CRL crl = null;
            try {
                crl = (X509CRL) ca.generateCRL(certs, number);
            } catch (CATokenOfflineException ctoe) {
                log.error("CA Token is Offline: ", ctoe);
                cadata.setStatus(SecConst.CA_OFFLINE);
                getLogSession().log(admin, cadata.getCaId().intValue(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECRL, "Signing CA " + cadata.getSubjectDN() + " is offline.", ctoe);
                throw new EJBException("Signing CA " + cadata.getSubjectDN() + " is offline.");
            }
            getLogSession().log(admin, caid, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_CREATECRL, "Number :" + number);

            // Store CRL in the database
            String fingerprint = CertTools.getFingerprintAsString(cacert);
            certificateStore.storeCRL(admin, crl.getEncoded(), fingerprint, number);
            // Store crl in ca CRL publishers.
            IPublisherSessionLocal pub = publishHome.create();
            pub.storeCRL(admin, ca.getCRLPublishers(), crl.getEncoded(), fingerprint, number);

            crlBytes = crl.getEncoded();
        } catch (Exception e) {
            getLogSession().log(admin, caid, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CREATECRL, "");
            throw new EJBException(e);
        }
        debug("<createCRL()");
        return crlBytes;
    } // createCRL

    /**
     * Method that publishes the given CA certificate chain to the list of publishers.
     * Is mainly used by CAAdminSessionBean when CA is created.
     *
     * @param admin            Information about the administrator or admin preforming the event.
     * @param certificatechain certchain of certificate to publish
     * @param usedpublishers   a collection if publisher id's (Integer) indicating which publisher that should be used.
     * @param certtype         is one of SecConst.CERTTYPE_ constants
     * @ejb.interface-method view-type="both"
     */
    public void publishCACertificate(Admin admin, Collection certificatechain, Collection usedpublishers, int certtype) {
        try {

            ICertificateStoreSessionLocal certificateStore = storeHome.create();

            Iterator certificates = certificatechain.iterator();
            while (certificates.hasNext()) {
                Certificate cacert = (Certificate) certificates.next();

                //     Store CA certificate in the database
                String fingerprint = CertTools.getFingerprintAsString((X509Certificate) cacert);

                if (certificateStore.findCertificateByFingerprint(admin, fingerprint) == null) {
                    certificateStore.storeCertificate(admin, cacert, "SYSTEMCA", fingerprint, CertificateDataBean.CERT_ACTIVE, certtype);
                }
                // Store cert in ca cert publishers.
                IPublisherSessionLocal pub = publishHome.create();
                if (usedpublishers != null)
                    pub.storeCertificate(admin, usedpublishers, cacert, fingerprint, null, fingerprint, CertificateDataBean.CERT_ACTIVE, certtype, null);
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

    private void finishUser(Admin admin, String username, String password) throws ObjectNotFoundException {
        // Finnish user and set new status
        try {
            IAuthenticationSessionLocal authSession = authHome.create();
            authSession.finishUser(admin, username, password);
        } catch (CreateException e) {
            log.error(e);
            throw new EJBException(e);
        }
    } // finishUser

    /**
     * Creates the certificate, does NOT check any authorization on user, profiles or CA!
     * This must be done earlier
     *
     * @param admin    administrator performing this task
     * @param data     auth data for user to get the certificate
     * @param ca       the CA that will sign the certificate
     * @param pk       ther users public key to be put in the certificate
     * @param keyusage requested key usage for the certificate, may be ignored by the CA
     * @return Certificate that has been generated and signed by the CA
     * @throws IllegalKeyException if the public key given is invalid
     */
    private Certificate createCertificate(Admin admin, UserDataVO data, CA ca, PublicKey pk, int keyusage) throws IllegalKeyException {
        debug(">createCertificate(pk, ku)");
        try {
            // If the user is of type USER_INVALID, it cannot have any other type (in the mask)
            if (data.getType() == SecConst.USER_INVALID) {
                getLogSession().log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "User type is invalid, cannot create certificate for this user.");
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

                // Sign Session bean is only able to issue certificates with a end entity type certificate profile.
                if (certProfile.getType() != CertificateProfile.TYPE_ENDENTITY) {
                    getLogSession().log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Wrong type of Certificate Profile for end entity. Only End Entity Certificate Profiles can be issued by signsession bean.");
                    throw new EJBException("Wrong type of Certificate Profile for end entity. Only End Entity Certificate Profiles can be issued by signsession bean.");
                }

                if (!caauthorized) {
                    getLogSession().log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogEntry.EVENT_ERROR_CREATECERTIFICATE, "End Entity data contains a CA which the Certificate Profile isn't authorized to use.");
                    throw new EJBException("End Entity data contains a CA which the Certificate Profile isn't authorized to use.");
                }

                log.debug("Using certificate profile with id " + certProfileId);
                int keyLength;
                try {
                    keyLength = ((RSAPublicKey) pk).getModulus().bitLength();
                } catch (ClassCastException e) {
                    throw new
                            IllegalKeyException("Unsupported public key (" +
                            pk.getClass().getName() +
                            "), only RSA keys are supported.");
                }
                log.debug("Keylength = " + keyLength); // bitBength() will return 1 less bit if BigInt i negative
                if ((keyLength < (certProfile.getMinimumAvailableBitLength() - 1))
                        || (keyLength > (certProfile.getMaximumAvailableBitLength()))) {
                    String msg = "Illegal key length " + keyLength;
                    log.error(msg);
                    throw new IllegalKeyException(msg);
                }

                X509Certificate cert = (X509Certificate) ca.generateCertificate(data, pk, keyusage, certProfile);

                getLogSession().log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), data.getUsername(), cert, LogEntry.EVENT_INFO_CREATECERTIFICATE, "");
                debug("Generated certificate with SerialNumber '" + Hex.encode(cert.getSerialNumber().toByteArray()) + "' for user '" + data.getUsername() + "'.");
                debug(cert.toString());

                // Store certificate in the database
                String cafingerprint = null;
                Certificate cacert = ca.getCACertificate();
                if (cacert instanceof X509Certificate) {
                    cafingerprint = CertTools.getFingerprintAsString((X509Certificate)cacert);
                }
                certificateStore.storeCertificate(admin, cert, data.getUsername(), cafingerprint, CertificateDataBean.CERT_ACTIVE, certProfile.getType());
                // Store the request data in history table.
                certificateStore.addCertReqHistoryData(admin,cert,data);
                // Store certificate in certificate profiles publishers.
                IPublisherSessionLocal pub = publishHome.create();
                if (certProfile.getPublisherList() != null)
                    pub.storeCertificate(admin, certProfile.getPublisherList(), cert, data.getUsername(), data.getPassword(), cafingerprint, CertificateDataBean.CERT_ACTIVE, certProfile.getType(), data.getExtendedinformation());

                debug("<createCertificate(pk, ku)");
                return cert;
            }
        } catch (IllegalKeyException ke) {
            throw ke;
        } catch (CATokenOfflineException ctoe) {
            ca.setStatus(SecConst.CA_OFFLINE);
            throw new EJBException("Error CA Token is Offline", ctoe);
        } catch (Exception e) {
            log.error(e);
            throw new EJBException(e);
        }
        debug("<createCertificate(pk, ku)");
        log.error("Invalid user type for user " + data.getUsername());
        throw new EJBException("Invalid user type for user " + data.getUsername());
    } // createCertificate

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
            returnval = cadata.getCA().extendedService(request);
        } catch (javax.ejb.FinderException fe) {
            throw new CADoesntExistsException(fe);
        } catch (UnsupportedEncodingException ue) {
            throw new EJBException(ue);
        }


        return returnval;

    }


} //RSASignSessionBean

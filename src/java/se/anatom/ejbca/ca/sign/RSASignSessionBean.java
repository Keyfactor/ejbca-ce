package se.anatom.ejbca.ca.sign;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;

import org.bouncycastle.jce.PKCS7SignedData;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.X509V2CRLGenerator;
import org.bouncycastle.jce.X509V3CertificateGenerator;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.auth.IAuthenticationSessionLocal;
import se.anatom.ejbca.ca.auth.IAuthenticationSessionLocalHome;
import se.anatom.ejbca.ca.auth.UserAuthData;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.IllegalKeyException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.ca.store.IPublisherSessionLocal;
import se.anatom.ejbca.ca.store.IPublisherSessionLocalHome;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import java.math.BigInteger;

import java.rmi.RemoteException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Properties;
import java.util.Vector;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.ObjectNotFoundException;


/**
 * Creates X509 certificates using RSA keys.
 *
 * @version $Id: RSASignSessionBean.java,v 1.89 2003-07-21 14:18:26 anatom Exp $
 */
public class RSASignSessionBean extends BaseSessionBean {
    transient X509Certificate caCert;
    transient X509Name caSubjectName;

    // CRL parameters
    private Long crlperiod;
    private Boolean useaki;
    private Boolean akicritical;
    private Boolean usecrln;
    private Boolean crlncritical;
    private Boolean emailindn;
    private Boolean finishUser;
    transient ISigningDevice signingDevice;

    /** Home interface to certificate store */
    private ICertificateStoreSessionLocalHome storeHome = null;

    /** A vector of publishers home interfaces where certs and CRLs are stored */
    private ArrayList publishers = null;

    /* Home interface to Authentication session */
    private IAuthenticationSessionLocalHome authHome = null;

    /** The remote interface of the log session bean */
    private ILogSessionRemote logsession;

    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");

        try {
            // Install BouncyCastle provider
            Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
            int result = Security.addProvider(BCJce);

            // get home interfaces to other session beans used
            storeHome = (ICertificateStoreSessionLocalHome) lookup(
                    "java:comp/env/ejb/CertificateStoreSessionLocal");
            authHome = (IAuthenticationSessionLocalHome) lookup(
                    "java:comp/env/ejb/AuthenticationSessionLocal");

            ILogSessionHome logsessionhome = (ILogSessionHome) lookup("java:comp/env/ejb/LogSession",
                    ILogSessionHome.class);
            logsession = logsessionhome.create();

            // Init the publisher session beans
            int i = 1;
            publishers = new ArrayList();

            try {
                while (true) {
                    String jndiName = "java:comp/env/ejb/PublisherSession" + i;
                    IPublisherSessionLocalHome pubHome = (IPublisherSessionLocalHome) lookup(jndiName);
                    publishers.add(pubHome);
                    debug("Added publisher class '" + pubHome.getClass().getName() + "'");
                    i++;
                }
            } catch (EJBException e) {
                // We could not find this publisher
                debug("Failed to find publisher at index '" + i + "', no more publishers.");
            }

            // Create a Signing device of type pointed to by env variable using properties ot pass args
            Properties p = new Properties();
            String keyStoreFile = (String) lookup("java:comp/env/keyStore", java.lang.String.class);
            p.setProperty("keyStore", keyStoreFile);

            String keyStorePass = getPassword("java:comp/env/keyStorePass");
            p.setProperty("keyStorePass", keyStorePass);

            String privateKeyAlias = (String) lookup("java:comp/env/privateKeyAlias",
                    java.lang.String.class);
            p.setProperty("privateKeyAlias", privateKeyAlias);

            String privateKeyPass = getPassword("java:comp/env/privateKeyPass");
            p.setProperty("privateKeyPass", privateKeyPass);

            String signingDeviceFactoryName = (String) lookup("java:comp/env/signingDeviceFactory");
            ISigningDeviceFactory signingDeviceFactory = (ISigningDeviceFactory) Class.forName(signingDeviceFactoryName)
                                                                                      .newInstance();
            debug("Creating SigningDeviceFactory of type " + signingDeviceFactoryName);
            signingDevice = signingDeviceFactory.makeInstance(p);

            //signingDevice = fact.makeInstance(p);
            // We must keep the same order in the DN in the issuer field in created certificates as there
            // is in the subject field of the CA-certificate.
            Certificate[] certs = signingDevice.getCertificateChain();
            caCert = CertTools.getCertfromByteArray(((X509Certificate) certs[0]).getEncoded());
            caSubjectName = new X509Name(caCert.getSubjectDN().toString());

            // Should extensions be used in CRLs? Critical or not?
            if ((useaki = (Boolean) lookup("java:comp/env/AuthorityKeyIdentifier",
                            java.lang.Boolean.class)).booleanValue() == true) {
                akicritical = (Boolean) lookup("java:comp/env/AuthorityKeyIdentifierCritical",
                        java.lang.Boolean.class);
            }

            if ((usecrln = (Boolean) lookup("java:comp/env/CRLNumber", java.lang.Boolean.class)).booleanValue() == true) {
                crlncritical = (Boolean) lookup("java:comp/env/CRLNumberCritical",
                        java.lang.Boolean.class);
            }

            // The period between CRL issue
            crlperiod = (Long) lookup("java:comp/env/CRLPeriod", java.lang.Long.class);

            // Use old style email address in DN? (really deprecated but old habits die hard...)
            emailindn = (Boolean) lookup("java:comp/env/EmailInDN", java.lang.Boolean.class);

            // Should we set user to finished state after generating certificate? Probably means onyl one cert can be issued
            // without resetting users state in user DB
            finishUser = (Boolean) lookup("java:comp/env/FinishUser", java.lang.Boolean.class);
        } catch (Exception e) {
            debug("Caught exception in ejbCreate(): ", e);
            throw new EJBException(e);
        }

        debug("<ejbCreate()");
    }

    /**
     * Implements ISignSession::getCertificateChain
     *
     * @param admin admin performing action!
     *
     * @return certificate
     */
    public Certificate[] getCertificateChain(Admin admin) {
        debug(":getCertificateChain()");

        return signingDevice.getCertificateChain();
    }

    // getCertificateChain

    /**
     * Implements ISignSession::createPKCS7
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param cert client certificate which we want ancapsulated in a PKCS7 together with
     *        certificate chain. If null, a PKCS7 with only CA certificate chain is returned.
     *
     * @return The DER-encoded PKCS7 message.
     *
     * @throws SignRequestSignatureException is the provided client certificate was not signed by
     *         the CA.
     */
    public byte[] createPKCS7(Admin admin, Certificate cert)
        throws SignRequestSignatureException {
        debug(">createPKCS7()");

        // First verify that we signed this certificate
        try {
            if (cert != null) {
                cert.verify(signingDevice.getPublicSignKey(), signingDevice.getProvider());
            }
        } catch (Exception e) {
            throw new SignRequestSignatureException(
                "Cannot verify certificate in createPKCS7(), did I sign this?");
        }

        Certificate[] chain = getCertificateChain(admin);
        Certificate[] certs;

        if (cert != null) {
            certs = new Certificate[chain.length + 1];
            certs[0] = cert;

            for (int i = 0; i < chain.length; i++) {
                certs[i + 1] = chain[i];
            }
        } else {
            certs = chain;
        }

        try {
            PKCS7SignedData pkcs7 = new PKCS7SignedData(signingDevice.getPrivateSignKey(), certs,
                    "SHA1", signingDevice.getProvider());
            debug("<createPKCS7()");

            return pkcs7.getEncoded();
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    // createPKCS7

    /**
     * Implements ISignSession::createCertificate
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk the public key to be put in the created certificate.
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     */
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException {
        debug(">createCertificate(pk)");

        // Default key usage is defined in certificate profiles
        debug("<createCertificate(pk)");

        return createCertificate(admin, username, password, pk, -1);
    }

    // createCertificate

    /**
     * Implements ISignSession::createCertificate
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk the public key to be put in the created certificate.
     * @param keyusage integer with mask describing desired key usage in format specified by
     *        X509Certificate.getKeyUsage(). id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
     *        KeyUsage ::= BIT STRING { digitalSignature        (0), nonRepudiation          (1),
     *        keyEncipherment         (2), dataEncipherment        (3), keyAgreement (4),
     *        keyCertSign             (5), cRLSign                 (6), encipherOnly (7),
     *        decipherOnly            (8) }
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        PublicKey pk, boolean[] keyusage)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException {
        return createCertificate(admin, username, password, pk, sunKeyUsageToBC(keyusage));
    }

    /**
     * Implements ISignSession::createCertificate
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk the public key to be put in the created certificate.
     * @param keyusage integer with bit mask describing desired keys usage, overrides keyUsage from
     *        CertificateProfiles if allowed. Bit mask is packed in in integer using constants
     *        from CertificateData. -1 means use default keyUsage from CertificateProfile. ex. int
     *        keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *        digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *        | CertificateData.cRLSign; gives keyCertSign and cRLSign
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        PublicKey pk, int keyusage)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException {
        debug(">createCertificate(pk, ku)");

        try {
            // Authorize user and get DN
            IAuthenticationSessionLocal authSession = authHome.create();
            UserAuthData data = authSession.authenticateUser(admin, username, password);
            debug("Authorized user " + username + " with DN='" + data.getDN() + "'.");
            debug("type=" + data.getType());

            // If the user is of type USER_INVALUD, it cannot have any other type (in the mask)
            if (data.getType() == SecConst.USER_INVALID) {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CREATECERTIFICATE,
                    "User type is invalid, cannot create certificate for this user.");
            } else {
                ICertificateStoreSessionLocal certificateStore = storeHome.create();

                // Retrieve the certificate profile this user should have
                int certProfileId = data.getCertProfileId();
                CertificateProfile certProfile = certificateStore.getCertificateProfile(admin,
                        certProfileId);

                // What if certProfile == null?
                if (certProfile == null) {
                    certProfileId = SecConst.CERTPROFILE_FIXED_ENDUSER;
                    certProfile = certificateStore.getCertificateProfile(admin, certProfileId);
                }

                log.debug("Using certificate profile with id " + certProfileId);

                int keyLength;

                try {
                    keyLength = ((RSAPublicKey) pk).getModulus().bitLength();
                } catch (ClassCastException e) {
                    throw new IllegalKeyException("Unsupported public key (" +
                        pk.getClass().getName() + "), only RSA keys are supported.");
                }

                log.debug("Keylength = " + keyLength); // bitBength() will return 1 less bit if BigInt i negative

                if ((keyLength < (certProfile.getMinimumAvailableBitLength() - 1)) ||
                        (keyLength > (certProfile.getMaximumAvailableBitLength()))) {
                    String msg = "Illegal key length " + keyLength;
                    log.error(msg);
                    throw new IllegalKeyException(msg);
                }

                X509Certificate cert = makeBCCertificate(data, caSubjectName, pk, keyusage,
                        certProfile);
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), username, cert,
                    LogEntry.EVENT_INFO_CREATECERTIFICATE, "");
                debug("Generated certificate with SerialNumber '" +
                    Hex.encode(cert.getSerialNumber().toByteArray()) + "' for user '" + username +
                    "'.");
                debug(cert.toString());

                // Verify before returning
                cert.verify(caCert.getPublicKey());

                // Store certificate in the database
                certificateStore.storeCertificate(admin, cert, username,
                    CertTools.getFingerprintAsString(caCert), CertificateData.CERT_ACTIVE,
                    certProfile.getType());

                // Store certificate in publishers
                for (int i = 0; i < publishers.size(); i++) {
                    IPublisherSessionLocalHome pubHome = (IPublisherSessionLocalHome) publishers.get(i);
                    IPublisherSessionLocal pub = pubHome.create();
                    pub.storeCertificate(admin, cert, username,
                        CertTools.getFingerprintAsString(caCert), CertificateData.CERT_ACTIVE,
                        certProfile.getType());
                }

                // Call authentication session and tell that we are finished with this user
                if (finishUser.booleanValue() == true) {
                    authSession.finishUser(admin, username, password);
                }

                debug("<createCertificate(pk, ku)");

                return cert;
            }
        } catch (ObjectNotFoundException oe) {
            throw oe;
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (IllegalKeyException ke) {
            throw ke;
        } catch (Exception e) {
            log.error(e);
            throw new EJBException(e);
        }

        debug("<createCertificate(pk, ku)");
        log.error("Invalid user type for user " + username);
        throw new EJBException("Invalid user type for user " + username);
    }

    // createCertificate

    /**
     * Implements ISignSession::createCertificate
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param certType integer type of certificate taken from CertificateData.CERT_TYPE_XXX. the
     *        type CertificateData.CERT_TYPE_ENCRYPTION gives keyUsage keyEncipherment,
     *        dataEncipherment. the type CertificateData.CERT_TYPE_SIGNATURE gives keyUsage
     *        digitalSignature, non-repudiation. all other CERT_TYPES gives the default keyUsage
     *        digitalSignature, keyEncipherment
     * @param pk the public key to be put in the created certificate.
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        int certType, PublicKey pk)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException {
        debug(">createCertificate(pk, certType)");

        // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
        boolean[] keyusage = new boolean[9];
        Arrays.fill(keyusage, false);

        switch (certType) {
        case CertificateData.CERT_TYPE_ENCRYPTION:

            // keyEncipherment
            keyusage[2] = true;

            // dataEncipherment
            keyusage[3] = true;

            break;

        case CertificateData.CERT_TYPE_SIGNATURE:

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
    }

    // createCertificate

    /**
     * Implements ISignSession::createCertificate
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param incert a certificate containing the public key to be put in the created certificate.
     *        Other (requested) parameters in the passed certificate can be used, such as DN,
     *        Validity, KeyUsage etc. Currently only KeyUsage is considered!
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *         the CA.
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        Certificate incert)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, SignRequestSignatureException {
        debug(">createCertificate(cert)");

        X509Certificate cert = (X509Certificate) incert;

        try {
            cert.verify(cert.getPublicKey());
        } catch (Exception e) {
            try {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CREATECERTIFICATE, "POPO verification failed.");
            } catch (RemoteException re) {
                throw new EJBException(re);
            }

            throw new SignRequestSignatureException(
                "Verification of signature (popo) on certificate failed.");
        }

        Certificate ret = createCertificate(admin, username, password, cert.getPublicKey(),
                cert.getKeyUsage());
        debug("<createCertificate(cert)");

        return ret;
    }

    // createCertificate

    /**
     * Implements ISignSession::createCertificate
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param req a Certification Request message, containing the public key to be put in the
     *        created certificate. Currently no additional parameters in requests are considered!
     *        Currently no additional parameters in the PKCS10 request is considered!
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws SignRequestException if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *         the CA.
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        IRequestMessage req)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, SignRequestException, SignRequestSignatureException {
        return createCertificate(admin, username, password, req, -1);
    }

    /**
     * Implements ISignSession::createCertificate
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param req a Certification Request message, containing the public key to be put in the
     *        created certificate. Currently no additional parameters in requests are considered!
     * @param keyUsage integer with bit mask describing desired keys usage. Bit mask is packed in
     *        in integer using contants from CertificateData. ex. int keyusage =
     *        CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *        digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *        | CertificateData.cRLSign; gives keyCertSign and cRLSign
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws SignRequestException if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *         the CA.
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        IRequestMessage req, int keyUsage)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, SignRequestException, SignRequestSignatureException {
        debug(">createCertificate(user,pwd,IRequestMessage)");

        Certificate ret = null;

        try {
            try {
                if (req.requireKeyInfo()) {
                    req.setKeyInfo(caCert, signingDevice.getPrivateDecKey());
                }

                if (req.verify() == false) {
                    logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), username, null,
                        LogEntry.EVENT_ERROR_CREATECERTIFICATE, "POPO verification failed.");
                    throw new EJBException("Verification of signature (popo) on request failed.");
                }

                PublicKey reqpk = req.getRequestPublicKey();

                if (reqpk == null) {
                    throw new InvalidKeyException("Key is null!");
                }

                if (keyUsage < 0) {
                    ret = createCertificate(admin, username, password, reqpk);
                } else {
                    ret = createCertificate(admin, username, password, reqpk, keyUsage);
                }
            } catch (IOException e) {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Error reading PKCS10-request.");
                throw new SignRequestException("Error reading PKCS10-request.");
            } catch (NoSuchAlgorithmException e) {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CREATECERTIFICATE,
                    "Error in PKCS10-request, no such algorithm.");
                throw new SignRequestException("Error in PKCS10-request, no such algorithm.");
            } catch (NoSuchProviderException e) {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CREATECERTIFICATE,
                    "Internal error processing PKCS10-request.");
                throw new SignRequestException("Internal error processing PKCS10-request.");
            } catch (InvalidKeyException e) {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), username, null,
                    LogEntry.EVENT_ERROR_CREATECERTIFICATE, "Error in PKCS10-request, invlid key.");
                throw new SignRequestException("Error in PKCS10-request, invalid key.");
            }
        } catch (RemoteException re) {
            throw new EJBException(re);
        }

        debug("<createCertificate(user,pwd,IRequestMessage)");

        return ret;
    }

    /**
     * Implements ISignSession::createCertificate
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param req a Certification Request message, containing the public key to be put in the
     *        created certificate. Currently no additional parameters in requests are considered!
     * @param keyUsage integer with bit mask describing desired keys usage. Bit mask is packed in
     *        in integer using contants from CertificateData. ex. int keyusage =
     *        CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *        digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *        | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @param responseClass The class that will be used as the response message.
     *
     * @return The newly created response or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws SignRequestException if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *         the CA.
     */
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, int keyUsage,
        Class responseClass)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, SignRequestException, SignRequestSignatureException {
        debug(">createCertificate(IRequestMessage)");

        IResponseMessage ret = null;

        if (req.requireKeyInfo()) {
            req.setKeyInfo(caCert, signingDevice.getPrivateDecKey());
        }

        String username = req.getUsername();
        String pwd = req.getPassword();

        if ((username == null) || (pwd == null)) {
            throw new SignRequestException("No username/password in request!");
        }

        Certificate cert = createCertificate(admin, username, pwd, req, keyUsage);

        try {
            ret = (IResponseMessage) responseClass.newInstance();

            if (ret.requireSignKeyInfo()) {
                ret.setSignKeyInfo(caCert, signingDevice.getPrivateSignKey());
            }

            if (ret.requireEncKeyInfo()) {
                ret.setEncKeyInfo(caCert, signingDevice.getPrivateDecKey());
            }

            ret.setCertificate(cert);
            ret.setStatus(IResponseMessage.STATUS_OK);
            if (req.getSenderNonce() != null) {
                ret.setRecipientNonce(req.getSenderNonce());
            }
            if (req.getTransactionId() != null) {
                ret.setTransactionId(req.getTransactionId());
            }
            // Sendernonce is a random number
            ret.setSenderNonce(Hex.encode("1234567890".getBytes()));
            // If we have a specified request key info, use it in the reply
            if (req.getRequestKeyInfo() != null) {
                ret.setRecipientKeyInfo(req.getRequestKeyInfo());
            }
            ret.create();

            // TODO: handle returning errors as response message,
            // javax.ejb.ObjectNotFoundException and the others thrown...
        } catch (NoSuchProviderException e) {
            log.error("Cannot create class for response message: ", e);
        } catch (InvalidKeyException e) {
            log.error("Cannot create class for response message: ", e);
        } catch (IOException e) {
            log.error("Cannot create class for response message: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("Cannot create class for response message: ", e);
        } catch (IllegalAccessException e) {
            log.error("Cannot create class for response message: ", e);
        } catch (InstantiationException e) {
            log.error("Cannot create class for response message: ", e);
        }

        debug("<createCertificate(IRequestMessage)");

        return ret;
    }

    /**
     * Implements ISignSession::createCRL
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param certs vector of RevokedCertInfo object.
     *
     * @return The newly created CRL or null.
     */
    public X509CRL createCRL(Admin admin, Vector certs) {
        debug(">createCRL()");

        X509CRL crl = null;

        try {
            ICertificateStoreSessionLocal certificateStore = storeHome.create();

            // Get number of last CRL and increase by 1
            int number = certificateStore.getLastCRLNumber(admin) + 1;
            crl = makeBCCRL(caSubjectName, crlperiod.longValue(), certs, number);

            // Verify before sending back
            crl.verify(caCert.getPublicKey());

            try {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_CREATECRL, "Number :" + number);
            } catch (RemoteException re) {
                throw new EJBException(re);
            }

            // Store CRL in the database
            certificateStore.storeCRL(admin, crl.getEncoded(),
                CertTools.getFingerprintAsString(caCert), number);

            // Store CRL in publishers
            for (int i = 0; i < publishers.size(); i++) {
                IPublisherSessionLocalHome pubHome = (IPublisherSessionLocalHome) publishers.get(i);
                IPublisherSessionLocal pub = pubHome.create();
                pub.storeCRL(admin, crl.getEncoded(), CertTools.getFingerprintAsString(caCert),
                    number);
            }
        } catch (Exception e) {
            try {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_CREATECRL, "");
            } catch (RemoteException re) {
                throw new EJBException(re);
            }

            throw new EJBException(e);
        }

        debug("<createCRL()");

        return crl;
    }

    // createCRL
    private String getPassword(String initKey) throws Exception {
        String password;

        try {
            password = (String) lookup(initKey, java.lang.String.class);
        } catch (EJBException e) {
            password = null;
        }

        if (password == null) {
            debug(initKey + " password: ");

            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

            return (in.readLine());
        } else {
            return password;
        }
    }

    private int sunKeyUsageToBC(boolean[] sku) {
        int bcku = 0;

        if (sku[0] == true) {
            bcku = bcku | X509KeyUsage.digitalSignature;
        }

        if (sku[1] == true) {
            bcku = bcku | X509KeyUsage.nonRepudiation;
        }

        if (sku[2] == true) {
            bcku = bcku | X509KeyUsage.keyEncipherment;
        }

        if (sku[3] == true) {
            bcku = bcku | X509KeyUsage.dataEncipherment;
        }

        if (sku[4] == true) {
            bcku = bcku | X509KeyUsage.keyAgreement;
        }

        if (sku[5] == true) {
            bcku = bcku | X509KeyUsage.keyCertSign;
        }

        if (sku[6] == true) {
            bcku = bcku | X509KeyUsage.cRLSign;
        }

        if (sku[7] == true) {
            bcku = bcku | X509KeyUsage.encipherOnly;
        }

        if (sku[8] == true) {
            bcku = bcku | X509KeyUsage.decipherOnly;
        }

        return bcku;
    }

    private X509Certificate makeBCCertificate(UserAuthData subject, X509Name caname,
        PublicKey publicKey, int keyusage, CertificateProfile certProfile)
        throws Exception {
        debug(">makeBCCertificate()");

        final String sigAlg = "SHA1WithRSA";
        Date firstDate = new Date();

        // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
        firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));

        Date lastDate = new Date();

        // validity in days = validity*24*60*60*1000 milliseconds
        lastDate.setTime(lastDate.getTime() + (certProfile.getValidity() * 24 * 60 * 60 * 1000));

        X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();

        // Serialnumber is random bits, where random generator is initialized when this
        // bean is created.
        BigInteger serno = SernoGenerator.instance().getSerno();
        certgen.setSerialNumber(serno);
        certgen.setNotBefore(firstDate);
        certgen.setNotAfter(lastDate);
        certgen.setSignatureAlgorithm(sigAlg);

        // Make DNs
        String dn = subject.getDN();
        String altName = subject.getAltName();

        /* Old stuff
        if (subject.getEmail() != null) {
            String email = null;
            if (altName != null) {
                email = CertTools.getPartFromDN(altName, CertTools.EMAIL);
                if (email == null)
                    email = CertTools.getPartFromDN(altName, CertTools.EMAIL1);
                if (email == null)
                    email = CertTools.getPartFromDN(altName, CertTools.EMAIL2);
            }
            if (email == null) {
                altName = "rfc822Name="+subject.getEmail()+ ((altName == null) ? "":(", "+altName));
            }
        } */
        /* This is handled automatically?? (anyway we don't want it)
        if ((subject.getEmail() != null) && (emailindn.booleanValue() == true))
            dn = dn + ", EmailAddress=" + subject.getEmail();
        */
        debug("Subject=" + dn);
        certgen.setSubjectDN(CertTools.stringToBcX509Name(dn));
        debug("Issuer=" + caname);
        certgen.setIssuerDN(caname);
        certgen.setPublicKey(publicKey);

        // Basic constranits, all subcerts are NOT CAs
        if (certProfile.getUseBasicConstraints() == true) {
            boolean isCA = false;

            if ((certProfile.getType() == CertificateProfile.TYPE_CA) ||
                    (certProfile.getType() == CertificateProfile.TYPE_ROOTCA)) {
                isCA = true;
            }

            BasicConstraints bc = new BasicConstraints(isCA);
            certgen.addExtension(X509Extensions.BasicConstraints.getId(),
                certProfile.getBasicConstraintsCritical(), bc);
        }

        // Key usage
        int newKeyUsage = -1;

        if (certProfile.getAllowKeyUsageOverride() && (keyusage >= 0)) {
            newKeyUsage = keyusage;
        } else {
            newKeyUsage = sunKeyUsageToBC(certProfile.getKeyUsage());
        }

        if ((certProfile.getUseKeyUsage() == true) && (newKeyUsage >= 0)) {
            X509KeyUsage ku = new X509KeyUsage(newKeyUsage);
            certgen.addExtension(X509Extensions.KeyUsage.getId(),
                certProfile.getKeyUsageCritical(), ku);
        }

        // Extended Key usage
        if (certProfile.getUseExtendedKeyUsage() == true) {
            // Get extended key usage from certificate profile
            Collection c = certProfile.getExtendedKeyUsageAsOIDStrings();
            Vector usage = new Vector();
            Iterator iter = c.iterator();

            while (iter.hasNext()) {
                usage.add(new DERObjectIdentifier((String) iter.next()));
            }

            ExtendedKeyUsage eku = new ExtendedKeyUsage(usage);

            // Extended Key Usage may be either critical or non-critical
            certgen.addExtension(X509Extensions.ExtendedKeyUsage.getId(),
                certProfile.getExtendedKeyUsageCritical(), eku);
        }

        // Subject key identifier
        if (certProfile.getUseSubjectKeyIdentifier() == true) {
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((ASN1Sequence) new DERInputStream(
                        new ByteArrayInputStream(publicKey.getEncoded())).readObject());
            SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);
            certgen.addExtension(X509Extensions.SubjectKeyIdentifier.getId(),
                certProfile.getSubjectKeyIdentifierCritical(), ski);
        }

        // Authority key identifier
        if (certProfile.getUseAuthorityKeyIdentifier() == true) {
            SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence) new DERInputStream(
                        new ByteArrayInputStream(caCert.getPublicKey().getEncoded())).readObject());
            AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
            certgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(),
                certProfile.getAuthorityKeyIdentifierCritical(), aki);
        }

        // Subject Alternative name
        if ((certProfile.getUseSubjectAlternativeName() == true) && (altName != null) &&
                (altName.length() > 0)) {
            String email = CertTools.getEmailFromDN(altName);
            DEREncodableVector vec = new DEREncodableVector();

            if (email != null) {
                GeneralName gn = new GeneralName(new DERIA5String(email), 1);
                vec.add(gn);
            }

            String dns = CertTools.getPartFromDN(altName, CertTools.DNS);

            if (dns != null) {
                GeneralName gn = new GeneralName(new DERIA5String(dns), 2);
                vec.add(gn);
            }

            String uri = CertTools.getPartFromDN(altName, CertTools.URI);

            if (uri == null) {
                uri = CertTools.getPartFromDN(altName, CertTools.URI1);
            }

            if (uri != null) {
                GeneralName gn = new GeneralName(new DERIA5String(uri), 6);
                vec.add(gn);
            }

            String upn = CertTools.getPartFromDN(altName, CertTools.UPN);

            if (upn != null) {
                ASN1EncodableVector v = new ASN1EncodableVector();
                v.add(new DERObjectIdentifier(CertTools.UPN_OBJECTID));
                v.add(new DERTaggedObject(true, 0, new DERUTF8String(upn)));

                //GeneralName gn = new GeneralName(new DERSequence(v), 0);
                DERObject gn = new DERTaggedObject(false, 0, new DERSequence(v));
                vec.add(gn);
            }

            if (vec.size() > 0) {
                GeneralNames san = new GeneralNames(new DERSequence(vec));
                certgen.addExtension(X509Extensions.SubjectAlternativeName.getId(),
                    certProfile.getSubjectAlternativeNameCritical(), san);
            }
        }

        // Certificate Policies
        if (certProfile.getUseCertificatePolicies() == true) {
            CertificatePolicies cp = new CertificatePolicies(certProfile.getCertificatePolicyId());
            certgen.addExtension(X509Extensions.CertificatePolicies.getId(),
                certProfile.getCertificatePoliciesCritical(), cp);
        }

        // CRL Distribution point URI
        if (certProfile.getUseCRLDistributionPoint() == true) {
            GeneralName gn = new GeneralName(new DERIA5String(
                        certProfile.getCRLDistributionPointURI()), 6);
            GeneralNames gns = new GeneralNames(new DERSequence(gn));
            DistributionPointName dpn = new DistributionPointName(0, gns);
            DistributionPoint distp = new DistributionPoint(dpn, null, null);
            certgen.addExtension(X509Extensions.CRLDistributionPoints.getId(),
                certProfile.getCRLDistributionPointCritical(), new DERSequence(distp));
        }

        X509Certificate cert = certgen.generateX509Certificate(signingDevice.getPrivateSignKey(),
                signingDevice.getProvider());
        debug("<makeBCCertificate()");

        FileOutputStream os = new FileOutputStream("\\foo.crt");
        os.write(cert.getEncoded());
        os.close();

        return (X509Certificate) cert;
    }

    // makeBCCertificate
    private X509CRL makeBCCRL(X509Name caname, long crlperiod, Vector certs, int crlnumber)
        throws Exception {
        debug(">makeBCCRL()");

        final String sigAlg = "SHA1WithRSA";

        Date thisUpdate = new Date();
        Date nextUpdate = new Date();

        // crlperiod is hours = crlperiod*60*60*1000 milliseconds
        nextUpdate.setTime(nextUpdate.getTime() + (crlperiod * 60 * 60 * 1000));

        X509V2CRLGenerator crlgen = new X509V2CRLGenerator();
        crlgen.setThisUpdate(thisUpdate);
        crlgen.setNextUpdate(nextUpdate);
        crlgen.setSignatureAlgorithm(sigAlg);

        // Make DNs
        debug("Issuer=" + caname);
        crlgen.setIssuerDN(caname);

        if (certs != null) {
            debug("Number of revoked certificates: " + certs.size());

            Iterator it = certs.iterator();

            while (it.hasNext()) {
                RevokedCertInfo certinfo = (RevokedCertInfo) it.next();
                crlgen.addCRLEntry(certinfo.getUserCertificate(), certinfo.getRevocationDate(),
                    certinfo.getReason());
            }
        }

        // Authority key identifier
        if (useaki.booleanValue() == true) {
            SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence) new DERInputStream(
                        new ByteArrayInputStream(caCert.getPublicKey().getEncoded())).readObject());
            AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
            crlgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(),
                akicritical.booleanValue(), aki);
        }

        // CRLNumber extension
        if (usecrln.booleanValue() == true) {
            CRLNumber crlnum = new CRLNumber(BigInteger.valueOf(crlnumber));
            crlgen.addExtension(X509Extensions.CRLNumber.getId(), crlncritical.booleanValue(),
                crlnum);
        }

        X509CRL crl = crlgen.generateX509CRL(signingDevice.getPrivateSignKey(),
                signingDevice.getProvider());

        debug("<makeBCCRL()");

        return (X509CRL) crl;
    }

    // makeBCCRL
}


//RSASignSessionBean


package se.anatom.ejbca.ca.sign;

import java.rmi.*;

import javax.naming.*;
import javax.rmi.*;
import javax.ejb.*;

import java.io.*;
import java.util.*;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.*;
import java.lang.reflect.Method;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ca.auth.IAuthenticationSessionLocalHome;
import se.anatom.ejbca.ca.auth.IAuthenticationSessionLocal;
import se.anatom.ejbca.ca.auth.UserAuthData;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.IPublisherSessionLocal;
import se.anatom.ejbca.ca.store.IPublisherSessionLocalHome;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;

import org.bouncycastle.jce.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.*;

/**
 * Creates X509 certificates using RSA keys.
 *
 * @version $Id: RSASignSessionBean.java,v 1.39 2002-08-31 11:51:08 anatom Exp $
 */
public class RSASignSessionBean extends BaseSessionBean {

    X509Certificate caCert;
    X509Name caSubjectName;
    private Long validity;
    private Long crlperiod;
    private Boolean usebc, bccritical;
    private Boolean useku, kucritical;
    private Boolean useski, skicritical;
    private Boolean useaki, akicritical;
    private Boolean usecrln, crlncritical;
    private Boolean usesan, sancritical;
    private Boolean usecertpol, certpolcritical;
    private String certpolid;
    private Boolean usecrldist, crldistcritical;
    String crldisturi;
    private Boolean emailindn;
    private Boolean finishUser;
    ISigningDevice signingDevice;

    /** Home interface to certificate store */
    private ICertificateStoreSessionLocalHome storeHome = null;

    /** A vector of publishers home interfaces where certs and CRLs are stored */
    private ArrayList publishers = null;

    /* Home interface to Authentication session */
    private IAuthenticationSessionLocalHome authHome = null;

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        try {
            // Install BouncyCastle provider
            Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
            int result = Security.addProvider(BCJce);

            // get home interfaces to other session beans used
            storeHome = (ICertificateStoreSessionLocalHome)lookup("java:comp/env/ejb/CertificateStoreSessionLocal");
            authHome = (IAuthenticationSessionLocalHome)lookup("java:comp/env/ejb/AuthenticationSessionLocal");

            // Init the publisher session beans
            int i = 1;
            publishers = new ArrayList();
            try {
                while (true) {
                    String jndiName = "java:comp/env/ejb/PublisherSession" + i;
                    IPublisherSessionLocalHome pubHome = (IPublisherSessionLocalHome)lookup(jndiName);
                    publishers.add(pubHome);
                    info("Added publisher class '"+pubHome.getClass().getName()+"'");
                    i++;
                }
            } catch (EJBException e) {
                // We could not find this publisher
                debug("Failed to find publisher at index '"+i+"', no more publishers.");
            }

            // Create a Signing device of type pointed to by env variable using properties ot pass args
            Properties p = new Properties();
            String keyStoreFile = (String)lookup("java:comp/env/keyStore", java.lang.String.class);
            p.setProperty("keyStore", keyStoreFile);
            String keyStorePass = getPassword("java:comp/env/keyStorePass");
            p.setProperty("keyStorePass", keyStorePass);
            String privateKeyAlias= (String)lookup("java:comp/env/privateKeyAlias", java.lang.String.class);
            p.setProperty("privateKeyAlias", privateKeyAlias);
            String privateKeyPass = getPassword("java:comp/env/privateKeyPass");
            p.setProperty("privateKeyPass", privateKeyPass);
            String signingDeviceFactoryClass= (String)lookup("java:comp/env/signingDeviceFactory", java.lang.String.class);
            debug("Creating SigningDeviceFactory of type "+signingDeviceFactoryClass);
            Class implClass = Class.forName( signingDeviceFactoryClass );
            Object fact = implClass.newInstance();
            Class[] paramTypes = new Class[1];
            paramTypes[0] = p.getClass();
            Method method = implClass.getMethod("makeInstance", paramTypes);
            Object[] params = new Object[1];
            params[0] = p;
            signingDevice = (ISigningDevice)method.invoke(fact, params);
            //signingDevice = fact.makeInstance(p);
            // We must keep the same order in the DN in the issuer field in created certificates as there
            // is in the subject field of the CA-certificate.
            Certificate[] certs = signingDevice.getCertificateChain();
            caCert = (X509Certificate)certs[0];
            caSubjectName = new X509Name(caCert.getSubjectDN().toString());

            // The validity in days is specified in environment
            validity = (Long)lookup("java:comp/env/validity", java.lang.Long.class);

            // Should extensions be used? Critical or not?
            if ((usebc = (Boolean)lookup("java:comp/env/BasicConstraints", java.lang.Boolean.class)).booleanValue() == true)
                bccritical = (Boolean)lookup("java:comp/env/BasicConstraintsCritical", java.lang.Boolean.class);
            if ((useku = (Boolean)lookup("java:comp/env/KeyUsage", java.lang.Boolean.class)).booleanValue() == true)
                kucritical = (Boolean)lookup("java:comp/env/KeyUsageCritical", java.lang.Boolean.class);
            if ((useski = (Boolean)lookup("java:comp/env/SubjectKeyIdentifier", java.lang.Boolean.class)).booleanValue() == true)
                skicritical = (Boolean)lookup("java:comp/env/SubjectKeyIdentifierCritical", java.lang.Boolean.class);
            if ((useaki = (Boolean)lookup("java:comp/env/AuthorityKeyIdentifier", java.lang.Boolean.class)).booleanValue() == true)
                akicritical = (Boolean)lookup("java:comp/env/AuthorityKeyIdentifierCritical", java.lang.Boolean.class);
            if ((usecrln = (Boolean)lookup("java:comp/env/CRLNumber", java.lang.Boolean.class)).booleanValue() == true)
                crlncritical = (Boolean)lookup("java:comp/env/CRLNumberCritical", java.lang.Boolean.class);
            if ((usesan = (Boolean)lookup("java:comp/env/SubjectAlternativeName", java.lang.Boolean.class)).booleanValue() == true)
                sancritical = (Boolean)lookup("java:comp/env/SubjectAlternativeNameCritical", java.lang.Boolean.class);
            if ((usecertpol = (Boolean)lookup("java:comp/env/CertificatePolicies", java.lang.Boolean.class)).booleanValue() == true) {
                certpolcritical = (Boolean)lookup("java:comp/env/CertificatePoliciesCritical", java.lang.Boolean.class);
                certpolid = (String)lookup("java:comp/env/CertificatePolicyId", java.lang.String.class);
            }
            if ((usecrldist = (Boolean)lookup("java:comp/env/CRLDistributionPoint", java.lang.Boolean.class)).booleanValue() == true) {
                crldistcritical = (Boolean)lookup("java:comp/env/CRLDistributionPointCritical", java.lang.Boolean.class);
                crldisturi = (String)lookup("java:comp/env/CRLDistURI", java.lang.String.class);
            }
            // Use old style email address in DN? (really deprecated but old habits die hard...)
            emailindn = (Boolean)lookup("java:comp/env/EmailInDN", java.lang.Boolean.class);
            // The period between CRL issue
            crlperiod = (Long)lookup("java:comp/env/CRLPeriod", java.lang.Long.class);
            // Should we set user to finished state after generating certificate? Probably means onyl one cert can be issued
            // without resetting users state in user DB
            finishUser = (Boolean)lookup("java:comp/env/FinishUser", java.lang.Boolean.class);

        } catch( Exception e ) {
            error("Caught exception in ejbCreate(): ", e);
            throw new EJBException(e);
        }
        debug("<ejbCreate()");
    }

    /**
     * Implements ISignSession::getCertificateChain
     */
    public Certificate[] getCertificateChain() {
        debug(">getCertificateChain()");
        return signingDevice.getCertificateChain();
    } // getCertificateChain

    /**
     * Implements ISignSession::createCertificate
     */

    public Certificate createCertificate(String username, String password, PublicKey pk) throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        debug(">createCertificate(pk)");
        // Standard key usages for end users are: digitalSignature | keyEncipherment or nonRepudiation
        // Default key usage is digitalSignature | keyEncipherment
        // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
        boolean[] keyusage = new boolean[9];
        Arrays.fill(keyusage, false);
        // digitalSignature
        keyusage[0] = true;
        // keyEncipherment
        keyusage[2] = true;
        debug("<createCertificate(pk)");
        return createCertificate(username, password, pk, keyusage);
    } // createCertificate

    /**
     * Implements ISignSession::createCertificate
     */
    public Certificate createCertificate(String username, String password, PublicKey pk, boolean[] keyusage) throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        return createCertificate(username, password, pk, sunKeyUsageToBC(keyusage));
    }

    /**
     * Implements ISignSession::createCertificate
     */
    public Certificate createCertificate(String username, String password, PublicKey pk, int keyusage) throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        debug(">createCertificate(pk, ku)");

        try {
            // Authorize user and get DN
            IAuthenticationSessionLocal authSession = authHome.create();
            UserAuthData data = authSession.authenticateUser(username, password);
            info("Authorized user " + username + " with DN='" + data.getDN()+"'.");
            debug("type="+ data.getType());
            if ((data.getType() & SecConst.USER_INVALID) !=0) {
                error("User type is invalid, cannot create certificate for this user.");
            } else {
                if ( ((data.getType() & SecConst.USER_CA) != 0) || ((data.getType() & SecConst.USER_ROOTCA) != 0) ) {
                    debug("Setting new keyusage...");
                    // If this is a CA, we only allow CA-type keyUsage
                    keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
                }
                X509Certificate cert = makeBCCertificate(data, caSubjectName, validity.longValue(), pk, keyusage);
                info("Generated certificate with SerialNumber '" + Hex.encode(cert.getSerialNumber().toByteArray())+"' for user '"+username+"'.");
                info(cert.toString());
                // Verify before returning
                cert.verify(caCert.getPublicKey());
                // Store certificate in the database
                ICertificateStoreSessionLocal certificateStore = storeHome.create();
                certificateStore.storeCertificate(cert, CertTools.getFingerprintAsString(caCert), CertificateData.CERT_ACTIVE, data.getType());
                // Call authentication session and tell that we are finished with this user
                for (int i=0;i<publishers.size();i++) {
                    IPublisherSessionLocalHome pubHome = (IPublisherSessionLocalHome)publishers.get(i);
                    IPublisherSessionLocal pub = pubHome.create();
                    pub.storeCertificate(cert, CertTools.getFingerprintAsString(caCert), CertificateData.CERT_ACTIVE, data.getType());
                }
                if (finishUser.booleanValue() == true)
                    authSession.finishUser(username, password);
                debug("<createCertificate(pk, ku)");
                return cert;
            }
        } catch (ObjectNotFoundException oe) {
            throw oe;
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (Exception e) {
            throw new EJBException(e);
        }
        debug("<createCertificate(pk, ku)");
        throw new EJBException("Invalid user type for user "+username);
    } // createCertificate

    /**
     * Implements ISignSession::createCertificate
     */

    public Certificate createCertificate(String username, String password, int certType, PublicKey pk) throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
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

        Certificate ret = createCertificate(username, password, pk, keyusage);
        debug("<createCertificate(pk, certType)");
        return ret;
    } // createCertificate

    /**
     * Implements ISignSession::createCertificate
     */
    public Certificate createCertificate(String username, String password, Certificate incert) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, SignRequestSignatureException {
        debug(">createCertificate(cert)");
        X509Certificate cert = (X509Certificate)incert;
        try {
            cert.verify(cert.getPublicKey());
        } catch (Exception e) {
            error("POPO verification failed for "+username, e);
            throw new SignRequestSignatureException("Verification of signature (popo) on certificate failed.");
        }

        // TODO: extract more extensions than just KeyUsage
        Certificate ret = createCertificate(username, password, cert.getPublicKey(), cert.getKeyUsage());
        debug("<createCertificate(cert)");
        return ret;
    } // createCertificate

    /**
     * Implements ISignSession::createCertificate
     */

    public Certificate createCertificate(String username, String password, byte[] pkcs10req) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, SignRequestException, SignRequestSignatureException {
        return createCertificate( username, password, pkcs10req, -1 );
    }

    /**
     * Implements ISignSession::createCertificate
     */

    public Certificate createCertificate(String username, String password, byte[] pkcs10req, int keyUsage) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, SignRequestException, SignRequestSignatureException {
        debug(">createCertificate(pkcs10)");
        Certificate ret = null;

        try {
            DERObject derobj = new DERInputStream(new ByteArrayInputStream(pkcs10req)).readObject();
            DERConstructedSequence seq = (DERConstructedSequence)derobj;
            PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(seq);
            if (pkcs10.verify() == false) {
                error("POPO verification failed for "+username);
                throw new EJBException("Verification of signature (popo) on PKCS10 request failed.");
            }
            // TODO: extract more information or attributes
            if ( keyUsage < 0 )
                ret = createCertificate(username, password, pkcs10.getPublicKey());
            else
                ret = createCertificate(username, password, pkcs10.getPublicKey(), keyUsage);

        } catch (IOException e) {
            error("Error reading PKCS10-request.", e);
            throw new SignRequestException("Error reading PKCS10-request.");

        } catch (NoSuchAlgorithmException e) {
            error("Error in PKCS10-request, no such algorithm.", e);
            throw new SignRequestException("Error in PKCS10-request, no such algorithm.");

        } catch (NoSuchProviderException e) {
            error("Internal error processing PKCS10-request.", e);
            throw new SignRequestException("Internal error processing PKCS10-request.");
        } catch (InvalidKeyException e) {
            error("Error in PKCS10-request, invlid key.", e);
            throw new SignRequestException("Error in PKCS10-request, invalid key.");
        } catch (SignatureException e) {
            error("Error in PKCS10-signature.", e);
            throw new SignRequestSignatureException("Error in PKCS10-signature.");
        }
        debug("<createCertificate(pkcs10)");
        return ret;
    }

    /**
     * Implements ISignSession::createCRL
     */

    public X509CRL createCRL(Vector certs) {
        debug(">createCRL()");
        X509CRL crl = null;
        try {
            ICertificateStoreSessionLocal certificateStore = storeHome.create();
            // Get number of last CRL and increase by 1
            int number = certificateStore.getLastCRLNumber() + 1;
            crl = makeBCCRL(caSubjectName, crlperiod.longValue(), certs, number);
            // Verify before sending back
            crl.verify(caCert.getPublicKey());
            info("Created CRL with number "+number);
            // Store CRL in the database
            certificateStore.storeCRL(crl.getEncoded(), CertTools.getFingerprintAsString(caCert), number);
            for (int i=0;i<publishers.size();i++) {
                IPublisherSessionLocalHome pubHome = (IPublisherSessionLocalHome)publishers.get(i);
                IPublisherSessionLocal pub = pubHome.create();
                pub.storeCRL(crl.getEncoded(), CertTools.getFingerprintAsString(caCert), number);
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        debug("<createCRL()");
        return crl;
    } // createCRL

    private String getPassword(String initKey) throws Exception {
        String password;
        try {
            password = (String)lookup(initKey, java.lang.String.class);
        } catch (EJBException e) {
            password = null;
        }
        if ( password == null ) {
            debug(initKey+" password: ");
            BufferedReader in
            = new BufferedReader(new InputStreamReader(System.in));
            return (in.readLine());
        } else
            return password;
    }

    private int sunKeyUsageToBC(boolean[] sku) {
        int bcku = 0;
        if (sku[0] == true)
            bcku = bcku | X509KeyUsage.digitalSignature;
        if (sku[1] == true)
            bcku = bcku | X509KeyUsage.nonRepudiation;
        if (sku[2] == true)
            bcku = bcku | X509KeyUsage.keyEncipherment;
        if (sku[3] == true)
            bcku = bcku | X509KeyUsage.dataEncipherment;
        if (sku[4] == true)
            bcku = bcku | X509KeyUsage.keyAgreement;
        if (sku[5] == true)
            bcku = bcku | X509KeyUsage.keyCertSign;
        if (sku[6] == true)
            bcku = bcku | X509KeyUsage.cRLSign;
        if (sku[7] == true)
            bcku = bcku | X509KeyUsage.encipherOnly;
        if (sku[8] == true)
            bcku = bcku | X509KeyUsage.decipherOnly;
        return bcku;
    }



	private X509Certificate makeBCCertificate(
		UserAuthData subject,
		X509Name caname,
		long validity,
		PublicKey publicKey,
		int keyusage)
		throws Exception {
		debug(">makeBCCertificate()");
		final String sigAlg = "SHA1WithRSA";
		Date firstDate = new Date();
		// Set back startdate ten minutes to avoid some problems with wrongly set clocks.
		firstDate.setTime(firstDate.getTime() - 10 * 60 * 1000);
		Date lastDate = new Date();
		// validity in days = validity*24*60*60*1000 milliseconds
		lastDate.setTime(lastDate.getTime() + (validity * 24 * 60 * 60 * 1000));
		X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();
		// Serialnumber is random bits, where random generator is initialized with Date.getTime() when this

		// bean is created.
		byte[] serno = SernoGenerator.instance().getSerno();
		certgen.setSerialNumber((new java.math.BigInteger(serno)).abs());
		certgen.setNotBefore(firstDate);
		certgen.setNotAfter(lastDate);
		certgen.setSignatureAlgorithm(sigAlg);
		// Make DNs
		String dn = subject.getDN();
		if ((subject.getEmail() != null) && (emailindn.booleanValue() == true))
			dn = dn + ", EmailAddress=" + subject.getEmail();

		debug("Subject=" + dn);
		certgen.setSubjectDN(CertTools.stringToBcX509Name(dn));
		debug("Issuer=" + caname);
		certgen.setIssuerDN(caname);
		certgen.setPublicKey(publicKey);

		// Basic constranits, all subcerts are NOT CAs
		if (usebc.booleanValue() == true) {
			boolean isCA = false;
			if (((subject.getType() & SecConst.USER_CA) == SecConst.USER_CA)
				|| ((subject.getType() & SecConst.USER_ROOTCA)
					== SecConst.USER_ROOTCA))
				isCA = true;
			BasicConstraints bc = new BasicConstraints(isCA);
			certgen.addExtension(
				X509Extensions.BasicConstraints.getId(),
				bccritical.booleanValue(),
				bc);
		}
		// Key usage
		if (useku.booleanValue() == true) {
			X509KeyUsage ku = new X509KeyUsage(keyusage);
			certgen.addExtension(
				X509Extensions.KeyUsage.getId(),
				kucritical.booleanValue(),
				ku);
		}
		// Subject key identifier
		if (useski.booleanValue() == true) {
			SubjectPublicKeyInfo spki =
				new SubjectPublicKeyInfo(
					(DERConstructedSequence) new DERInputStream(new ByteArrayInputStream(publicKey
						.getEncoded()))
						.readObject());
			SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);
			certgen.addExtension(
				X509Extensions.SubjectKeyIdentifier.getId(),
				skicritical.booleanValue(),
				ski);
		}
		// Authority key identifier
		if (useaki.booleanValue() == true) {
			SubjectPublicKeyInfo apki =
				new SubjectPublicKeyInfo(
					(DERConstructedSequence) new DERInputStream(new ByteArrayInputStream(caCert
						.getPublicKey()
						.getEncoded()))
						.readObject());
			AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
			certgen.addExtension(
				X509Extensions.AuthorityKeyIdentifier.getId(),
				akicritical.booleanValue(),
				aki);
		}
		// Subject Alternative name
		if ((usesan.booleanValue() == true) && (subject.getEmail() != null)) {
			GeneralName gn =
				new GeneralName(new DERIA5String(subject.getEmail()), 1);
			DERConstructedSequence seq = new DERConstructedSequence();
			seq.addObject(gn);
			GeneralNames san = new GeneralNames(seq);
			certgen.addExtension(
				X509Extensions.SubjectAlternativeName.getId(),
				sancritical.booleanValue(),
				san);
		}
		// Certificate Policies
		if (usecertpol.booleanValue() == true) {
			CertificatePolicies cp = new CertificatePolicies(certpolid);
			certgen.addExtension(
				X509Extensions.CertificatePolicies.getId(),
				certpolcritical.booleanValue(),
				cp);
		}
		// CRL Distribution point URI
		if (usecrldist.booleanValue() == true) {
			GeneralName gn = new GeneralName(new DERIA5String(crldisturi), 6);
			DERConstructedSequence seq = new DERConstructedSequence();
			seq.addObject(gn);
			GeneralNames gns = new GeneralNames(seq);
			DistributionPointName dpn = new DistributionPointName(0, gns);
			DistributionPoint distp = new DistributionPoint(dpn, null, null);
			DERConstructedSequence ext = new DERConstructedSequence();
			ext.addObject(distp);
			certgen.addExtension(
				X509Extensions.CRLDistributionPoints.getId(),
				crldistcritical.booleanValue(),
				ext);
		}
		X509Certificate cert =
			certgen.generateX509Certificate(
				signingDevice.getPrivateSignKey(),
				signingDevice.getProvider());
		debug("<makeBCCertificate()");
		return (X509Certificate) cert;
	} // makeBCCertificate

    private X509CRL makeBCCRL(X509Name caname, long crlperiod, Vector certs, int crlnumber)
    throws Exception {
        debug(">makeBCCRL()");
        final String sigAlg="SHA1WithRSA";

        Date thisUpdate = new Date();
        Date nextUpdate = new Date();

        // crlperiod is hours = crlperiod*60*60*1000 milliseconds
        nextUpdate.setTime(nextUpdate.getTime() + (crlperiod * 60 * 60 * 1000));
        X509V2CRLGenerator crlgen = new X509V2CRLGenerator();
        crlgen.setThisUpdate(thisUpdate);
        crlgen.setNextUpdate(nextUpdate);
        crlgen.setSignatureAlgorithm(sigAlg);
        // Make DNs
        debug("Issuer="+caname);
        crlgen.setIssuerDN(caname);
        if (certs != null) {
            debug("Number of revoked certificates: "+certs.size());
            Iterator it = certs.iterator();
            while( it.hasNext() ) {
                RevokedCertInfo certinfo = (RevokedCertInfo)it.next();
                crlgen.addCRLEntry(certinfo.getUserCertificate(), certinfo.getRevocationDate(), certinfo.getReason());
            }
        }

        // Authority key identifier
        if (useaki.booleanValue() == true) {
            SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((DERConstructedSequence)new DERInputStream(
                new ByteArrayInputStream(caCert.getPublicKey().getEncoded())).readObject());
            AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
            crlgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), akicritical.booleanValue(), aki);
        }
        // CRLNumber extension
        if (usecrln.booleanValue() == true) {
            CRLNumber crlnum = new CRLNumber(BigInteger.valueOf(crlnumber));
            crlgen.addExtension(X509Extensions.CRLNumber.getId(), crlncritical.booleanValue(), crlnum);
        }
        X509CRL crl = crlgen.generateX509CRL(signingDevice.getPrivateSignKey(), signingDevice.getProvider());

        debug("<makeBCCRL()");
        return (X509CRL)crl;
    } // makeBCCRL
} //RSASignSessionBean




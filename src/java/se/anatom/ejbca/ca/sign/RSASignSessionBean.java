
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

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ca.auth.IAuthenticationSessionHome;
import se.anatom.ejbca.ca.auth.IAuthenticationSessionRemote;
import se.anatom.ejbca.ca.auth.UserAuthData;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.IPublisherSession;
import se.anatom.ejbca.ca.store.IPublisherSessionHome;
import se.anatom.ejbca.ca.store.IPublisherSessionRemote;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.SecConst;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;

import org.bouncycastle.jce.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.*;

/**
 * Creates X509 certificates using RSA keys.
 *
 * @version $Id: RSASignSessionBean.java,v 1.11 2002-01-24 14:31:51 anatom Exp $
 */
public class RSASignSessionBean extends BaseSessionBean implements ISignSession {

    private PrivateKey privateKey;
    private X509Certificate rootCert;
    private X509Certificate caCert;
    X509Name caSubjectName;
    private Long validity;
    private Long crlperiod;
    private Boolean usebc, bccritical;
    private Boolean useku, kucritical;
    private Boolean useski, skicritical;
    private Boolean useaki, akicritical;
    private Boolean usecrln, crlncritical;
    private Boolean usesan, sancritical;
    private Boolean usecrldist, crldistcritical;
    String crldisturi;
    private Boolean emailindn;
    private Boolean finishUser;
    private SecureRandom random;

    /** Pointer to main certificate store */
    private ICertificateStoreSessionRemote certificateStore = null;
    /** A vector of publishers where certs and CRLs are stored */
    private Vector publishers = null;
    /* AuthenticationSession for authentication of users when certs are created */
    private IAuthenticationSessionRemote authSession = null;
    
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

            // Get env variables and read in nessecary data
            KeyStore keyStore=KeyStore.getInstance("PKCS12", "BC");
            String keyStoreFile = (String)lookup("java:comp/env/keyStore", java.lang.String.class);
            debug("keystore:" + keyStoreFile);
            InputStream is = new FileInputStream(keyStoreFile);
            char[] keyStorePass = getPassword("java:comp/env/keyStorePass");
            //debug("keystorepass: " + keyStorePass);
            keyStore.load(is, keyStorePass);
            String privateKeyAlias= (String)lookup("java:comp/env/privateKeyAlias", java.lang.String.class);
            debug("privateKeyAlias: " + privateKeyAlias);
            char[] privateKeyPass = getPassword("java:comp/env/privateKeyPass");
            if ((new String(privateKeyPass)).equals("null"))
                privateKeyPass = null;
            //debug("privateKeyPass: " + privateKeyPass);
            privateKey = (PrivateKey)keyStore.getKey(privateKeyAlias, privateKeyPass);
            if (privateKey == null) {
                error("Cannot load key with alias '"+privateKeyAlias+"' from keystore '"+keyStoreFile+"'");
                throw new Exception("Cannot load key with alias '"+privateKeyAlias+"' from keystore '"+keyStoreFile+"'");
            }
            Certificate[] certchain = keyStore.getCertificateChain(privateKeyAlias);
            if (certchain.length < 1) {
                error("Cannot load certificate chain with alias '"+privateKeyAlias+"' from keystore '"+keyStoreFile+"'");
                throw new Exception("Cannot load certificate chain with alias '"+privateKeyAlias+"' from keystore '"+keyStoreFile+"'");
            }
            // We only support a ca hierarchy with depth 2.
            // TODO:
            caCert = (X509Certificate)certchain[0];
            TBSCertificateStructure tbs = new TBSCertificateStructure((DERConstructedSequence)new DERInputStream(new ByteArrayInputStream(caCert.getTBSCertificate())).readObject());
            caSubjectName=tbs.getSubject();
            debug("cacertIssuer: " + caCert.getIssuerDN().toString());
            debug("cacertSubject: " + caSubjectName.toString());
            // is there only one root cert?
            if (CertTools.isSelfSigned(caCert))
                rootCert = caCert;
            else {
                // is root cert in same chain as ca cert?
                if (certchain.length > 1)
                    rootCert = (X509Certificate)certchain[2];
                else {
                    String ialias = CertTools.getPartFromDN(caCert.getIssuerDN().toString(), "CN");
                    Certificate[] chain1 = keyStore.getCertificateChain(ialias);
                    System.out.println("Loaded certificate chain with length "+ chain1.length+" with alias '"+ialias+"'.");
                    if (chain1.length == 0) {
                        System.out.println("No RootCA certificate found!");
                        System.exit(1);
                    }
                    rootCert = (X509Certificate)chain1[0];
                }
            }
            debug("rootcertIssuer: " + rootCert.getIssuerDN().toString());
            debug("rootcertSubject: " + rootCert.getSubjectDN().toString());
            if (!CertTools.isSelfSigned(rootCert))
                throw new EJBException("Root certificate is not self signed!");

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

            // Init random number generator for random serialnumbers
            random = SecureRandom.getInstance("SHA1PRNG");
            // Using this seed we should get a different seed every time.
            // We are not concerned about the security of the random bits, only that they are different every time.
            // Extracting 64 bit random numbers out of this should give us 2^32 (4 294 967 296) serialnumbers before
            // collisions (which are seriously BAD), well anyhow sufficien for pretty large scale installations.
            // Design criteria: 1. No counter to keep track on. 2. Multiple thereads can generate numbers at once, in
            // a clustered environment etc.
            long seed = (new Date().getTime()) + this.hashCode();
            random.setSeed(seed);
        } catch( Exception e ) {
            throw new EJBException(e);
        }
        debug("<ejbCreate()");
    }

    /**
     * Implements ISignSession::getCertificateChain
     */
    public Certificate[] getCertificateChain() throws RemoteException {
        debug(">getCertificateChain()");
        // TODO: should support more than 2 levels of CAs
        Certificate[] chain;
        if (CertTools.isSelfSigned(caCert)) {
            chain = new Certificate[1];
        } else {
            chain = new Certificate[2];
            chain[1] = rootCert;
        }
        chain[0] = caCert;
        debug("<getCertificateChain()");
        return chain;
    } // getRootCertificate

    /**
     * Implements ISignSession::createCertificate
     */
    public Certificate createCertificate(String username, String password, PublicKey pk) throws RemoteException {
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
    public Certificate createCertificate(String username, String password, PublicKey pk, boolean[] keyusage) throws RemoteException {
        debug(">createCertificate(pk, ku)");

        try {
            // Authorize user and get DN
            initAuthSession();
            UserAuthData data = authSession.authenticateUser(username, password);
            info("Authorized user " + username + " with DN=" + data.getDN());
            System.out.println("type="+ data.getType());
            if ((data.getType() & SecConst.USER_INVALID) !=0) {
                error("User type is invalid, cannot create certificate for this user.");
            } else {
                if ( ((data.getType() & SecConst.USER_CA) != 0) || ((data.getType() & SecConst.USER_ROOTCA) != 0) ) {
                    System.out.println("Setting new keyusage...");
                    // If this is a CA, we only allow CA-type keyUsage
                    Arrays.fill(keyusage, false);
                    // digitalSignature
                    keyusage[5] = true;
                    // keyEncipherment
                    keyusage[6] = true;
                }
                X509Certificate cert = makeBCCertificate(data, caSubjectName, validity.longValue(), pk, sunKeyUsageToBC(keyusage));
                info("Generated certificate with SerialNumber " + Hex.encode(cert.getSerialNumber().toByteArray()));
                info(cert.toString());
                // Verify before returning
                cert.verify(caCert.getPublicKey());
                // Store certificate in the database
                initCertificateStore();
                certificateStore.storeCertificate(cert, CertTools.getFingerprintAsString(caCert), CertificateData.CERT_ACTIVE, data.getType());
                // Call authentication session and tell that we are finished with this user
                for (int i=0;i<publishers.size();i++) {
                    ((IPublisherSession)(publishers.get(i))).storeCertificate(cert, CertTools.getFingerprintAsString(caCert), CertificateData.CERT_ACTIVE, data.getType());
                }
                if (finishUser.booleanValue() == true)
                    authSession.finishUser(username, password);
                debug("<createCertificate(pk, ku)");
                return cert;
            }
        } catch (Exception e) {
            if (e instanceof EJBException)
                throw (EJBException)e;
            throw new EJBException(e);
        }
        debug("<createCertificate(pk, ku)");
        throw new EJBException("Invalid user type for user "+username);
    } // createCertificate

    /**
     * Implements ISignSession::createCertificate
     */
    public Certificate createCertificate(String username, String password, Certificate incert) throws RemoteException {
        debug(">createCertificate(cert)");
        X509Certificate cert = (X509Certificate)incert;
        try {
            cert.verify(cert.getPublicKey());
        } catch (Exception e) {
            error("POPO verification failed for "+username);
            throw new EJBException("Verification of signature (popo) on certificate failed.", e);
        }
        // TODO: extract more extensions than just KeyUsage
        Certificate ret = createCertificate(username, password, cert.getPublicKey(), cert.getKeyUsage());
        debug("<createCertificate(cert)");
        return ret;
    } // createCertificate

    /**
     * Implements ISignSession::createCertificate
     */
    public Certificate createCertificate(String username, String password, byte[] pkcs10req) throws RemoteException {
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
            ret = createCertificate(username, password, pkcs10.getPublicKey());
        } catch (IOException e) {
            error("Error reading PKSC10-request.", e);
            throw new EJBException("Error reading PKSC10-request.", e);
        } catch (NoSuchAlgorithmException e) {
            error("Error in PKSC10-request, no such algorithm.", e);
            throw new EJBException("Error in PKSC10-request, no such algorithm.", e);
        } catch (NoSuchProviderException e) {
            error("Internal error processing PKCS10-request.", e);
            throw new EJBException("Internal error processing PKCS10-request.", e);
        } catch (InvalidKeyException e) {
            error("Error in PKSC10-request, invlid key.", e);
            throw new EJBException("Error in PKSC10-request, invalid key.", e);
        } catch (SignatureException e) {
            error("Error in PKSC10-signature.", e);
            throw new EJBException("Error in PKSC10-signature.", e);
        }
        debug("<createCertificate(pkcs10)");
        return ret;
    }

    /**
     * Implements ISignSession::createCRL
     */
    public X509CRL createCRL(Vector certs) throws RemoteException {
        debug(">createCRL()");
        X509CRL crl = null;
        try {
            initCertificateStore();
            // Get number of last CRL and increase by 1
            int number = certificateStore.getLastCRLNumber() + 1;
            crl = makeBCCRL(caSubjectName, crlperiod.longValue(), certs, number);
            // Verify before sending back
            crl.verify(caCert.getPublicKey());
            info("Created CRL with number "+number);
            // Store CRL in the database
            certificateStore.storeCRL(crl.getEncoded(), CertTools.getFingerprintAsString(caCert), number);
            for (int i=0;i<publishers.size();i++) {
                ((IPublisherSession)(publishers.get(i))).storeCRL(crl.getEncoded(), CertTools.getFingerprintAsString(caCert), number);
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        debug("<createCRL()");
        return crl;
    } // createCRL

    private char[] getPassword(String initKey) throws Exception {
        String password;
        try {
            password = (String)lookup(initKey, java.lang.String.class);
        } catch (EJBException e) {
            password = null;
        }
        if ( password == null ) {
            System.out.print(initKey+" password: ");
            BufferedReader in
            = new BufferedReader(new InputStreamReader(System.in));
            return (in.readLine()).toCharArray();
        } else
            return password.toCharArray();
    }

    /**
     * Creates the authenticationSession so it is available.
     */
    private void initAuthSession() throws CreateException, RemoteException {
        debug(">initAuthSession()");
        if (authSession == null) {
            IAuthenticationSessionHome home = (IAuthenticationSessionHome)lookup("AuthenticationSession",IAuthenticationSessionHome.class);
            authSession = home.create();
        }
        debug("<initAuthSession()");
    } // initAuthSession
    
    /**
     * Creates the CertificateStore and Publishers so they are available.
     */
    private void initCertificateStore() throws CreateException, RemoteException {
        debug(">initCertificateStore()");
        // First init main certificate store
        if (certificateStore == null) {
            ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) lookup("CertificateStoreSession", ICertificateStoreSessionHome.class);
            certificateStore = storehome.create();
        }
        // Init the publisher session beans
        if (publishers == null) {
            int i = 1;
            publishers = new Vector(0);
            try {
                while (true) {
                    String jndiName = "PublisherSession" + i;
                    IPublisherSessionHome pubhome = (IPublisherSessionHome) lookup(jndiName, IPublisherSessionHome.class);
                    IPublisherSessionRemote pubremote = pubhome.create();
                    publishers.add(pubremote);
                    info("Added publisher class '"+pubremote.getClass().getName()+"'");
                    i++;
                }
            } catch (EJBException e) {
                // We could not find this publisher
                debug("Failed to find publisher at index '"+i+"', no more publishers.");
            }
        }
        debug("<initCertificateStore()");
    } // initCertificateStore

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

    private X509Certificate makeBCCertificate(UserAuthData subject, X509Name caname,
    long validity, PublicKey publicKey, int keyusage)
    throws Exception {
        debug(">makeBCCertificate()");

        final String sigAlg="SHA1WithRSA";

        Date firstDate = new Date();
        // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
        firstDate.setTime(firstDate.getTime() - 10*60*1000);
        Date lastDate = new Date();
        // validity in days = validity*24*60*60*1000 milliseconds
        lastDate.setTime(lastDate.getTime() + (validity * 24 * 60 * 60 * 1000));

        X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();
        // Serialnumber is random bits, where random generator is initialized with Date.getTime() when this
        // bean is created.
        byte[] serno = new byte[8];
        random.nextBytes(serno);
        certgen.setSerialNumber((new java.math.BigInteger(serno)).abs());
        certgen.setNotBefore(firstDate);
        certgen.setNotAfter(lastDate);
        certgen.setSignatureAlgorithm(sigAlg);
        // Make DNs
        String dn=subject.getDN();
        if ((subject.getEmail() != null) && (emailindn.booleanValue() == true))
            dn=dn+", EmailAddress="+subject.getEmail();
        debug("Subject="+dn);
        certgen.setSubjectDN(CertTools.stringToBcX509Name(dn));
        debug("Issuer="+caname);
        certgen.setIssuerDN(caname);
        certgen.setPublicKey(publicKey);

        // Basic constranits, all subcerts are NOT CAs
        if (usebc.booleanValue() == true) {
            boolean isCA = false;
            if ( ((subject.getType() & SecConst.USER_CA) == SecConst.USER_CA) ||
                ((subject.getType() & SecConst.USER_ROOTCA) == SecConst.USER_ROOTCA) )
                isCA=true;
            BasicConstraints bc = new BasicConstraints(isCA);
            certgen.addExtension(X509Extensions.BasicConstraints.getId(), bccritical.booleanValue(), bc);
        }
        // Key usage
        if (useku.booleanValue() == true) {
            X509KeyUsage ku = new X509KeyUsage(keyusage);
            certgen.addExtension(X509Extensions.KeyUsage.getId(), kucritical.booleanValue(), ku);
        }
        // Subject key identifier
        if (useski.booleanValue() == true) {
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((DERConstructedSequence)new DERInputStream(
                new ByteArrayInputStream(publicKey.getEncoded())).readObject());
            SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);
            certgen.addExtension(X509Extensions.SubjectKeyIdentifier.getId(), skicritical.booleanValue(), ski);
        }
        // Authority key identifier
        if (useaki.booleanValue() == true) {
            SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((DERConstructedSequence)new DERInputStream(
                new ByteArrayInputStream(caCert.getPublicKey().getEncoded())).readObject());
            AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
            certgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), akicritical.booleanValue(), aki);
        }

        // Subject Alternative name
        if ((usesan.booleanValue() == true) && (subject.getEmail() != null)) {
            GeneralName gn = new GeneralName(new DERIA5String(subject.getEmail()),1);
            DERConstructedSequence seq = new DERConstructedSequence();
            seq.addObject(gn);
            GeneralNames san = new GeneralNames(seq);
            certgen.addExtension(X509Extensions.SubjectAlternativeName.getId(), sancritical.booleanValue(), san);
        }

        // CRL Distribution point URI
        if (usecrldist.booleanValue() == true) {
            GeneralName gn = new GeneralName(new DERIA5String(crldisturi),6);
            DERConstructedSequence seq = new DERConstructedSequence();
            seq.addObject(gn);
            GeneralNames gns = new GeneralNames(seq);
            DistributionPointName dpn = new DistributionPointName(0, gns);
            DistributionPoint distp = new DistributionPoint(dpn, null, null);
            certgen.addExtension(X509Extensions.CRLDistributionPoints.getId(), crldistcritical.booleanValue(), distp);
        }

        X509Certificate cert = certgen.generateX509Certificate(privateKey);

        debug("<makeBCCertificate()");
        return (X509Certificate)cert;

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
        X509CRL crl = crlgen.generateX509CRL(privateKey);

        debug("<makeBCCRL()");
        return (X509CRL)crl;
    } // makeBCCRL

} //RSASignSessionBean


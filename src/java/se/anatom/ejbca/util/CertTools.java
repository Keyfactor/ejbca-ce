
package se.anatom.ejbca.util;

import java.io.*;

import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.util.*;

import org.bouncycastle.jce.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERConstructedSequence;
import org.bouncycastle.asn1.DERObjectIdentifier;

import org.apache.log4j.*;

import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.util.StringTools;

/**
 * Tools to handle common certificate operations.
 *
 * @version $Id: CertTools.java,v 1.11 2002-05-29 12:52:52 anatom Exp $
 */
public class CertTools {

    private static Category cat = Category.getInstance(CertTools.class.getName());

    /** Creates new CertTools */
    public CertTools() {
    }

    /**
     * Creates a (Bouncycastle) X509Name object from a string with a DN.
     * <p>Known OID (with order) are:
     * <pre>
     * CN, SN, OU, O, L, ST, DC, C
     *
     * @param dn String containing DN that will be transformed into X509Name, The DN string has the format
"CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in the string will be silently dropped.
     * @return X509Name
     *
     */
    public static X509Name stringToBcX509Name(String dn) {
        cat.debug(">stringToBcX509Name: " + dn);
        // Strip bad chars
        String stipeddn = StringTools.strip(dn);
        String trimmeddn = stipeddn.trim();
        StringTokenizer st = new StringTokenizer(trimmeddn, ",=");
        Hashtable dntable = new Hashtable();
        String o = null;
        DERObjectIdentifier oid=null;
        Collection coll = new ArrayList();
        while (st.hasMoreTokens()) {
            o = st.nextToken();
            if (o.trim().equalsIgnoreCase("C")) {
                oid = X509Name.C;
                coll.add(X509Name.C);
            }
            else if (o.trim().equalsIgnoreCase("DC")) {
                oid = X509Name.DC;
                coll.add(X509Name.DC);
            }
            else if (o.trim().equalsIgnoreCase("ST")) {
                oid = X509Name.ST;
                coll.add(X509Name.ST);
            }
            else if (o.trim().equalsIgnoreCase("L")) {
                oid = X509Name.L;
                coll.add(X509Name.L);
            }
            else if (o.trim().equalsIgnoreCase("O")) {
                oid = X509Name.O;
                coll.add(X509Name.O);
            }
            else if (o.trim().equalsIgnoreCase("OU")) {
                oid = X509Name.OU;
                coll.add(X509Name.OU);
            }
            else if (o.trim().equalsIgnoreCase("SN")) {
                oid = X509Name.SN;
                coll.add(X509Name.SN);
            }
            else if (o.trim().equalsIgnoreCase("CN")) {
                oid = X509Name.CN;
                coll.add(X509Name.CN);
            }
            else if (o.trim().equalsIgnoreCase("EmailAddress")) {
                oid = X509Name.EmailAddress;
                coll.add(X509Name.EmailAddress);
            }
            else
                oid=null; // Just drop unknown entries in the DN
            if (oid != null)
                dntable.put(oid, st.nextToken());
        }
        Vector order = new Vector();
        order.add(X509Name.EmailAddress);
        order.add(X509Name.CN);
        order.add(X509Name.SN);
        order.add(X509Name.OU);
        order.add(X509Name.O);
        order.add(X509Name.L);
        order.add(X509Name.ST);
        order.add(X509Name.DC);
        order.add(X509Name.C);
        order.retainAll(coll);

        cat.debug(order.toString());
        cat.debug(dntable.toString());

        cat.debug("<stringToBcX509Name");
        return new X509Name(order, dntable);
    }

    /**
     * Every DN-string should look the same.
     * Creates a name string ordered and looking like we want it...
     *
     * @param dn String containing DN
     * @return String containing DN
     **/
     public static String stringToBCDNString(String dn) {
        cat.debug(">stringToBcDNString:"+dn);
        String name = stringToBcX509Name(dn).toString();

        // Older worksround for bug in BC X509Name.java, kept for fun...
        //X509Name name = stringToBcX509Name(dn);
        //DERObject obj =name.getDERObject();
        //X509Name ret = new X509Name((DERConstructedSequence)obj);
        //return ret.toString();

        cat.debug("<stringToBcDNString");
        return name;
     }


    /**
     * Gets a specified part of a DN.
     *
     * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
     * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
     * @return String containing dnpart or null if dnpart is not present
     */
    public static String getPartFromDN(String dn, String dnpart) {
        cat.debug(">getPartFromDN: dn:'" + dn+"', dnpart="+dnpart);
        String trimmeddn = dn.trim();
        String part = null, o = null;
        StringTokenizer st = new StringTokenizer(trimmeddn, ",=");
        while (st.hasMoreTokens()) {
            o = st.nextToken();
            if (o.trim().equalsIgnoreCase(dnpart)) {
                part = st.nextToken();
            }
        }
        cat.debug("<getpartFromDN: resulting DN part="+part);
        return part;
    } //getCNFromDN


    /**
     * Reads a certificate in PEM-format from a file. The file may contain other things,
     * the first certificate in the file is read.
     *
     * @param certFile the file containing the certificate in PEM-format
     * @return X509Certificate
     * @exception IOException if the filen cannot be read.
     * @exception CertificateException if the filen does not contain a correct certificate.
     */
    public static X509Certificate getCertfromPEM(String certFile) throws IOException, CertificateException {
        cat.debug(">getCertfromPEM: certFile=" + certFile);
        InputStream inStrm = new FileInputStream(certFile);
        X509Certificate cert = getCertfromPEM(inStrm);
        cat.debug("<getCertfromPEM: certFile=" + certFile);
        return cert;
    }

    /**
     * Reads a certificate in PEM-format from an InputStream. The stream may contain other things,
     * the first certificate in the stream is read.
     *
     * @param certFile the input stream containing the certificate in PEM-format
     * @return X509Certificate
     * @exception IOException if the stream cannot be read.
     * @exception CertificateException if the stream does not contain a correct certificate.
     */
    public static X509Certificate getCertfromPEM(InputStream certstream)
    throws IOException, CertificateException {
        cat.debug(">getCertfromPEM:");

        String beginKey = "-----BEGIN CERTIFICATE-----";
        String endKey = "-----END CERTIFICATE-----";
        BufferedReader bufRdr = new BufferedReader(new InputStreamReader(certstream));
        ByteArrayOutputStream ostr = new ByteArrayOutputStream();
        PrintStream opstr = new PrintStream(ostr);
        String temp;
        while ((temp = bufRdr.readLine()) != null &&
        !temp.equals(beginKey))
            continue;
        if (temp == null)
            throw new IOException("Error in " + certstream.toString() + ", missing " + beginKey + " boundary");
        while ((temp = bufRdr.readLine()) != null &&
        !temp.equals(endKey))
            opstr.print(temp);
        if (temp == null)
            throw new IOException("Error in " + certstream.toString() + ", missing " + endKey + " boundary");
        opstr.close();

        byte[] certbuf = Base64.decode(ostr.toByteArray());

        // Phweeew, were done, now decode the cert from file back to X509Certificate object
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certbuf));

        cat.debug("<getcertfromPEM:" + x509cert.toString());
        return x509cert;
    } // getCertfromPEM

    /**
     * Creates X509Certificate from byte[].
     *
     * @param cert byte array containing certificate in DER-format
     * @return X509Certificate
     * @exception CertificateException if the byte array does not contain a proper certificate.
     * @exception IOException if the byte array cannot be read.
     */
    public static X509Certificate getCertfromByteArray(byte[] cert)
    throws IOException, CertificateException {
        cat.debug(">getCertfromByteArray:");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cert));
        cat.debug("<getCertfromByteArray:");
        return x509cert;
    } // getCertfromByteArray

    /**
     * Creates X509CRL from byte[].
     *
     * @param crl byte array containing CRL in DER-format
     * @return X509CRL
     * @exception IOException if the byte array can not be read.
     * @exception CertificateException if the byte arrayen does not contani a correct CRL.
     * @exception CRLException if the byte arrayen does not contani a correct CRL.
     */
    public static X509CRL getCRLfromByteArray(byte[] crl)
    throws IOException, CertificateException, CRLException {
        cat.debug(">getCRLfromByteArray:");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL x509crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crl));
        cat.debug("<getCRLfromByteArray:");
        return x509crl;
    } // getCRLfromByteArray

    /**
     * Checks if a certificate is self signed by verifying if subject and issuer are the same.
     *
     * @param cert the certificate that skall be checked.
     * @return boolean true if the certificate has the same issuer and subject, false otherwise.
     */
    public static boolean isSelfSigned(X509Certificate cert) {
        cat.debug(">isSelfSigned: cert: " + cert.getIssuerDN() + "\n" + cert.getSubjectDN());
        boolean ret = cert.getSubjectDN().equals(cert.getIssuerDN());
        cat.debug("<isSelfSigned:" + ret);
        return ret;
    } // isSelfSigned

    public static X509Certificate genSelfCert(String dn, long validity, PrivateKey privKey, PublicKey pubKey, boolean isCA)
    throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // Create self signed certificate
        String sigAlg="SHA1WithRSA";
        Date firstDate = new Date();
        // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
        firstDate.setTime(firstDate.getTime() - 10*60*1000);
        Date lastDate = new Date();
        // validity in days = validity*24*60*60*1000 milliseconds
        lastDate.setTime(lastDate.getTime() + (validity * (24 * 60 * 60 * 1000)));
        X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();
        // Serialnumber is random bits, where random generator is initialized with Date.getTime() when this
        // bean is created.
        byte[] serno = new byte[8];
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed((long)(new Date().getTime()));
        random.nextBytes(serno);
        certgen.setSerialNumber((new java.math.BigInteger(serno)).abs());
        certgen.setNotBefore(firstDate);
        certgen.setNotAfter(lastDate);
        certgen.setSignatureAlgorithm(sigAlg);
        certgen.setSubjectDN(CertTools.stringToBcX509Name(dn));
        certgen.setIssuerDN(CertTools.stringToBcX509Name(dn));
        certgen.setPublicKey(pubKey);
        // Basic constranits is always critical and MUST be present at-least in CA-certificates.
        BasicConstraints bc = new BasicConstraints(isCA);
        certgen.addExtension(X509Extensions.BasicConstraints.getId(), true, bc);

        // Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Mozilla.
        try {
            if (isCA == true) {
                SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((DERConstructedSequence)new DERInputStream(
                new ByteArrayInputStream(pubKey.getEncoded())).readObject());
                SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);

                SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((DERConstructedSequence)new DERInputStream(
                new ByteArrayInputStream(pubKey.getEncoded())).readObject());
                AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);

                certgen.addExtension(X509Extensions.SubjectKeyIdentifier.getId(), false, ski);
                certgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), false, aki);
            }
        } catch (IOException e) {// do nothing
        }

        X509Certificate selfcert = certgen.generateX509Certificate(privKey);
        return selfcert;
    } //genselfCert

    public static byte[] getAuthorityKeyId(X509Certificate cert) throws IOException {
        byte[] extvalue = cert.getExtensionValue("2.5.29.35");
        if (extvalue == null)
            return null;

        DEROctetString oct = (DEROctetString)(new DERInputStream(new ByteArrayInputStream(extvalue)).readObject());
        AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifier((DERConstructedSequence)new DERInputStream(new ByteArrayInputStream(oct.getOctets())).readObject());
        return keyId.getKeyIdentifier();
    } // getAuthorityKeyId

    public static byte[] getSubjectKeyId(X509Certificate cert) throws IOException {
        byte[] extvalue = cert.getExtensionValue("2.5.29.14");
        if (extvalue == null)
            return null;

        DEROctetString oct = (DEROctetString)(new DERInputStream(new ByteArrayInputStream(extvalue)).readObject());
        SubjectKeyIdentifier keyId = new SubjectKeyIdentifier(oct);
        return keyId.getKeyIdentifier();
    } // getSubjectKeyId

    /**
      * Generate SHA1 fingerprint in string representation.
      *
      * @param cert Byte array containing DER encoded X509Certificate.
      * @return String containing hex format of SHA1 fingerprint.
      **/
    public static String getCertFingerprintAsString(byte[] ba) {

        try {
            X509Certificate cert = getCertfromByteArray(ba);
            byte[] res = generateSHA1Fingerprint(cert.getEncoded());
            return Hex.encode(res);
        } catch (CertificateEncodingException cee) {
            cat.error("Error encoding X509 certificate.", cee);
        } catch (CertificateException cee) {
            cat.error("Error decoding X509 certificate.", cee);
        } catch (IOException ioe) {
            cat.error("Error reading byte array for X509 certificate.", ioe);
        }
        return null;
    }

    /**
     * Generate SHA1 fingerprint of certificate in string representation.
     *
     * @param cert X509Certificate.
     * @return String containing hex format of SHA1 fingerprint.
     **/
    public static String getFingerprintAsString(X509Certificate cert) {

        try {
            byte[] res = generateSHA1Fingerprint(cert.getEncoded());
            return Hex.encode(res);
        } catch (CertificateEncodingException cee) {
            cat.error("Error encoding X509 certificate.", cee);
        }
        return null;
    }

    /**
     * Generate SHA1 fingerprint of CRL in string representation.
     *
     * @param crl X509CRL.
     * @return String containing hex format of SHA1 fingerprint.
     **/
    public static String getFingerprintAsString(X509CRL crl) {

        try {
            byte[] res = generateSHA1Fingerprint(crl.getEncoded());
            return Hex.encode(res);
        } catch (CRLException ce) {
            cat.error("Error encoding X509 CRL.", ce);
        }
        return null;
    }

    /**
     * Generate a SHA1 fingerprint from a byte array containing a X.509 certificate
     *
     * @param ba Byte array containing DER encoded X509Certificate.
     * @return Byte array containing SHA1 hash of DER encoded certificate.
     */
    public static byte[] generateSHA1Fingerprint(byte[] ba) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            return md.digest(ba);
        } catch (NoSuchAlgorithmException nsae) {
            cat.error("SHA1 algorithm not supported", nsae);
        }
        return null;
    } // generateSHA1Fingerprint

    /**
     * Generate a MD5 fingerprint from a byte array containing a X.509 certificate
     *
     * @param ba Byte array containing DER encoded X509Certificate.
     * @return Byte array containing MD5 hash of DER encoded certificate.
     */
    public static byte[] generateMD5Fingerprint(byte[] ba) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(ba);
        } catch (NoSuchAlgorithmException nsae) {
            cat.error("MD5 algorithm not supported", nsae);
        }
        return null;
    } // generateMD5Fingerprint

} // CertTools


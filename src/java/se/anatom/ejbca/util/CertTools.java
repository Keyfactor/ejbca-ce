
package se.anatom.ejbca.util;

import java.io.*;

import java.security.*;
import java.security.cert.*;
import java.security.PrivateKey;
import java.util.*;

import org.bouncycastle.jce.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;

import org.apache.log4j.Category;


/**
 * Tools to handle common certificate operations.
 *
 * @version $Id: CertTools.java,v 1.29 2003-01-22 09:06:13 scop Exp $
 */
public class CertTools {

    private static Category cat = Category.getInstance(CertTools.class.getName());

    public static final String EMAIL = "rfc822name";
    public static final String EMAIL1 = "email";
    public static final String EMAIL2 = "EmailAddress";
    public static final String DNS = "dNSName";
    public static final String URI = "uniformResourceIdentifier";
    public static final String URI1 = "uri";

    /** inhibits creation of new CertTools */
    private CertTools() {
    }

    private static String[] dNObjects = { "EmailAddress", "E", "EMail", "UID", "CN", "SN", "SerialNumber", "GN", "GivenName", "Initials", "SurName", "T", "OU", "O", "L", "ST", "DC", "C" };

    private static DERObjectIdentifier getOid(String o) {
        if (o.trim().equalsIgnoreCase("C")) {
            return X509Name.C;
        }
       if (o.trim().equalsIgnoreCase("DC")) {
            return X509Name.DC;
        }
        if (o.trim().equalsIgnoreCase("ST")) {
            return X509Name.ST;
        }
        if (o.trim().equalsIgnoreCase("L")) {
            return X509Name.L;
        }
        if (o.trim().equalsIgnoreCase("O")) {
            return X509Name.O;
        }
        if (o.trim().equalsIgnoreCase("OU")) {
            return X509Name.OU;
        }
        if (o.trim().equalsIgnoreCase("T")) {
            return X509Name.T;
        }
        if (o.trim().equalsIgnoreCase("SurName")) {
            return X509Name.SURNAME;
        }
        if (o.trim().equalsIgnoreCase("Initials")) {
            return X509Name.INITIALS;
        }
        if (o.trim().equalsIgnoreCase("GivenName")) {
            return X509Name.GIVENNAME;
        }
        if (o.trim().equalsIgnoreCase("GN")) {
            return X509Name.GIVENNAME;
        }
        if (o.trim().equalsIgnoreCase("SerialNumber")) {
            return X509Name.SN;
        }
        if (o.trim().equalsIgnoreCase("SN")) {
            return X509Name.SN;
        }
        if (o.trim().equalsIgnoreCase("CN")) {
            return X509Name.CN;
        }
        if (o.trim().equalsIgnoreCase("UID")) {
            return X509Name.UID;
        }
        if (o.trim().equalsIgnoreCase("EmailAddress")) {
            return X509Name.EmailAddress;
        }
        if (o.trim().equalsIgnoreCase("E")) {
            return X509Name.EmailAddress;
        }
        if (o.trim().equalsIgnoreCase("EMail")) {
            return X509Name.EmailAddress;
        }
        return null;
    } // getOid

    /**
     * Creates a (Bouncycastle) X509Name object from a string with a DN.
     * <p>Known OID (with order) are:
     * <pre>
     * EmailAddress, UID, CN, SN (SerialNumber), GivenName, Initials, SurName, T, OU, O, L, ST, DC, C
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
        // first make two vectors, one with all the C, O, OU etc specifying the order
        // and one holding the actual values
        ArrayList oldordering = new ArrayList();
        ArrayList oldvalues = new ArrayList();
        while (st.hasMoreTokens()) {
            // Assume this is a pair (CN=xx)
            String order = st.nextToken().trim();
            if (st.hasMoreTokens()) {
                // make lower case so we can easily compare without bothering about case
                oldordering.add(order.toLowerCase());
                oldvalues.add(st.nextToken().trim());
            }
        }
        // Now in the specified order, move from oldordering to newordering, reshuffling as we go along
        Vector ordering = new Vector();
        Vector values = new Vector();
        int index = -1;
        for (int i = 0; i < dNObjects.length; i++) {
            //cat.debug("Looking for "+objects[i]);
            String object = dNObjects[i].toLowerCase();
            while ((index = oldordering.indexOf(object)) != -1) {
                //cat.debug("Found 1 "+object+" at index " + index);
                if (getOid(object) != null) {
                    //cat.debug("Added "+object+", "+oldvalues.elementAt(index));
                    ordering.add(getOid(object));
                    values.add(oldvalues.get(index));
                    // remove from the old vectors, so we start clean the next round
                    oldordering.remove(index);
                    oldvalues.remove(index);
                    index = -1;
                }
            }
        }
        /*
        if (cat.isDebugEnabled()) {
            Iterator i1 = ordering.iterator();
            Iterator i2 = values.iterator();
            cat.debug("Order: ");
            while (i1.hasNext()) {
                cat.debug(((DERObjectIdentifier)i1.next()).getId());
            }
            cat.debug("Values: ");
            while (i2.hasNext()) {
                cat.debug((String)i2.next());
            }
        } */
        cat.debug("<stringToBcX509Name");
        return new X509Name(ordering, values);
    } // stringToBcX509Name

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

        // Older workaround for bug in BC X509Name.java, kept for fun...
        //X509Name name = stringToBcX509Name(dn);
        //DERObject obj =name.getDERObject();
        //X509Name ret = new X509Name((DERConstructedSequence)obj);
        //return ret.toString();

        cat.debug("<stringToBcDNString");
        return name;
     }


    /**
     * Gets a specified part of a DN. Specifically the first occurrence it the DN contains several
     * instances of a part (i.e. cn=x, cn=y returns x).
     *
     * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
     * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
     * @return String containing dnpart or null if dnpart is not present
     */
    public static String getPartFromDN(String dn, String dnpart) {
        cat.debug(">getPartFromDN: dn:'" + dn+"', dnpart="+dnpart);
        if (dn == null) {
            return null;
        }
        String trimmeddn = dn.trim();
        String part = null, o = null;
        dnpart += "="; // we search for 'CN=' etc.
        StringTokenizer st = new StringTokenizer(trimmeddn, ",");
        while (st.hasMoreTokens()) {
            o = st.nextToken();
            //cat.debug("checking: "+o.trim().substring(0,dnpart.length()));
            if (o.length() > dnpart.length()) {
                if (o.trim().substring(0,dnpart.length()).equalsIgnoreCase(dnpart)) {
                    part = o.trim().substring(dnpart.length());
                    break;
                }
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
        if (crl == null)
            throw new IOException("Cannot read byte[] that is 'null'!");
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

    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, boolean isCA)
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
        // Put critical KeyUsage in CA-certificates
        if (isCA == true) {
            int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
            X509KeyUsage ku = new X509KeyUsage(keyusage);
            certgen.addExtension(X509Extensions.KeyUsage.getId(), true, ku);
        }
        // Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Mozilla.
        try {
            if (isCA == true) {
                SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((ASN1Sequence)new DERInputStream(
                new ByteArrayInputStream(pubKey.getEncoded())).readObject());
                SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);

                SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence)new DERInputStream(
                new ByteArrayInputStream(pubKey.getEncoded())).readObject());
                AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);

                certgen.addExtension(X509Extensions.SubjectKeyIdentifier.getId(), false, ski);
                certgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), false, aki);
            }
        } catch (IOException e) {// do nothing
        }
        // CertificatePolicies extension if supplied policy ID, always non-critical
        if (policyId != null) {
            CertificatePolicies cp = new CertificatePolicies(policyId);
            certgen.addExtension(X509Extensions.CertificatePolicies.getId(), false, cp);
        }

        X509Certificate selfcert = certgen.generateX509Certificate(privKey);
        return selfcert;
    } //genselfCert

    public static byte[] getAuthorityKeyId(X509Certificate cert) throws IOException {
        byte[] extvalue = cert.getExtensionValue("2.5.29.35");
        if (extvalue == null)
            return null;

        DEROctetString oct = (DEROctetString)(new DERInputStream(new ByteArrayInputStream(extvalue)).readObject());
        AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifier((ASN1Sequence)new DERInputStream(new ByteArrayInputStream(oct.getOctets())).readObject());
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

    public static String getCertificatePolicyId(X509Certificate cert) throws IOException {
        byte[] extvalue = cert.getExtensionValue("2.5.29.32");
        if (extvalue == null)
            return null;

        DEROctetString oct = (DEROctetString)(new DERInputStream(new ByteArrayInputStream(extvalue)).readObject());
        CertificatePolicies cp = new CertificatePolicies((ASN1Sequence)new DERInputStream(new ByteArrayInputStream(oct.getOctets())).readObject());
        String id = cp.getPolicy(0);
        return id;
    } // getCertificatePolicyId

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


package se.anatom.ejbca.webdist.rainterface;

import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;

import java.math.BigInteger;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import java.util.Date;


/**
 * A class transforming X509 certificate data inte more readable form used by JSP pages.
 *
 * @author Philip Vendil
 * @version $Id: CertificateView.java,v 1.10 2003-06-26 11:43:26 anatom Exp $
 */
public class CertificateView {
    public static final int DIGITALSIGNATURE = CertificateProfile.DIGITALSIGNATURE;
    public static final int NONREPUDIATION = CertificateProfile.NONREPUDIATION;
    public static final int KEYENCIPHERMENT = CertificateProfile.KEYENCIPHERMENT;
    public static final int DATAENCIPHERMENT = CertificateProfile.DATAENCIPHERMENT;
    public static final int KEYAGREEMENT = CertificateProfile.KEYAGREEMENT;
    public static final int KEYCERTSIGN = CertificateProfile.KEYCERTSIGN;
    public static final int CRLSIGN = CertificateProfile.CRLSIGN;
    public static final int ENCIPHERONLY = CertificateProfile.ENCIPHERONLY;
    public static final int DECIPHERONLY = CertificateProfile.DECIPHERONLY;

    /**
     * Creates a new instance of CertificateView
     *
     * @param certificate DOCUMENT ME!
     * @param revokedinfo DOCUMENT ME!
     * @param username DOCUMENT ME!
     */
    public CertificateView(X509Certificate certificate, RevokedInfoView revokedinfo, String username) {
        this.certificate = certificate;
        this.revokedinfo = revokedinfo;
        this.username = username;

        subjectdnfieldextractor = new DNFieldExtractor(CertTools.getSubjectDN(certificate),
                DNFieldExtractor.TYPE_SUBJECTDN);
        issuerdnfieldextractor = new DNFieldExtractor(CertTools.getIssuerDN(certificate),
                DNFieldExtractor.TYPE_SUBJECTDN);
    }

    // Public methods

    /**
     * Method that returns the version number of the X509 certificate.
     *
     * @return DOCUMENT ME!
     */
    public String getVersion() {
        return Integer.toString(certificate.getVersion());
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getType() {
        return "X509";
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSerialNumber() {
        return certificate.getSerialNumber().toString(16).toUpperCase();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public BigInteger getSerialNumberBigInt() {
        return certificate.getSerialNumber();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getIssuerDN() {
        return CertTools.getIssuerDN(certificate);
    }

    /**
     * DOCUMENT ME!
     *
     * @param field DOCUMENT ME!
     * @param number DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getIssuerDNField(int field, int number) {
        return issuerdnfieldextractor.getField(field, number);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSubjectDN() {
        return CertTools.getSubjectDN(certificate);
    }

    /**
     * DOCUMENT ME!
     *
     * @param field DOCUMENT ME!
     * @param number DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSubjectDNField(int field, int number) {
        return subjectdnfieldextractor.getField(field, number);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getValidFrom() {
        return certificate.getNotBefore();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getValidTo() {
        return certificate.getNotAfter();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean checkValidity() {
        boolean valid = true;

        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException e) {
            valid = false;
        } catch (CertificateNotYetValidException e) {
            valid = false;
        }

        return valid;
    }

    /**
     * DOCUMENT ME!
     *
     * @param date DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean checkValidity(Date date) {
        boolean valid = true;

        try {
            certificate.checkValidity(date);
        } catch (CertificateExpiredException e) {
            valid = false;
        } catch (CertificateNotYetValidException e) {
            valid = false;
        }

        return valid;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getPublicKeyAlgorithm() {
        return certificate.getPublicKey().getAlgorithm();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getPublicKeyLength() {
        String keylength = null;

        if (certificate.getPublicKey() instanceof RSAPublicKey) {
            keylength = "" + ((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength();
        }

        return keylength;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSignatureAlgoritm() {
        return certificate.getSigAlgName();
    }

    /**
     * Method that returns if key is allowed for given usage. Usage must be one of this class key
     * usage constants.
     *
     * @param usage DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getKeyUsage(int usage) {
        boolean returnval = false;

        if (certificate.getKeyUsage() != null) {
            returnval = certificate.getKeyUsage()[usage];
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean[] getAllKeyUsage() {
        return certificate.getKeyUsage();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getBasicConstraints() {
        return Integer.toString(certificate.getBasicConstraints());
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSignature() {
        return (new java.math.BigInteger(certificate.getSignature())).toString(16);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSHA1Fingerprint() {
        String returnval = "";

        try {
            byte[] res = CertTools.generateSHA1Fingerprint(certificate.getEncoded());
            returnval = (Hex.encode(res)).toUpperCase();
        } catch (CertificateEncodingException cee) {
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getMD5Fingerprint() {
        String returnval = "";

        try {
            byte[] res = CertTools.generateMD5Fingerprint(certificate.getEncoded());
            returnval = (Hex.encode(res)).toUpperCase();
        } catch (CertificateEncodingException cee) {
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean isRevoked() {
        return revokedinfo != null;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String[] getRevokationReasons() {
        String[] returnval = null;

        if (revokedinfo != null) {
            returnval = revokedinfo.getRevokationReasons();
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getRevokationDate() {
        Date returnval = null;

        if (revokedinfo != null) {
            returnval = revokedinfo.getRevocationDate();
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getUsername() {
        return this.username;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    // Private fields
    private X509Certificate certificate;
    private DNFieldExtractor subjectdnfieldextractor;
    private DNFieldExtractor issuerdnfieldextractor;
    private RevokedInfoView revokedinfo;
    private String username;
}

package se.anatom.ejbca.ca.store;

/**
 * The primary key of the CRL is the SHA1 fingerprint which should be unique.
 */
public class CertificateDataPK implements java.io.Serializable {
    public String fingerprint;

    /**
     * Creates a new CertificateDataPK object.
     *
     * @param fingerprint fingerprint of certificate
     */
    public CertificateDataPK(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    /**
     * Creates a new CertificateDataPK object.
     */
    public CertificateDataPK() {
    }

    /**
     * standard method
     *
     * @return hash code
     */
    public int hashCode() {
        return fingerprint.hashCode();
    }

    /**
     * checks for equality
     *
     * @param obj object
     *
     * @return true if equal, fals otherwise
     */
    public boolean equals(Object obj) {
        return ((CertificateDataPK) obj).fingerprint.equals(fingerprint);
    }

    /**
     * standard method
     *
     * @return string representation
     */
    public String toString() {
        return fingerprint.toString();
    }
}

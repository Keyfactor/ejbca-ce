package se.anatom.ejbca.ca.store;

/**
 * The primary key of the CRL is the SHA1 fingerprint which should be unique.
 **/
public class CertificateDataPK implements java.io.Serializable {
    public String fingerprint;

    public CertificateDataPK(String fingerprint) {
        this.fingerprint = fingerprint;
    }
    public CertificateDataPK() {
    }
    public int hashCode( ){
        return fingerprint.hashCode();
    }
    public boolean equals(Object obj){
        return ((CertificateDataPK)obj).fingerprint.equals(fingerprint);
    }
    public String toString(){
       return fingerprint.toString();
    }

}

package se.anatom.ejbca.ca.store;

/**
 * The primary key of the CRL is the SHA1 fingerprint which should be unique.
 **/
public class CRLDataPK implements java.io.Serializable {
    public String fingerprint;

    public CRLDataPK(String fingerprint) {
        this.fingerprint = fingerprint;
    }
    public CRLDataPK() {
    }
    
    public int hashCode( ){
        return fingerprint.hashCode();
    }
    public boolean equals(Object obj){
        return ((CRLDataPK)obj).fingerprint.equals(fingerprint);
    }
    public String toString(){
       return fingerprint.toString();
    }

}

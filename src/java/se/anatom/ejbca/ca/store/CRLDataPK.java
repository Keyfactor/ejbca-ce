package se.anatom.ejbca.ca.store;

/**
 * The primary key of the CRL is the SHA1 fingerprint which should be unique.
 **/
public class CRLDataPK implements java.io.Serializable {
    public String fp;

    public int hashCode( ){
        return fp.hashCode();
    }
    public boolean equals(Object obj){
        if(obj instanceof CRLDataPK){
            return (fp == ((CRLDataPK)obj).fp);
        }
        return false;
    }
    public String toString(){
       return fp;
    }

}

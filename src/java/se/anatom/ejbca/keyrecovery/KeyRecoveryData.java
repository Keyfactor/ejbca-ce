/*
 * KeyRecoveryData.java
 *
 * Created on den 6 februari 2003, 22:27
 */

package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;
import java.security.KeyPair;

/**
 *  This is a value class containing the data relating to key saved for recovery for a user, sent between 
 *  server and clients.
 *
 * @author  TomSelleck
 */

public class KeyRecoveryData implements java.io.Serializable {
  
    // Public Constructors
    public KeyRecoveryData(BigInteger certificatesn, String issuerdn, String username, boolean markedasrecoverable, KeyPair keypair){
      this.certificatesn=certificatesn;
      this.issuerdn=issuerdn;
      this.username=username;     
      this.markedasrecoverable=markedasrecoverable;
      this.keypair=keypair;
    }
    
    public KeyRecoveryData(){
    }    
    
    // Public Methods    
    
    public BigInteger getCertificateSN(){ return this.certificatesn; }   
    public void setCertificateSN(BigInteger certificatesn){ this.certificatesn=certificatesn; }
    
    public String getIssuerDN(){ return this.issuerdn; }   
    public void setIssuerDN(String issuerdn){ this.issuerdn=issuerdn; }       
    
    public String getUsername(){ return this.username; }   
    public void setUsername(String username){ this.username=username; }    
    
    public boolean getMarkedAsRecoverable(){ return this.markedasrecoverable; }   
    public void setMarkedAsRecoverable(boolean markedasrecoverable){ this.markedasrecoverable=markedasrecoverable; }
    
    public KeyPair getKeyPair(){ return this.keypair; }   
    public void setKeyPair(KeyPair keypair){ this.keypair=keypair; }
          
    // Private fields
    private     BigInteger       certificatesn;
    private     String           issuerdn;
    private     String           username;
    private     boolean          markedasrecoverable;
    private     KeyPair          keypair;

}

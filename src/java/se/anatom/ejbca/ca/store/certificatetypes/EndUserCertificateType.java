/*
 * EndUserCertificateType.java
 *
 * Created on den 29 juli 2002, 22:08
 */
package se.anatom.ejbca.ca.store.certificatetypes;

import java.io.Serializable;
import java.util.Vector;

/**
 * EndUserCertificateType is a class defining the fixed characteristics of an enduser certificate type
 *
 * @author  TomSelleck
 */
public class EndUserCertificateType extends CertificateType{
    
    // Public Constants

    public final static String CERTIFICATETYPENAME =  "ENDUSER";
    
    // Public Methods
    /** Creates a certificate with the characteristics of an end user. */
    public EndUserCertificateType() {
      version = VERSION_X509V3;         
      validity= new Long(730);
    
      usebasicconstraints= new Boolean(true);
      basicconstraintscritical= new Boolean(true); 
    
      usekeyusage= new Boolean(true);
      keyusagecritical= new Boolean(true);
    
      usesubjectkeyidentifier= new Boolean(true);
      subjectkeyidentifiercritical= new Boolean(false);    
   
      useauthoritykeyidentifier= new Boolean(true);
      authoritykeyidentifiercritical= new Boolean(false);
    
      usecrlnumber = new Boolean(true);
      crlnumbercritical = new Boolean(false);
    
      usesubjectalternativename= new Boolean(true);
      subjectalternativenamecritical = new Boolean(false);
    
      usecrldistributionpoint = new Boolean(false);
      crldistributionpointcritical = new Boolean(false);
      crldistributionpointuri = "";
    
      emailindn  = new Boolean(false);
      crlperiod  = new Long(24);
      finishuser = new Boolean(true);
    
      availablebitlengths = new Vector();
      availablebitlengths.addElement(new Integer(512));
      availablebitlengths.addElement(new Integer(1024));
      availablebitlengths.addElement(new Integer(2048));
      availablebitlengths.addElement(new Integer(4096));
      
      minimumavailablebitlength = 512;
      maximumavailablebitlength = 4096;
      
      keyusage = new boolean[9];  
      keyusage[DIGITALSIGNATURE] = true;
      keyusage[KEYENCIPHERMENT] = true;      
    }
    
    // Public Methods.

    
    // Private fields.
}

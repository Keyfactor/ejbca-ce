/*
 * CertificateType.java
 *
 * Created on den 29 juli 2002, 22:08
 */
package se.anatom.ejbca.ca.store.certificatetypes;

import java.io.Serializable;
import java.util.Vector;

/**
 * CertificateType is a basic class used to customize a certificate configuration or be inherited by fixed certificate types.
 *
 * @author  TomSelleck
 */
public class CertificateType implements Serializable, Cloneable {
    
    // Public Constants
    public static final int DIGITALSIGNATURE = 0;
    public static final int NONREPUDATION    = 1;
    public static final int KEYENCIPHERMENT  = 2;
    public static final int DATAENCIPHERMENT = 3;
    public static final int KEYAGREEMENT     = 4;
    public static final int KEYCERTSIGN      = 5;
    public static final int CRLSIGN          = 6;
    public static final int ENCIPHERONLY     = 7;
    public static final int DECIPHERONLY     = 8;    
       
    public static final String TRUE  = "true";
    public static final String FALSE = "false";
    
    /** Supported certificate versions. */
    public final static String VERSION_X509V3 = "X509v3";    
    
    public final static String CERTIFICATETYPENAME =  "CUSTOM";    
    
    // Public Methods
    /** Creates a new instance of CertificateType */
    public CertificateType() {
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
    }
    
    // Public Methods.
    /** Returns the version of the certificate, should be one of the VERSION_ constants defined in CertificateType class. */
    public String getVersion(){return version;}
    /** Sets the version of the certificate, should be one of the VERSION_ constants defined in CertificateType class. */    
    public void setVersion(String version){this.version = version;}
    
    public Long getValidity(){return validity;}
    public void setValidity(long validity) { this.validity = new Long(validity);}
    
    public Boolean getUseBasicConstraints(){ return usebasicconstraints; }
    public void setUseBasicConstraints(boolean usebasicconstraints) { this.usebasicconstraints = new Boolean(usebasicconstraints);} 
   
    public Boolean getBasicConstraintsCritical(){ return basicconstraintscritical; }
    public void setBasicConstraintsCritical(boolean basicconstraintscritical) { this.basicconstraintscritical = new Boolean(basicconstraintscritical);} 
    
    public Boolean getUseKeyUsage(){ return usekeyusage; }
    public void setUseKeyUsage(boolean usekeyusage) { this.usekeyusage = new Boolean(usekeyusage);} 
   
    public Boolean getKeyUsageCritical(){ return keyusagecritical; }
    public void setKeyUsageCritical(boolean keyusagecritical) { this.keyusagecritical = new Boolean(keyusagecritical);}     
    
    public Boolean getUseSubjectKeyIdentifier(){ return usesubjectkeyidentifier; }
    public void setUseSubjectKeyIdentifier(boolean usesubjectkeyidentifier) { this.usesubjectkeyidentifier = new Boolean(usesubjectkeyidentifier);} 
   
    public Boolean getSubjectKeyIdentifierCritical(){ return subjectkeyidentifiercritical; }
    public void setSubjectKeyIdentifierCritical(boolean subjectkeyidentifiercritical) { this.subjectkeyidentifiercritical = new Boolean(subjectkeyidentifiercritical);}     
    
    public Boolean getUseAuthorityKeyIdentifier(){ return useauthoritykeyidentifier; }
    public void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier) { this.useauthoritykeyidentifier = new Boolean(useauthoritykeyidentifier);} 
   
    public Boolean getAuthorityKeyIdentifierCritical(){ return authoritykeyidentifiercritical; }
    public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical) { this.authoritykeyidentifiercritical = new Boolean(authoritykeyidentifiercritical);}     
    
    public Boolean getUseCRLNumber(){ return usecrlnumber; }
    public void setUseCRLNumber(boolean usecrlnumber) { this.usecrlnumber = new Boolean(usecrlnumber);} 
   
    public Boolean getCRLNumberCritical(){ return crlnumbercritical; }
    public void setCRLNumberCritical(boolean crlnumbercritical) { this.crlnumbercritical = new Boolean(crlnumbercritical);}  
    
    public Boolean getUseSubjectAlternativeName(){ return usesubjectalternativename; }
    public void setUseSubjectAlternativeName(boolean usesubjectalternativename) { this.usesubjectalternativename = new Boolean(usesubjectalternativename);} 
   
    public Boolean getSubjectAlternativeNameCritical(){ return subjectalternativenamecritical; }
    public void setSubjectAlternativeNameCritical(boolean subjectalternativenamecritical) { this.subjectalternativenamecritical = new Boolean(subjectalternativenamecritical);}      
 
    public Boolean getUseCRLDistributionPoint(){ return usecrldistributionpoint; }
    public void setUseCRLDistributionPoint(boolean usecrldistributionpoint) { this.usecrldistributionpoint = new Boolean(usecrldistributionpoint);} 
   
    public Boolean getCRLDistributionPointCritical(){ return crldistributionpointcritical; }
    public void setCRLDistributionPointCritical(boolean crldistributionpointcritical) { this.crldistributionpointcritical = new Boolean(crldistributionpointcritical);}  
    
    public String getCRLDistributionPointURI(){ return crldistributionpointuri; }
    public void setCRLDistributionPointURI(String crldistributionpointuri) { 
      if(crldistributionpointuri==null)
        this.crldistributionpointuri = "";
      else
        this.crldistributionpointuri = crldistributionpointuri;
    }  
    
    public Boolean getEmailInDN(){ return emailindn; }
    public void setEmailInDN(boolean emailindn) { this.emailindn = new Boolean(emailindn);}   
    
    public Long getCRLPeriod(){ return crlperiod; }
    public void setCRLPeriod(long crlperiod){this.crlperiod=new Long(crlperiod);}
    
    public Boolean getFinishUser(){ return finishuser; }
    public void setFinishUser(boolean finishuser) { this.finishuser = new Boolean(finishuser);}       
   
    public int[] getAvailableBitLengths(){
      int[] returnval = new int[availablebitlengths.size()]; 
      
      for(int i=0; i < availablebitlengths.size(); i++){
        returnval[i] = ((Integer) availablebitlengths.get(i)).intValue();   
      }
      
      return returnval;  
    }
    
    public void setAvailableBitLengths(int[] availablebitlengths){
      this.availablebitlengths.removeAllElements(); 
      
      minimumavailablebitlength = 99999999;
      maximumavailablebitlength = 0;     
      
      for(int i=0;i< availablebitlengths.length;i++){
        if( availablebitlengths[i] > maximumavailablebitlength)
          maximumavailablebitlength = availablebitlengths[i];  
        if( availablebitlengths[i] < minimumavailablebitlength)
          minimumavailablebitlength = availablebitlengths[i];          
          
        this.availablebitlengths.addElement(new Integer(availablebitlengths[i]));
      }  
      java.util.Arrays.sort(availablebitlengths);
    }
    
    public int getMinimumAvailableBitLength(){return this.minimumavailablebitlength;}
    public int getMaximumAvailableBitLength(){return this.maximumavailablebitlength;}    
    
    public boolean[] getKeyUsage(){return this.keyusage;}
    public boolean getKeyUsage(int keyusageconstant){return this.keyusage[keyusageconstant];}
    
    public void setKeyUsage(boolean[] keyusage){this.keyusage = keyusage;}
    public void setKeyUsage(int keyusageconstant, boolean value){this.keyusage[keyusageconstant] =value;}

    
    public Object clone() throws CloneNotSupportedException {
      return super.clone();
    }    
    
    // protected fields.
    protected String version;
    
    protected Long validity;
    
    protected Boolean usebasicconstraints;
    protected Boolean basicconstraintscritical; 
    
    protected Boolean usekeyusage;
    protected Boolean keyusagecritical;
    
    protected Boolean usesubjectkeyidentifier;
    protected Boolean subjectkeyidentifiercritical;    
   
    protected Boolean useauthoritykeyidentifier;
    protected Boolean authoritykeyidentifiercritical;
    
    protected Boolean usecrlnumber;
    protected Boolean crlnumbercritical;
    
    protected Boolean usesubjectalternativename;
    protected Boolean subjectalternativenamecritical;
    
    protected Boolean usecrldistributionpoint;
    protected Boolean crldistributionpointcritical;
    protected String  crldistributionpointuri;
    
    protected Boolean emailindn;
    protected Long    crlperiod;
    protected Boolean finishuser;
    
    protected Vector availablebitlengths;
    protected boolean[] keyusage;
    
    protected int minimumavailablebitlength;
    protected int maximumavailablebitlength;
}

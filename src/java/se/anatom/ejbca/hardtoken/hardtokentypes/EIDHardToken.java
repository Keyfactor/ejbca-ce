package se.anatom.ejbca.hardtoken.hardtokentypes;

import se.anatom.ejbca.SecConst;

/**
 * EIDHardToken is a class defining data stored in database for a EID token.
 *
 * @version $Id$
 */
public class EIDHardToken extends HardToken{

    // Public Constants
    public static final String INITIALBASICPIN     = "INITIALBASICPIN";
    public static final String BASICPUK            = "BASICPUK";
    public static final String INITIALSIGNATUREPIN = "INITIALSIGNATUREPIN";    
    public static final String SIGNATUREPUK        = "SIGNATUREPUK"; 
    
    public static final int THIS_TOKENTYPE      = SecConst.TOKEN_EID;
    
    public static final String[] FIELDS     = {INITIALBASICPIN, BASICPUK, EMPTYROW_FIELD, INITIALSIGNATUREPIN,SIGNATUREPUK}; 
    public static final int[]    DATATYPES  = {STRING,STRING,EMPTYROW,STRING,STRING};
    public static final String[] FIELDTEXTS = {INITIALBASICPIN, BASICPUK, EMPTYROW_FIELD, INITIALSIGNATUREPIN,SIGNATUREPUK};
    
    // Public Methods
    /** Creates a certificate with the characteristics of an end user. */
    public EIDHardToken() {
       setInitialBasicPIN("");
       setBasicPUK("");
       setInitialSignaturePIN("");
       setSignaturePUK("");       
       
       data.put(TOKENTYPE, new Integer(THIS_TOKENTYPE)); 
    }
    
    // Public Overloaded Methods.
    public int getNumberOfFields(){
      return EIDHardToken.FIELDS.length;  
    }
    public String getFieldText(int index){
      return EIDHardToken.FIELDTEXTS[index];   
    }
    
    public String getFieldPointer(int index){
      return EIDHardToken.FIELDS[index];  
    }
    
    public int getFieldDataType(int index){
      return EIDHardToken.DATATYPES[index];   
    }
    

    // Public Methods.
    public String getInitialBasicPIN(){  return (String) data.get(INITIALBASICPIN);  }
    public void setInitialBasicPIN(String initialbasicpin){ data.put(INITIALBASICPIN, initialbasicpin); };
        
    public String getBasicPUK(){  return (String) data.get(BASICPUK);  }
    public void setBasicPUK(String basicpuk){ data.put(BASICPUK, basicpuk); };
    
    public String getInitialSignaturePIN(){  return (String) data.get(INITIALSIGNATUREPIN);  }
    public void setInitialSignaturePIN(String initialsignaturepin){ data.put(INITIALSIGNATUREPIN, initialsignaturepin); };
    
    public String getSignaturePUK(){  return (String) data.get(SIGNATUREPUK);  }
    public void setSignaturePUK(String signaturepuk){ data.put(SIGNATUREPUK, signaturepuk); };

    // Private fields.
}

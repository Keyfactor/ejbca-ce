package se.anatom.ejbca.authorization;

/**
 * A class containing constats used when configuring Basic Access Rule Set 
 *
 * @author  herrvendil 
 * @version $Id: BasicAccessRuleSet.java,v 1.1 2004-02-11 10:43:15 herrvendil Exp $
 */
public class BasicAccessRuleSet implements java.io.Serializable {

    public static final int ROLE_SUPERADMINISTRATOR = 1;
    public static final int ROLE_CAADMINISTRATOR       = 2;
    public static final int ROLE_RAADMINISTRATOR       = 3;
    public static final int ROLE_SUPERVISOR                 = 4;
    public static final int ROLE_HARDTOKENISSUER       = 5;

    public static final int ENDENTITY_VIEW                      = 1;
    public static final int ENDENTITY_VIEWHISTORY         = 2;
    public static final int ENDENTITY_VIEWHARDTOKENS  = 3;    
    public static final int ENDENTITY_CREATE                   = 4;    
    public static final int ENDENTITY_EDIT                        = 5;
    public static final int ENDENTITY_REVOKE                   = 6;
    
    public static final int ENDENTITYPROFILE_ALL  = 0;
    
    public static final int CA_ALL  = 0;
    
    public static final int OTHER_VIEWLOG = 1;
    public static final int OTHER_ISSUEHARDTOKENS = 2;
    
    public static final String[]  ROLETEXTS = {"","SUPERADMINISTRATOR","CAADMINISTRATOR",
    		                                                         "RAADMINISTRATOR", "SUPERVISOR",
                                                                     "HARDTOKENISSUER"};
    
    public static final String[]  ENDENTITYRULETEXTS =  {"","VIEWENDENTITY","VIEWHISTORY","VIEWHARDTOKENS",
    	                                                                                  "CREATEENDENTITY","EDITENDENTITY","REVOKEENDENTITY"};
    		
    public static final String[]  OTHERTEXTS = {"","VIEWLOG","ISSUEHARDTOKENS"};
        
   /**
     * This class should not be able to be instantiated.
     */
    private BasicAccessRuleSet(){}
    
    
    
   
}

/*
 * UserMatch.java
 *
 * Created on den 20 juli 2002, 23:20
 */

package se.anatom.ejbca.util.query;



/**
 * A class used by Query class to build a query for ejbca ra module. Inherits BasicMatch.
 * 
 *
 * Main function is getQueryString which returns a fragment of SQL statment.
 *
 * @see se.anatom.ejbca.util.query.BasicMatch
 * @see se.anatom.ejbca.util.query.TimeMatch
 * @see se.anatom.ejbca.util.query.LogMatch
 * @author  TomSelleck
 */
public class UserMatch extends BasicMatch {
    
    // Public Constants
    public final static int MATCH_WITH_USERNAME         = 0;
    public final static int MATCH_WITH_EMAIL            = 1;
    public final static int MATCH_WITH_STATUS           = 2; // Value must the number representation.
    public final static int MATCH_WITH_PROFILE          = 3; // Matches the profile id not profilename.
    public final static int MATCH_WITH_CERTIFICATETYPE  = 4; // Matches the certificatetype id not name.
        // Subject DN fields.
    public final static int MATCH_WITH_COMMONNAME       = 100;
    public final static int MATCH_WITH_ORGANIZATIONUNIT = 101;
    public final static int MATCH_WITH_ORGANIZATION     = 102;
    public final static int MATCH_WITH_LOCALE           = 103;
    public final static int MATCH_WITH_STATE            = 104;
    public final static int MATCH_WITH_COUNTRY          = 105;    

    // Private Constants.
    private final static String[] MATCH_WITH_SQLNAMES = {"username", "subjectEmail", "status"
                                                         , "profileId", "certificateTypeId"}; // Represents the column names in ra userdata table.

    private final static String MATCH_WITH_SUBJECTDN        = "subjectDN";
    private final static String[] MATCH_WITH_SUBJECTDN_NAMES  = {"CN=", "OU=", "O=", "L=", "ST=", "C="};        
    
    // Public methods.
    /** Creates a new instance of UserMatch.
     *
     *  @param matchwith determines which field i userdata table to match with.
     *  @param matchtype determines how to match the field. SubjectDN fields can only be matched with 'begins with'.
     *  @param matchvalue the value to match with.
     * 
     *  @throws NumberFormatException if matchvalue constains illegal numbervalue when matching number field.
     */
    public UserMatch(int matchwith, int matchtype, String matchvalue) throws NumberFormatException {
      this.matchwith=matchwith;
      this.matchtype=matchtype;
      this.matchvalue=matchvalue;
      
      if(matchwith >= MATCH_WITH_STATUS && matchwith <= MATCH_WITH_CERTIFICATETYPE)
        new Integer(matchvalue);
    }
    
    /**
     * Returns a SQL statement fragment from the given data.
     */
    public String getQueryString(){
      String returnval = "";
      
      if(isSubjectDNMatch()){
          // Ignore MATCH_TYPE_EQUALS.
          returnval = MATCH_WITH_SUBJECTDN + " LIKE '%" + MATCH_WITH_SUBJECTDN_NAMES[matchwith -100] + matchvalue + "%'";
      }
      else{
        if(matchtype == BasicMatch.MATCH_TYPE_EQUALS)
           returnval =  MATCH_WITH_SQLNAMES[matchwith] + " = '" + matchvalue + "'";              
        
        if(matchtype == BasicMatch.MATCH_TYPE_BEGINSWITH)
           returnval =  MATCH_WITH_SQLNAMES[matchwith] + " LIKE '" + matchvalue + "%'";  
      }
        
      return returnval;  
    } // getQueryString
    
    /** Checks if query data is ok. */  
    public boolean isLegalQuery(){
      return !(matchvalue.trim().equals(""));
    }
    
    // Private Methods
    private boolean isSubjectDNMatch(){
      return this.matchwith >= 100;   
    }
    

      // Private Fields.
    private int matchwith;
    private int matchtype;
    private String matchvalue;
}

package se.anatom.ejbca.ra;

import java.util.Date;
import java.text.DateFormat;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;

/**
 * This class is used to create notification messages
 *
 * @version $Id: NotificationCreator.java,v 1.1 2003-02-21 12:13:58 herrvendil Exp $
 */
public class NotificationCreator {
    
    
    /** Availabe vairables used to replace text i message, message is retrived from ejb-jar.xml 
     *  Variable text are case-insensitive.
     */
    private static String USERNAME = "$Username";
    private static String PASSWORD = "$Password";
    private static String CN       = "$CN";
    private static String O        = "$O";
    private static String OU       = "$OU";
    private static String C        = "$C";    
    private static String DATE     = "$DATE";    
    
    private static String NEWLINE  = "\\n";

    
    /**
     * Creates a notification creator.
     * @param sender is the address of the sender sending the message.
     * @param subject is the string to be used as subject of notification message
     * @param message is the actual message sent in the email. Should contain the supported variables.
     *
     */
    public NotificationCreator(String sender, String subject, String message){   
      this.sender=sender;
      this.subject=subject;
      this.message=message;
    }
    
    public String getSender(){
      return sender;   
    } 
    
    public String getSubject(){
      return subject;
    } 
    
    public String getMessage(String username, String password, String dn, String subjectaltname, String email) throws Exception{
      String returnval = new String(message);
      DNFieldExtractor dnfields = new DNFieldExtractor(dn,DNFieldExtractor.TYPE_SUBJECTDN);      
      // DNFieldExtractor subaltnamefields = new DNFieldExtractor(dn,DNFieldExtractor.TYPE_SUBJECTALTNAME); 
      String currentdate = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date());
      String newline = System.getProperty("line.separator");

      
      returnval = new RegularExpression.RE(USERNAME,false).replace(returnval,username);   
      returnval = new RegularExpression.RE(PASSWORD,false).replace(returnval,password);        
      returnval = new RegularExpression.RE(CN,false).replace(returnval,dnfields.getField(DNFieldExtractor.CN,0));
      returnval = new RegularExpression.RE(OU,false).replace(returnval,dnfields.getField(DNFieldExtractor.OU,0));       
      returnval = new RegularExpression.RE(O,false).replace(returnval,dnfields.getField(DNFieldExtractor.O,0));   
      returnval = new RegularExpression.RE(C,false).replace(returnval,dnfields.getField(DNFieldExtractor.C,0));           
      returnval = new RegularExpression.RE(DATE,false).replace(returnval,currentdate); 
      
      returnval = new RegularExpression.RE(NEWLINE,false).replace(returnval,newline); 
      
      return returnval;
    }
    
    // Provate Variables
    private String sender;
    private String subject;
    private String message;
}

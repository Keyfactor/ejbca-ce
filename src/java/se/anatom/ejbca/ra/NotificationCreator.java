package se.anatom.ejbca.ra;

import java.util.Date;
import java.util.regex.Pattern;
import java.text.DateFormat;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;

/**
 * This class is used to create notification messages
 *
 * @version $Id: NotificationCreator.java,v 1.3 2003-04-20 13:36:35 herrvendil Exp $
 */
public class NotificationCreator {


    /** Availabe vairables used to replace text i message, message is retrived from ejb-jar.xml
     *  Variable text are case-insensitive.
     */
    private static final Pattern USERNAME =
      Pattern.compile("\\$Username", Pattern.CASE_INSENSITIVE);
    private static final Pattern PASSWORD =
      Pattern.compile("\\$Password", Pattern.CASE_INSENSITIVE);
    private static final Pattern CN =
      Pattern.compile("\\$CN", Pattern.CASE_INSENSITIVE);
    private static final Pattern O =
      Pattern.compile("\\$O", Pattern.CASE_INSENSITIVE);
    private static final Pattern OU =
      Pattern.compile("\\$OU", Pattern.CASE_INSENSITIVE);
    private static final Pattern C =
      Pattern.compile("\\$C", Pattern.CASE_INSENSITIVE);
    private static final Pattern DATE =
      Pattern.compile("\\$DATE", Pattern.CASE_INSENSITIVE);

    private static final Pattern NEWLINE = Pattern.compile("\\n");


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

      returnval = USERNAME.matcher(returnval).replaceAll(username);
      returnval = PASSWORD.matcher(returnval).replaceAll(password);
      returnval = CN.matcher(returnval).replaceAll(dnfields.getField(DNFieldExtractor.CN, 0));
      returnval = OU.matcher(returnval).replaceAll(dnfields.getField(DNFieldExtractor.OU, 0));
      returnval = O.matcher(returnval).replaceAll(dnfields.getField(DNFieldExtractor.O, 0));
      returnval = C.matcher(returnval).replaceAll(dnfields.getField(DNFieldExtractor.C, 0));
      returnval = DATE.matcher(returnval).replaceAll(currentdate);

      returnval = NEWLINE.matcher(returnval).replaceAll(newline);

      return returnval;
    }

    // Private Variables
    private String sender;
    private String subject;
    private String message;
}

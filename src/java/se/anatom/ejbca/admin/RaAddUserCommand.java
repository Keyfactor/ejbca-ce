
package se.anatom.ejbca.admin;

import java.io.*;

/** Adds a user to the database.
 *
 * @version $Id: RaAddUserCommand.java,v 1.2 2002-04-14 09:11:10 anatom Exp $
 */
public class RaAddUserCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaAddUserCommand */
    public RaAddUserCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 6) {
                System.out.println("Usage: RA adduser <username> <password> <dn> <email> <type>");
                System.out.println("Type (mask): INVALID=0; END-USER=1; CA=2; RA=4; ROOTCA=8; CAADMIN=16; RAADMIN=0x32");
                System.out.println("If the user does not have an email address, use the value 'null'.");
                return;
            }
            String username = args[1];
            String password = args[2];
            String dn = args[3];
            String email = args[4];
            int type = Integer.parseInt(args[5]);
            
            System.out.println("Trying to add user:");
            System.out.println("Username: "+username);
            System.out.println("Password (hashed only): "+password);
            System.out.println("DN: "+dn);
            System.out.println("Email: "+email);
            System.out.println("Type: "+type);
            if (email.equals("null"))
                email = null;
            getAdminSession().addUser(username, password, dn, email, type);
            System.out.println("User '"+username+"' has been added.");
            System.out.println();
            System.out.println("Note: If batch processing should be possible, \nalso use 'ra setclearpwd "+username+" <pwd>'.");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}

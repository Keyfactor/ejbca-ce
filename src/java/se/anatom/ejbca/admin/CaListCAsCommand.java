package se.anatom.ejbca.admin;

import java.util.Collection;
import java.util.Iterator;

import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionRemote;

/**
 * Lists the names of all available CAs.
 *
 * @version $Id: CaListCAsCommand.java,v 1.1 2003-11-02 08:46:03 anatom Exp $
 */
public class CaListCAsCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaListCAsCommand
     *
     * @param args command line arguments
     */
    public CaListCAsCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
            
        if (args.length > 1) {
           String msg = "Lists the names of all available CAs.\nUsage: CA listcas";               
           throw new IllegalAdminCommandException(msg);
        }            
        try {
            ICAAdminSessionRemote casession = getCAAdminSessionRemote();
            Collection caids = casession.getAvailableCAs(administrator);
            Iterator iter = caids.iterator();
            while (iter.hasNext()) {
                int caid = ((Integer)iter.next()).intValue();
                CAInfo ca = casession.getCAInfo(administrator,caid);
                System.out.println();
                System.out.println("CA Name: "+ca.getName());
                System.out.println("Id: "+ca.getCAId());
                System.out.println("DN: "+ca.getSubjectDN());
                System.out.println("Type: "+ca.getCAType());
                System.out.println("Expire time: "+ca.getExpireTime());
                System.out.println("Signed by: "+ca.getSignedBy());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}

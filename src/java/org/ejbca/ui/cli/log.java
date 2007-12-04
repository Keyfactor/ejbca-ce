package org.ejbca.ui.cli;

public class log extends BaseCommand {

    public static void main(String[] args) {
        try {
            IAdminCommand cmd = LogAdminCommandFactory.getCommand(args);

            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println(
                    "Usage: LOG accept | verifyprotected | resetexports | resetprotected");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());            
            //e.printStackTrace();
            System.exit(-1);
        }
    } // main

}

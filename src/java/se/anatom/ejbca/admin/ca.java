package se.anatom.ejbca.admin;

import org.apache.log4j.PropertyConfigurator;

public class ca {

    public static void main(String [] args){
        PropertyConfigurator.configure("log4j.properties");
        try {
            IAdminCommand cmd = CaAdminCommandFactory.getCommand(args);
            if (cmd != null) {
                cmd.execute();
            } else {
                System.out.println("Usage: CA info | makeroot | getrootcert | makereq | recrep | processreq | init | createcrl | getcrl | rolloverroot | rolloversub | listexpired");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            //e.printStackTrace();
        }
    }


} //ca

package se.anatom.ejbca.util;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;


/**
 * DOCUMENT ME!
 *
 * @version $Id: TomcatServiceXMLPasswordReplace.java,v 1.4 2003-07-24 08:43:32 anatom Exp $
 */
public class TomcatServiceXMLPasswordReplace {
    /**
     * Creates a new instance of TomcatServiceXMLPasswordReplace
     */
    public TomcatServiceXMLPasswordReplace() {
    }

    /**
     * DOCUMENT ME!
     *
     * @param args DOCUMENT ME!
     */
    public static void main(String[] args) {
        try {
            // Check number of parameter.
            if (args.length != 3) {
                System.out.println(
                    "Required parameters : <tomcatservice.xml infile> <tomcatservice.xml outfile> <replacementpassword>");
                System.exit(0);
            }

            BufferedReader br = new BufferedReader(new FileReader(args[0]));
            FileWriter fwr = new FileWriter(args[1]);
            String line = null;

            while ((line = br.readLine()) != null) {
                fwr.write(line.replaceAll("foo123", args[2]) + "\n");
            }

            br.close();
            fwr.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // main
}


//  TomcatServiceXMLPasswordReplace

/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.util;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;


/**
 * DOCUMENT ME!
 *
 * @version $Id: TomcatServiceXMLPasswordReplace.java,v 1.5 2004-04-16 07:38:59 anatom Exp $
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

/*
 * TomcatServiceXMLPasswordReplace.java
 *
 * Created on den 7 november 2002, 22:49
 */

package se.anatom.ejbca.util;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.BufferedReader;

/**
 *
 * @author  tomselleck
 */
public class TomcatServiceXMLPasswordReplace {
    
    /** Creates a new instance of TomcatServiceXMLPasswordReplace */
    public TomcatServiceXMLPasswordReplace() {
    }
    
    
    public static void main(String[] args) {
      try {
             // Check number of parameter.
           if(args.length != 3 ) {
               System.out.println("Required parameters : <tomcatservice.xml infile> <tomcatservice.xml outfile> <replacementpassword>");
               System.exit(0);
            }      
                
            BufferedReader br = new BufferedReader(new FileReader(args[0]));
            FileWriter fwr    = new FileWriter(args[1]); 
            RegularExpression.RE re = new RegularExpression.RE("foo123",false);
            String line = null;
            
            while((line = br.readLine()) != null){
              line = re.replace(line,args[2]);
              fwr.write(line + "\n");
            }
           
            br.close();
            fwr.close();
         } catch( Exception e ) {
            e.printStackTrace();
         }
    } // main

    
} //  TomcatServiceXMLPasswordReplace

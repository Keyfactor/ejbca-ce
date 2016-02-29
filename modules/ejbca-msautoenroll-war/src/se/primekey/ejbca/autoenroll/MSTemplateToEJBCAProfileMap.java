/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package se.primekey.ejbca.autoenroll;

/**
 * @author Daniel Horn, SiO2 Corp.
 *
 * @version $Id$
 */
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;
import javax.servlet.ServletContext;

public class MSTemplateToEJBCAProfileMap extends Properties
{

    public MSTemplateToEJBCAProfileMap()
    {
    }
    
    // TODO What should the name be?
    private static final String strFileName = "MSTemplateToEJBCAProfile.conf";

    // Originally used a relative path but in that case
    // "." relative means something like
    // /Applications/apache-tomcat-6.0.32/bin/MSTemplateToEJBCAProfile.conf
    private InputStream getMapFile(ServletContext context)
    {
        return context.getResourceAsStream("/WEB-INF/" + strFileName);
    }

    // Note that there is no corresponding store method because this file
    // should be read-only with respect to this application.
    boolean load(ServletContext context)
    {
        boolean rc = false;
        try
        {
//            String strFileName = getPropertiesFileName(context);
//            File file = new File(strFileName);
//            System.out.println(file.getAbsolutePath());
//            System.out.println(file.getCanonicalPath());
            InputStream in = getMapFile(context);
            super.load(in);
            in.close();

            rc = true;
        }
        catch (FileNotFoundException ex)
        {
            // Probably should be created first time app is run, so exception here is not a problem as long as reasonable defaults are set.
            ex.printStackTrace();
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }

        return rc;
    }

    // For debugging:
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append("MSTemplateToEJBCAMap:");
        Enumeration<Object> templates = keys();
        while (templates.hasMoreElements())
        {
            String elem = (String) templates.nextElement();
            sb.append("\n\t").append(elem).append(" = ").append(getProperty(elem));
        }

        return sb.toString();
    }
}

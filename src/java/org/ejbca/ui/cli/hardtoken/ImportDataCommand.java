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
 
package org.ejbca.ui.cli.hardtoken;

import java.io.FileInputStream;
import java.util.Properties;

import javax.naming.InitialContext;

import org.ejbca.core.ejb.hardtoken.IHardTokenSessionHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionRemote;
import org.ejbca.core.model.hardtoken.HardTokenData;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.cli.BaseAdminCommand;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.ui.cli.hardtoken.importer.IHardTokenImporter;

/**
 * Command used to import hard token data from a source.
 * 
 * It reads its properties from a file specified and there are two required
 * properties by default.
 * importer.classpath pointing to an implementation of a org.ejbca.ui.cli.hardtoken.IHardTokenImporter 
 * significantissuerdn should contain the DN of the CA that the tokens should be connected to, used 
 * for authorization purposes. 
 * 
 * The -force flag indicates that rows that already exists in the data will be overwritten.
 * @version $Id$
 */
public class ImportDataCommand extends BaseAdminCommand {
    /**
     * Creates a new instance of ImportDataCommand
     *
     * @param args command line arguments
     */
    public ImportDataCommand(String[] args) {
        super(args, Admin.TYPE_CACOMMANDLINE_USER, "cli");
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
    	String usageText = "Usage: hardtoken importdata <propertyfile> -force\n" + 
           "Example: hardtoken importdata tokenimport.properties -force \n\n" +
           "The force flags indicates that existing hard token info will be overwritten.";
        if (args.length < 2 || args.length > 3) {
	       throw new IllegalAdminCommandException(usageText);	       
	    }	
        try {            
        	//InitialContext jndicontext = new InitialContext();
        	InitialContext jndicontext = getInitialContext();
        	
        	Properties props = new Properties();
        	props.load(new FileInputStream(args[1]));
        	
        	boolean force = false;
        	if(args.length == 3){
        		force = args[2].equalsIgnoreCase("-force");
        		if(!force){
        			throw new IllegalAdminCommandException(usageText);
        		}
        	}
        	
        	IHardTokenSessionHome sessionhome = (IHardTokenSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("HardTokenSession"),
        			IHardTokenSessionHome.class);
        	
        	IHardTokenSessionRemote session = sessionhome.create();
        	
        	// Read the significat issuer dn and check that it exists
        	if(props.getProperty("significantissuerdn") == null){
        		throw new IllegalAdminCommandException("Error, the property significantissuerdn isn't set in the propertyfile " + args[1]);
        	}
        	
        	String significantIssuerDN = props.getProperty("significantissuerdn");
        	int cAId = significantIssuerDN.hashCode();
        	if(getCAAdminSessionRemote().getCAInfo(administrator, cAId) == null){
        		throw new IllegalAdminCommandException("Error, the property significantissuerdn '" + significantIssuerDN +  "' doesn't exists as CA in the system.");
        	}
        	
        	// Create the importer
        	if(props.getProperty("importer.classpath") == null){
        		throw new IllegalAdminCommandException("Error, the property importer.classpath isn't set in the propertyfile " + args[1]);
        	}
        	
        	IHardTokenImporter importer =  (IHardTokenImporter) this.getClass().getClassLoader().loadClass(props.getProperty("importer.classpath")).newInstance();
        	importer.startImport(props);
        	HardTokenData htd;
        	try{
        	  while((htd = importer.readHardTokenData()) != null){
        		  try{
        	         session.addHardToken(administrator, htd.getTokenSN(), htd.getUsername(), significantIssuerDN, htd.getTokenType(), htd.getHardToken(), null, htd.getCopyOf());
        	         getOutputStream().println("Info: Token with SN " + htd.getTokenSN() + " were added to the database.");
        		  }catch(HardTokenExistsException e){
        			  if(force){
        				  session.removeHardToken(administrator, htd.getTokenSN());
        				  session.addHardToken(administrator, htd.getTokenSN(), htd.getUsername(), significantIssuerDN, htd.getTokenType(), htd.getHardToken(), null, htd.getCopyOf());
        				  getOutputStream().println("Info: Token with SN " + htd.getTokenSN() + " already existed in the database but was OVERWRITTEN.");        				  
        			  }else{
        				  getOutputStream().println("Error: Token with SN " + htd.getTokenSN() + " already exists in the database and is NOT imported.");
        			  }
        		  }
        	  }
        	}finally{
        		  importer.endImport();
        	}
        	
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

    // execute
}

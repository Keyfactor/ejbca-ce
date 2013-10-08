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
import java.util.List;
import java.util.Properties;

import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.ui.cli.BaseCommand;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.ui.cli.hardtoken.importer.IHardTokenImporter;
import org.ejbca.util.CliTools;

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
public class ImportDataCommand extends BaseCommand {

	public String getMainCommand() { return "hardtoken"; }
	public String getSubCommand() { return "importdata"; }
	public String getDescription() { return "Used to import hard token data from a source"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
		// Get and remove switches
		List<String> argsList = CliTools.getAsModifyableList(args);
		boolean force = argsList.remove("-force");
		args = argsList.toArray(new String[argsList.size()]);
		// Parse the rest of the arguments
        if (args.length < 2 || args.length > 3) {
    		getLogger().info("Description: " + getDescription());
        	getLogger().info("Usage: " + getCommand() + " <propertyfile> -force");
        	getLogger().info("Example: hardtoken importdata tokenimport.properties -force");
        	getLogger().info(" -force   indicates that existing hard token info will be overwritten.");
        	return;	       
	    }	
        try {            
        	Properties props = new Properties();
        	props.load(new FileInputStream(args[1]));
        	// Read the significant issuer dn and check that it exists
        	if(props.getProperty("significantissuerdn") == null){
        		throw new IllegalAdminCommandException("Error, the property significantissuerdn isn't set in the propertyfile " + args[1]);
        	}
        	String significantIssuerDN = props.getProperty("significantissuerdn");
        	int cAId = significantIssuerDN.hashCode();
        	try {
        	    EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAdmin(cliUserName, cliPassword), cAId);
        	}catch (CADoesntExistsException e) {
        		throw new IllegalAdminCommandException("Error, the property significantissuerdn '" + significantIssuerDN +  "' does not exist as CA in the system.");
        	}
        	// Create the importer
        	if(props.getProperty("importer.classpath") == null){
        		throw new IllegalAdminCommandException("Error, the property importer.classpath isn't set in the propertyfile " + args[1]);
        	}
        	IHardTokenImporter importer =  (IHardTokenImporter) Thread.currentThread().getContextClassLoader().loadClass(props.getProperty("importer.classpath")).newInstance();
        	importer.startImport(props);
        	HardTokenInformation htd;
        	try{
        	  while((htd = importer.readHardTokenData()) != null){
        		  try{
        	         ejb.getRemoteSession(HardTokenSessionRemote.class).addHardToken(getAdmin(cliUserName, cliPassword), htd.getTokenSN(), htd.getUsername(), significantIssuerDN, htd.getTokenType(), htd.getHardToken(), null, htd.getCopyOf());
        	         getLogger().info("Token with SN " + htd.getTokenSN() + " were added to the database.");
        		  }catch(HardTokenExistsException e){
        			  if(force){
        			      ejb.getRemoteSession(HardTokenSessionRemote.class).removeHardToken(getAdmin(cliUserName, cliPassword), htd.getTokenSN());
        			      ejb.getRemoteSession(HardTokenSessionRemote.class).addHardToken(getAdmin(cliUserName, cliPassword), htd.getTokenSN(), htd.getUsername(), significantIssuerDN, htd.getTokenType(), htd.getHardToken(), null, htd.getCopyOf());
        				  getLogger().info("Token with SN " + htd.getTokenSN() + " already existed in the database but was OVERWRITTEN.");        				  
        			  }else{
        				  getLogger().error("Token with SN " + htd.getTokenSN() + " already exists in the database and is NOT imported.");
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
    
    @Override
    public String[] getMainCommandAliases() {
        return new String[]{};
    }
}

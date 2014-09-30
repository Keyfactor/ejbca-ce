/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.cli.hardtoken.importer;

import java.io.IOException;
import java.util.Date;
import java.util.Properties;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;

/**
 * The standard file hard token importer, reading the a textfile line by line.
 * 
 * The Importer have the following properties:
 * separator   : indicates which column separator that should be used.
 * 
 * columnorder : A list of columnnames separated by ',' of how the columns
 * are ordered. Valid values are 'tokensn', 'pin1', 'pin2', 'bothpin', 'puk1', 'puk2', 'bothpuk'
 * Example the line: 'columnorder=tokensn, pin1, pin2, bothpuk' will generate a
 * hardtokendata with the tokensn from first column, basicpin from the secondcolumn, 
 * signaturepin from third and finally both puk codes from the forth column.
 * 
 * tokentype : either 'enhancedeid' or 'swedisheid'. And indicates what type of token that will be created.
 * 
 * import.properties:
 * <pre>
 * importer.classpath=org.ejbca.ui.cli.hardtoken.importer.StandardFileHardTokenImporter
 * significantissuerdn=CN=LunaCA
 * file=hardtoken.txt
 * separator=,
 * columnorder=tokensn, pin1, pin2, bothpuk
 * tokentype=swedisheid
 * </pre>
 * hardtoken.txt
 * <pre>
 * 123456789,1234,5678,123456
 * 234567890,4321,9876,987654
 * </pre>
 * 
 * @author Philip Vendil 2007 apr 23
 *
 * @version $Id$
 */

public class StandardFileHardTokenImporter extends FileReadHardTokenImporter {

	public static final String PROPERTY_SEPARATOR   = "separator";
	public static final String PROPERTY_COLUMNORDER = "columnorder";
	public static final String PROPERTY_TOKENTYPE   = "tokentype";
	
	private static final int COLUMN_TOKENSN = 1;
	private static final int COLUMN_PIN1    = 2;
	private static final int COLUMN_PIN2    = 3;
	private static final int COLUMN_BOTHPIN = 4;
	private static final int COLUMN_PUK1    = 5;
	private static final int COLUMN_PUK2    = 6;
	private static final int COLUMN_BOTHPUK = 7;
	
	private String columnSeparator;
	private int[] columns = null;
	private String hardTokenType = null;
	
	public void startImport(Properties props) throws IOException {		
		super.startImport(props);		
		
		getColumns(props);
		
		if(props.getProperty(PROPERTY_SEPARATOR) == null){
			throw new IOException("Error property " + PROPERTY_SEPARATOR + " not set.");
		}
		columnSeparator = props.getProperty(PROPERTY_SEPARATOR);
		
		if(props.getProperty(PROPERTY_TOKENTYPE) == null){
			throw new IOException("Error property " + PROPERTY_TOKENTYPE + " not set.");
		}		
		hardTokenType = props.getProperty(PROPERTY_TOKENTYPE);
		if(!hardTokenType.equalsIgnoreCase("enhancedeid") && !hardTokenType.equalsIgnoreCase("swedisheid")){
			throw new IOException("Error property " + PROPERTY_TOKENTYPE + " must have either the value 'enhancedeid' or 'swedisheid'.");
		}
	}

	private void getColumns(Properties props) throws IOException{
		if(props.getProperty("columnorder") == null){
			throw new IOException("Error the required property 'columnorder' isn't set.");
		}
		
		String[] c = props.getProperty(PROPERTY_COLUMNORDER).split(",");
		columns = new int[c.length];
		for(int i=0;i<c.length;i++){
			columns[i] = getColumn(c[i].trim());
		}
		
	}

	private int getColumn(String column) throws IOException {
		if(column.equalsIgnoreCase("tokensn")){
			return COLUMN_TOKENSN;
		}
		if(column.equalsIgnoreCase("pin1")){
			return COLUMN_PIN1;
		}
		if(column.equalsIgnoreCase("pin2")){
			return COLUMN_PIN2;
		}
		if(column.equalsIgnoreCase("bothpin")){
			return COLUMN_BOTHPIN;
		}
		if(column.equalsIgnoreCase("puk1")){
			return COLUMN_PUK1;
		}
		if(column.equalsIgnoreCase("puk2")){
			return COLUMN_PUK2;
		}
		if(column.equalsIgnoreCase("bothpuk")){
			return COLUMN_BOTHPUK;
		}
		throw new IOException("Error illegal column " + column + " in the " + PROPERTY_COLUMNORDER + " property.");
	}

	/**
	 * @see org.ejbca.ui.cli.hardtoken.importer.FileReadHardTokenImporter#readHardTokenData()
	 */
	public HardTokenInformation readHardTokenData() throws IOException {
		HardTokenInformation retval = null;
		
		
		String line = bufferedReader.readLine();
		if(line != null){
			String basicPIN = "";
			String signaturePIN = "";
			String basicPUK = "";
			String signaturePUK = "";
			String tokenSN = "";
			
			
			String[] lineColumns = line.split(columnSeparator);
			for(int i=0;i < lineColumns.length;i++){
				lineColumns[i] = lineColumns[i].trim();
				switch(columns[i]){
				case COLUMN_TOKENSN :
					tokenSN = lineColumns[i];
					break;
				case COLUMN_PIN1 :
					basicPIN = lineColumns[i];
					break;
				case COLUMN_PIN2 :
					signaturePIN = lineColumns[i];
					break;
				case COLUMN_BOTHPIN :
					basicPIN = lineColumns[i];
					signaturePIN = lineColumns[i];
					break;
				case COLUMN_PUK1:
					basicPUK = lineColumns[i];
					break;
				case COLUMN_PUK2 :
					signaturePUK = lineColumns[i];
					break;		
				case COLUMN_BOTHPUK :
					basicPUK = lineColumns[i];
					signaturePUK = lineColumns[i];
					break;		
				default:
					throw new IOException("Error reading column + " + i + " of hard token import data.");
				}
			}
			int tokenType = SecConst.TOKEN_SWEDISHEID;
			if(hardTokenType.equalsIgnoreCase("enhancedeid")){
				tokenType = SecConst.TOKEN_ENHANCEDEID;				
			}
			HardToken ht = getHardTokenType(basicPIN, basicPUK, signaturePIN, signaturePUK);
			retval = new HardTokenInformation(tokenSN,null,new Date(),new Date(), tokenType,null, ht,null,null);
		}
		
		
		return retval;
	}
	
	
	private HardToken getHardTokenType(String basicPIN, String basicPUK, String signaturePIN, String signaturePUK){
		if(hardTokenType.equalsIgnoreCase("enhancedeid")){
			return new EnhancedEIDHardToken(signaturePIN,signaturePUK,basicPIN,basicPUK,false,0);
		}
		return new SwedishEIDHardToken(basicPIN,basicPUK,signaturePIN,signaturePUK,0);
	}

}

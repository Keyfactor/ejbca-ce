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
 
package org.ejbca.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * JAX-WS Support.
 * Utility for supporting JavaDoc creation of JAX-WS objects as well
 * as supporting an option for securely reusing server-objects on the client
 * to achieve a more uniform system.
 * @author Anders Rundgren
 * @version $Id$ 
 */
public class JAXWSDocAndConvTools {

	CompilationUnit server;
	CompilationUnit client;

	enum Types {
		COMMENT,IDENTIFIER, SEMICOLON, STRING, CHARLITERAL, COMMA, NUMBER, LEFTPAR, RIGHTPAR, LEFTBRACK, RIGHTBRACK, 
		LEFTARRAY, RIGHTARRAY, BINOP, EQUALOP, LEFTCURL, RIGHTCURL;
	}
	  
	class Token {
		 int start = c_start;
		 int stop = c_index;
		 Types type;

		 Token (Types type){
			 this.type = type;
			 curr = this;
		 }

		 Types getType () {return type;}
		 
		 String getText (){
			 return lines.substring(start, stop);
		 }
		 
		 boolean equals (String value){
			 return value.equals(getText ());
		 }
	}
	
	class Method{
		String java_doc;
		String method_name;
		String return_type;
		List<String> declarators = new ArrayList<String> ();
		List<String> argument_names = new ArrayList<String> ();
		List<String> exceptions = new ArrayList<String> ();
		String signature (){
			final StringBuilder sig = new StringBuilder();
			sig.append(method_name).append(':').append(return_type);
			for (String decl : declarators){
				sig.append('/').append(decl);
			}
			return sig.toString();
		}
	}
	
	class CompilationUnit{
		String package_name;
		String class_name;
		String class_java_doc;
		List<String> imports = new ArrayList<String> ();
		LinkedHashMap<String,String> exceptions = new LinkedHashMap<String,String> ();
		LinkedHashMap<String,Method> methods = new LinkedHashMap<String,Method> ();
		
	}
	int c_index;
	int c_start;
	StringBuilder lines;
	boolean ws_gen;
	Token curr;
	
	void bad (String error) throws Exception{
		throw new Exception (error);
	}
	
	  
    Token scan () throws Exception{
    	while (true){
    		if (c_index >= lines.length()){
    			return null;
    		}
    			
        	c_start = c_index;
        	int c = lines.charAt(c_index++);
        	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'){
        		while (((c =lines.charAt(c_index)) >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.'){
        			c_index++;
        		}
        		return new Token (Types.IDENTIFIER);
        	}
        	if (c == '@'){
        		if (scan ().getType() != Types.IDENTIFIER){
        			bad ("@ should be followed by an identifier");
        		}
        		Token nxt = scan ();
        		if (nxt.getType () == Types.LEFTPAR){
        			while (scan ().getType () != Types.RIGHTPAR) {} // NOPMD, just loop through
            		continue;
        		}
        		return nxt;
        	}
        	if (c == '/'){
        		if (lines.charAt(c_index) == '*'){
        			c_index++;
        			while (true){
            			if (lines.charAt(c_index++) == '*'){
            				if (lines.charAt(c_index) == '/'){
            					c_index++;
            					return new Token (Types.COMMENT);
            				}
            			}
        			}
        		}
        		if (lines.charAt(c_index) == '/'){
        			c_index++;
        			while (lines.charAt(c_index++) != '\n') { // NOPMD, just loop through
        			}
        			continue;
        		}
        	}
        	if (c <= ' '){
        		continue;
        	}

        	if (c == ';'){
        		return new Token (Types.SEMICOLON);
        	}

        	if (c == '('){
        		return new Token (Types.LEFTPAR);
        	}
        	if (c == ')'){
        		return new Token (Types.RIGHTPAR);
        	}
        	if (c == '['){
        		return new Token (Types.LEFTARRAY);
        	}
        	if (c == ']'){
        		return new Token (Types.RIGHTARRAY);
        	}
        	if (c == '<'){
        		return new Token (Types.LEFTBRACK);
        	}
        	if (c == '>'){
        		return new Token (Types.RIGHTBRACK);
        	}
        	if (c == '{'){
        		return new Token (Types.LEFTCURL);
        	}
        	if (c == '}'){
        		return new Token (Types.RIGHTCURL);
        	}
        	if (c == ','){
        		return new Token (Types.COMMA);
        	}
        	if (c == '&'){
        		if (lines.charAt(c_index) == '&'){
        			c_index++;
        		}
        		return new Token (Types.BINOP);
        	}
        	if (c == '|'){
        		if (lines.charAt(c_index) == '|'){
        			c_index++;
        		}
        		return new Token (Types.BINOP);
        	}
        	if (c == '.' || c == '!' || c == '~' || c == '?' || c == ':'){
        		return new Token (Types.BINOP);
        	}
        	if (c == '='){
        		if ((c = lines.charAt(c_index)) == '='){
        			c_index++;
            		return new Token (Types.BINOP);
        		}
        		return new Token (Types.EQUALOP);
        	}
        	if (c == '+' || c == '-' || c == '*' || c== '%' || c == '&' || c == '|' || c == '^'){
        		if ((c = lines.charAt(c_index)) == '='){
        			c_index++;
        		}
        		return new Token (Types.BINOP);
        	}
        	if (c >= '0' && c <= '9'){
        		while (((c = lines.charAt(c_index)) >= '0' && c <= '9') || c == 'x' || c == 'l' || c == 'X' || c == 'L'){
        			c_index++;
        		}
        		return new Token (Types.NUMBER);
        	}
        	if (c == '"'){
        		while ((c = lines.charAt(c_index++)) != '"'){
        			if (c == '\\'){
        				c_index++;
        			}
        		}
        		return new Token (Types.STRING);
        	}
        	if (c == '\''){
        		while ((c = lines.charAt(c_index++)) != '\''){
        			if (c == '\\'){
        				c_index++;
        			}
        		}
        		return new Token (Types.CHARLITERAL);
        	}
        	bad ("Parser did not get it: " + (char) c);
    	}
    		
    }
    

    void readSemicolon () throws Exception{
    	if (scan ().getType () != Types.SEMICOLON) {
    		bad ("Semicolon expected");
    	}
    }

    Token removeModifiers (Token start) throws Exception{
		boolean changed = false;
		do{
	    	changed = false;
	     	if (start.equals("public")){
	     		start = scan ();
	     		changed = true;
	     	}
	    	if (start.equals("static")){
	    		start = scan ();
	    		changed = true;
	    	}
	        if (start.equals("final")){
	        	start = scan ();
	        	changed = true;
	    	}
	        if (start.equals("abstract")){
	        	start = scan ();
	        	changed = true;
	    	}
		}while (changed);
		if (start.getType () != Types.IDENTIFIER) {
			bad ("Identifier expected:" + start.getType ());
		}
		return start;
    }

    
    boolean isInterfaceOrClass (Token token){
    	return token.equals("class") || token.equals("interface");
    }

    void implementsOrExtends (Token token) throws Exception{
    	if (!token.equals("implements") && !token.equals("extends")) {
    		bad ("Expected implements/extend");
    	}
    }
    
    void checkSource () throws Exception{
    	if (ws_gen) {
    		bad ("Unexpected element for generated file:" + curr.getText());
    	}
    }
    
    Token nameList (Token id) throws Exception{
    	while (true){
    		if (id.getType() != Types.IDENTIFIER) {
    			bad ("Missing identifier in extend/impl");
    		}
    		Token nxt = scan ();
    		if (nxt.getType () != Types.COMMA) {
    			return nxt;
    		}
    		id = scan ();
    	}
    }
    
    String getTypeDeclaration (Token start) throws Exception{
    	final StringBuilder type_decl = new StringBuilder();
    	type_decl.append(start.getText());
    	Token nxt = scan ();
    	if (nxt.getType() == Types.LEFTBRACK){
    		do{
       			type_decl.append(nxt.getText());
    			if (scan ().getType() != Types.IDENTIFIER) {
    				bad ("Missing <ID");
    			}
       			type_decl.append(getTypeDeclaration (curr));
    		}
    		while ((nxt = curr).getType() == Types.COMMA);
    	    if (nxt.getType() != Types.RIGHTBRACK) {
    	    	bad ("> expected");
    	    }
   			type_decl.append(nxt.getText());
   	    	scan ();
    	}
    	if (nxt.getType () == Types.LEFTARRAY){
    		boolean byte_array = type_decl.toString ().equals("byte");
    		if (ws_gen && !byte_array) {
    			bad ("did not expect [] in WS-gen");
    		}
    		while ((nxt = scan()).getType() != Types.RIGHTARRAY) { // NOPMD, just loop through
    		}
    		if (byte_array) {
    			type_decl.append("[]");
    		} else{
        		type_decl.insert(0, "List<").append('>');
    		}
   			scan ();
    	}
    	return type_decl.toString();
    }
    
    void decodeDeclaration (Token start, CompilationUnit compilation) throws Exception{
    	start = removeModifiers (start);
    	if (!isInterfaceOrClass (start)) {
    		bad ("Expected class/interface declaration");
    	}
		Token id;
		if ((id = scan ()).getType() != Types.IDENTIFIER) {
			bad ("class/interface identifier missing");
		}
		compilation.class_name = id.getText();
//		System.out.println ("Class:" + id.getText());
		Token nxt;
		if ((nxt = scan()).getType() == Types.IDENTIFIER){
			checkSource ();
			implementsOrExtends (nxt);
			nxt = nameList(scan ());
		}
		if (nxt.getType() != Types.LEFTCURL) {
			bad ("Missing {");
		}
		String jdoc = null;
		while (true){
			nxt = scan ();
			if (nxt.getType () == Types.RIGHTCURL){
				break;
			} else if (nxt.getType () == Types.COMMENT){
				jdoc = nxt.getText();
//				System.out.println ("Comment");
			} else {
				nxt = removeModifiers (nxt);
				if (isInterfaceOrClass (nxt)) {
					bad ("Nested classes not implemented yet");
				}
				String return_type = null;
				String method_name = null;
				if (compilation.class_name.equals (nxt.getText())){
					return_type = "";
					method_name = nxt.getText();
				}else{
					return_type = getTypeDeclaration (nxt);
					method_name = curr.getText();
				}
				scan ();
				if (curr.getType() == Types.LEFTPAR){
//					System.out.println ("Return type: '" + return_type + "' method: '" + method_name + "'");
					Method method = new Method ();
					method.return_type = return_type;
					method.method_name = method_name;
					method.java_doc = jdoc;
					scan ();
					do{
						if (curr.getType () == Types.IDENTIFIER){
							String arg_type = getTypeDeclaration (curr);
//							System.out.println ("Argtype:" + arg_type);
//							System.out.println ("Argname:" + 	curr.getText ());
							method.declarators.add (arg_type);
							method.argument_names.add (curr.getText());
							if (scan ().getType() == Types.COMMA){
								scan ();
							}
						}
					}while (curr.getType () != Types.RIGHTPAR);
					scan ();
					if (curr.equals ("throws")){
						while (true){
							scan ();
							if (curr.getType() != Types.IDENTIFIER) {
								bad ("exception id missing");
							}
							compilation.exceptions.put(curr.getText(), "YES");
							method.exceptions.add(curr.getText());
							if (scan ().getType () != Types.COMMA) {
								break;
							}
						}
					}
					if (compilation.methods.put(method.signature (), method) != null) {
						bad ("Collision");
					}
//					bad ("Done");
				}
				while (curr.getType() != Types.SEMICOLON && curr.getType() != Types.LEFTCURL){
					scan ();
				}
				jdoc = null;
				if (curr.getType() == Types.LEFTCURL){
					int i = 0;
					while (true){
						scan ();
						if (curr.getType () == Types.LEFTCURL){
							i++;
						}
						if (curr.getType() == Types.RIGHTCURL){
							if (i-- == 0){
								break;
							}
						}
					}
					
				}
			}
		}
    }
    
	
    CompilationUnit parse(String file_name) throws Exception {
        System.out.println("File to parse: " + file_name);
        CompilationUnit compilation = new CompilationUnit();
        lines = new StringBuilder();
        BufferedReader in = new BufferedReader(new FileReader(file_name));
        try {
            String line;
            while ((line = in.readLine()) != null) {
                lines.append(line).append('\n');
            }
        } finally {
            in.close();
        }
        c_index = 0;
        curr = null;
        boolean packfound = false;
        String class_jdoc = null;
        while (scan() != null) {
            switch (curr.getType()) {
            case COMMENT:
                class_jdoc = curr.getText();
                break;

            case IDENTIFIER:
                if (packfound) {
                    if (curr.equals("import")) {
                        Token imp = scan();
                        if (imp.getType() != Types.IDENTIFIER) {
                            bad("Misformed import");
                        }
                        readSemicolon();
                        compilation.imports.add(imp.getText());
                        class_jdoc = null;
                    } else {
                        compilation.class_java_doc = class_jdoc;
                        decodeDeclaration(curr, compilation);
                    }
                } else {
                    if (!curr.equals("package")) {
                        bad("No package key-word found");
                    }
                    Token pack = scan();
                    if (pack.getType() != Types.IDENTIFIER) {
                        bad("Package missing");
                    }
                    compilation.package_name = pack.getText();
                    readSemicolon();
                    packfound = true;
                    class_jdoc = null;
                }
                break;
            default:
                break;
            }
        }
        return compilation;
    }

	void generateJDocFriendlyFile(String gen_directory) throws Exception{
		
/*
		for (String s : client.methods.keySet()){
			System.out.print ("method=" + (server.methods.get(s) == null) + "=" + s + "\nthrows:");
			for (String e : client.methods.get(s).exceptions){
				System.out.print(" " + e);
			}
			System.out.println ();
		}
*/
		final StringBuilder ofile = new StringBuilder();
		ofile.append(gen_directory).append("/");
		for (int i = 0; i < client.package_name.length (); i++){
			if (client.package_name.charAt(i) == '.'){
				ofile.append('/');
			} else {
				ofile.append(client.package_name.charAt(i));
			}
		}
		String outPath = ofile.toString ();
		String[] cf = new File (outPath).list();
		for (String f : cf){
			if (f.toUpperCase().endsWith("EXCEPTION.JAVA")){
				if (client.exceptions.get (f.substring (0, f.length () - 5)) == null){
	/*
					if (!new File (outPath + "/" + f).delete()){
						bad ("Couldn't delete " + f);
					}
	*/
				}
			}
		}
		ofile.append('/').append(client.class_name).append(".java");
//		System.out.println ("f=" + ofile.toString());
		FileWriter out = new FileWriter (ofile.toString());
		out.write ("package " + client.package_name + ";\n\n");
		for (String imp : client.imports){
			out.write("import " + imp + ";\n");
		}
		if (server.class_java_doc != null){
			out.write("\n" + server.class_java_doc);
		}
		out.write("\npublic interface " + client.class_name + "\n{\n");
		for (String s : client.methods.keySet()){
			Method client_method = client.methods.get(s);
			for (String f : cf){
				if (f.equalsIgnoreCase(client_method.method_name + ".java") ||
					f.equalsIgnoreCase(client_method.method_name + "response.java")){
					if (!new File (outPath + "/" + f).delete()){
						bad ("Couldn't delete:" + f);
					}
				}
			}
			String jdoc = server.methods.get(s).java_doc;
			if (jdoc == null) { 
				bad ("missing javadoc for " + s);
			}
			for (String e : client_method.exceptions){
			    int i = jdoc.indexOf("@throws " + e.substring(0, e.length () - 10));
			    if (i > 0) {
			    	jdoc = jdoc.substring (0, i) + "@throws " + e + jdoc.substring(i + e.length () - 2);
			    } else {
			    	bad("You need to declare @throws for '" + e.substring(0, e.length () - 10) + "' in method:" + client_method.method_name);
			    }
			}
			out.write("\n" + jdoc + "\n");
			out.write(" public " + client_method.return_type + " " + client_method.method_name + "(");
			boolean comma = false;
			List<String> arg_names = server.methods.get(s).argument_names;
			int q = 0;
			for (String arg : client_method.declarators){
				if (comma){
					out.write(", ");
				}
				comma = true;
				out.write(arg + " " + arg_names.get(q++));
			}
			out.write(")");
			if (!client_method.exceptions.isEmpty()){
				out.write(" throws ");
				comma = false;
				for (String e : client_method.exceptions){
					if (comma){
						out.write(", ");
					}
					comma = true;
					out.write(e);
				}
				
			}
			out.write(";\n");
		}
		out.write("}\n");
		out.close();
	}

	
	void compareGeneratedWithWritten () throws Exception{
	    for (String s : client.methods.keySet()){
	    	Method m = server.methods.get(s);
	    	if (m == null){
	    	    for (String o : server.methods.keySet()){
	    	    	System.out.println (server.methods.get(o).signature());
	    	    }
	    		bad ("Method mismatch: " + s);
	    	}
	    	
		}
	}
	
	JAXWSDocAndConvTools (String server_interface, String client_interface, String gen_directory) throws Exception {
		server = parse (server_interface);
		ws_gen = (gen_directory != null);
		client = parse (client_interface);
		if (gen_directory == null) {
			compareGeneratedWithWritten ();
		} else {
			generateJDocFriendlyFile (gen_directory);
		}
		
	}
	  
	static public void main (String[] args) throws Exception{
		if (args.length != 3 && args.length != 2){
			System.out.println (JAXWSDocAndConvTools.class.getName() + " WS-server-interface-file  WS-generated-client-interface-file jdoc-\"gen\"-dir\n" +
					            JAXWSDocAndConvTools.class.getName() + " WS-hand-written-file WS-generated-file\n\n" +
					            "Generate JDoc\nCompare Declarations\n");
			System.exit(2); // NOPMD this is a cli command
		}
		new JAXWSDocAndConvTools (args[0], args[1], args.length == 3 ? args[2] : null);
	}

}

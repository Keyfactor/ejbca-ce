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

package org.ejbca.ui.cli;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.cesecore.util.CertTools;

/**
 * <p>Various tools aimed for Professional Services at PrimeKey.
 *
 * <p><b>CaId Module Module</b>
 * <p>Generates CA IDs which can be used with Statedump.
 *
 * <p><b>PasswordGenerator Module</b>
 * <p>Implements a cryptographically secure password generator. Runs as a
 * command line client which may ask for the following parameters (if specified)
 *
 *      Flag    Description                              Default
 *      -h      Hash function used for mixing            SHA-256
 *      -c      Charset used for the generated password  [a-zA-Z0-9]
 *      -b      Length of the password in bits           128
 *      -s      User input to mix into the password      null
 *
 * @version $Id$
 */
public class ProfessionalServices extends ClientToolBox {
    private static final SecureRandom secureRandom = new SecureRandom();

    @Override
    protected void execute(final String[] args) {
        final List<String> argsList = new ArrayList<String>(Arrays.asList(args));
        argsList.remove(getName());
        if (argsList.isEmpty() || argsList.get(0).equals("help")) {
            System.out.println("Available modules");
            System.out.println("PasswordGenerator - Generate cryptographically strong passwords");
            System.out.println("CaIdGenerator     - Generate CA IDs for Statedump");
            return;
        }
        if (argsList.contains("PasswordGenerator")) {
            argsList.remove("PasswordGenerator");
            executePasswordModule(argsList);
        } else if (argsList.contains("CaIdGenerator")) {
            argsList.remove("CaIdGenerator");
            executeCaIdModule(argsList);
        } else {
            System.out.println(String.format("Unknown module %s. Type 'help' to list all available modules.", argsList.get(0)));
        }
    }

    private void executeCaIdModule(final List<String> args) {
        if (args.contains("help") || args.isEmpty()) {
            System.out.println("Usage: CaIdGenerator <SubjectDN>");
            return;
        }
        if (args.size() > 1) {
            System.out.println("Too many arguments. Type 'help' for more information.");
            return;
        }
        final int id = CertTools.stringToBCDNString(args.get(0)).hashCode();
        System.out.println(id);
    }

    private void executePasswordModule(final List<String> args) {
        if (args.contains("help")) {
            System.out.println("Flag    Description                              Default");
            System.out.println("-h      Hash function used for mixing            SHA-256");
            System.out.println("-c      Charset used for the generated password  [a-zA-Z0-9]");
            System.out.println("-b      Length of the password in bits           128");
            System.out.println("-s      User input to mix into the password      null");
            return;
        }

        try {
            final String algorithm = readInput(args, "Algorithm [SHA-256]", "-h", "SHA-256");
            final String charset = expandRegex(readInput(args, "Charset [a-zA-Z0-9]", "-c", "[a-zA-Z0-9]"));
            final int passwordBits = Integer.valueOf(readInput(args, "Bit strength [128]", "-b", "128"));
            final String seed = readInput(args, "Seed [null]", "-s", "");

            if (charset.length() < 2) {
                System.err.println("Charset must consist of at least 2 characters.");
                return;
            }

            byte[] state = new byte[256];
            secureRandom.nextBytes(state);
            state = mix(algorithm, state, seed.getBytes("UTF-8"));
            final int charCount = (int) Math.ceil((passwordBits * Math.log(2)) / Math.log(charset.length()));
            final StringBuilder password = new StringBuilder();
            for (int i = 0; i < charCount; ++i) {
                state = mix(algorithm, state, state);
                final int p = new BigInteger(1, state).mod(BigInteger.valueOf(charset.length())).intValue();
                password.append(charset.charAt(p));
            }
            System.out.println(password.toString());
        } catch (final NumberFormatException e) {
            System.err.println(e.getMessage());
        } catch (final UnsupportedEncodingException e) {
            System.err.println(e.getMessage());
        } catch (final NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        } catch (final IllegalStateException e) {
            System.err.println("Bye!");
            return;
        }
    }

    private String readInput(final List<String> args, final String title, final String flag, final String defaultValue) throws IllegalStateException {
        if (args.contains(flag)) {
            System.out.print(title + ": ");
            System.out.flush();
            final String input = System.console().readLine();
            if (input == null) {
                throw new IllegalStateException();
            }
            if (input.length() > 0) {
                return input;
            }
        }
        return defaultValue;
    }

    private byte[] mix(final String algorithm, final byte[] b1, final byte[] b2) throws NoSuchAlgorithmException {
        final byte[] b = new byte[b1.length + b2.length];
        for (int i = 0; i < b1.length; ++i) {
            b[i] = b1[i];
        }
        for (int i = 0; i < b2.length; ++i) {
            b[b1.length + i] = b2[i];
        }
        return MessageDigest.getInstance(algorithm).digest(b);
    }

    String expandRegex(final String regex) {
        final StringBuilder charset = new StringBuilder();
        final Pattern pattern = Pattern.compile(regex);
        for (int i = 0; i < 256; ++i) {
            if (pattern.matcher(Character.toString((char) i)).matches()) {
                charset.append((char) i);
            }
        }
        return charset.toString();
    }

    @Override
    protected String getName() {
        return "ProfessionalServices";
    }
}

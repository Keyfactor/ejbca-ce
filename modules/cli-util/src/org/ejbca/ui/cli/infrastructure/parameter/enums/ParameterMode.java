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
package org.ejbca.ui.cli.infrastructure.parameter.enums;

/**
 * This enum declares the four types of CLI inputs possible. These are:
 *      ARGUMENT
 *          A switch and an associated value following that switch. The switch should never be alone, but the value may be if the parameter is 
 *          declared standalone.
 *      FLAG
 *          A switch without a following input value, such as --verbose
 *      INPUT
 *          Like an argument, but the value is expected to be prompted instead of read from the command line.
 *      PASSWORD
 *          Like INPUT, but the input is never echoed on the screen. 
 * 
 * @version $Id$
 *
 */
public enum ParameterMode {
    ARGUMENT, FLAG, INPUT, PASSWORD;
    
}

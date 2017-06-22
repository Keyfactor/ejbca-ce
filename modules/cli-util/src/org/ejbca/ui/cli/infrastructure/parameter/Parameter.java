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
package org.ejbca.ui.cli.infrastructure.parameter;

import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Wrapper class for a command parameter
 * 
 * @version $Id$
 *
 */
public class Parameter {

    private final String keyWord;
    private final StandaloneMode allowStandAlone;
    private final ParameterMode parameterMode;
    private final MandatoryMode mandatoryMode;
    private final String instruction;
    private final String name;
    //Uncommon value set as false if this Parameter shouldn't be listed as part of the man page.
    private boolean allowList = true;

    /**
     * Constructor for defining a parameter
     * 
     * @param keyWord The keyword used to identify this parameter. Commonly prefixed with a dash ('-')
     * @param name What this parameter denotes. Used for documentation purposes.
     * @param mandatoryMode Defines whether this parameter is mandatory or not. 
     * @param allowStandAlone true if this parameter can be inputed without its keyword. 
     * @param parameterMode the type of parameter, if it requires an argument, if it's a flag, or a password etc
     */
    public Parameter(String keyWord, String name, MandatoryMode mandatoryMode, StandaloneMode allowStandAlone, ParameterMode parameterMode,
            String instruction) {
        //Perform validation
        if (allowStandAlone.equals(StandaloneMode.ALLOW) && !parameterMode.equals(ParameterMode.ARGUMENT)) {
            throw new IllegalStateException("A non argument parameter can not be set to standalone.");
        }
        this.keyWord = keyWord;
        this.allowStandAlone = allowStandAlone;
        this.parameterMode = parameterMode;
        this.mandatoryMode = mandatoryMode;
        this.instruction = instruction;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public boolean isMandatory() {
        return mandatoryMode.isMandatory();
    }
    
    public boolean isStandAlone() {
        return allowStandAlone.isStandAlone();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((keyWord == null) ? 0 : keyWord.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Parameter other = (Parameter) obj;
        if (keyWord == null) {
            if (other.keyWord != null)
                return false;
        } else if (!keyWord.equals(other.keyWord))
            return false;
        return true;
    }

    public ParameterMode getParameterMode() {
        return parameterMode;
    }

    public StandaloneMode allowStandAlone() {
        return allowStandAlone;
    }

    /**
     * @return the keyWord
     */
    public String getKeyWord() {
        return keyWord;
    }

    public String getInstruction() {
        return instruction;
    }
    
    /**
     * Quick factory method for creating flags.
     * 
     */
    public static Parameter createFlag(String keyWord, String instruction) {
        return new Parameter(keyWord, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG, instruction);
    }

    public boolean allowList() {
        return allowList;
    }

    public void setAllowList(boolean allowList) {
        this.allowList = allowList;
    }
}

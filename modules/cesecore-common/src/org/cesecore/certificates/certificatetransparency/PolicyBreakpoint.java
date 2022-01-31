package org.cesecore.certificates.certificatetransparency;

import java.io.Serializable;

public class PolicyBreakpoint implements Serializable {
    private static final long serialVersionUID = 9339L;

    private int moreThan;
    private int lessThan;
    private int minSct;

    public PolicyBreakpoint(int moreThan, int lessThan, int minSct) {
        this.moreThan = moreThan;
        this.lessThan = lessThan;
        this.minSct = minSct;
    }

    public int getMoreThan() {
        return moreThan;
    }

    public void setMoreThan(int moreThan) {
        this.moreThan = moreThan;
    }

    public int getLessThan() {
        return lessThan;
    }

    public void setLessThan(int lessThan) {
        this.lessThan = lessThan;
    }

    public int getMinSct() {
        return minSct;
    }

    public void setMinSct(int minSct) {
        this.minSct = minSct;
    }

    @Override
    public int hashCode() {
        return Integer.hashCode(minSct) +  397*Integer.hashCode(moreThan) + 499*Integer.hashCode(lessThan);
    }

    @Override
    public boolean equals(Object o) {
        final PolicyBreakpoint other = (PolicyBreakpoint) o;
        return other.moreThan == moreThan && other.lessThan == lessThan && other.minSct == minSct;
    }

    @Override
    public String toString() {
        return "PolicyBreakpoint{For validity" + moreThan + " to " + lessThan + "months, minimum " + minSct + " SCT required.}";
    }
}

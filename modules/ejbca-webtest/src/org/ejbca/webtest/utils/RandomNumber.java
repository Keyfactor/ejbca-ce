package org.ejbca.webtest.utils;

import java.util.Random;

public class RandomNumber {
    
    public Integer generateNumbers(int upperBound) {
        Random rand = new Random();
        //generate random number from 0 to (upperBound -1)
        int testNum = rand.nextInt(upperBound);
        return testNum;
    }
}

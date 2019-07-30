/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zrl.idmx.tests.idmx;

/**
 * Contains constants used for the generation of a key pair.
 */
public class KeyPair {

    /**
     * Number of attributes an issuer key supports (i.e., number of bases
     * excluding the reserved attributes such as the master secret).
     */
    public static final int NBR_ATTRS = 9;
    /**
     * Issuer public key should have epoch length of 120 days -- 432000 seconds.
     * Note that this will require him to issuer an update for each credential every 120
     * days.
     */
    public static final int EPOCH_LENGTH = 432000;

}

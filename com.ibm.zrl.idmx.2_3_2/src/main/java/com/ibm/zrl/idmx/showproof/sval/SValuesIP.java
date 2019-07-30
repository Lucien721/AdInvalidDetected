/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zrl.idmx.showproof.sval;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * S-values for inequality proof.
 */
public class SValuesIP implements Serializable {

    /** Serial version number. */
    private static final long serialVersionUID = 1L;

    /**
     * the uHat values for range proof. for the delta-index we store here the
     * mHat of the attribute.
     */
    private final BigInteger uHat[];
    /** the rHat values for range proof. */
    private final BigInteger rHat[];
    /** alphaHat for range proof. */
    private final BigInteger alphaHat;

    /**
     * Constructor.
     * 
     * @param theUHat
     *            The uHat values for inequality proof. For the delta-index we
     *            store here the mHat of the attribute.
     * @param theRHat
     *            rHat values for inequality proof.
     * @param theAlphaHat
     *            alphaHat for inequality proof.
     */
    public SValuesIP(final BigInteger[] theUHat, final BigInteger[] theRHat,
            final BigInteger theAlphaHat) {
        super();
        uHat = theUHat;
        rHat = theRHat;
        alphaHat = theAlphaHat;
    }

    /**
     * @return The uHat values for range proof. for the delta-index we store
     *         here the mHat of the attribute.
     */
    public final BigInteger[] getUHat() {
        return uHat;
    }

    /**
     * @return The rHat values for an inequality proof.
     */
    public final BigInteger[] getRHat() {
        return rHat;
    }

    /**
     * @return The alphaHat for an inequality proof.
     */
    public final BigInteger getAlphaHat() {
        return alphaHat;
    }
}

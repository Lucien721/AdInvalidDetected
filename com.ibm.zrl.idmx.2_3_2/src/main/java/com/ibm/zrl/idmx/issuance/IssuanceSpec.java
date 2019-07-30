/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zrl.idmx.issuance;

import java.math.BigInteger;
import java.net.URI;

import com.ibm.zrl.idmx.dm.structure.CredentialStructure;
import com.ibm.zrl.idmx.key.IssuerPublicKey;
import com.ibm.zrl.idmx.utils.StructureStore;
import com.ibm.zrl.idmx.utils.Utils;

/**
 * Specification of a certificate issuance, which is primarily a description the
 * attributes, their types and how they should be issued.
 */
public class IssuanceSpec {

    /** Index of the public key base where the master secret is signed. */
    public static final int MASTER_SECRET_INDEX = 0;
    /** Name of the master secret attribute. */
    public static final String MASTER_SECRET_NAME = "master_secret";
    /** Name of the s-value to be used when stored to the additional values map. */
    public static final String s_e = "s_e";
    public static final String vHatPrime = "vHatPrime";
    public static final String rHat = "rHat";

    /** Credential structure location. */
    private URI credStructLocation;

    /** Convenience: Credential structure. */
    private CredentialStructure credStruct;
    /** Convenience: Public key of the issuer. */
    private final IssuerPublicKey pubKey;
    /** Cached context value. */
    private BigInteger context = null;

    /**
     * Create an issuance specification. An issuance specification loads the
     * corresponding credential structure. The number of attributes which may be
     * added is limited by the size of the IssuerPublicKey. This process is
     * illustrated in the certificate issuance test cases.
     * 
     * @param theCredStructLocation
     *            Location of the credential structure.
     * 
     * @see IssuerPublicKey
     * @see CredentialStructure
     */
    public IssuanceSpec(final URI theCredStructLocation) {
        credStructLocation = theCredStructLocation;
        credStruct = (CredentialStructure) StructureStore.getInstance().get(
                credStructLocation);
        pubKey = credStruct.getPublicKey();
    }

    /**
     * @return Location of the credential structure.
     */
    public final URI getCredStructureLocation() {
        return credStructLocation;
    }

    /**
     * @return Credential structure used in this issuance specification.
     */
    public final CredentialStructure getCredentialStructure() {
        return credStruct;
    }

    /**
     * @return Issuer public key as stored in the credential structure.
     */
    public final IssuerPublicKey getPublicKey() {
        return pubKey;
    }

    /**
     * Returns the specification's context: a hash of the group parameters and
     * the issuer's public key.
     * 
     * @return context value.
     */
    public final BigInteger getContext() {
        if (context == null) {
            context = Utils.computeContext(pubKey);
        }
        return context;
    }
}

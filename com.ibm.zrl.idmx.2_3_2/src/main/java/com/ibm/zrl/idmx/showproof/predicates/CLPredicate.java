/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zrl.idmx.showproof.predicates;

import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;

import com.ibm.zrl.idmx.showproof.Identifier;
import com.ibm.zrl.idmx.utils.Constants;

/**
 * This predicate expresses proofs of knowledge about credentials. It uses a
 * credential and a map from attribute names to identifiers to determine over
 * which attributes it should issue equality proofs.
 */
public class CLPredicate extends Predicate {

    /** Location of the credential structure associated to this predicate. */
    private final URI credStructLocation;
    /** Temporary name of the credential as used in the proof specification. */
    private final String credName;
    /** Map from attribute names to identifiers used in this predicate. */
    private HashMap<String, Identifier> attToIdentifierMap;

    /**
     * Constructor.
     * 
     * @param theCredStructLocation
     *            Location of the credential structure associated to this
     *            predicate.
     * @param theCredName
     *            Temporary name of the credential as used in the proof
     *            specification.
     * @param attToIds
     *            Map from attribute names to identifiers used in this
     *            predicate.
     */
    public CLPredicate(final URI theCredStructLocation,
            final String theCredName, final HashMap<String, Identifier> attToIds) {
        super(PredicateType.CL);

        credStructLocation = theCredStructLocation;
        credName = theCredName;
        attToIdentifierMap = attToIds;
    }

    /**
     * @param attName
     *            Name of the attribute associated with some identifier.
     * @return Identifier associated with the given <code>attName</code>.
     */
    public final Identifier getIdentifier(final String attName) {
        return attToIdentifierMap.get(attName);
    }

    /**
     * @return Temporary name for the credential associated with this predicate.
     *         The name consists of a concatenation of the structure location
     *         and the credential name given in the proof specification.
     */
    public final String getTempCredName() {
        return credStructLocation.toString().concat(Constants.DELIMITER)
                .concat(credName);
    }

    /**
     * @return Credential structure location of the credential associated with
     *         this predicate.
     */
    public final URI getCredStructLocation() {
        return credStructLocation;
    }

    /**
     * @return Human-readable string of this predicate.
     */
    public final String toStringPretty() {
        String s = "CLPredicate( " + credStructLocation + Constants.DELIMITER
                + credName + ")\n";
        Iterator<String> iterator = attToIdentifierMap.keySet().iterator();
        while (iterator.hasNext()) {
            String attName = iterator.next();
            s += "\t(" + attName + " -> "
                    + attToIdentifierMap.get(attName).getName() + ")\n";
        }
        return s;
    }
}

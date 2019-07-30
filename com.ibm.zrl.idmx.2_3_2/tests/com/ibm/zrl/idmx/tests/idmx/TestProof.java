/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zrl.idmx.tests.idmx;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.Vector;

import junit.framework.TestCase;

import com.ibm.zrl.idmx.dm.Commitment;
import com.ibm.zrl.idmx.dm.CommitmentOpening;
import com.ibm.zrl.idmx.dm.Credential;
import com.ibm.zrl.idmx.dm.MasterSecret;
import com.ibm.zrl.idmx.dm.MessageToSign;
import com.ibm.zrl.idmx.dm.Representation;
import com.ibm.zrl.idmx.dm.RepresentationOpening;
import com.ibm.zrl.idmx.key.IssuerPublicKey;
import com.ibm.zrl.idmx.key.VEPrivateKey;
import com.ibm.zrl.idmx.key.VEPublicKey;
import com.ibm.zrl.idmx.showproof.Proof;
import com.ibm.zrl.idmx.showproof.ProofSpec;
import com.ibm.zrl.idmx.showproof.Prover;
import com.ibm.zrl.idmx.showproof.Verifier;
import com.ibm.zrl.idmx.utils.Constants;
import com.ibm.zrl.idmx.utils.Parser;
import com.ibm.zrl.idmx.utils.StructureStore;
import com.ibm.zrl.idmx.utils.SystemParameters;
import com.ibm.zrl.idmx.utils.Utils;
import com.ibm.zrl.idmx.utils.XMLSerializer;
import com.ibm.zrl.idmx.ve.Decryption;
import com.ibm.zrl.idmx.ve.VerifiableEncryption;
import com.ibm.zrl.idmx.ve.VerifiableEncryptionOpening;

/**
 * Testing show-proofs. For each test there is first a specification created.
 * Using the specification the prover creates the proof and serializes it. The
 * verifier uses the specification and the proof and verifies the given
 * statement.
 */
public class TestProof extends TestCase {

    private IssuerPublicKey issuerPublicKey = null;
    private MasterSecret masterSecret = null;

    /** Names of the Proof and Nonce objects. */
    private static final String CL_NO = "clNoValues";
    private static final String CL_KNOWN = "clKnownValues";
    private static final String CL_HIDDEN = "clHiddenValues";
    private static final String CL_KNOWN_UPDATEABLE = "clKnownUpdateableValues";
    private static final String CL_EPOCH = "clEpoch";
    private static final String CL1 = "cl1";
    private static final String CL2 = "cl2";
    private static final String CL3 = "cl3";
    private static final String COMM1 = "comm1";
    private static final String COMM2 = "comm2";
    private static final String DOM_NYM1 = "domNym1";
    private static final String NYM1 = "nym1";
    private static final String RANGE1 = "range1";
    private static final String VE1 = "ve1";
    private static final String VE2 = "ve2";
    private static final String REP1 = "rep1";
    private static final String MESSAGE1 = "message1";
    private static final String PE_AND1 = "peAnd1";
    private static final String PE_NOT1 = "peNot1";
    private static final String PE_OR1 = "peOr1";

    /** Commitment Opening of {@link TestIssuance#ATTRIBUTE_VALUE_1}. */
    private static final String COMM1_PROVER = "comm1_prover.bin";
    /** Commitment to {@link TestIssuance#ATTRIBUTE_VALUE_}. */
    private static final String COMM1_VERIFIER = "comm1_verifier.bin";
    /**
     * Commitment Opening of {@link TestIssuance#ATTRIBUTE_VALUE_2} and
     * {@link TestIssuance#ATTRIBUTE_VALUE_5}.
     */
    private static final String COMM2_5_PROVER = "comm2_5_prover.bin";
    /**
     * Commitment to {@link TestIssuance#ATTRIBUTE_VALUE_2} and
     * {@link TestIssuance#ATTRIBUTE_VALUE_5}.
     */
    private static final String COMM2_5_VERIFIER = "comm2_5_verifier.bin";
    /** Commitment Opening of {@link TestIssuance#ATTRIBUTE_VALUE_3}. */
    private static final String COMM3_PROVER = "comm3_prover.bin";
    /** Commitment to {@link TestIssuance#ATTRIBUTE_VALUE_3}. */
    private static final String COMM3_VERIFIER = "comm3_verifier.bin";

    public static final String COMM1COMPLETE_PROVER = "comm1complete_prover";
    public static final String COMM1COMPLETE_VERIFIER = "comm1complete_verifier";
    public static final String COMM2COMPLETE_PROVER = "comm2complete_prover";
    public static final String COMM2COMPLETE_VERIFIER = "comm2complete_verifier";

    private final static String VE1_PROVER = "ve1_prover";
    private final static String VE2_PROVER = "ve2_prover";
    private final static String VE1_VERIFIER = "ve1_verifier";
    private final static String VE2_VERIFIER = "ve2_verifier";

    private final static String REP1V_FN = "rep1v.bin";
    private final static String REP2V_FN = "rep2v.bin";

    public final static String ENDING = "\n "
            + "============================================================\n";
    public final static String PROOF_VERIFIED = "Proof Verified." + ENDING;

    /**
     * Performs the setup for the tests, i.e., loads the parameters and
     * instantiates the master secret.
     */
    protected final void setUp() {
        Locations.loadParameters(TestIssuance.BASE_ID,
                TestIssuance.BASE_LOCATION);

        issuerPublicKey = (IssuerPublicKey) StructureStore.getInstance().get(
                Locations.ipkIdUri);

        // loading credential structures
        preloadCredStructs();

        masterSecret = Locations.getMasterSecret();
    }

    /**
     * Loading all credential structures - required if they are not available at
     * the location indicated within the files (e.g., proof specification).
     */
    public static final void preloadCredStructs() {
        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_1A);
//        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_1B);
//        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_1C);
//        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_1D);
//        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_2);
//        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_3);
//        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_4);
//        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_5);
//        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_6);
    }

    /**
     * @param credUri
     *            File name of the credential.
     * @param tempCredName
     *            Temporary name of the credential in the proof specification.
     * @return Map with credentials that will be needed for the proof.
     */
    public final static HashMap<String, Credential> loadCredential(URI credUri,
            String tempCredName) {

        final Credential c = (Credential) Parser.getInstance().parse(credUri);
        if (c == null) {
            fail("getting credential");
        }

        HashMap<String, Credential> creds = new HashMap<String, Credential>();
        String credTempName = c.getCredStructLocation().toString()
                .concat(Constants.DELIMITER).concat(tempCredName);
        creds.put(credTempName, c);
        return creds;
    }

    /**
     * Test: Reads the library version and fails if the version is not the
     * expected version.
     */
    public final void testVersion() {
        if (Constants.getVersion() != "2.3.2") {
            fail("wrong version");
        }
    }

    /**
     * Test: Builds a proof according to the specification.
     * 
     * @see TestIssuance#testIssuance_Cred_noValues()
     */
//    public final void testProve_Cred_noValues() {
//
//        // load the credential structure
//        Locations.initIssuerId("http://www.issuer.com/");
//        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_1A);
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec1a"));
//        System.out.println(spec.toStringPretty());
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce (done by the verifier)
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        // load credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED1A_FN),
//                "someRandomName");
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(CL_NO));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(CL_NO));
//    }
//
//    /**
//     * Test: Verifies the proof according to the specification.
//     * 
//     * @see TestProof#testProve_Cred_noValues()
//     */
//    public final void testVerify_Cred_noValues() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec0"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(CL_NO));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(CL_NO));
//
//        // now p is sent to the verifier
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }

    /**
     * Test: Builds a proof according to the specification.
     * 
     * @see TestIssuance#testIssuance_Cred1a_knownValues()
     */
    public final void testProve_Cred1a() {

        // load the proof specification
        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
                Locations.getProofSpecLocation("ProofSpec1a"));
        System.out.println(spec.toStringPretty());

        SystemParameters sp = spec.getGroupParams().getSystemParams();

        // first get the nonce (done by the verifier)
        System.out.println("Getting nonce.");
        BigInteger nonce = Verifier.getNonce(sp);

        // load credentials
        HashMap<String, Credential> creds = loadCredential(
                Locations.getCredentialLocation(TestIssuance.CRED1A_FN),
                "someRandomName");

        Prover prover = new Prover(masterSecret, creds, spec, nonce);
        // create the proof
        Proof p = prover.buildProof();
        System.out.println("Proof Created.");

        // save the proof
        XMLSerializer.getInstance().serialize(p,
                Locations.getProofLocation(CL_KNOWN));
        // save the nonce for the verification test case
        XMLSerializer.getInstance().serialize(nonce,
                Locations.getNonceLocation(CL_KNOWN));
    }
//
//    /**
//     * Test: Verifies the proof according to the specification.
//     * 
//     * @see TestProof#testProve_Cred1a()
//     */
//    public final void testVerify_Cred1a() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec1a"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(CL_KNOWN));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(CL_KNOWN));
//
//        // now p is sent to the verifier
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }

//    /**
//     * Test: Builds a proof according to the specification.
//     * 
//     * @see TestIssuance#testIssuance_Cred1b_hiddenValues()
//     */
//    public final void testProve_Cred1b() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec1b"));
//        System.out.println(spec.toStringPretty());
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce (done by the verifier)
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED1B_FN),
//                "someRandomName");
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(CL_HIDDEN));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(CL_HIDDEN));
//    }
//
//    /**
//     * Test: Verifies the proof according to the specification.
//     * 
//     * @see TestProof#testProve_Cred1b()
//     */
//    public final void testVerify_Cred1b() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec1b"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(CL_HIDDEN));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(CL_HIDDEN));
//
//        // now p is sent to the verifier
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Builds a proof according to the specification.
//     * 
//     * @see TestIssuance#testIssuance_Cred1c_knownValuesUpdateable()
//     */
//    public final void testProve_Cred1c() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec1c"));
//        System.out.println(spec.toStringPretty());
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce (done by the verifier)
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED1C_FN),
//                "someRandomName");
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(CL_KNOWN_UPDATEABLE));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(CL_KNOWN_UPDATEABLE));
//    }
//
//    /**
//     * Test: Verifies the proof according to the specification.
//     * 
//     * @see TestProof#testProve_Cred1c()
//     */
//    public final void testVerify_Cred1c() {
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec1c"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(CL_KNOWN_UPDATEABLE));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(CL_KNOWN_UPDATEABLE));
//
//        // now p is sent to the verifier
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Builds a proof according to the specification.
//     * 
//     * @see TestIssuance#testIssuance_Cred1d_knownValuesUpdateable()
//     */
//    public final void testProve_Cred1d() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec1d"));
//        System.out.println(spec.toStringPretty());
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce (done by the verifier)
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED1D_FN),
//                "someRandomName");
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(CL_EPOCH));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(CL_EPOCH));
//    }
//
//    /**
//     * Test: Verifies the proof according to the specification.
//     * 
//     * @see TestProof#testProve_Cred1d()
//     */
//    public final void testVerify_Cred1d() {
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec1d"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(CL_EPOCH));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(CL_EPOCH));
//
//        // now p is sent to the verifier
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads a proof specification and creates the corresponding proof
//     * (Prover's side).
//     */
//    public final void testProve_Cred2() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec2"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(CL1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(CL1));
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed CL1 and
//     * verifies the proof (Verifier's side).
//     */
//    public final void testVerify_Cred2() {
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec2"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(CL1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(CL1));
//
//        // now p is sent to the verifier
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed CL1 and creates the proof
//     * (Prover's side).
//     * 
//     * @see TestIssuance#testIssuance_Cred1b_hiddenValues()
//     * @see TestIssuance#testIssuance_Cred2_knownHiddenValues()
//     */
//    public final void testProve_Cred1bCred2() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec1b-2"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED1B_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(CL2));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(CL2));
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed CL1 and
//     * verifies the proof (Verifier's side).
//     */
//    public final void testVerify_Cred1bCred2() {
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec1b-2"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(CL2));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(CL2));
//
//        // now p is sent to the verifier
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed CL2 and creates the proof
//     * (Prover's side).
//     */
//    public final void testProve_Cred2Cred4Cred5() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec2-4"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED4_FN),
//                "someOtherRandomNameToMakeItDistinct"));
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED5_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(CL3));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(CL3));
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed CL2 and
//     * verifies the proof (Verifier's side).
//     */
//    public final void testVerify_Cred2Cred4Cred5() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec2-4"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(CL3));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(CL3));
//
//        // now p is sent to the verifier
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }

    /**
     * Creates and serializes two commitments, each to a single value.<br>
     * 
     * @see TestProof#COMM1_PROVER
     * @see TestProof#COMM1_VERIFIER
     * @see TestProof#COMM3_PROVER
     * @see TestProof#COMM1_VERIFIER
     */
//    public final void testBuildCommitments() {
//
//        // Build first commitment (based on public key used in Credential 3)
//        final Credential cred3 = (Credential) Parser.getInstance().parse(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN));
//        IssuerPublicKey publicKey = cred3.getPublicKey();
//
//        BigInteger n = publicKey.getN();
//        BigInteger capS = publicKey.getCapS();
//        BigInteger capZ = publicKey.getCapZ();
//        BigInteger message = TestIssuance.ATTRIBUTE_VALUE_1;
//        BigInteger r = new BigInteger("7"); // "randomness" for commitment
//
//        SystemParameters sp = issuerPublicKey.getGroupParams()
//                .getSystemParams();
//        CommitmentOpening commOpening = new CommitmentOpening(capZ, message,
//                capS, r, n, sp.getL_n());
//        if (!commOpening.verifyCommitment()) {
//            fail("proverCommitment fails testGetCommitmentObject");
//        }
//
//        if (!(commOpening.save(COMM1_PROVER) && commOpening
//                .getCommitmentObject().save(COMM1_VERIFIER))) {
//            fail("Failed to serialize one of first commitments.");
//        }
//
//        CommitmentOpening p = CommitmentOpening.load(COMM1_PROVER);
//        Commitment v = Commitment.load(COMM1_VERIFIER);
//
//        if (!p.equals(commOpening)) {
//            fail("deserialization of COMM1_PROVER failed");
//        }
//        if (!v.equals(commOpening.getCommitmentObject())) {
//            fail("deserialization of COMM1_VERIFIER failed");
//        }
//
//        if (!commOpening.getCommitment().equals(
//                commOpening.getCommitmentObject().getCommitment())) {
//            fail("commitments differ");
//        }
//
//        // Build second commitment
//        final Credential cred2 = (Credential) Parser.getInstance().parse(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN));
//        publicKey = cred2.getPublicKey();
//
//        n = publicKey.getN();
//        capS = publicKey.getCapS();
//        capZ = publicKey.getCapZ();
//        message = TestIssuance.ATTRIBUTE_VALUE_3;
//        r = new BigInteger("8"); // "randomness"
//
//        commOpening = new CommitmentOpening(capZ, message, capS, r, n,
//                sp.getL_n());
//        if (!commOpening.verifyCommitment()) {
//            fail("proverCommitment fails testGetCommitmentObject");
//        }
//
//        if (!(commOpening.save(COMM3_PROVER) && commOpening
//                .getCommitmentObject().save(COMM3_VERIFIER))) {
//            fail("Failed to serialize one of second commitments.");
//        }
//
//        p = CommitmentOpening.load(COMM3_PROVER);
//        v = Commitment.load(COMM3_VERIFIER);
//
//        if (!p.equals(commOpening)) {
//            fail("deserialization of COMM3_PROVER failed");
//        }
//        if (!v.equals(commOpening.getCommitmentObject())) {
//            fail("deserialization of COMM3_VERIFIER failed");
//        }
//        if (!commOpening.getCommitment().equals(
//                commOpening.getCommitmentObject().getCommitment())) {
//            fail("commitments differ");
//        }
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed COMM1 and creates the proof
//     * (Prover's side).
//     */
//    public final void testProveCommitment_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecComm2-3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        // load the CommitmentOpenings
//        CommitmentOpening c1p = CommitmentOpening.load(COMM1_PROVER);
//        CommitmentOpening c2p = CommitmentOpening.load(COMM3_PROVER);
//        HashMap<String, CommitmentOpening> pCommitments;
//        pCommitments = new HashMap<String, CommitmentOpening>();
//        pCommitments.put("again a random name", c1p);
//        pCommitments.put("another random name", c2p);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce, null,
//                pCommitments, null, null);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(COMM1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(COMM1));
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed COMM1 and
//     * verifies the proof (Verifier's side).
//     */
//    public final void testVerifyCommitment_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecComm2-3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(COMM1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(COMM1));
//
//        // load the Commitments
//        Commitment c1v = Commitment.load(COMM1_VERIFIER);
//        Commitment c2v = Commitment.load(COMM3_VERIFIER);
//        HashMap<String, Commitment> vCommitments = new HashMap<String, Commitment>();
//        vCommitments.put("again a random name", c1v);
//        vCommitments.put("another random name", c2v);
//
//        Verifier verifier = new Verifier(spec, p, nonce, null, vCommitments,
//                null, null);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }

    /**
     * Creates and serializes a single commitment to multiple values.<br>
     * 
     * @see TestProof#COMM2_5_PROVER
     * @see TestProof#COMM2_5_VERIFIER
     */
//    public final void testBuildMultivalueCommitments() {
//
//        // Build commitment
//        final Credential cred3 = (Credential) Parser.getInstance().parse(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN));
//        Vector<BigInteger> m = new Vector<BigInteger>();
//        m.add(TestIssuance.ATTRIBUTE_VALUE_2);
//        m.add(TestIssuance.ATTRIBUTE_VALUE_5);
//        BigInteger r = new BigInteger("7"); // "randomness" for commitment
//
//        CommitmentOpening proverCommitment = new CommitmentOpening(m, r,
//                cred3.getPublicKey());
//        if (!proverCommitment.verifyCommitment()) {
//            fail("proverCommitment fails testGetCommitmentObject");
//        }
//        Commitment verifierCommitment = proverCommitment.getCommitmentObject();
//
//        if (!(proverCommitment.save(COMM2_5_PROVER) && verifierCommitment
//                .save(COMM2_5_VERIFIER))) {
//            fail("Failed to serialize one of first commitments.");
//        }
//
//        CommitmentOpening p = CommitmentOpening.load(COMM2_5_PROVER);
//        Commitment v = Commitment.load(COMM2_5_VERIFIER);
//
//        if (!p.equals(proverCommitment)) {
//            fail("deserialization of commitment opening failed");
//        }
//        if (!v.equals(verifierCommitment)) {
//            fail("deserialization of commitment failed");
//        }
//
//        if (!proverCommitment.getCommitment().equals(
//                verifierCommitment.getCommitment())) {
//            fail("commitments differ");
//        }
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed COMM2 and creates the proof
//     * (Prover's side).
//     * 
//     * @see TestIssuance#CRED3_FN
//     */
//    public final void testProveMultivalueCommitment_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecMultivalComm2-3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        // load the CommitmentOpenings
//        CommitmentOpening c1p = CommitmentOpening.load(COMM2_5_PROVER);
//        HashMap<String, CommitmentOpening> pCommitments;
//        pCommitments = new HashMap<String, CommitmentOpening>();
//        pCommitments.put("again a random name", c1p);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce, null,
//                pCommitments, null, null);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(COMM2));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(COMM2));
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed COMM2 and
//     * verifies the proof (Verifier's side).
//     */
//    public final void testVerifyMultivalueCommitment_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecMultivalComm2-3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(COMM2));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(COMM2));
//
//        // load the Commitments
//        Commitment c1v = Commitment.load(COMM2_5_VERIFIER);
//        HashMap<String, Commitment> vCommitments = new HashMap<String, Commitment>();
//        vCommitments.put("again a random name", c1v);
//
//        Verifier verifier = new Verifier(spec, p, nonce, null, vCommitments,
//                null, null);
//
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed DOM_NYM1 and creates the
//     * proof (Prover's side).
//     */
//    public final void testProveCreatedDomNym_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecDomNym"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        // Vector<String> domNymNames = new Vector<String>();
//        // domNymNames.add("http://www.zurich.ibm.com/employeeCorner");
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce, null,
//                null, null, null);
//
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(DOM_NYM1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(DOM_NYM1));
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed DOM_NYM1 and
//     * verifies the proof (Verifier's side).
//     */
//    public final void testVerifyCreatedDomNym_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecDomNym"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(DOM_NYM1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(DOM_NYM1));
//
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed NYM1 and creates the proof
//     * (Prover's side).
//     */
//    public final void testProveCreatedNym() {
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecNym"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        masterSecret.loadNym("Mark Twain");
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce, null,
//                null, null, null);
//
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(NYM1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(NYM1));
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed NYM1 and
//     * verifies the proof (Verifier's side). This proof uses a pseudonym
//     * transmitted through the proof.
//     */
//    public final void testVerifyNym1() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecNym"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(NYM1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(NYM1));
//
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed NYM1 and
//     * verifies the proof (Verifier's side). This proof uses a nym transmitted
//     * through an orthogonal channel.
//     */
//    public final void testVerifyNym2() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecNym"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(NYM1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(NYM1));
//
//        // we assume the transmission of the nym through an orthogonal channel
//
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed RANGE1 and creates the proof
//     * (Prover's side).
//     */
//    public final void testProveInequality() {
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecInequality_Cred2"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(RANGE1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(RANGE1));
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed RANGE1 and
//     * verifies the proof (Verifier's side).
//     */
//    public final void testVerifyInequality() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecInequality_Cred2"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(RANGE1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(RANGE1));
//
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Creates two verifiable encryptions and stores them to disk. <br>
//     * Verifiable encryptions:<br>
//     * ve1: ATTRIBUTE_VALUE_1, "verEnc1" <br>
//     * ve2: ATTRIBUTE_VALUE_2, ATTRIBUTE_VALUE_3<br>
//     */
//    public final void testBuildVerifiableEncryption1() {
//
//        VEPublicKey pk = Locations.getVEPublicKey();
//        VEPrivateKey sk = Locations.getVEPrivateKey();
//
//        BigInteger r1 = pk.getRandom();
//        BigInteger r2 = pk.getRandom();
//        VerifiableEncryptionOpening pEnc1 = new VerifiableEncryptionOpening(
//                TestIssuance.ATTRIBUTE_VALUE_1, r1, Locations.vepkIdUri,
//                "Label 1");
//        VerifiableEncryptionOpening pEnc2 = new VerifiableEncryptionOpening(
//                TestIssuance.ATTRIBUTE_VALUE_2, r2, Locations.vepkIdUri,
//                TestIssuance.ATTRIBUTE_VALUE_3);
//
//        VerifiableEncryption vEnc1 = pEnc1.getEncryption();
//        VerifiableEncryption vEnc2 = pEnc2.getEncryption();
//
//        // Double check that encryptions are valid
//        if (!Decryption.decrypt(sk, vEnc1).equals(
//                TestIssuance.ATTRIBUTE_VALUE_1)) {
//            fail("Decryption of vEnc1 failed");
//        }
//
//        if (!Decryption.decrypt(sk, vEnc2).equals(
//                TestIssuance.ATTRIBUTE_VALUE_2)) {
//            fail("Decryption of vEnc2 failed");
//        }
//
//        // serialize the encryptions to disk
//        XMLSerializer.getInstance().serialize(pEnc1,
//                Locations.getPrivateLocation(VE1_PROVER));
//        XMLSerializer.getInstance().serialize(vEnc1,
//                Locations.getTrustedPartyLocation(VE1_VERIFIER));
//        XMLSerializer.getInstance().serialize(pEnc2,
//                Locations.getPrivateLocation(VE2_PROVER));
//        XMLSerializer.getInstance().serialize(vEnc2,
//                Locations.getTrustedPartyLocation(VE2_VERIFIER));
//
//        // test the serialization
//
//        VerifiableEncryptionOpening e1 = (VerifiableEncryptionOpening) Parser
//                .getInstance().parse(Locations.getPrivateLocation(VE1_PROVER));
//        VerifiableEncryption v1 = (VerifiableEncryption) Parser.getInstance()
//                .parse(Locations.getTrustedPartyLocation(VE1_VERIFIER));
//        VerifiableEncryptionOpening e2 = (VerifiableEncryptionOpening) Parser
//                .getInstance().parse(Locations.getPrivateLocation(VE2_PROVER));
//        VerifiableEncryption v2 = (VerifiableEncryption) Parser.getInstance()
//                .parse(Locations.getTrustedPartyLocation(VE2_VERIFIER));
//
//        if (!e1.equals(pEnc1)) {
//            fail("prover enc 1 did not deserialize correctly");
//        }
//        if (!e2.equals(pEnc2)) {
//            fail("prover enc 2 did not deserialize correctly");
//        }
//        if (!v1.equals(vEnc1)) {
//            fail("verifier enc 1 did not deserialize correctly");
//        }
//        if (!v2.equals(vEnc2)) {
//            fail("verifier enc 2 did not deserialize correctly");
//        }
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed VE1 and creates the proof
//     * (Prover's side).
//     */
//    public final void testProveLoadedVE_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecVE_Cred2Cred3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        // load the prover's verifiable encryptions
//        VerifiableEncryptionOpening e1 = (VerifiableEncryptionOpening) Parser
//                .getInstance().parse(Locations.getPrivateLocation(VE1_PROVER));
//        VerifiableEncryptionOpening e2 = (VerifiableEncryptionOpening) Parser
//                .getInstance().parse(Locations.getPrivateLocation(VE2_PROVER));
//        HashMap<String, VerifiableEncryptionOpening> vep;
//        vep = new HashMap<String, VerifiableEncryptionOpening>();
//        vep.put("randomVerEncName1", e1);
//        vep.put("randomVerEncName2", e2);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce, null,
//                null, null, vep);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(VE1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(VE1));
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed VE1 and
//     * verifies the proof (Verifier's side).
//     */
//    public final void testVerifyLoadedVE_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecVE_Cred2Cred3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(VE1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(VE1));
//
//        // load verifiable encryptions
//        VerifiableEncryption v1 = (VerifiableEncryption) Parser.getInstance()
//                .parse(Locations.getTrustedPartyLocation(VE1_VERIFIER));
//        VerifiableEncryption v2 = (VerifiableEncryption) Parser.getInstance()
//                .parse(Locations.getTrustedPartyLocation(VE2_VERIFIER));
//        TreeMap<String, VerifiableEncryption> vev = new TreeMap<String, VerifiableEncryption>();
//        vev.put("randomVerEncName1", v1);
//        vev.put("randomVerEncName2", v2);
//
//        Verifier verifier = new Verifier(spec, p, nonce, null, null, null, vev);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed VE1 and creates the proof
//     * (Prover's side).
//     */
//    public final void testProveCreatedVE_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecVE_Cred2Cred3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(VE2));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(VE2));
//    }
//
//    /**
//     * Test: Loads the proof specification and the proof prefixed VE1 and
//     * verifies the proof (Verifier's side).
//     */
//    public final void testVerifyCreatedVE_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecVE_Cred2Cred3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(VE2));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(VE2));
//
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed REP1 and creates the proof
//     * (Prover's side).
//     */
//    public final void testProveLoadedRep_Cred2Cred3() {
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecRep_Cred2Cred3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        // create the RepresentationOpening objects for the prover.
//        // use the R_i values in certificate 1's issuer public key as bases
//
//        Vector<BigInteger> bases = new Vector<BigInteger>(3);
//        bases.add(issuerPublicKey.getCapR()[6]);
//        bases.add(issuerPublicKey.getCapR()[5]);
//        bases.add(issuerPublicKey.getCapR()[4]);
//
//        Vector<BigInteger> exponents1 = new Vector<BigInteger>(3);
//        exponents1.add(TestIssuance.ATTRIBUTE_VALUE_2);
//        exponents1.add(TestIssuance.ATTRIBUTE_VALUE_3);
//        exponents1.add(TestIssuance.ATTRIBUTE_VALUE_5);
//
//        RepresentationOpening ro1 = new RepresentationOpening(bases,
//                exponents1, issuerPublicKey.getN(), "rep1");
//
//        Vector<BigInteger> exponents2 = new Vector<BigInteger>(3);
//        exponents2.add(TestIssuance.ATTRIBUTE_VALUE_1);
//        exponents2.add(TestIssuance.ATTRIBUTE_VALUE_2);
//        exponents2.add(TestIssuance.ATTRIBUTE_VALUE_3);
//
//        RepresentationOpening ro2 = new RepresentationOpening(bases,
//                exponents2, issuerPublicKey.getN(), "rep2");
//
//        HashMap<String, RepresentationOpening> proverReps;
//        proverReps = new HashMap<String, RepresentationOpening>();
//        proverReps.put("randomRepName1", ro1);
//        proverReps.put("randomRepName2", ro2);
//
//        // Serialize the Representations for the verifier
//        ro1.getRepresentationObject().save(REP1V_FN);
//        ro2.getRepresentationObject().save(REP2V_FN);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce, null,
//                null, proverReps, null);
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(REP1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(REP1));
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed and the proof prefixed REP1
//     * and verifies the proof (Verifier's side).
//     */
//    public final void testVerifyLoadedRep_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecRep_Cred2Cred3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(REP1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(REP1));
//
//        TreeMap<String, Representation> verifierReps;
//        verifierReps = new TreeMap<String, Representation>();
//
//        verifierReps.put("randomRepName1", Representation.load(REP1V_FN));
//        verifierReps.put("randomRepName2", Representation.load(REP2V_FN));
//
//        Verifier verifier = new Verifier(spec, p, nonce, null, null,
//                verifierReps, null);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed MESSAGE1 and creates the
//     * proof (Prover's side).
//     */
//    public final void testProveLoadedMessage_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecMessage_Cred2Cred3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED2_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        creds.putAll(loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED3_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        TreeMap<String, MessageToSign> msgs = new TreeMap<String, MessageToSign>();
//        MessageToSign msg = new MessageToSign(
//                "This is the message we want signed. It can be any string.");
//        msgs.put("randMessageName", msg);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce, msgs,
//                null, null, null);
//
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(MESSAGE1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(MESSAGE1));
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed and the proof prefixed
//     * MESSAGE1 and verifies the proof (Verifier's side).
//     */
//    public final void testVerifyLoadedMessage_Cred2Cred3() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecMessage_Cred2Cred3"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(MESSAGE1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(MESSAGE1));
//
//        // Verifier knows the messages too
//        TreeMap<String, MessageToSign> msgs = new TreeMap<String, MessageToSign>();
//        MessageToSign msg = new MessageToSign(
//                "This is the message we want signed. It can be any string.");
//        msgs.put("randMessageName", msg);
//
//        // now p is "sent" to the verifier
//        Verifier verifier = new Verifier(spec, p, nonce, msgs, null, null, null);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed PE_AND1 and creates the
//     * proof (Prover's side).
//     */
//    public final void testProvePeAnd_Cred7() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecEnumAnd_Cred7"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED7_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        // creds.putAll(loadCredential(TestIssuance.CRED3_FN,
//        // "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(PE_AND1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(PE_AND1));
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed and the proof prefixed
//     * PE_AND1 and verifies the proof (Verifier's side).
//     */
//    public final void testVerifyPeAnd_Cred7() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecEnumAnd_Cred7"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(PE_AND1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(PE_AND1));
//
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed PE_NOT1 and creates the
//     * proof (Prover's side).
//     */
//    public final void testProvePeNot_Cred7() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecEnumNot_Cred7"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED7_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//        // creds.putAll(loadCredential(TestIssuance.CRED3_FN,
//        // "someRandomNameMatchingTheOneInTheProofSpec"));
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(PE_NOT1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(PE_NOT1));
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed and the proof prefixed
//     * PE_NOT1 and verifies the proof (Verifier's side).
//     */
//    public final void testVerifyPeNot_Cred7() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecEnumNot_Cred7"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(PE_NOT1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(PE_NOT1));
//
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed PE_OR1 and creates the proof
//     * (Prover's side).
//     */
//    public final void testProvePeOr_Cred7() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecEnumOr_Cred7"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED7_FN),
//                "someRandomNameMatchingTheOneInTheProofSpec");
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce);
//
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // save the proof
//        XMLSerializer.getInstance().serialize(p,
//                Locations.getProofLocation(PE_OR1));
//        // save the nonce for the verification test case
//        XMLSerializer.getInstance().serialize(nonce,
//                Locations.getNonceLocation(PE_OR1));
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed and the proof prefixed
//     * PE_OR1 and verifies the proof (Verifier's side).
//     */
//    public final void testVerifyPeOr_Cred7() {
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpecEnumOr_Cred7"));
//        System.out.println(spec.toStringPretty());
//
//        // load the proof
//        Proof p = (Proof) Parser.getInstance().parse(
//                Locations.getProofLocation(PE_OR1));
//        BigInteger nonce = (BigInteger) Parser.getInstance().parse(
//                Locations.getNonceLocation(PE_OR1));
//
//        Verifier verifier = new Verifier(spec, p, nonce);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * Test: Loads the proof specification prefixed PE_AND1 and creates the
//     * proof (Prover's side).
//     * 
//     * @see TestIssuance#CRED_COMPLETE_FN
//     */
//    public final void testProve_CredComplete() {
//
//        // reload issuer parameters with different issuer URI
//        Locations.initIssuerId("http://www.ch.ch/identityCard/v2012/");
//
//        // load credential structure
//        Locations.loadCredStruct(TestIssuance.CRED_STRUCT_COMPLETE);
//
//        // load the proof specification
//        ProofSpec spec = (ProofSpec) StructureStore.getInstance().get(
//                Locations.getProofSpecLocation("ProofSpec_CredComplete"));
//        System.out.println(spec.toStringPretty());
//
//        // load the prover's credentials
//        HashMap<String, Credential> creds = loadCredential(
//                Locations.getCredentialLocation(TestIssuance.CRED_COMPLETE_FN),
//                "kdsfjk230fsefj329");
//
//        SystemParameters sp = spec.getGroupParams().getSystemParams();
//
//        Vector<BigInteger> committedValues = new Vector<BigInteger>();
//        committedValues.add(Utils.encode(sp.getL_H(), "Hans"));
//        committedValues.add(Utils.encode(sp.getL_H(), "Muster"));
//        CommitmentOpening c1p = new CommitmentOpening(
//                committedValues,
//                CommitmentOpening.genRandom(issuerPublicKey.getN(), sp.getL_n()),
//                issuerPublicKey);
//        CommitmentOpening c2p = new CommitmentOpening(
//                TestIssuance.ATTRIBUTE_VALUE_1, CommitmentOpening.genRandom(
//                        issuerPublicKey.getN(), sp.getL_n()), issuerPublicKey);
//        HashMap<String, CommitmentOpening> commOpening;
//        commOpening = new HashMap<String, CommitmentOpening>();
//        commOpening.put("j39rfj3rf903jfsga", c1p);
//        commOpening.put("29saoxcznbfjsapqw", c2p);
//
//        Vector<BigInteger> bases = new Vector<BigInteger>(2);
//        bases.add(issuerPublicKey.getCapR()[0]);
//        bases.add(issuerPublicKey.getCapR()[1]);
//        Vector<BigInteger> exponents = new Vector<BigInteger>(2);
//        exponents.add(TestIssuance.ATTRIBUTE_VALUE_1);
//        exponents.add(Utils.encode(sp.getL_H(), "Diabetes"));
//        RepresentationOpening r1p = new RepresentationOpening(bases, exponents,
//                issuerPublicKey.getN(), "eoifdvak924dzl021");
//        HashMap<String, RepresentationOpening> repOpening;
//        repOpening = new HashMap<String, RepresentationOpening>();
//        repOpening.put("eoifdvak924dzl021", r1p);
//
//        // load the verifiable encryption public key
//        VEPublicKey pk = Locations.getVEPublicKey();
//
//        BigInteger r1 = pk.getRandom();
//        BigInteger r2 = pk.getRandom();
//        VerifiableEncryptionOpening pEnc1 = new VerifiableEncryptionOpening(
//                TestIssuance.ATTRIBUTE_VALUE_1, r1, Locations.vepkIdUri,
//                "Label 1");
//        VerifiableEncryptionOpening pEnc2 = new VerifiableEncryptionOpening(
//                Utils.encode(sp.getL_H(), "Muster"), r2, Locations.vepkIdUri,
//                "Label 2");
//        HashMap<String, VerifiableEncryptionOpening> vep;
//        vep = new HashMap<String, VerifiableEncryptionOpening>();
//        vep.put("jd2e0asfdkkj3rqq1", pEnc1);
//        vep.put("39asxz0x09dfsdka2", pEnc2);
//
//        TreeMap<String, MessageToSign> msgs = new TreeMap<String, MessageToSign>();
//        MessageToSign msg = new MessageToSign(
//                "Some message that is going to be included into the Hash.");
//        msgs.put("d0fsdfkii2fucxzkl", msg);
//
//        // first get the nonce from the verifier
//        System.out.println("Getting nonce.");
//        BigInteger nonce = Verifier.getNonce(sp);
//
//        Prover prover = new Prover(masterSecret, creds, spec, nonce, msgs,
//                commOpening, repOpening, vep);
//
//        // create the proof
//        Proof p = prover.buildProof();
//        System.out.println("Proof Created.");
//
//        // verify the proof
//        Commitment c1v = c1p.getCommitmentObject();
//        Commitment c2v = c2p.getCommitmentObject();
//        HashMap<String, Commitment> comms = new HashMap<String, Commitment>();
//        comms.put("j39rfj3rf903jfsga", c1v);
//        comms.put("29saoxcznbfjsapqw", c2v);
//
//        TreeMap<String, Representation> reps;
//        reps = new TreeMap<String, Representation>();
//        reps.put("eoifdvak924dzl021", r1p.getRepresentationObject());
//
//        TreeMap<String, VerifiableEncryption> vev = new TreeMap<String, VerifiableEncryption>();
//        VerifiableEncryption vEnc1 = pEnc1.getEncryption();
//        VerifiableEncryption vEnc2 = pEnc2.getEncryption();
//        vev.put("jd2e0asfdkkj3rqq1", vEnc1);
//        vev.put("39asxz0x09dfsdka2", vEnc2);
//
//        Verifier verifier = new Verifier(spec, p, nonce, msgs, comms, reps, vev);
//        if (!verifier.verify()) {
//            fail("The proof does not verify");
//        } else {
//            System.out.println(PROOF_VERIFIED);
//        }
//
//        // shows the values that have been revealed during the proof
//        HashMap<String, BigInteger> revealedValues = verifier
//                .getRevealedValues();
//        outputRevealedValues(revealedValues);
//    }
//
//    /**
//     * @param revealedValues
//     */
//    private static final void outputRevealedValues(
//            HashMap<String, BigInteger> revealedValues) {
//        Iterator<String> it = revealedValues.keySet().iterator();
//        System.out.println("Revealed values...");
//        while (it.hasNext()) {
//            String key = it.next();
//            System.out.println("\t" + key + "\t"
//                    + Utils.logBigInt(revealedValues.get(key)));
//        }
//        System.out.println(ENDING);
//    }
}

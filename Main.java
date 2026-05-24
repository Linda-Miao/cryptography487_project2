/*
 * WHAT: Main.java is the entry point of the application.
 *       It reads a command from args[0] and runs the matching service.
 * WHY:  The project spec requires all services to be accessible
 *       from the command line via the args[] argument.
 * HOW:  Switch on args[0] to call the right service method.
 *       Each service reads its inputs from args[1], args[2], etc.
 *
 * Usage:
 *   java Main keygen  <passphrase> <pubkeyfile>
 *   java Main encrypt <pubkeyfile> <inputfile>  <outputfile>
 *   java Main decrypt <passphrase> <inputfile>  <outputfile>
 *   java Main sign    <passphrase> <inputfile>  <sigfile>
 *   java Main verify  <pubkeyfile> <inputfile>  <sigfile>
 */

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {

    // the curve — created once, shared by all services
    static Edwards E = new Edwards();

    // the generator point G — starting point for all crypto operations
    static Edwards.Point G = E.gen();

    public static void main(String[] args) throws Exception {

        // make sure the user gave at least one argument (the command)
        if (args.length < 1) {
            System.out.println("Usage:");
            System.out.println("  java Main keygen  <passphrase> <pubkeyfile>");
            System.out.println("  java Main encrypt <pubkeyfile> <inputfile> <outputfile>");
            System.out.println("  java Main decrypt <passphrase> <inputfile> <outputfile>");
            System.out.println("  java Main sign    <passphrase> <inputfile> <sigfile>");
            System.out.println("  java Main verify  <pubkeyfile> <inputfile> <sigfile>");
            return;
        }

        // route to the correct service based on the command
        switch (args[0]) {
            case "keygen":
                keygen(args[1], args[2]);
                break;
            case "encrypt":
                encrypt(args[1], args[2], args[3]);
                break;
            case "decrypt":
                decrypt(args[1], args[2], args[3]);
                break;
            case "sign":
                sign(args[1], args[2], args[3]);
                break;
            case "verify":
                verify(args[1], args[2], args[3]);
                break;
            case "signencrypt":
                signencrypt(args[1], args[2], args[3],args[4]);
                break;
            case "decryptverify":
                decryptverify(args[1], args[2], args[3], args[4]);
                break;
            default:
                System.out.println("Unknown command: " + args[0]);
        }
    }

    // ── HELPER: derive private key s from a passphrase ───────────────────────
    /*
     * WHAT: Converts a passphrase string into a private key scalar s.
     * WHY:  Used by keygen, decrypt, and sign — all need s from passphrase.
     *       Putting it in one helper avoids repeating the same code 3 times.
     * HOW:  Init SHAKE-128, absorb passphrase bytes, squeeze 48 bytes (384 bits),
     *       convert to BigInteger, reduce mod r.
     */
    static BigInteger derivePrivateKey(String passphrase) {
        // convert passphrase string to bytes using UTF-8 encoding
        byte[] passphraseBytes = passphrase.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // init SHAKE-128 and absorb the passphrase bytes
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(passphraseBytes);

        // squeeze 48 bytes (384 bits) — twice the size of r for uniform distribution
        byte[] squeezed = sponge.squeeze(48);

        // convert bytes to BigInteger and reduce mod r
        // new BigInteger(1, bytes) treats bytes as positive (unsigned)
        return new BigInteger(1, squeezed).mod(E.r);
    }

    // ── SERVICE 1: keygen ────────────────────────────────────────────────────
    /*
     * WHAT: Generates an elliptic key pair (s, V) from a passphrase
     *       and writes the public key V to a file.
     * WHY:  V is needed by others to encrypt messages to you,
     *       or to verify your signatures.
     * HOW:  1. Derive private key s from passphrase via SHAKE-128
     *       2. Compute public key V = s * G
     *       3. If LSB of V.x is 1: flip s = r - s, V = -V
     *          (ensures V.x is always even — canonical form)
     *       4. Write V.y and LSB of V.x to the public key file
     *
     * @param passphrase  the secret passphrase
     * @param pubkeyFile  path to write the public key to
     */
    static void keygen(String passphrase, String pubkeyFile) throws Exception {

        // step 1: derive private key s from passphrase
        BigInteger s = derivePrivateKey(passphrase);

        // step 2: compute public key V = s * G
        Edwards.Point V = G.mul(s);

        // step 3: if LSB of V.x is 1, negate both s and V
        // this gives V a canonical form where V.x is always even
        if (V.x.testBit(0)) {
            s = E.r.subtract(s);   // s = r - s
            V = V.negate();        // V = -V
        }

        // step 4: write public key to file
        // we store: y-coordinate and the LSB of x (0 or 1)
        // LSB of x is always 0 here due to step 3, but we store it for completeness
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(pubkeyFile))) {
            oos.writeObject(V.y);           // write y coordinate
            oos.writeBoolean(V.x.testBit(0)); // write LSB of x
        }

        System.out.println("Key pair generated successfully.");
        System.out.println("Public key written to: " + pubkeyFile);
        System.out.println("Public key V = " + V);
    }

    // -- HELPER: read all bytes from a file ---
    /*
    WHAT: Reads all bytes from a file into a byte array
    WHY: encrypt, decrypt, sign and verify all need to read file contents
        one helper avoids repeating the same code everywhere.
    HOW: used java's built-in Files. readAllBytes(). 
    */
    static byte[] readFile(String path) throws Exception {
        return java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path));
    }

    //-- HELPER: write bytes to a file ---
    /*
    WHAT: writes a byte array to a file.
    WHY: encrypt, decrypt, sign all need to write output files.
    HOW: uses java's built-in Files.write().
    */
    static void writeFile(String path, byte[] data) throws Exception {
        java.nio.file.Files.write(
            java.nio.file.Paths.get(path), data);
    }

    // --HELPER: load public key from file---
    /*
    WHAT: Reads a public key(V) from a file written by keygen.
    WHY: encrypt and verify both need to load a public key from a file.
    HOW: reads y-coordinate and x LSB, then calls getPoint() to reconstruct the full point V.
    */
    static Edwards.Point loadPublicKey(String pubkeyFile) throws Exception{
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(pubkeyFile))){
            BigInteger y = (BigInteger) ois.readObject();
            boolean xLsb = ois.readBoolean();
            return E.getPoint(y,xLsb);
            }
    }

    // -- SERVICE 2: encrypt ---
    /*
    WHAT: Encrypts a file using ECIES under a recipient's public key.
    WHY: only the recipient (who knows the matching passphrase) can decrypt.
    HOW: from the spec: 
        1: pick random k mod r
        2: W= k*V, Z = k*G
        3: SHAK-256(W.y) -> ka(32 bytes), ke(32 bytes)
        4: c = message XOR SHAKE-128(ke)
        5: t = SHA-3-256(ka || c)
        6: write (Z,c,t) to output file
    @param pubkeyFile recipient's public key file
    @param inputFile plaintext file to encrypt
    @param outputFile where to write to ciphertext
    */
    static void encrypt(String pubkeyFile, String inputFile,
                        String outputFile) throws Exception{
        Edwards.Point V = loadPublicKey(pubkeyFile); // laod recipent's public key V
        byte[] message = readFile(inputFile); // read the message bytes
        // step 1: pick random k mod r
        // use twice as many bytes as r for uniform distribution
        int rbytes = (E.r.bitLength() + 7) >> 3;
        BigInteger k = new BigInteger(
            new SecureRandom().generateSeed(rbytes << 1)).mod(E.r);
        // step 2: compute W = k*V and Z = k*G
        Edwards.Point W = V.mul(k);
        Edwards.Point Z = G.mul(k);

        //Step 3: derive ka and ke from W.y using SHAKE-256; absorb W.y, squeeze 32 bytes for ka, then 32 bytes for ke
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(256);
        sponge.absorb(W.y.toByteArray());
        byte[] ka = sponge.squeeze(32); // authentication key
        byte[] ke = sponge.squeeze(32); // encryption key

        // step 4: encrypt message by XOR with SHAKE - 128(ke)
        // squeeeze exactly as many bytes as the message length
        sponge.init(128);
        sponge.absorb(ke);
        byte[] keystream = sponge.squeeze(message.length);
        //XOR keystream with message to get ciphertext x
        byte[] c = new byte[message.length];
        for (int i = 0; i < message.length; i++){
            c[i] = (byte) (message[i] ^ keystream[i]);
        }

        // step 5: compute authentication tag t = SHA-3-256(ke || c)
        sponge.init(256);
        sponge.absorb(ka);
        sponge.absorb(c);
        byte[] t = sponge.digest();
        //step 6: write cryptogram(Z, c, t) to output file
        try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(outputFile))){
            oos.writeObject(Z.y); // Z point y-coordinate
            oos.writeBoolean(Z.x.testBit(0)); // Z point x LSB
            oos.writeObject(c); // ciphertext
            oos.writeObject(t); // authentication tag
        }
        System.out.println("Encryption successful.");
        System.out.println("Ciphertext written to: " + outputFile);

        }

        // -- SERVICE 3: decrypt ---
        /*
        WHAT: Decrypts an ECIES-encrypted file using a passphrase.
        WHY: only the person who knows the passphrase can decrypt.
        HOW: from the spec: 
            1: recompute private key s from passphrase
            2: W = s*Z (recomputes the shred secret)
            3: SHAKE-256(W.y) -> ke, ke (same as encryption)
            4: t' = SHA-3-256(ke || c)
            5: only if t' == t: decrypt c XOR SHAKE-128(ke)-> message
            6: if t' !=t: reject (authentication failed)
         @param passphrase the scret passphrase
         @param inputFile the encrypted file (cipher.bin)
         @param outputFile where to write the decrypted message
        */
        static void decrypt(String passphrase, String inputFile,
                            String outputFile) throws Exception {
            // step 1: recompute private key s from passphrase
            BigInteger s = derivePrivateKey(passphrase);

            // read the cryptogram(Z, c, t) from the input file
            BigInteger Zy;
            boolean Zxlsb;
            byte[] c, t;
            try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(inputFile))){
                    Zy = (BigInteger) ois.readObject(); // Z y-coordinate
                    Zxlsb = ois.readBoolean(); // Z x LSB
                    c = (byte[]) ois.readObject(); // ciphertext
                    t = (byte[]) ois.readObject(); // authentication tag
            }
            // reconstruct point Z from its stored y and x LSB
            Edwards.Point Z = E.getPoint(Zy, Zxlsb);
            // step 2: recompute shred secret W = s*Z
            // this works because s*(k*G) = k*(s*G) = k*V
            Edwards.Point W = Z.mul(s);
            // step 3: re-derive ka and ke from W.y - identical to encryption
            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(256);
            sponge.absorb(W.y.toByteArray());
            byte[] ka = sponge.squeeze(32); // authentication key
            byte[] ke = sponge.squeeze(32); // encryption key
            // step 4: recompute expected tag t' = SHA-3-256 (ka || c)
            sponge.init(256);
            sponge.absorb(ka);
            sponge.absorb(c);
            byte[] tPrime = sponge.digest();
            // step 5: check t' == t BEFORE decrypting
            // if tags don;e match, data was tampered - reject immediately
            if (!java.util.Arrays.equals(t, tPrime)) {
                System.out.println("Decryption error: authentication tag mismatch.");
                System.out.println("The file may have been tampered with.");
                return;
            }
            // step 6: decrypt c XOR SHAKE-128(ke) -> message
            sponge.init(128);
            sponge.absorb(ke);
            byte[] keystream = sponge.squeeze(c.length);
            byte[] message = new byte[c.length];
            for (int i = 0; i < c.length; i++) {
                message[i] = (byte)(c[i] ^ keystream[i]);
            }

            // write decrypted message to output file
            writeFile(outputFile, message);
            System.out.println("Decryption successful.");
            System.out.println("Decrypted message written to: " + outputFile);
        }

        // -- SERVICE 4: sign --
        /*
        WHAT: Signs a file using schnorr sighnatures under a passphrase
        WHY: lets the recipient verify the message really came from you.
        HOW: from the spec: 
            1: recompute private key s from passphrase
            2: pick random k mod r
            3: U = k*G
            4: h = SHA-3-256(U.y || message) mod r
            5: z = (k - h*s) mod r
            6: write signature (h,z) to file
         @param passphrase the secrete passphrase
         @param inputFile the file to sign
         @param sigFile where to write the signature
        */
        static void sign(String passphrase, String inputFile,
                        String sigFile) throws Exception{
            // Step 1: recompute private key s from passphrase
            BigInteger s = derivePrivateKey(passphrase);
            // read the message bytes to sign
            byte[] message = readFile(inputFile);
            // step 2: pick random k mod r
            // use twice as many bytes as r for uniform distribution
            int rbytes = (E.r.bitLength() + 7) >> 3;
            BigInteger k = new BigInteger(
                new SecureRandom().generateSeed(rbytes << 1)).mod(E.r);
            // step 3: compute U = k*G
            Edwards.Point U = G.mul(k);
            // step 4: h = SHA-3-256(U.y || message) mod r
            // absorb U.y first, then the message bytes
            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(256);
            sponge.absorb(U.y.toByteArray());
            sponge.absorb(message);
            byte[] hBytes = sponge.digest();

            // convert digest to BigInteger and reduce mod r
            BigInteger h = new BigInteger(1, hBytes).mod(E.r);
            // step 5; z = (k - h*s) mod r
            BigInteger z = k.subtract(h.multiply(s)).mod(E.r);

            // step 6: write signature (h,z) to file
            try(ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(sigFile))){
                oos.writeObject(h); // hash component
                oos.writeObject(z); // response component
            }

            System.out.println("Signing successful");
            System.out.println("Signature written to: " + sigFile);
                        }
        // -- SERVICE 5: verify --
        /*
        WHAT: verifies a Schonrr signature on a file under public key. 
        WHY: lets anyone confirm the message was signed by the private key
             matching the given public key - without knowing the passphrase.
        HOW: From the spec:
            1: load public key V from file
            2: load signature (h,z) from sig file
            3: U' = z*G + h*V
            4: h' = SHA-3-256(U'.y || message) mod r
            5: Accept if h' == h, reject otherwise
         @param pubkeyFile the signer's public key file
         @param inputFile the file that was signed
         @param sigFile the signature file to verify
        */
        static void verify(String pubkeyFile, String inputFile, String sigFile) throws Exception{
            // load the signer's public key V
            Edwards.Point V = loadPublicKey(pubkeyFile);
            // read the message bytes
            byte[] message = readFile(inputFile);
            // read the signature (h,z) from the sig file
            BigInteger h,z;
            try(ObjectInputStream ois = new ObjectInputStream(new FileInputStream(sigFile))){
                h = (BigInteger) ois.readObject(); // hash component
                z = (BigInteger) ois.readObject(); // response component
            }
            // step 3: compute U' = z*G + h*V
            // if signature is valid, U' should equal the orignal U from signing
            Edwards.Point U1 = G.mul(z); // z*G
            Edwards.Point U2 = V.mul(h); // h*V
            Edwards.Point Uprime = U1.add(U2); // U' = z*G + h*V

            // step 4: h' = SHA-3-256(U'.y || message) mod r
            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(256);
            sponge.absorb(Uprime.y.toByteArray());
            sponge.absorb(message);
            byte[] hPrimeBytes = sponge.digest();

            //convert to BigInteger and reduce mod r
            BigInteger hPrime = new BigInteger(1, hPrimeBytes).mod(E.r);
            // step 5; accept if h' == h
            if(hPrime.equals(h)){
                System.out.println("Signature is VALID.");
            } else {
                System.out.println("Signature is INVALID.");
            }
        }
        // -- BONUS SERVICE 1: signencrypt --
        /*
        WHAT: signs a file then encrypts both the file and signature together
        WHY: provides both confidentiality (only recipient can read)
            and authenticity (recipient can verify sender).
        HOW: 1: sign inputFile with sender's passphrase -> signature
             2: combine message + signature into one byte array
             3: encrypt the combined data under recipient's public key
         @param senderPass sender's passphrase (for signing) 
         @param pubkeyFile recipient's public key file (for encrypting)
         @param inputFile the file to sign and encrypt
         @param outputFile where to write the encrypted output
        */
        static void signencrypt(String senderPass, String pubkeyFile,
                                String inputFile, String outputFile) throws Exception {
            // step 1: sign the message with sender's private key 
            BigInteger s = derivePrivateKey(senderPass);
            byte[] message = readFile(inputFile);
            // pick random k for signing
            int rbytes = (E.r.bitLength() + 7) >> 3;
            BigInteger k = new BigInteger(
                new SecureRandom().generateSeed(rbytes << 1)).mod(E.r);
            Edwards.Point U = G.mul(k);
            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(256);
            sponge.absorb(U.y.toByteArray());
            sponge.absorb(message);
            byte[] hBytes = sponge.digest();
            BigInteger h = new BigInteger(1, hBytes).mod(E.r);
            BigInteger z = k.subtract(h.multiply(s)).mod(E.r);

            // step 2: srialize message + signature (h,z) into one byte array
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(message); // orignal message
            oos.writeObject(h); // signature h
            oos.writeObject(z); // signature z
            oos.flush();
            byte[] combined = baos.toByteArray();

            // step 3: enctrypt the combined data under recipient's public key
            Edwards.Point V = loadPublicKey(pubkeyFile);
            BigInteger k2 = new BigInteger(
                new SecureRandom().generateSeed(rbytes << 1)).mod(E.r);
            Edwards.Point W = V.mul(k2);
            Edwards.Point Z = G.mul(k2);

            sponge.init(256);
            sponge.absorb(W.y.toByteArray());
            byte[] ka = sponge.squeeze(32);
            byte[] ke = sponge.squeeze(32);
            sponge.init(128);
            sponge.absorb(ke);
            byte[] keystream = sponge.squeeze(combined.length);
            byte[] c = new byte[combined.length];
            for (int i = 0; i < combined.length; i++){
                c[i] = (byte)(combined[i] ^ keystream[i]);
            }
            sponge.init(256);
            sponge.absorb(ka);
            sponge.absorb(c);
            byte[] t = sponge.digest();
            try(ObjectOutputStream out = new ObjectOutputStream(
                new FileOutputStream(outputFile))){
                out.writeObject(Z.y);
                out.writeBoolean(Z.x.testBit(0));
                out.writeObject(c);
                out.writeObject(t);
            }
            System.out.println("Sign+Encrypt successful.");
            System.out.println("Output written to: " + outputFile);
        }

        // -- BONUS SERVICE 2: decryptverify --
        /*
        WHAT: decrypts a file and verifies the embedded signature.
        WHY: undoes signencrypt - recovers message and confirms sender.
        HOW: 1: decrypt the file with recipient's passphrase
             2: extract message and signature(h,z) from decrypted data
             3: verify signature under sender's public key
         @param recipientPass recipient's passphrase (for decrypting)
         @param senderPubkey sender's public key file (foe veryfying)
         @param outputFile where to write the decrypted message
        */
        static void decryptverify(String recipientPass, String senderPubkey,
                                 String inputFile, String outputFile)throws Exception {
        // step 1: decrypt with recipient's private key
        BigInteger s = derivePrivateKey(recipientPass);
        BigInteger Zy;
        boolean Zxlsb;
        byte[] c, t;
        try(ObjectInputStream ois = new ObjectInputStream(
               new FileInputStream(inputFile))){
            Zy = (BigInteger) ois.readObject();
            Zxlsb = ois.readBoolean();
            c = (byte[]) ois.readObject();
            t = (byte[]) ois.readObject();
            }
            Edwards.Point Z = E.getPoint(Zy, Zxlsb);
            Edwards.Point W = Z.mul(s);
            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(256);
            sponge.absorb(W.y.toByteArray());
            byte[] ka = sponge.squeeze(32);
            byte[] ke = sponge.squeeze(32);
            sponge.init(256);
            sponge.absorb(ka);
            sponge.absorb(c);
            byte[] tPrime = sponge.digest();
            if(!java.util.Arrays.equals(t,tPrime)){
                System.out.println("Decreyption error: authentication tag mismatch.");
                return;
            }
            sponge.init(128);
            sponge.absorb(ke);
            byte[] keystream = sponge.squeeze(c.length);
            byte[] combined = new byte[c.length];
            for (int i=0; i < c.length; i++){
                combined[i] = (byte)(c[i]^ keystream[i]);
            }
            // step 2: extract message and signature from decrypted data
            ObjectInputStream ois2 = new ObjectInputStream(
                new ByteArrayInputStream(combined));
            byte[] message = (byte[]) ois2. readObject();
            BigInteger h = (BigInteger) ois2.readObject();
            BigInteger z = (BigInteger) ois2.readObject();
            // step 3: verify signature under sender's public key
            Edwards.Point V = loadPublicKey(senderPubkey);
            Edwards.Point U1 = G.mul(z);
            Edwards.Point U2 = V.mul(h);
            Edwards.Point Uprime = U1.add(U2);
            sponge.init(256);
            sponge.absorb(Uprime.y.toByteArray());
            sponge.absorb(message);
            byte[] hPrimeBytes = sponge.digest();
            BigInteger hPrime = new BigInteger(1, hPrimeBytes).mod(E.r);

           // write the recovered message
           writeFile(outputFile, message);
           System.out.println("Decryption successful.");
           System.out.println("Decrypted message written to: " + outputFile);

           if (hPrime.equals(h)) {
               System.out.println("Signature is VALID.");
            } else {
               System.out.println("Signature is INVALID.");
            }
        }
}
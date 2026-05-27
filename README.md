# TCSS 487 — Cryptography, Project 2

**Authors:** Rudolf Arakelyan (rudik30), Linda Miao
**Topic:** NUMS-256 Edwards curve + ECIES public-key encryption + Schnorr signatures

This is Part 2 of the course project. It builds the asymmetric layer on top of
the SHA-3 / SHAKE sponge from Part 1.

For the full write-up (design, testing, known limitations) see **TCSS487_Project2_Report.pdf**.

## Files

| File             | Purpose                                                 |
|------------------|---------------------------------------------------------|
| `Main.java`      | CLI dispatcher + 7 services + small helpers             |
| `Edwards.java`   | NUMS-256 curve + nested `Point` class (Appendix D spec) |
| `SHA3SHAKE.java` | FIPS-202 SHA-3 / SHAKE sponge (from Part 1)             |
| `TCSS487_Project2_Report.pdf`     | Required project report                                 |
| `README.md`      | This file                                               |

## Build

Requires Java 11 or newer (uses `BigInteger.TWO`).

```sh
javac *.java
```

No external dependencies — only `java.math`, `java.io`, `java.nio`, `java.security`.

## Commands

```
java Main keygen        <passphrase>    <pubkeyfile>
java Main encrypt       <pubkeyfile>    <inputfile>    <outputfile>
java Main decrypt       <passphrase>    <inputfile>    <outputfile>
java Main sign          <passphrase>    <inputfile>    <sigfile>
java Main verify        <pubkeyfile>    <inputfile>    <sigfile>
java Main signencrypt   <senderpass>    <recipientpub> <inputfile> <outputfile>   # BONUS
java Main decryptverify <recipientpass> <senderpub>    <inputfile> <outputfile>   # BONUS
```

Running `java Main` with no arguments prints the same cheat-sheet.

## End-to-end example

```sh
# 1. Each party generates a key pair.
java Main keygen aliceSecret alice_pub.key
java Main keygen bobSecret   bob_pub.key

# 2. Alice encrypts a message for Bob using his public key.
echo "Hello Bob, this is Alice." > note.txt
java Main encrypt bob_pub.key note.txt note.enc

# 3. Bob decrypts using his own passphrase.
java Main decrypt bobSecret note.enc note.out
cat note.out                       # -> Hello Bob, this is Alice.

# 4. Alice signs the file.
java Main sign aliceSecret note.txt note.sig

# 5. Anyone with Alice's public key can verify.
java Main verify alice_pub.key note.txt note.sig
# -> Signature is VALID.

# 6. BONUS: Alice signs AND encrypts in one shot for Bob.
java Main signencrypt aliceSecret bob_pub.key note.txt sealed.bin

# 7. BONUS: Bob decrypts AND verifies in one shot.
java Main decryptverify bobSecret alice_pub.key sealed.bin opened.txt
# -> Decryption successful.
# -> Signature is VALID.
```

## Notes

- All classes live in the **default (unnamed) package**, as required by the
  spec.
- All filenames and passphrases come from `String[] args`.
- **No JUnit**, no third-party libraries, no `.class`/`.jar`/`.exe` files in
  the submission.
- The MAC in ECIES is over the **ciphertext** (per the explicit DHIES-paper
  erratum in the project handout).
- `decrypt` and `decryptverify` check the authentication tag **before**
  writing any plaintext — a tampered or wrong-key file produces no output.

## Known limitations

None functional. See **TCSS487_Project2_Report.pdf §6** for design-level limitations
(in-memory file I/O, non-constant-time scalar mul, Java-only key-file format).

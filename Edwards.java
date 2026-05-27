// TCSS 487 Cryptography Project 2
// Authors: Rudolf Arakelyan (rudik30) and Linda Miao

/*
 * WHAT: Defines the NUMS ed-256-mers* Edwards elliptic curve and its
 *       nested Point class implementing the curve arithmetic.
 * WHY:  Every operation in this project (encryption, signatures, key generation)
 *       depends on these three numbers:
 *         - p: all point coordinates (x, y) are computed mod p
 *         - d: the curve shape coefficient in x^2 + y^2 = 1 + d*x^2*y^2
 *         - r: all private keys and nonces are computed mod r
 * HOW:  The Edwards constructor hard-codes the NUMS-256 parameters from the
 *       project spec using java's BigInteger class, which handles arbitrarily
 *       large integers precisely (these numbers are ~256 bits, far too big
 *       for int or long).
 */

import java.math.BigInteger;

public class Edwards {
    // -- Curve constants --
    // p is the field modulus: all x and y coordinates are integers mod p.
    // p = 2^256 - 189, which is a prime number (~78 demical digits).
    // every time we add, subtract. or multiply coordinates, we take mod p.
    final BigInteger p;

    // d is the curve coefficient in the equation: x^2 + y^2 = 1 + d * x^2 * y^2
    // for NUM-256, d = 15343, this specific value makes the curve cryptographically secure and ensures the addition formul always works.
    final BigInteger d;

    // r is the grou order: the number of points on the curve divided by 4. it is a prime number (~254 bits)
    // private keys, nonces (k), and signature scalars are all integer mod r.
    // Important: p is for coordinates, r is for scalars = don't mix them up!
    final BigInteger r;

    // -- Constructor ---
    /*
    Creates an instance of the NUMS-256 curve by initializing p,d and r to their exact values from the project spec.
    called once at the start of Main.java; Edwards E = new Edwards();
    */
    public Edwards() {
        // p = 2^256 - 189; BigInteger.TWO.pow(256) computes 2^256 exactly (no floating point).
        // .subtract() then subtracts 189 to get the prime p
        p = BigInteger.TWO.pow(256).subtract(BigInteger.valueOf(189));

        d = BigInteger.valueOf(15343); // d = 15343 (fits in a regular long, so valueOF() is fine here)
        
        // r = 2^254 - 87175310462106073678594642380840586067
        // the long nuber is tooo big for valueOf(), so we pass it as a string. 
        // new BigInteger("...) parses a decimal string into a BigInteger
        r = BigInteger.TWO.pow(254)
            .subtract(new BigInteger("87175310462106073678594642380840586067"));
    }

    //-- toString---
    // returns a human-readabl description of this curve. Useful for printing and debugging
    // i.g. output: NUMS ed-256-mers*: x^2 + y^2 = 1 + 15343*x^2*y^2 mod 115792...
    public String toString(){
        return "NUMS ed-256-mers*: x^2 + y^2 = 1 + " + d + " * x^2 * y^2 mod " + p;
    }
    /*
    WHAT: Computes a square root of v mod p. 
    WHY: We need this to recover the x-coordinate of G from its y-coordinate.
        Java's BigInteger has no built-in square root mod p method
    HOW: uses the formula r = v^((p+1)/4) mod p, which works because p mod 4 = 3 for the NUMS-256 prime.
        then checks if r*r == v mod p (root might not exist)
        lsb controls whether we want to even or add root.
    */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb){
        // p must satisfy p mod 4 = 3 for this formula to work
        assert (p.testBit(0) && p.testBit(1));
        // if v = 0, the only square root is 0
        if (v.signum() == 0){
            return BigInteger.ZERO;
        }

        // compute r = v^((p+1)/4) mod p
        // this is the candidate square root
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);

        // if the least. significant bit does not match what we want, flip to p - r
        if (r.testBit(0) != lsb){
            r = p.subtract(r);
        }
        // verify r is actually a square root: r*r mod must equal v
        // if not, no square root exists - return null
        return (r.multiply(r).subtract(v).mod(p).signum() ==0) ? r: null;
    }
    /*
    WHAT: finds and returns the generator point G on the NUMS - 256 curve.
    WHY: G is starting point for all cryptographic operations. every public key, encrytion
        , and signature starts with G.
    HOW: The spec says H has y0 = -4 mod p, and x0 is the unique even square root of (1-y0^2)/(1-d*y0^2) mod p
        it compute that radicand and call sqrt() with lsb=false (even x)
    */
    public Point gen() {
        // y0 = -4 mod p = p - 4
        BigInteger y0 = p.subtract(BigInteger.valueOf(4));
        // compute numerator: 1 - y0^2 mod p
        BigInteger num = BigInteger.ONE
            .subtract(y0.multiply(y0)).mod(p);
        // compute denominator: 1 - d*y0^2 mod p
        BigInteger den = BigInteger.ONE
            .subtract(d.multiply(y0).multiply(y0)).mod(p);

        // radcand = num * den^(-1) mod p
        // (division = multiple by modular inverse)
        BigInteger radicand = num
            .multiply(den.modInverse(p)).mod(p);

        // x0 = even square root of radican mod p (lsb = false means even)
        BigInteger x0 = sqrt(radicand, p, false);
        // return the generator point G = (x0, y0)
        return new Point(x0, y0);
    }
    /*
    WHAT: Checks if a given (x,y) pair is actually a point on the curve. 
    WHY: Used to validate points received from outside (e.g. a public key loaded from a file). A bad point would break all crypto operation.
    HOW: plugs x and y into the curve equation and check both sides match:
        x^2 + y^2 == 1 + d*x^2*y^2(mod p)
    */
    public boolean isPoint(java.math.BigInteger x, java.math.BigInteger y){
        // compute x^2 mod p and y^2 mod p
        java.math.BigInteger x2 = x.multiply(x).mod(p);
        java.math.BigInteger y2 = y.multiply(y).mod(p);

        // left size: x^2 + y^2 mod p
        java.math.BigInteger left = x2.add(y2).mod(p);
        // right side: 1 + d*x^2*y^2 mod p
        java.math.BigInteger right = java.math.BigInteger.ONE
            .add(d.multiply(x2).multiply(y2)).mod(p);
        return left.equals(right);
    }

    /*
    WHAT: Recover a full point (x,y) from just its y-coordinate and the leat significant bit (LSB) of x.
    WHY: Public keys are stored compactly as (y, x_lsb) instead of storing the full x (which is 256 bits). 
        this method reconstructs the full point when loading a public key from a file.
    HOW: Rearranges the curve equation t solve for x:
        x^2 = (1-y^2) / (1-d*y^2) mod p
        then takes the square root with the correct LSB.
        returns neutral element 0 if no valid point exists.
    */
    public Point getPoint(java.math.BigInteger y, boolean x_lsb){
        // compute y^2 mod p
        java.math.BigInteger y2 = y.multiply(y).mod(p);
       // numerator: 1 - y^2 mod p
        java.math.BigInteger num = java.math.BigInteger.ONE
            .subtract(y2).mod(p);

        // denominator: 1 - d*y^2 mod p
        java.math.BigInteger den = java.math.BigInteger.ONE
            .subtract(d.multiply(y2)).mod(p);

        // radicand = num * den^(-1) mod p
        java.math.BigInteger radicand = num
            .multiply(den.modInverse(p)).mod(p);

        // compute square root with the desired LSB
        java.math.BigInteger x = sqrt(radicand, p, x_lsb);
        // if no square root exists, return neutral element 0
        if(x == null) {
            return new Point();
        }

        // verify (x, y) is actually on the curve
        if(!isPoint(x,y)){
            return new Point();
        }
        // spec (Appendix D) requires the returned point to have order r.
        // a point P has order dividing r iff r*P = O. since r is prime,
        // a non-O point with r*P = O has order exactly r — exactly what we want.
        // this rejects low-order points and protects against small-subgroup attacks.
        Point P = new Point(x, y);
        if (!P.mul(r).isZero()) {
            return new Point();
        }
        return P;
    }
    /* 
    WHAT: Point reprecents a single point (x,y) on the Edwards curve
    WHY: All cryptographic operations (encryption, signing, key generation)
        work by adding and multiplying points on the curve. each point needs its own x and y coordinates stored together.
    HOW: Point is a nested class inside Edwards class without passing them around everwhere
    */
    public class Point {
        // the x and y coordinates of this point, stored as BigIntegers. 
        // all values are in the range 0... p-1 (they are reduced mod p)
        final BigInteger x; 
        final BigInteger y;

        /*
        WHAT: Creates the neutral element 0 = (0,1).
        WHY: 0 is the 'zero' of elliptic curve addition. p + 0 = p for any point p.
        HOW: Sets x = 0 and y = 1, which satisfies the curve equation: 0^2+1^2 = 1+d*0^2*1^2 -> 1 = 1 ✓
        */

        public Point(){
            x = BigInteger.ZERO;
            y = BigInteger.ONE;
        }
        /*
        WHAT: Creates a point with specific coordinates (x ,y).
        WHY: used internally when addition or multiplication produces a new point - wee need. to store its coordinates.
        HOW: directly assigns x and y, private because outside. code should use getPoint() which validates the coordinates first.
         */
        private Point(BigInteger x, BigInteger y){
            this.x = x;
            this.y = y;
        }

        /*
        WHAT: Returns true if this point is the neutral element 0 = (0,1).
        WHY: Several algorithms need to check if a result is 0. i.g.: r * G shold equal 0.
        HOW: checks if x == 0 and y == 1
        */
        public boolean isZero(){
            return x.equals(BigInteger.ZERO) && y.equals(BigInteger.ONE);
        }

        /*
        WHAT: Returns true if this point equals another point p.
        WHY: Needed for all the Appendic C debug tests (e.g. checking that r*G == 0)
        HOW: Two points are equal if their x and y coordinates match.
        */
        public boolean equals(Point P){
            return x.equals(P.x) && y.equals(P.y);
        }

        /*
        WHAT: return the opposite(negation) of this point.
        WHY: On Edwards curves, -p = (-x,y). used in key generation: if LSB of V.x is 1. we replace V with -V
        HOW: Negates x by computing p - x (mod p), y stay the same
        */
        public Point negate(){
            // -x mod p = p - x (keeps the result positive)
            BigInteger negX = p.subtract(x).mod(p);
            return new Point(negX,y);
        }
        /*
        WHAT: Adds this point to another point P using the Edwards formula. 
        WHY: Point is the fundamental operation of elliptic curce cryptography. Every encryption and signature used this.
        HOW: Edwards addition formula from the spec:
            x3 = (x1 * y1 + y1 * x2) / (1 + d * x1 * x2 * y1 * y2) mod p
            y3 = (y1 * y2 - x1 * x2) / (1 - d * x1 * x2 * y1 * y2) mod p
            "Division" in modular math = multiply by modular inverse. this single formula works for all cases:
            P + Q, P + P, P + (-P). 
            No special cases need, that is the beauty of Edwards curves.
        */
        public Point add(Point P){
        // step 1: name the coordinates clearly; this point is (x1, y1), the other point is (x2, y2)
            BigInteger x1 = this.x;
            BigInteger y1 = this.y;
            BigInteger x2 = P.x;
            BigInteger y2 = P.y;

        // step 2: compute the shared factor d*x1*x2*y1*y2 mod p
        // this appears in both denominators
        BigInteger factor = d
            .multiply(x1).mod(p)
            .multiply(x2).mod(p)
            .multiply(y1).mod(p)
            .multiply(y2).mod(p);
        // step 3: compute x3 numerator and enominator
        // x3 numerator = x1*y2 + y1*x2
        BigInteger x3num = x1.multiply(y2)
            .add(y1.multiply(x2)).mod(p);

        // x3 denominato = 1+ factor; modInverse comutes (1+factor)^-1 mod p
        BigInteger x3den = BigInteger.ONE
            .add(factor).mod(p).modInverse(p);
        // x3 = numberator * inverse (denominator) mod p
        BigInteger x3 = x3num.multiply(x3den).mod(p);

        // step 4" compute y3 numerator and denominator; y3 numerator = y1*y2 - x1*x2
        BigInteger y3num = y1.multiply(y2)
            .subtract(x1.multiply(x2)).mod(p);
        // y3 denominator = 1 - factor
        BigInteger y3den = BigInteger.ONE
            .subtract(factor).mod(p).modInverse(p);
        // y3 = numerator * inverse(denominator) mod p
        BigInteger y3 = y3num.multiply(y3den).mod(p);
        // step 5: return the resulting point
        return new Point(x3,y3);
        }
        /*
        WHAT: Multiplies this point by a scalar m, computing mp.
        WHY: Scalar multiplication is how we compute public keys(s*G), encryption ephemeral point (k*G, k*v)
            and signature nonce points (k*G). it is the core operation of the project.
        HOW: Uses the double-and-add algorithm, from Appendix B of the spec. Scans bits of m from high to low:
            - always doble the running result(V = V + V)
            - if the current bit is 1, alsoo add P (V = V + P)
            this runs i O(log m) steps instead of O(m) steps
            NEVER use plain repeated addition , it would take forever with 256-bit scalers (more steps than otoms in the universe)
        */
        public Point mul(BigInteger m) {
            // start with he neutral element 0 = (0,1)
            // this is our running result, like starting a sum at 0
            Point V = new Point();
            // scan every bit of m from the most significant to least significant
            for (int i = m.bitLength() - 1; i >= 0; i--){
                // alwys double: V = V + V
                V = V.add(V);

                // if bit i of m is 1, also add the original point P
                if (m.testBit(i)) {
                    V = V.add(this);
                }
            }
            return V; // V now equals m*p
            
        }
        /* 
        WHAT: Returns a human-readable reprecentation of this point. 
        WHY: usefu for printing and debugging
        HOW: Formats as "(x,y)".
        */
        public String toString(){
            return "(" + x + ", " + y +")";
        }



    }
}


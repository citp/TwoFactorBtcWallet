package threshold.mr04;

import static threshold.mr04.Util.calculateMPrime;
import static threshold.mr04.Util.getBytes;
import static threshold.mr04.Util.isElementOfZn;
import static threshold.mr04.Util.randomFromZn;
import static threshold.mr04.Util.randomFromZnStar;
import static threshold.mr04.Util.sha256Hash;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import threshold.mr04.data.PublicParameters;
import threshold.mr04.data.Round1Message;
import threshold.mr04.data.Round2Message;
import threshold.mr04.data.Round3Message;
import threshold.mr04.data.Round4Message;

public class Alice implements Serializable {

	transient private ECDomainParameters CURVE;
    private final BigInteger q;
    private final byte[] gRaw;
    private final byte[] qRaw;
    private final int kPrime;
    private BigInteger h1;
    private BigInteger h2;
    private BigInteger g;
    private BigInteger N;
    private BigInteger nHat;
    private BigInteger Nsquared;
    Paillier paillier;
    BigInteger gPrime;
    BigInteger nPrime;
    BigInteger nPrimeSquared;

    private final BigInteger keyShare;
    private final SecureRandom rand;
    private final PaillierPublicKey alicesPaillierPubKey;

    private BigInteger kAlice;
    private BigInteger ciphertext1;
    private BigInteger ciphertext2;
    // the random values used for the Paillier ciphertexts
    private BigInteger zAlice;
    private BigInteger r1;
    private BigInteger r2;
    private byte[] rRaw;
    BigInteger rPrime;
    BigInteger mPrime;

    public Alice(BigInteger keyShare, byte[] publicKey, SecureRandom rand, Paillier paillier, PublicParameters params) {
        this.rand = rand;
        this.keyShare = keyShare;
        this.paillier = paillier;
        X9ECParameters CURVEparams = SECNamedCurves.getByName("secp256k1");
        this.CURVE = new ECDomainParameters(CURVEparams.getCurve(), CURVEparams.getG(), CURVEparams.getN(),
        		CURVEparams.getH());
        this.q = params.q;
        this.gRaw = params.G(this.CURVE.getCurve()).getEncoded();
        this.kPrime = params.kPrime;
        this.h1 = params.h1;
        this.h2 = params.h2;
        g = params.alicesPaillierPubKey.g;
        N = params.alicesPaillierPubKey.N;
        this.nHat = params.nHat;
        Nsquared = N.pow(2);
        gPrime = params.otherPaillierPubKey.g;
        nPrime = params.otherPaillierPubKey.N;
        nPrimeSquared = nPrime.pow(2);
        qRaw = CURVE.getCurve().decodePoint(publicKey).getEncoded();
        alicesPaillierPubKey = params.alicesPaillierPubKey;
    }
    
    /**
     * Always treat de-serialization as a full-blown constructor, by
     * validating the final state of the de-serialized object.
     */
     private void readObject(ObjectInputStream aInputStream) throws ClassNotFoundException, IOException {
       //always perform the default de-serialization first
       aInputStream.defaultReadObject();
       X9ECParameters CURVEparams = SECNamedCurves.getByName("secp256k1");
       this.CURVE = new ECDomainParameters(CURVEparams.getCurve(), CURVEparams.getG(), CURVEparams.getN(),
       		CURVEparams.getH());
    }

      /**
      * This is the default implementation of writeObject.
      * Customize if necessary.
      */
      private void writeObject(ObjectOutputStream aOutputStream) throws IOException {
        //perform the default serialization for all non-transient, non-static fields
        aOutputStream.defaultWriteObject();
      }

    public Round1Message aliceToBobRound1(byte[] message) {
        do {
            kAlice = new BigInteger(256, rand);
        } while (kAlice.compareTo(q) != -1);
        zAlice = kAlice.modInverse(q);
        r1 = new BigInteger(kPrime, rand);
        r2 = new BigInteger(kPrime, rand);
        ciphertext1 = Paillier.encrypt(zAlice, alicesPaillierPubKey, r1);
        ciphertext2 = Paillier.encrypt(keyShare.multiply(zAlice).mod(q), alicesPaillierPubKey, r2);

        mPrime = calculateMPrime(q, message);

        return new Round1Message(mPrime, ciphertext1, ciphertext2);
    }

    public Round3Message aliceToBobRound3(Round2Message input) {
        // verify that rBob * q = O
        ECPoint rBob = input.getrBob(CURVE.getCurve());
        if (!rBob.multiply(q).isInfinity()) {
            throw new AssertionError();
        }
        // Ask Rosario. this is the equivalent of cheming that it's in Zp*
        if (rBob.getCurve() != CURVE.getCurve()) {
            throw new AssertionError();
        }
        setR(rBob.multiply(kAlice));
        rPrime = getR().getX().toBigInteger().mod(q);

        
        long startTime = System.nanoTime();
        // first zkp

        BigInteger alpha = randomFromZn(q.pow(3), rand);
        BigInteger beta = randomFromZnStar(N, rand);
        BigInteger gamma = randomFromZn(q.pow(3).multiply(nHat), rand);
        BigInteger rho1 = randomFromZn(q.multiply(nHat), rand);
        BigInteger delta = randomFromZn(q.pow(3), rand);
        BigInteger mu = randomFromZnStar(N, rand);
        BigInteger nu = randomFromZn(q.pow(3).multiply(nHat), rand);
        BigInteger rho2 = randomFromZn(q.multiply(nHat), rand);
        BigInteger rho3 = randomFromZn(q, rand);
        BigInteger epsilon = randomFromZn(q, rand);

        BigInteger x1 = zAlice;
        BigInteger x2 = zAlice.multiply(keyShare).mod(q);
        ECPoint c = getR();
        ECPoint d = getG();
        ECPoint w1 = getR().multiply(zAlice);
        ECPoint w2 = getG().multiply(keyShare);
        BigInteger m1 = ciphertext1;
        BigInteger m2 = ciphertext2;

        BigInteger z1 = h1.modPow(x1, nHat).multiply(h2.modPow(rho1, nHat)).mod(nHat);
        ECPoint u1 = c.multiply(alpha);
        BigInteger u2 = g.modPow(alpha, Nsquared).multiply(beta.modPow(N, Nsquared)).mod(Nsquared);
        BigInteger u3 = h1.modPow(alpha, nHat).multiply(h2.modPow(gamma, nHat)).mod(nHat);
        BigInteger z2 = h1.modPow(x2, nHat).multiply(h2.modPow(rho2, nHat)).mod(nHat);
        ECPoint y = d.multiply(x2.add(rho3));
        ECPoint v1 = d.multiply(delta.add(epsilon));
        ECPoint v2 = w2.multiply(alpha).add(getG().multiply(epsilon));
        BigInteger v3 = g.modPow(delta, Nsquared).multiply(mu.modPow(N, Nsquared)).mod(Nsquared);
        BigInteger v4 = h1.modPow(delta, nHat).multiply(h2.modPow(nu, nHat)).mod(nHat);

        byte[] digest = sha256Hash(getBytes(c), getBytes(w1), getBytes(d), getBytes(w2),
                getBytes(m1), getBytes(m2), getBytes(z1), getBytes(u1), getBytes(u2), getBytes(u3),
                getBytes(z2), getBytes(y), getBytes(v1), getBytes(v2), getBytes(v3), getBytes(v4));

        if (digest == null) {
            throw new AssertionError();
        }

        BigInteger e = new BigInteger(1, digest);

        BigInteger s1 = e.multiply(x1).add(alpha);
        BigInteger s2 = r1.modPow(e, N).multiply(beta).mod(N);
        BigInteger s3 = e.multiply(rho1).add(gamma);
        BigInteger t1 = e.multiply(x2).add(delta);
        BigInteger t2 = e.multiply(rho3).add(epsilon).mod(q);
        BigInteger t3 = r2.modPow(e, Nsquared).multiply(mu).mod(Nsquared);
        BigInteger t4 = e.multiply(rho2).add(nu);
        
        System.out.println("create zkp1: " + (System.nanoTime() - startTime));

        return new Round3Message(getR(), z1, z2, y, e, s1, s2, s3, t1, t2, t3, t4);

    }

    public BigInteger[] aliceOutput(Round4Message input) {
        verifyZkp2(input);
        BigInteger u = input.getU();
        BigInteger s = paillier.decrypt(u).mod(q);
        return new BigInteger[] { rPrime, s };
    }

    private void verifyZkp2(Round4Message input) {
    	long startTime = System.nanoTime();
        ECPoint c = getR().multiply(zAlice);//G.multiply(kBob);
        ECPoint d = getG();
        ECPoint w1 = getG();
        ECPoint w2 = getQ().multiply(keyShare.modInverse(q));//G.multiply(bobShare);
        BigInteger m1 = input.getUPrime();
        BigInteger m2 = input.getU();
        BigInteger m3 = ciphertext1.modPow(mPrime, paillier.nSquared);
        BigInteger m4 = ciphertext2.modPow(rPrime, paillier.nSquared);

        BigInteger z1 = input.getZ1();
        BigInteger z2 = input.getZ2();
        BigInteger z3 = input.getZ3();
        ECPoint y = input.getY(CURVE.getCurve());
        BigInteger e = input.getE();

        BigInteger s1 = input.getS1();
        BigInteger s2 = input.getS2();
        BigInteger s3 = input.getS3();
        BigInteger t1 = input.getT1();
        BigInteger t2 = input.getT2();
        BigInteger t3 = input.getT3();
        BigInteger t4 = input.getT4();
        BigInteger t5 = input.getT5();
        BigInteger t6 = input.getT6();

        // verification
        if (!isElementOfZn(s1, q.pow(3))) {
            throw new AssertionError();
        }

        if (!isElementOfZn(t1, q.pow(3))) {
            throw new AssertionError();
        }

        if (!isElementOfZn(t5, q.pow(7))) {
            throw new AssertionError();
        }

        ECPoint u1Recovered = c.multiply(s1).add(w1.negate().multiply(e));
        BigInteger u2Recovered = gPrime.modPow(s1, nPrimeSquared)
                .multiply(s2.modPow(nPrime, nPrimeSquared))
                .multiply(m1.modPow(e.negate(), nPrimeSquared)).mod(nPrimeSquared);
        BigInteger u3Recovered = h1.modPow(s1, nHat).multiply(h2.modPow(s3, nHat))
                .multiply(z1.modPow(e.negate(), nHat)).mod(nHat);
        ECPoint v1Recovered = d.multiply(t1.add(t2)).add(y.negate().multiply(e));
        ECPoint v2Recovered = w2.multiply(s1).add(d.multiply(t2)).add(y.negate().multiply(e));
        BigInteger v3Recovered = m3.modPow(s1, Nsquared).multiply(m4.modPow(t1, Nsquared))
                .multiply(g.modPow(q.multiply(t5), Nsquared)).multiply(t3.modPow(N, Nsquared))
                .multiply(m2.modPow(e.negate(), Nsquared)).mod(Nsquared);
        BigInteger v4Recovered = h1.modPow(t1, nHat).multiply(h2.modPow(t4, nHat))
                .multiply(z2.modPow(e.negate(), nHat)).mod(nHat);
        BigInteger v5Recovered = h1.modPow(t5, nHat).multiply(h2.modPow(t6, nHat))
                .multiply(z3.modPow(e.negate(), nHat)).mod(nHat);

        byte[] digestRecovered = sha256Hash(getBytes(c), getBytes(w1), getBytes(d), getBytes(w2),
                getBytes(m1), getBytes(m2), getBytes(z1), getBytes(u1Recovered),
                getBytes(u2Recovered), getBytes(u3Recovered), getBytes(z2), getBytes(z3),
                getBytes(y), getBytes(v1Recovered), getBytes(v2Recovered), getBytes(v3Recovered),
                getBytes(v4Recovered), getBytes(v5Recovered));

        if (digestRecovered == null) {
            throw new AssertionError();
        }

        BigInteger eRecovered = new BigInteger(1, digestRecovered);

        if (!e.equals(eRecovered)) {
            throw new AssertionError();
        }
        System.out.println("verifyZkp2: " + (System.nanoTime() - startTime));
    }

    private void setR(ECPoint r) {
    	rRaw = r.getEncoded();
    }
    
    private ECPoint getR() {
    	return CURVE.getCurve().decodePoint(rRaw);
    }
    
    private ECPoint getG() {
    	return CURVE.getCurve().decodePoint(gRaw);
    }
    
    public ECPoint getQ() {
    	return CURVE.getCurve().decodePoint(qRaw);
    }
}

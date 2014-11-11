package threshold.mr04;

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

public class Bob implements Serializable {

	private static final long serialVersionUID = 8800505726362446507L;
	
	public final BigInteger q;
    private final byte[] gRaw;
    private final SecureRandom rand;
    private final BigInteger keyShare;
    private final int kPrime;
    transient private ECDomainParameters CURVE;
    private final BigInteger h1;
    private final BigInteger h2;
    private final BigInteger g;
    private final BigInteger N;
    private final BigInteger nHat;
    private final BigInteger nSquared;
    private final BigInteger gPrime;
    private final BigInteger nPrime;
    private final BigInteger nPrimeSquared;
    private final byte[] qRaw;
    private final PaillierPublicKey alicesPaillierPubKey;
    private final PaillierPublicKey otherPaillierPubKey;

    private BigInteger kBob;
    private byte[] rBobRaw;
    private BigInteger ciphertext1;
    private BigInteger ciphertext2;
    private BigInteger mPrime;

    public Bob(BigInteger keyShare, byte[] publicKey, SecureRandom rand, PublicParameters params) {
        this.rand = rand;
        this.keyShare = keyShare;
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
        nSquared = N.pow(2);
        gPrime = params.otherPaillierPubKey.g;
        nPrime = params.otherPaillierPubKey.N;
        nPrimeSquared = nPrime.pow(2);
        qRaw = CURVE.getCurve().decodePoint(publicKey).getEncoded();
        alicesPaillierPubKey = params.alicesPaillierPubKey;
        otherPaillierPubKey = params.otherPaillierPubKey;
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

    public Round2Message bobToAliceRound2(Round1Message input) {
        ciphertext1 = input.getCiphertext1();
        ciphertext2 = input.getCiphertext2();
        mPrime = input.getmPrime();

        if (!isElementOfZn(ciphertext1, nSquared)) {
            throw new AssertionError();
        }
        
        if (!isElementOfZn(ciphertext2, nSquared)) {
            throw new AssertionError();
        }
        
        do {
            kBob = new BigInteger(256, rand);
        } while (kBob.compareTo(q) != -1);
        rBobRaw = getG().multiply(kBob).getEncoded();
        return new Round2Message(getRBob());
    }

    public Round4Message bobToAliceRound4(Round3Message input) {
        ECPoint r = input.getR(CURVE.getCurve());
        // verify that r * q = O
        if (!r.multiply(q).isInfinity()) {
            throw new AssertionError();
        }

        if (r.getCurve() != CURVE.getCurve()) {
            throw new AssertionError();
        }

        // verification of zkp1
        verifyZkp1(input);

        BigInteger zBob = kBob.modInverse(q);
        BigInteger rPrime = r.getX().toBigInteger().mod(q);
        BigInteger cBlind = randomFromZn(q.pow(5), rand);
        BigInteger cBlindq = cBlind.multiply(q);
        BigInteger rPrime2 = new BigInteger(kPrime, rand);
        BigInteger cBlindqEncrypted = Paillier.encrypt(cBlindq, alicesPaillierPubKey, rPrime2);
        BigInteger u = ciphertext1.modPow(zBob.multiply(mPrime), nSquared)
                .multiply(ciphertext2.modPow(keyShare.multiply(zBob).multiply(rPrime), nSquared))
                .mod(nSquared).multiply(cBlindqEncrypted).mod(nSquared);

        BigInteger rPrime1 = new BigInteger(kPrime, rand);
        BigInteger uPrime = Paillier.encrypt(zBob, otherPaillierPubKey, rPrime1);

        long startTime = System.nanoTime();
        // zkp2
        BigInteger alpha = randomFromZn(q.pow(3), rand);
        BigInteger beta = randomFromZnStar(nPrime, rand);
        BigInteger gamma = randomFromZn(q.pow(3).multiply(nHat), rand);
        BigInteger rho1 = randomFromZn(q.multiply(nHat), rand);
        BigInteger delta = randomFromZn(q.pow(3), rand);
        BigInteger mu = randomFromZnStar(N, rand);
        BigInteger nu = randomFromZn(q.pow(3).multiply(nHat), rand);
        BigInteger rho2 = randomFromZn(q.multiply(nHat), rand);
        BigInteger rho3 = randomFromZn(q, rand);
        BigInteger rho4 = randomFromZn(q.pow(5).multiply(nHat), rand);
        BigInteger epsilon = randomFromZn(q, rand);
        BigInteger theta = randomFromZn(q.pow(7), rand);
        BigInteger tau = randomFromZn(q.pow(7).multiply(nHat), rand);

        BigInteger x1 = zBob;
        BigInteger x2 = zBob.multiply(keyShare);
        BigInteger x3 = cBlind;
        ECPoint c = getG().multiply(kBob);
        ECPoint d = getG();
        ECPoint w1 = getG();
        ECPoint w2 = getG().multiply(keyShare);
        BigInteger m1 = uPrime;
        BigInteger m2 = u;
        BigInteger m3 = ciphertext1.modPow(mPrime, nSquared);
        BigInteger m4 = ciphertext2.modPow(rPrime, nSquared);

        BigInteger z1 = h1.modPow(x1, nHat).multiply(h2.modPow(rho1, nHat)).mod(nHat);
        ECPoint u1 = c.multiply(alpha);
        BigInteger u2 = gPrime.modPow(alpha, nPrimeSquared)
                .multiply(beta.modPow(nPrime, nPrimeSquared)).mod(nPrimeSquared);
        BigInteger u3 = h1.modPow(alpha, nHat).multiply(h2.modPow(gamma, nHat)).mod(nHat);
        BigInteger z2 = h1.modPow(x2, nHat).multiply(h2.modPow(rho2, nHat)).mod(nHat);
        ECPoint y = d.multiply(x2.add(rho3));
        ECPoint v1 = d.multiply(delta.add(epsilon));
        ECPoint v2 = w2.multiply(alpha).add(d.multiply(epsilon));
        BigInteger v3 = m3.modPow(alpha, nSquared).multiply(m4.modPow(delta, nSquared))
                .multiply(g.modPow(q.multiply(theta), nSquared)).multiply(mu.modPow(N, nSquared))
                .mod(nSquared);
        BigInteger v4 = h1.modPow(delta, nHat).multiply(h2.modPow(nu, nHat)).mod(nHat);
        BigInteger z3 = h1.modPow(x3, nHat).multiply(h2.modPow(rho4, nHat)).mod(nHat);
        BigInteger v5 = h1.modPow(theta, nHat).multiply(h2.modPow(tau, nHat)).mod(nHat);
        byte[] digest = sha256Hash(getBytes(c), getBytes(w1), getBytes(d), getBytes(w2),
                getBytes(m1), getBytes(m2), getBytes(z1), getBytes(u1), getBytes(u2), getBytes(u3),
                getBytes(z2), getBytes(z3), getBytes(y), getBytes(v1), getBytes(v2), getBytes(v3),
                getBytes(v4), getBytes(v5));

        if (digest == null) {
            throw new AssertionError();
        }

        BigInteger e = new BigInteger(1, digest);

        BigInteger s1 = e.multiply(x1).add(alpha);
        BigInteger s2 = rPrime1.modPow(e, nPrime).multiply(beta).mod(nPrime);
        BigInteger s3 = e.multiply(rho1).add(gamma);
        BigInteger t1 = e.multiply(x2).add(delta);
        BigInteger t2 = e.multiply(rho3).add(epsilon).mod(q);
        BigInteger t3 = rPrime2.modPow(e, N).multiply(mu).mod(N);
        BigInteger t4 = e.multiply(rho2).add(nu);
        BigInteger t5 = e.multiply(x3).add(theta);
        BigInteger t6 = e.multiply(rho4).add(tau);
        
        System.out.println("create zkp2: " + (System.nanoTime() - startTime));

        return new Round4Message(u, uPrime, z1, z2, z3, y, e, s1, s2, s3, t1, t2, t3, t4, t5, t6);
    }

    private void verifyZkp1(Round3Message input) {
    	long startTime = System.nanoTime();
        ECPoint r = input.getR(CURVE.getCurve());
        ECPoint c = r;
        ECPoint d = getG();
        ECPoint w1 = getRBob();
        ECPoint w2 = getQ().multiply(keyShare.modInverse(q));//G.multiply(aliceShare);

        BigInteger m1 = ciphertext1;
        BigInteger m2 = ciphertext2;

        BigInteger z1 = input.getZ1();
        BigInteger z2 = input.getZ2();
        ECPoint y = input.getY(CURVE.getCurve());
        BigInteger e = input.getE();
        BigInteger s1 = input.getS1();
        BigInteger s2 = input.getS2();
        BigInteger s3 = input.getS3();
        BigInteger t1 = input.getT1();
        BigInteger t2 = input.getT2();
        BigInteger t3 = input.getT3();
        BigInteger t4 = input.getT4();

        if (!isElementOfZn(s1, q.pow(3))) {
            throw new AssertionError();
        }

        if (!isElementOfZn(t1, q.pow(3))) {
            throw new AssertionError();
        }

        ECPoint u1 = c.multiply(s1).add(w1.negate().multiply(e));
        BigInteger u2 = g.modPow(s1, nSquared).multiply(s2.modPow(N, nSquared))
                .multiply(m1.modPow(e.negate(), nSquared)).mod(nSquared);
        BigInteger u3 = h1.modPow(s1, nHat).multiply(h2.modPow(s3, nHat))
                .multiply(z1.modPow(e.negate(), nHat)).mod(nHat);
        ECPoint v1 = d.multiply(t1.add(t2)).add(y.negate().multiply(e));
        ECPoint v2 = w2.multiply(s1).add(d.multiply(t2)).add(y.negate().multiply(e));
        BigInteger v3 = g.modPow(t1, nSquared).multiply(t3.modPow(N, nSquared))
                .multiply(m2.modPow(e.negate(), nSquared)).mod(nSquared);
        BigInteger v4 = h1.modPow(t1, nHat).multiply(h2.modPow(t4, nHat))
                .multiply(z2.modPow(e.negate(), nHat)).mod(nHat);

        byte[] digestRecovered = sha256Hash(getBytes(c), getBytes(w1), getBytes(d), getBytes(w2),
                getBytes(m1), getBytes(m2), getBytes(z1), getBytes(u1), getBytes(u2), getBytes(u3),
                getBytes(z2), getBytes(y), getBytes(v1), getBytes(v2), getBytes(v3), getBytes(v4));

        if (digestRecovered == null) {
            throw new AssertionError();
        }

        BigInteger eRecovered = new BigInteger(1, digestRecovered);

        if (!eRecovered.equals(e)) {
            throw new AssertionError();
        }
        System.out.println("verifyZkp1: " + (System.nanoTime() - startTime));
    }
    
    private ECPoint getRBob() {
    	return CURVE.getCurve().decodePoint(rBobRaw);
    }
    
    private ECPoint getG() {
    	return CURVE.getCurve().decodePoint(gRaw);
    }
    
    public ECPoint getQ() {
    	return CURVE.getCurve().decodePoint(qRaw);
    }
}

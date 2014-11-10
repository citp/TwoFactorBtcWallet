package threshold.mr04;

import static threshold.mr04.Util.calculateMPrime;
import static threshold.mr04.Util.getBytes;
import static threshold.mr04.Util.isElementOfZn;
import static threshold.mr04.Util.randomFromZn;
import static threshold.mr04.Util.randomFromZnStar;
import static threshold.mr04.Util.sha256Hash;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECPoint;

import threshold.mr04.data.PublicParameters;
import threshold.mr04.data.Round1Message;
import threshold.mr04.data.Round2Message;
import threshold.mr04.data.Round3Message;
import threshold.mr04.data.Round4Message;

public class Alice {

    private final ECDomainParameters CURVE;
    private final BigInteger q;
    private final ECPoint G;
    private final ECPoint Q; //public key
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
    private ECPoint r;
    BigInteger rPrime;
    BigInteger mPrime;

    public Alice(BigInteger keyShare, byte[] publicKey, SecureRandom rand, Paillier paillier,
            PublicParameters params) {
        this.rand = rand;
        this.keyShare = keyShare;
        this.paillier = paillier;
        this.q = params.q;
        this.G = params.G;
        this.kPrime = params.kPrime;
        this.CURVE = params.CURVE;
        this.h1 = params.h1;
        this.h2 = params.h2;
        g = params.alicesPaillierPubKey.g;
        N = params.alicesPaillierPubKey.N;
        this.nHat = params.nHat;
        Nsquared = N.pow(2);
        gPrime = params.otherPaillierPubKey.g;
        nPrime = params.otherPaillierPubKey.N;
        nPrimeSquared = nPrime.pow(2);
        Q = CURVE.getCurve().decodePoint(publicKey);
        alicesPaillierPubKey = params.alicesPaillierPubKey;
    }

    Round1Message aliceToBobRound1(byte[] message) {
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

    Round3Message aliceToBobRound3(Round2Message input) {
        // verify that rBob * q = O
        ECPoint rBob = input.getrBob();
        if (!rBob.multiply(q).isInfinity()) {
            throw new AssertionError();
        }
        // Ask Rosario. this is the equivalent of cheming that it's in Zp*
        if (rBob.getCurve() != CURVE.getCurve()) {
            throw new AssertionError();
        }
        r = rBob.multiply(kAlice);
        rPrime = r.normalize().getXCoord().toBigInteger().mod(q);

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
        ECPoint c = r;
        ECPoint d = G;
        ECPoint w1 = r.multiply(zAlice);
        ECPoint w2 = G.multiply(keyShare);
        BigInteger m1 = ciphertext1;
        BigInteger m2 = ciphertext2;

        BigInteger z1 = h1.modPow(x1, nHat).multiply(h2.modPow(rho1, nHat)).mod(nHat);
        ECPoint u1 = c.multiply(alpha);
        BigInteger u2 = g.modPow(alpha, Nsquared).multiply(beta.modPow(N, Nsquared)).mod(Nsquared);
        BigInteger u3 = h1.modPow(alpha, nHat).multiply(h2.modPow(gamma, nHat)).mod(nHat);
        BigInteger z2 = h1.modPow(x2, nHat).multiply(h2.modPow(rho2, nHat)).mod(nHat);
        ECPoint y = d.multiply(x2.add(rho3));
        ECPoint v1 = d.multiply(delta.add(epsilon));
        ECPoint v2 = w2.multiply(alpha).add(G.multiply(epsilon));
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

        return new Round3Message(r, z1, z2, y, e, s1, s2, s3, t1, t2, t3, t4);

    }

    BigInteger[] aliceOutput(Round4Message input) {
        verifyZkp2(input);
        BigInteger u = input.getU();
        BigInteger s = paillier.decrypt(u).mod(q);
        return new BigInteger[] { rPrime, s };
    }

    private void verifyZkp2(Round4Message input) {

        ECPoint c = r.multiply(zAlice);//G.multiply(kBob);
        ECPoint d = G;
        ECPoint w1 = G;
        ECPoint w2 = Q.multiply(keyShare.modInverse(q));//G.multiply(bobShare);
        BigInteger m1 = input.getUPrime();
        BigInteger m2 = input.getU();
        BigInteger m3 = ciphertext1.modPow(mPrime, paillier.nSquared);
        BigInteger m4 = ciphertext2.modPow(rPrime, paillier.nSquared);

        BigInteger z1 = input.getZ1();
        BigInteger z2 = input.getZ2();
        BigInteger z3 = input.getZ3();
        ECPoint y = input.getY();
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
    }

}

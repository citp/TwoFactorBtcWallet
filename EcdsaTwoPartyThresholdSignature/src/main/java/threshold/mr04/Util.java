package threshold.mr04;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import threshold.mr04.data.PublicParameters;

public class Util {
	
    /**
     * Method taken (renamed) from SpongyCastle ECDSASigner class. Cannot call
     * from there since it's private and non static.
     */
    public static BigInteger calculateMPrime(BigInteger n, byte[] message) {
        if (n.bitLength() > message.length * 8) {
            return new BigInteger(1, message);
        } else {
            int messageBitLength = message.length * 8;
            BigInteger trunc = new BigInteger(1, message);

            if (messageBitLength - n.bitLength() > 0) {
                trunc = trunc.shiftRight(messageBitLength - n.bitLength());
            }
            return trunc;
        }
    }

    // modified from bitcoinj ECKEy
    public static ECPoint compressPoint(ECPoint uncompressed, ECDomainParameters CURVE) {
        return new ECPoint.Fp(CURVE.getCurve(), uncompressed.getX(), uncompressed.getY(), true);
    }

    public static boolean verifySignature(byte[] message, BigInteger r, BigInteger s, byte[] pub,
            ECDomainParameters Curve) {
        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(Curve.getCurve().decodePoint(pub),
                Curve);
        signer.init(false, params);
        try {
            return signer.verifySignature(message, r, s);
        } catch (NullPointerException e) {
            // Bouncy Castle contains a bug that can cause NPEs given specially
            // crafted signatures. Those signatures
            // are inherently invalid/attack sigs so we just fail them here
            // rather than crash the thread.
            System.out.println("Caught NPE inside bouncy castle");
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] getBytes(BigInteger n) {
        return n.toByteArray();
    }

    public static byte[] getBytes(ECPoint e) { // ASK ROSARIO
        byte[] x = e.getX().toBigInteger().toByteArray();
        byte[] y = e.getY().toBigInteger().toByteArray();
        byte[] output = new byte[x.length + y.length];
        System.arraycopy(x, 0, output, 0, x.length);
        System.arraycopy(y, 0, output, x.length, y.length);
        return output;
    }

    /**
     * Returns an element from Z_n randomly seleted using the randomness from
     * {@code rand}
     * 
     * @param n
     *            the modulus
     */
    public static BigInteger randomFromZn(BigInteger n, Random rand) {
        BigInteger result;
        do {
            result = new BigInteger(n.bitLength(), rand);
            // check that it's in Zn
        } while (result.compareTo(n) != -1);
        return result;
    }

    public static boolean isElementOfZn(BigInteger element, BigInteger n) {
        return (element.compareTo(BigInteger.ZERO) != -1) && (element.compareTo(n) == -1);
    }

    /**
     * Returns an element from Z_n^* randomly seleted using the randomness from
     * {@code rand}
     * 
     * @param n
     *            the modulus
     */
    public static BigInteger randomFromZnStar(BigInteger n, Random rand) {
        BigInteger result;
        do {
            result = new BigInteger(n.bitLength(), rand);
            // check that it's in Zn*
        } while (result.compareTo(n) != -1 || !result.gcd(n).equals(BigInteger.ONE));
        return result;
    }

    public static byte[] sha256Hash(byte[]... inputs) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] input : inputs) {
                md.update(input);
            }
            return md.digest();

        } catch (NoSuchAlgorithmException ex) {
            throw new AssertionError();
        }
    }

    public static PublicParameters generateParamsforBitcoin(int k, int kPrime, SecureRandom rand,
            PaillierPublicKey alicesPaillierPubKey) {

        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters CURVE = new ECDomainParameters(params.getCurve(), params.getG(),
                params.getN(), params.getH());
        Paillier otherPaillier = new Paillier(kPrime, k);
        PaillierPublicKey otherPaillierPubKey = new PaillierPublicKey(otherPaillier.n,
                otherPaillier.g);

        int primeCertainty = k;
        BigInteger p;
        BigInteger q;
        BigInteger pPrime;
        BigInteger qPrime;
        BigInteger pPrimeqPrime;
        BigInteger nHat;

        do {
            p = new BigInteger(kPrime / 2, primeCertainty, rand);
        } while (!p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
                .isProbablePrime(primeCertainty));

        pPrime = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));

        do {
            q = new BigInteger(kPrime / 2, primeCertainty, rand);
        } while (!q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
                .isProbablePrime(primeCertainty));

        qPrime = q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));

        nHat = p.multiply(q);

        BigInteger h2 = randomFromZnStar(nHat, rand);
        pPrimeqPrime = pPrime.multiply(qPrime);

        BigInteger x = randomFromZn(pPrimeqPrime, rand);
        BigInteger h1 = h2.modPow(x, nHat);

        return new PublicParameters(CURVE, nHat, kPrime, h1, h2, alicesPaillierPubKey,
                otherPaillierPubKey);

    };

}

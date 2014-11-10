package threshold.mr04.data;

import java.math.BigInteger;

import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECPoint;

import threshold.mr04.PaillierPublicKey;

public class PublicParameters {

    public final ECDomainParameters CURVE;
    public final ECPoint G;
    public BigInteger q;
    public final int kPrime;
    public final BigInteger h1;
    public final BigInteger h2;
    public final BigInteger nHat;
    public final PaillierPublicKey alicesPaillierPubKey;
    public final PaillierPublicKey otherPaillierPubKey;

    public PublicParameters(ECDomainParameters CURVE, BigInteger nHat, int kPrime, BigInteger h1,
            BigInteger h2, PaillierPublicKey alicesPaillierPubKey, PaillierPublicKey otherPaillierPubKey) {
        this.CURVE = CURVE;
        G = CURVE.getG();
        q = CURVE.getN();
        this.nHat = nHat;
        this.kPrime = kPrime;
        this.h1 = h1;
        this.h2 = h2;
        this.alicesPaillierPubKey = alicesPaillierPubKey;
        this.otherPaillierPubKey = otherPaillierPubKey;
    }

}

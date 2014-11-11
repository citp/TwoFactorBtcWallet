package threshold.mr04.data;

import java.io.Serializable;
import java.math.BigInteger;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import threshold.mr04.PaillierPublicKey;

public class PublicParameters implements Serializable {

	private static final long serialVersionUID = 446196880585148373L;
//	public final ECDomainParameters CURVE;
    public final byte[] gRaw;
    public BigInteger q;
    public final int kPrime;
    public final BigInteger h1;
    public final BigInteger h2;
    public final BigInteger nHat;
    public final PaillierPublicKey alicesPaillierPubKey;
    public final PaillierPublicKey otherPaillierPubKey;

    public PublicParameters(ECDomainParameters CURVE, BigInteger nHat, int kPrime, BigInteger h1,
            BigInteger h2, PaillierPublicKey alicesPaillierPubKey, PaillierPublicKey otherPaillierPubKey) {
//        this.CURVE = CURVE;
        gRaw = CURVE.getG().getEncoded();
        q = CURVE.getN();
        this.nHat = nHat;
        this.kPrime = kPrime;
        this.h1 = h1;
        this.h2 = h2;
        this.alicesPaillierPubKey = alicesPaillierPubKey;
        this.otherPaillierPubKey = otherPaillierPubKey;
    }

    public ECPoint G(ECCurve curve) {
    	return curve.decodePoint(gRaw);
    }
}

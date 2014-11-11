package threshold.mr04.benchmarking;

import static threshold.mr04.Util.getBytes;
import static threshold.mr04.Util.randomFromZn;
import static threshold.mr04.Util.randomFromZnStar;
import static threshold.mr04.Util.sha256Hash;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import threshold.mr04.Paillier;
import threshold.mr04.PaillierPublicKey;
import threshold.mr04.SignatureTest;
import threshold.mr04.data.PublicParameters;

public class Proofs implements Serializable {

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

    private BigInteger keyShare;
    private final SecureRandom rand;
    private final PaillierPublicKey alicesPaillierPubKey;

    private BigInteger kP1;
    private BigInteger ciphertext1;
    private BigInteger ciphertext2;
    // the random values used for the Paillier ciphertexts
    private BigInteger zP1;
    private BigInteger r1;
    private BigInteger r2;
    ECPoint yP1;
    private byte[] rRaw;
    BigInteger rPrime;
    BigInteger mPrime;
    ECPoint G;
    ECPoint Ri;
    ECPoint ROfIPlus1;
    BigInteger r5;
    BigInteger r6;
    BigInteger m1;
    BigInteger m2;
    BigInteger m3;
    BigInteger m4;
    BigInteger m5;
    BigInteger m6;

    public Proofs( byte[] publicKey, SecureRandom rand, PublicParameters params) {
        this.rand = rand;
        this.q = params.q;
        do {
            keyShare = new BigInteger(256, rand);
        } while (keyShare.compareTo(q) != -1);
        X9ECParameters CURVEparams = SECNamedCurves.getByName("secp256k1");
        this.CURVE = new ECDomainParameters(CURVEparams.getCurve(), CURVEparams.getG(), CURVEparams.getN(),
        		CURVEparams.getH());
        this.gRaw = params.G(this.CURVE.getCurve()).getEncoded();
        this.kPrime = params.kPrime;
        this.h1 = params.h1;
        this.h2 = params.h2;
        g = params.alicesPaillierPubKey.g;
        N = params.alicesPaillierPubKey.N;
        this.nHat = params.nHat;
        Nsquared = N.pow(2);
        qRaw = CURVE.getCurve().decodePoint(publicKey).getEncoded();
        alicesPaillierPubKey = params.alicesPaillierPubKey;
        do {
            kP1 = new BigInteger(256, rand);
        } while (kP1.compareTo(q) != -1);
        zP1 = kP1.modInverse(q);   
        
        BigInteger kP1minus1;
        do {
            kP1minus1 = new BigInteger(256, rand);
        } while (kP1minus1.compareTo(q) != -1);
        zP1 = zP1.modInverse(q);
        G = getG();
        yP1 = G.multiply(keyShare);

        
         ROfIPlus1 = G.multiply(kP1minus1);
        Ri = ROfIPlus1.multiply(kP1);
        
        r5 = randomFromZnStar(N, rand);
        r6 = randomFromZnStar(N, rand);
         
    }
    
    // NOTE NOT ACTUALLY IMPLENTING THE PROOF WITH THE CORRECT VALUES AS THOSE DEPEND ON PREVIOUS PARTS OF THE PROTOCOL
     // JUST DOING THE EXPONENTIATION WITH
    // THE CORRECT SIZED NUMBERS SO THAT WE CAN BENCHMARK THE PROOF
	public void zkpI(int number){
		//grows by a factor of q for each proof
		BigInteger alphaIminus1 = randomFromZn(q.pow(number), rand);
		BigInteger betaIminus1 = randomFromZn(q.pow(number), rand);

		BigInteger r1 = randomFromZn(N, rand);
		BigInteger r2 = randomFromZn(N, rand);
		BigInteger r3 = randomFromZn(N, rand);
		BigInteger r4 = randomFromZn(N, rand);

		
        m1 = Paillier.encrypt(zP1.multiply(alphaIminus1), alicesPaillierPubKey,r1);
        long startTime = System.nanoTime();
        m2 = Paillier.encrypt(zP1.multiply(keyShare).mod(q).multiply(betaIminus1), alicesPaillierPubKey,r2);
        System.out.println("Paillier: " + (System.nanoTime() - startTime));
        m3 = Paillier.encrypt(alphaIminus1, alicesPaillierPubKey,r3);
        m4 = Paillier.encrypt(betaIminus1, alicesPaillierPubKey,r4);

        
         m5 = Paillier.encrypt(zP1, alicesPaillierPubKey, r5);
         m6 = Paillier.encrypt(zP1.multiply(keyShare).mod(q), alicesPaillierPubKey, r6);
		
		
		ECPoint d = G;
		BigInteger x1 = zP1;
    	BigInteger x2 = zP1.multiply(keyShare).mod(q);
    	ECPoint w1 = ROfIPlus1;
    	ECPoint w2 = yP1;
    	ECPoint c = Ri;
    	
    	
    	//zkpi
		
		BigInteger alpha = randomFromZn(q.pow(3), rand);
    	BigInteger delta = randomFromZn(q.pow(3), rand);
    	
    	BigInteger beta1 = randomFromZnStar(N, rand);
    	BigInteger beta2 = randomFromZnStar(N, rand);
    	
    	BigInteger rho1 = randomFromZn(q.multiply(nHat), rand);
    	BigInteger rho2 = randomFromZn(q.multiply(nHat), rand);
    	
    	BigInteger gamma = randomFromZn(q.multiply(nHat), rand);
    	BigInteger nu = randomFromZn(q.pow(3).multiply(nHat), rand);
    	
    	BigInteger rho3 = randomFromZn(q, rand);
    	BigInteger epsilon = randomFromZn(q, rand);
    	
    	BigInteger z1 = h1.modPow(x1, nHat).multiply(h2.modPow(rho1, nHat)).mod(nHat);
    	ECPoint u1 = c.multiply(alpha);
    	BigInteger u2= g.modPow(alpha, Nsquared).multiply(beta1.modPow(N, Nsquared)).mod(Nsquared);
    	BigInteger u3 = h1.modPow(alpha, nHat).multiply(h2.modPow(gamma, nHat)).mod(nHat);
    	BigInteger z2 = h1.modPow(x2, nHat).multiply(h2.modPow(rho2, nHat)).mod(nHat);
    	ECPoint y = d.multiply(x2.add(rho3));    	
    	ECPoint v1 = d.multiply(delta.add(epsilon));
    	startTime = System.nanoTime();
    	ECPoint v2 = w2.multiply(alpha).add(d.multiply(epsilon));
    	System.out.println("ECPoint: " + (System.nanoTime() - startTime));
    	startTime = System.nanoTime();
    	BigInteger v3 = m3.modPow(alpha, Nsquared);
    	System.out.println("modPow: " + (System.nanoTime() - startTime));
    	BigInteger v4 = m4.modPow(delta, Nsquared);
    	BigInteger v5 = g.modPow(delta, Nsquared).multiply(beta2.modPow(N, Nsquared)).mod(Nsquared);
    	BigInteger v6 = h1.modPow(delta, nHat).multiply(h2.modPow(nu, nHat)).mod(nHat);
    	byte[] eBytes = sha256Hash(getBytes(c),getBytes(d),getBytes(w1),getBytes(w2),getBytes(m1),getBytes(m2),getBytes(m3),getBytes(m4),getBytes(m5),getBytes(m6),getBytes(z1),getBytes(u1),getBytes(u2),getBytes(u3),getBytes(z2),getBytes(y),getBytes(v1),getBytes(v3),getBytes(v4),getBytes(v5),getBytes(v6));
    	BigInteger e = new BigInteger(1, eBytes);
    	BigInteger s1 = e.multiply(x1).add(alpha);
    	BigInteger s2 = r5.modPow(e, N).multiply(beta1).mod(N);
    	BigInteger s3 = e.multiply(rho1).add(gamma);
    	BigInteger t1 = e.multiply(x2).add(delta);
    	BigInteger t2 = e.multiply(rho3).add(epsilon);
    	BigInteger t3 = r6.modPow(e, N).multiply(beta2).mod(N);
    	BigInteger t4 = alpha= e.multiply(rho2).add(nu);
    	
    	
    	//verification--we're not actually doing the proof--just exponentitating to check the time
    	
    	c.multiply(s1).add(w1.multiply(e.negate()));
    
    	
    	startTime = System.nanoTime();
    	g.modPow(s1, Nsquared).multiply(s2.modPow(N, Nsquared)).multiply(m5.modPow(e.negate(), Nsquared)).mod(Nsquared);
    	System.out.println("big ugly: " + (System.nanoTime() - startTime));
     h1.modPow(s1, nHat).multiply(h2.modPow(s3, nHat)).multiply(z1.modPow(e.negate(), nHat)).mod(nHat);
    	
     	d.multiply(t1.add(t2)).add(y.multiply(e.negate()));

     	w2.multiply(s1).add(d.multiply(t2)).add(y.multiply(e.negate()));
    
     	m3.modPow(s1, Nsquared).multiply(m1.modPow(e.negate(), Nsquared)).mod(Nsquared);

     	
      	m4.modPow(t1, Nsquared).multiply(m2.modPow(e.negate(), Nsquared)).mod(Nsquared);
   
      	
   

      	g.modPow(t1, Nsquared).multiply(t3.modPow(N, Nsquared)).multiply(m6.modPow(e.negate(), Nsquared)).mod(Nsquared);
  
      	
    	h1.modPow(t1, nHat).multiply(h2.modPow(t4, nHat)).multiply(z2.modPow(e.negate(), nHat)).mod(nHat);
 
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

package com.google.bitcoin.core;

import java.security.interfaces.ECKey;

public class RemoteECKey extends ECKey {
    /**
     * Signs the given hash and returns the R and S components as BigIntegers. In the Bitcoin protocol, they are
     * usually encoded using DER format, so you want {@link com.google.bitcoin.core.ECKey.ECDSASignature#encodeToDER()}
     * instead. However sometimes the independent components can be useful, for instance, if you're doing to do further
     * EC maths on them.
     *
     * @param aesKey The AES key to use for decryption of the private key. If null then no decryption is required.
     * @throws KeyCrypterException if this ECKey doesn't have a private part.
     */
    public ECDSASignature sign(Sha256Hash input, @Nullable KeyParameter aesKey) throws KeyCrypterException {
        if (FAKE_SIGNATURES)
            return TransactionSignature.dummy();

        ECDSASigner signer = new ECDSASigner();
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKeyForSigning, CURVE);
        signer.init(true, privKey);
        BigInteger[] components = signer.generateSignature(input.getBytes());
        final ECDSASignature signature = new ECDSASignature(components[0], components[1]);
        signature.ensureCanonical();
        return signature;
    }
}
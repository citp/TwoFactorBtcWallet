/*
 * Copyright 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.multibit.store;

import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.core.WalletExtension;

/**
 * Wallet extension to cater for MultiBit wallets
 */
public class MultiBitWalletExtension implements WalletExtension {

    @Override
    public String getWalletExtensionID() {
        return MultiBitWalletProtobufSerializer.ORG_MULTIBIT_WALLET_PROTECT_2;
    }

    @Override
    public boolean isWalletExtensionMandatory() {
        return true;
    }

    @Override
    public byte[] serializeWalletExtension() {
        // The payload of the MultiBit protect is a single byte with value x01.
        // (Only the extension id is used really).
        return new byte[0x01];
    }

    @Override
    public void deserializeWalletExtension(Wallet containingWallet, byte[] data) {
        // TODO Auto-generated method stub
    }
}

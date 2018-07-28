/* Copyright (c) 2018, Eric McCorkle.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.metricspace.crypto.multihash;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

import java.security.Provider;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public enum MultihashAlgorithm {
    RIPEMD_160((byte)0x0, "RIPEMD-160", 160),
    SHA_512((byte)0x1, "SHA-512", 512),
    SHA3_512((byte)0x2, "SHA3-512", 512),
    BLAKE2b_512((byte)0x3, "BLAKE2b-512", 512),
    SKEIN((byte)0x4, "Skein-512", 512),
    WHIRLPOOL((byte)0x5, "Whirlpool", 512);

    private final byte code;
    private final String name;
    private final int nbits;

    private MultihashAlgorithm(final byte code,
                               final String name,
                               final int nbits) {
        this.code = code;
        this.name = name;
        this.nbits = nbits;
    }

    /**
     * Get the algorithm name of the hash function.
     *
     * @return The algorithm name of the hash function.
     */
    public String algorithmName() {
        return name;
    }

    /**
     * Get the number of bits of a hash value.
     *
     * @return The number of bits of a hash value.
     */
    public int nbits() {
        return nbits;
    }

    /**
     * Get the size in bytes of a hash value.
     *
     * @return The size in bytes of a hash value.
     */
    public int size() {
        return nbits / 8;
    }

    /**
     * Get the wire-format identifier for this hash function.
     *
     * @return The wire-format code for this hash function.
     */
    public byte code() {
        return code;
    }

    /**
     * Write this {@code MultihashAlgorithm} in binary form to an
     * {@link OutputStream}.
     *
     * @param out The {@link OutputStream} to which to write.
     * @throws IOException If an IO error occurs while writing.
     */
    public void write(final OutputStream out)
        throws IOException {
        write(new DataOutputStream(out));
    }

    /**
     * Write this {@code MultihashAlgorithm} in binary form to a
     * {@link DataOutputStream}.
     *
     * @param out The {@link DataOutputStream} to which to write.
     * @throws IOException If an IO error occurs while writing.
     */
    public void write(final DataOutputStream out)
        throws IOException {
        out.write(code);
    }

    public MessageDigest getInstance()
        throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(name);
    }

    public MessageDigest getInstance(final Provider provider)
        throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(name, provider);
    }

    public MessageDigest getInstance(final String provider)
        throws NoSuchAlgorithmException,
               NoSuchProviderException {
        return MessageDigest.getInstance(name, provider);
    }

    public static MultihashAlgorithm decode(final int code)
        throws NoSuchAlgorithmException {
        switch(code) {
        default: throw new NoSuchAlgorithmException("Unknown code " + code);
        case 0x0: return RIPEMD_160;
        case 0x1: return SHA_512;
        case 0x2: return SHA3_512;
        case 0x3: return BLAKE2b_512;
        case 0x4: return SKEIN;
        case 0x5: return WHIRLPOOL;
        }
    }
}

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

import java.nio.ByteBuffer;

import java.security.Provider;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;

/**
 * Hash values from multiple different hash functions.  This is a
 * flexible collection, which must contain at least one value.
 */
public final class Multihash {
    /**
     * The size of the referenced data.
     */
    private final long size;

    /**
     * The hash values.
     */
    private final EnumMap<MultihashAlgorithm, byte[]> hashes;

    /**
     * Initialize a {@code Multihash} from its components.
     *
     * @param size The size of the referenced data.
     * @param hashes The hash values.
     */
    private Multihash(final long size,
                      final EnumMap<MultihashAlgorithm, byte[]> hashes) {
        this.size = size;
        this.hashes = hashes;
    }

    /**
     * Get the expected size of the referenced data.
     *
     * @return The expected size of the referenced data.
     */
    public long size() {
        return size;
    }

    /**
     * Check whether this {@code Multihash} has a value for the given
     * hash function.
     *
     * @param algo The hash algorithm.
     * @return Whether this {@code Multihash} has a value for the
     *         given hash function.
     */
    public boolean hasHash(final MultihashAlgorithm algo) {
        return hashes.containsKey(algo);
    }

    /**
     * Get the hash code for a given hash algorithm.
     *
     * @param algo The hash algorithm.
     * @return The code produced by {@code algo} on the referenced data.
     */
    public byte[] getHash(final MultihashAlgorithm algo) {
        if (hashes.containsKey(algo)) {
            return hashes.get(algo).clone();
        } else {
            return null;
        }
    }

    /**
     * Add a hash value to this {@code Multihash}.  This requires
     * access to the referenced data.
     *
     * @param algo The hash to add.
     * @param buf The referenced data.
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public void addHash(final MultihashAlgorithm algo,
                        final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        if (!hasHash(algo)) {
            hashes.put(algo, computeHash(algo.getInstance(), buf));
        }
    }

    /**
     * Add a hash value to this {@code Multihash}.  This requires
     * access to the referenced data.
     *
     * @param provider The {@link Provider} to use to obtain a {@link
     *                 MessageDigest} implementation.
     * @param algo The hash to add.
     * @param buf The referenced data.
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public void addHash(final Provider provider,
                               final MultihashAlgorithm algo,
                               final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        if (!hasHash(algo)) {
            hashes.put(algo, computeHash(algo.getInstance(provider), buf));
        }
    }

    /**
     * Add a hash value to this {@code Multihash}.  This requires
     * access to the referenced data.
     *
     * @param provider The name of the {@link Provider} to use to
     *                 obtain a {@link MessageDigest} implementation.
     * @param algo The hash to add.
     * @param buf The referenced data.
     * @throws NoSuchProviderException If the no {@link Provider}
     *                                 exists with the given name
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public void addHash(final String provider,
                               final MultihashAlgorithm algo,
                               final ByteBuffer buf)
        throws NoSuchAlgorithmException,
               NoSuchProviderException {
        if (!hasHash(algo)) {
            hashes.put(algo, computeHash(algo.getInstance(provider), buf));
        }
    }

    /**
     * Verify a specific hash algorithm's hash value against the
     * referenced data.  The position of the {@link ByteBuffer} is not
     * affected.
     *
     * @param algo The hash algorithm to verify.
     * @param buf The referenced data.
     * @return Whether or not the hash value is correct.
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public boolean verifyHash(final MultihashAlgorithm algo,
                              final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        if (!hasHash(algo)) {
            final byte[] expected = hashes.get(algo);
            final byte[] actual = computeHash(algo.getInstance(), buf);

            return expected.equals(actual);
        } else {
            throw new IllegalArgumentException("No hash value for " + algo);
        }
    }

    /**
     * Verify a specific hash algorithm's hash value against the
     * referenced data.  The position of the {@link ByteBuffer} is not
     * affected.
     *
     * @param provider The {@link Provider} to use to obtain a {@link
     *                 MessageDigest} implementation.
     * @param algo The hash algorithm to verify.
     * @param buf The referenced data.
     * @return Whether or not the hash value is correct.
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public boolean verifyHash(final Provider provider,
                              final MultihashAlgorithm algo,
                              final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        if (!hasHash(algo)) {
            final byte[] expected = hashes.get(algo);
            final byte[] actual = computeHash(algo.getInstance(provider), buf);

            return expected.equals(actual);
        } else {
            throw new IllegalArgumentException("No hash value for " + algo);
        }
    }

    /**
     * Verify a specific hash algorithm's hash value against the
     * referenced data.  The position of the {@link ByteBuffer} is not
     * affected.
     *
     * @param provider The name of the {@link Provider} to use to
     *                 obtain a {@link MessageDigest} implementation.
     * @param algo The hash algorithm to verify.
     * @param buf The referenced data.
     * @return Whether or not the hash value is correct.
     * @throws NoSuchProviderException If the no {@link Provider}
     *                                 exists with the given name
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public boolean verifyHash(final String provider,
                              final MultihashAlgorithm algo,
                              final ByteBuffer buf)
        throws NoSuchAlgorithmException,
               NoSuchProviderException {
        if (!hasHash(algo)) {
            final byte[] expected = hashes.get(algo);
            final byte[] actual = computeHash(algo.getInstance(provider), buf);

            return expected.equals(actual);
        } else {
            throw new IllegalArgumentException("No hash value for " + algo);
        }
    }

    /**
     * Verify all hash algorithms' hash values against the referenced
     * data.  The position of the {@link ByteBuffer} is not affected.
     *
     * @param buf The referenced data.
     * @return Whether or not the hash value is correct.
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public boolean verify(final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        for(final MultihashAlgorithm algo : hashes.keySet()) {
            if (!verifyHash(algo, buf)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Verify all hash algorithms' hash values against the referenced
     * data.  The position of the {@link ByteBuffer} is not affected.
     *
     * @param provider The {@link Provider} to use to obtain a {@link
     *                 MessageDigest} implementation.
     * @param buf The referenced data.
     * @return Whether or not the hash value is correct.
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public boolean verify(final Provider provider,
                          final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        for(final MultihashAlgorithm algo : MultihashAlgorithm.values()) {
            if (!verifyHash(provider, algo, buf)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Verify all hash algorithms' hash values against the referenced
     * data.  The position of the {@link ByteBuffer} is not affected.
     *
     * @param provider The name of the {@link Provider} to use to
     *                 obtain a {@link MessageDigest} implementation.
     * @param buf The referenced data.
     * @return Whether or not the hash value is correct.
     * @throws NoSuchProviderException If the no {@link Provider}
     *                                 exists with the given name
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public boolean verify(final String provider,
                          final ByteBuffer buf)
        throws NoSuchAlgorithmException,
               NoSuchProviderException {
        for(final MultihashAlgorithm algo : MultihashAlgorithm.values()) {
            if (!verifyHash(provider, algo, buf)) {
                return false;
            }
        }

        return true;
    }

    private static byte[] computeHash(final MultihashAlgorithm algo,
                               final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        return computeHash(algo.getInstance(), buf);
    }

    private static byte[] computeHash(final Provider provider,
                                      final MultihashAlgorithm algo,
                                      final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        return computeHash(algo.getInstance(provider), buf);
    }

    private static byte[] computeHash(final String provider,
                                      final MultihashAlgorithm algo,
                                      final ByteBuffer buf)
        throws NoSuchAlgorithmException,
               NoSuchProviderException {
        return computeHash(algo.getInstance(provider), buf);
    }

    private static byte[] computeHash(final MessageDigest md,
                                      final ByteBuffer buf) {
        try {
            buf.mark();

            md.update(buf);

            return md.digest();
        } finally {
            buf.reset();
        }
    }

    /**
     * Write this {@code Multihash} in binary form to an {@link
     * OutputStream}.
     *
     * @param out The {@link OutputStream} to which to write.
     * @throws IOException If an IO error occurs while writing.
     */
    public void write(final OutputStream out)
        throws IOException {
        write(new DataOutputStream(out));
    }

    /**
     * Write this {@code Multihash} in binary form to an {@link
     * DataOutputStream}.
     *
     * @param out The {@link DataOutputStream} to which to write.
     * @throws IOException If an IO error occurs while writing.
     */
    public void write(final DataOutputStream out)
        throws IOException {
        out.writeLong(size);
        out.write((byte)hashes.size());

        for(final Map.Entry<MultihashAlgorithm, byte[]> entry :
                hashes.entrySet()) {
            entry.getKey().write(out);
            out.write(entry.getValue());
        }
    }

    /**
     * Create a {@code Multihash} by reading its binary encoding from
     * a {@link InputStream}.
     *
     * @param in The stream to read.
     * @return The {@code Multihash} read from the stream.
     * @throws IOException If an IO error occurred.
     * @throws NoSuchAlgorithmException If an unknown algorithm was specified.
     */
    public static Multihash read(final InputStream in)
        throws IOException,
               NoSuchAlgorithmException {
        return read(new DataInputStream(in));
    }

    /**
     * Create a {@code Multihash} by reading its binary encoding from
     * a {@link DataInputStream}.
     *
     * @param in The stream to read.
     * @return The {@code Multihash} read from the stream.
     * @throws IOException If an IO error occurred.
     * @throws NoSuchAlgorithmException If an unknown algorithm was specified.
     */
    public static Multihash read(final DataInputStream in)
        throws IOException,
               NoSuchAlgorithmException {
        final long size = in.readLong();
        final int nentries = in.read();

        if (nentries < 1) {
            throw new IllegalArgumentException("Multihashes must contain at " +
                                               "least one hash value");
        }

        final EnumMap<MultihashAlgorithm, byte[]> hashes =
            new EnumMap<>(MultihashAlgorithm.class);

        for(int i = 0; i < nentries; i++) {
            final byte code = in.readByte();
            final MultihashAlgorithm algo = MultihashAlgorithm.decode(code);
            final byte[] hash = new byte[algo.size()];

            in.read(hash);
            hashes.put(algo, hash);
        }

        return new Multihash(size, hashes);
    }

    /**
     * Create a {@code Multihash} for the given data, containing
     * values for all hashes.  The position of the {@link ByteBuffer}
     * is not affected.
     *
     * @param buf The data for which to create the {@code Multihash}.
     * @return The new {@code Multihash}.
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public static Multihash create(final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        return create(EnumSet.allOf(MultihashAlgorithm.class), buf);
    }

    /**
     * Create a {@code Multihash} for the given data, containing
     * values for all hashes.  The position of the {@link ByteBuffer}
     * is not affected.
     *
     * @param provider The {@link Provider} to use to obtain a {@link
     *                 MessageDigest} implementation.
     * @param buf The data for which to create the {@code Multihash}.
     * @return The new {@code Multihash}.
     * @throws NoSuchAlgorithmException If the {@link Provider} does
     *                                  not provide the given hash
     *                                  function.
     */
    public static Multihash create(final Provider provider,
                                   final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        return create(EnumSet.allOf(MultihashAlgorithm.class), provider, buf);
    }

    /**
     * Create a {@code Multihash} for the given data, containing
     * values for all hashes.  The position of the {@link ByteBuffer}
     * is not affected.
     *
     * @param provider The name of the {@link Provider} to use to
     *                 obtain a {@link MessageDigest} implementation.
     * @param buf The data for which to create the {@code Multihash}.
     * @return The new {@code Multihash}.
     * @throws NoSuchProviderException If the no {@link Provider}
     *                                 exists with the given name
     * @throws NoSuchAlgorithmException If the {@link Provider} does
     *                                  not provide the given hash
     *                                  function.
     */
    public static Multihash create(final String provider,
                                   final ByteBuffer buf)
        throws NoSuchAlgorithmException,
               NoSuchProviderException {
        return create(EnumSet.allOf(MultihashAlgorithm.class), provider, buf);
    }

    /**
     * Create a {@code Multihash} for the given data, containing
     * values for a certain set of hashes.  The position of the {@link
     * ByteBuffer} is not affected.
     *
     * @param algos The algorithms for which to compute hashes.
     * @param buf The data for which to create the {@code Multihash}.
     * @return The new {@code Multihash}.
     * @throws NoSuchAlgorithmException If the default {@link
     *                                  Provider} does not provide the
     *                                  given hash function.
     */
    public static Multihash create(final EnumSet<MultihashAlgorithm> algos,
                                   final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        if (algos.isEmpty()) {
            throw new IllegalArgumentException("Multihashes must contain at " +
                                               "least one hash value");
        }

        final long size = buf.remaining();
        final EnumMap<MultihashAlgorithm, byte[]> hashes =
            new EnumMap<>(MultihashAlgorithm.class);

        for(final MultihashAlgorithm algo : algos) {
            hashes.put(algo, computeHash(algo.getInstance(), buf));
        }

        return new Multihash(size, hashes);
    }

    /**
     * Create a {@code Multihash} for the given data, containing
     * values for a certain set of hashes.  The position of the {@link
     * ByteBuffer} is not affected.
     *
     * @param algos The algorithms for which to compute hashes.
     * @param provider The {@link Provider} to use to obtain a {@link
     *                 MessageDigest} implementation.
     * @param buf The data for which to create the {@code Multihash}.
     * @return The new {@code Multihash}.
     * @throws NoSuchAlgorithmException If the {@link Provider} does
     *                                  not provide the given hash
     *                                  function.
     */
    public static Multihash create(final EnumSet<MultihashAlgorithm> algos,
                                   final Provider provider,
                                   final ByteBuffer buf)
        throws NoSuchAlgorithmException {
        if (algos.isEmpty()) {
            throw new IllegalArgumentException("Multihashes must contain at " +
                                               "least one hash value");
        }

        final long size = buf.remaining();
        final EnumMap<MultihashAlgorithm, byte[]> hashes =
            new EnumMap<>(MultihashAlgorithm.class);

        for(final MultihashAlgorithm algo : algos) {
            hashes.put(algo, computeHash(algo.getInstance(provider), buf));
        }

        return new Multihash(size, hashes);
    }

    /**
     * Create a {@code Multihash} for the given data, containing
     * values for a certain set of hashes.  The position of the {@link
     * ByteBuffer} is not affected.
     *
     * @param algos The algorithms for which to compute hashes.
     * @param provider The name of the {@link Provider} to use to
     *                 obtain a {@link MessageDigest} implementation.
     * @param buf The data for which to create the {@code Multihash}.
     * @return The new {@code Multihash}.
     * @throws NoSuchProviderException If the no {@link Provider}
     *                                 exists with the given name
     * @throws NoSuchAlgorithmException If the {@link Provider} does
     *                                  not provide the given hash
     *                                  function.
     */
    public static Multihash create(final EnumSet<MultihashAlgorithm> algos,
                                   final String provider,
                                   final ByteBuffer buf)
        throws NoSuchAlgorithmException,
               NoSuchProviderException {
        if (algos.isEmpty()) {
            throw new IllegalArgumentException("Multihashes must contain at " +
                                               "least one hash value");
        }

        final long size = buf.remaining();
        final EnumMap<MultihashAlgorithm, byte[]> hashes =
            new EnumMap<>(MultihashAlgorithm.class);

        for(final MultihashAlgorithm algo : algos) {
            hashes.put(algo, computeHash(algo.getInstance(provider), buf));
        }

        return new Multihash(size, hashes);
    }
}

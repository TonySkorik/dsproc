using Space.Core.Infrastructure;
using Space.Core.Interfaces;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Space.Core.Hasher
{
    public class Hasher : IHasher
    {
        public byte[] ComputeHash(Stream input, GostFlavor gostFlavor)
        {
            using (HashAlgorithm hashAlgorithm =
                GostAlgorithmSelector.GetHashAlgorithm(gostFlavor))
            {
                var hash = hashAlgorithm.ComputeHash(input);
                return hash;
            }
        }

        public byte[] ComputeHash(byte[] input, GostFlavor gostFlavor)
        {
            using (HashAlgorithm hashAlgorithm =
                GostAlgorithmSelector.GetHashAlgorithm(gostFlavor))
            {
                var hash = hashAlgorithm.ComputeHash(input);
                return hash;
            }
        }

        public string ComputeHashString(byte[] input, GostFlavor gostFlavor)
        {
            var hash = ComputeHash(input, gostFlavor);
            return Convert.ToBase64String(hash);
        }

        public string ComputeHashString(Stream input, GostFlavor gostFlavor)
        {
            var hash = ComputeHash(input, gostFlavor);
            return Convert.ToBase64String(hash);
        }
    }
}

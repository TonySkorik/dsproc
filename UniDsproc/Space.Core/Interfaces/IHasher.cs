using Space.Core.Infrastructure;
using System.IO;

namespace Space.Core.Interfaces
{
    public interface IHasher
    {
        byte[] ComputeHash(byte[] input, GostFlavor gostFlavor);

        byte[] ComputeHash(Stream input, GostFlavor gostFlavor);

        string ComputeHashString(byte[] input, GostFlavor gostFlavor);

        string ComputeHashString(Stream input, GostFlavor gostFlavor);
    }
}

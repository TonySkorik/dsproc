using CryptoPro.Sharpei;
using CryptoPro.Sharpei.Xml;
using System;
using System.Security.Cryptography;

namespace Space.Core.Infrastructure
{
    public static class GostAlgorithmSelector
    {
        public static string GetHashAlgorithmDescriptor(GostFlavor gostFlavor)
        {
            switch (gostFlavor)
            {
                case GostFlavor.Gost_Obsolete:
#pragma warning disable 612
                    return CPSignedXml.XmlDsigGost3411UrlObsolete;
#pragma warning restore 612
                case GostFlavor.Gost2012_256:
                    return CPSignedXml.XmlDsigGost3411_2012_256Url;
                case GostFlavor.Gost2012_512:
                    return CPSignedXml.XmlDsigGost3411_2012_512Url;
                default:
                    throw new ArgumentOutOfRangeException(nameof(gostFlavor), gostFlavor, null);
            }
        }

        public static string GetSignatureAlgorithmDescriptor(GostFlavor gostFlavor)
        {
            switch (gostFlavor)
            {
                case GostFlavor.Gost_Obsolete:
#pragma warning disable 612
                    return CPSignedXml.XmlDsigGost3410UrlObsolete;
#pragma warning restore 612
                case GostFlavor.Gost2012_256:
                    return CPSignedXml.XmlDsigGost3410_2012_256Url;
                case GostFlavor.Gost2012_512:
                    return CPSignedXml.XmlDsigGost3410_2012_512Url;
                default:
                    throw new ArgumentOutOfRangeException(nameof(gostFlavor), gostFlavor, null);
            }
        }

        public static HashAlgorithm GetHashAlgorithm(GostFlavor gostFlavor)
        {
            switch (gostFlavor)
            {
                case GostFlavor.Gost2012_256:
                    return Gost3411_2012_256.Create();

                case GostFlavor.Gost2012_512:
                    return Gost3411_2012_512.Create();

                case GostFlavor.Gost_Obsolete:
                case GostFlavor.None:
                default:
                    throw new NotSupportedException($"Gost flavor {gostFlavor} is not supported");
            }
        }
    }
}
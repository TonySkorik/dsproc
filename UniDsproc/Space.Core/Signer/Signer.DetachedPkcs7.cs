using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Space.Core
{
    /// <summary>
    /// Detached PKCS7 Sign
    /// </summary>
    /// <seealso cref="Space.Core.Interfaces.ISigner" />
    public partial class Signer
    {
        private byte[] SignStringPkcs7(
            string stringToSign,
            X509Certificate2 certificate,
            X509IncludeOption certificateIncludeOption,
            bool isAddSigningTime)
        {
            byte[] msg = Encoding.UTF8.GetBytes(stringToSign);
            return SignPkcs7(msg, certificate, certificateIncludeOption, isAddSigningTime);
        }

        private byte[] SignPkcs7(
            byte[] bytesToSign,
            X509Certificate2 certificate,
            X509IncludeOption certificateIncludeOption,
            bool isAddSigningTime)
        {
            // Создаем объект ContentInfo по сообщению.
            // Это необходимо для создания объекта SignedCms.
            ContentInfo contentInfo = new ContentInfo(bytesToSign);
            // Создаем объект SignedCms по только что созданному
            // объекту ContentInfo.
            // SubjectIdentifierType установлен по умолчанию в 
            // IssuerAndSerialNumber.
            // Свойство Detached устанавливаем явно в true, таким 
            // образом сообщение будет отделено от подписи.
            SignedCms signedCms = new SignedCms(contentInfo, detached: true);
            // Определяем подписывающего, объектом CmsSigner.
            CmsSigner cmsSigner = new CmsSigner(certificate)
            {
                IncludeOption = certificateIncludeOption
            };

            // NOTE: if above doesn't work for SMEV - use the following
            //cmsSigner.SignedAttributes.Add(
            //	new CryptographicAttributeObject(
            //		new Oid("1.2.840.113549.1.9.3"),
            //		new AsnEncodedDataCollection(
            //			new AsnEncodedData(Encoding.UTF8.GetBytes("1.2.840.113549.1.7.1"))
            //		)
            //	)
            //);

            if (isAddSigningTime)
            {
                cmsSigner.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
            }

            // Подписываем CMS/PKCS #7 сообение.
            signedCms.ComputeSignature(cmsSigner);
            // Кодируем CMS/PKCS #7 подпись сообщения.
            return signedCms.Encode();
        }
    }
}
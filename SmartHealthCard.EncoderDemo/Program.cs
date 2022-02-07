using SmartHealthCard.QRCode;
using SmartHealthCard.Token;
using SmartHealthCard.Token.Certificates;
using SmartHealthCard.Token.Exceptions;
using SmartHealthCard.Token.Model.Shc;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace SHC.EncoderDemo
{
  class Program
  {
    static void Main(string[] args)
    {
      //Run the Encoder demo
      EncoderDemoRunner().Wait();
    }

    static async Task EncoderDemoRunner()
    {
      //Get the Certificate containing a private Elliptic Curve key using the P-256 curve
      //from the Windows Certificate Store by Thumb-print
      // string CertificateThumbprint = "89faeeea715ab86bd0ade30830cc313ff76cca79".ToUpper();
      // X509Certificate2 Certificate = X509CertificateSupport.GetFirstMatchingCertificate(
      //       CertificateThumbprint.ToUpper(),
      //       X509FindType.FindByThumbprint,
      //       StoreName.My,
      //       StoreLocation.LocalMachine,
      //       true
      //       );

      //Set the Version of FHIR in use
      string FhirVersion = "4.0.1";

      //This library does not validate that the FHIR Bundle provided is valid FHIR, it only parses it as valid JSON.      
      //I strongly suggest you use the FIRELY .NET SDK as found here: https://docs.fire.ly/projects/Firely-NET-SDK/index.html       
      //See the FHIR SMART Health Card FHIR profile site here: http://build.fhir.org/ig/dvci/vaccine-credential-ig/branches/main/index.html   

      //Set a FHIR Bundle as a JSON string. 
      string FhirBundleJson = @"
                {
            ""ResourceType"": ""Bundle"",
            ""Type"": ""collection"",
            ""Entry"": [
            {
                ""FullUrl"": ""resource:0"",
                ""Resource"": {
                    ""ResourceType"": ""Patient"",
                    ""Name"": [
                    {
                        ""Family"": ""DEVELOPMENTFIVE"",
                        ""Given"": [
                        ""WEB""
                            ]
                    }
                    ],
                    ""BirthDate"": ""01/01/1991""
                }
            },
            {
                ""FullUrl"": ""resource:1"",
                ""Resource"": {
                    ""ResourceType"": ""Immunization"",
                    ""Status"": ""completed"",
                    ""VaccineCode"": {
                        ""Coding"": [
                        {
                            ""System"": ""http://hl7.org/fhir/sid/cvx"",
                            ""Code"": ""212""
                        }
                        ]
                    },
                    ""Patient"": {
                        ""Reference"": ""resource:0""
                    },
                    ""OccurrenceDateTime"": ""09/29/2021"",
                    ""Performer"": [
                    {
                        ""Actor"": ""Hy-Vee Pella #1516""
                    }
                    ]
                }
            }
            ]
        }
        ";

      // Issuer obtained from: https://demo-portals.smarthealth.cards/DevPortal.html
      //Set the base of the URL where any validator will retrieve the public keys from (e.g : [Issuer]/.well-known/jwks.json)
      Uri Issuer = new Uri("https://spec.smarthealth.cards/examples/issuer");

      //Set when the Smart Health Card becomes valid, (e.g the from date).
      DateTimeOffset IssuanceDateTimeOffset = DateTimeOffset.Now.AddMinutes(-1);

      //Set the appropriate VerifiableCredentialsType enum list, for more info see: see: https://smarthealth.cards/vocabulary/
      List<VerifiableCredentialType> VerifiableCredentialTypeList = new List<VerifiableCredentialType>()
      {
        VerifiableCredentialType.VerifiableCredential,
        VerifiableCredentialType.HealthCard,
        VerifiableCredentialType.Covid19
      };

      //Instantiate and populate the Smart Health Card Model with the properties we just setup
      SmartHealthCardModel SmartHealthCard = new SmartHealthCardModel(Issuer, IssuanceDateTimeOffset,
          new VerifiableCredential(VerifiableCredentialTypeList,
            new CredentialSubject(FhirVersion, FhirBundleJson)));

      //Instantiate the Smart Health Card Encoder
      SmartHealthCardEncoder SmartHealthCardEncoder = new SmartHealthCardEncoder();

      // private key obtained from: https://demo-portals.smarthealth.cards/DevPortal.html
      // {
      //   “kty”: “EC”,
      //     “kid”: “3Kfdg-XwP-7gXyywtUfUADwBumDOPKMQx-iELL11W9s”,
      //     “use”: “sig”,
      //     “alg”: “ES256",
      //     “crv”: “P-256",
      //     “x”: “11XvRWy1I2S0EyJlyf_bWfw_TQ5CJJNLw78bHXNxcgw”,
      //     “y”: “eZXwxvO1hvCY0KucrPfKo7yAyMT6Ajc3N7OkAB6VYy8",
      //     “d”: “FvOOk6hMixJ2o9zt4PCfan_UW7i4aOEnzj76ZaCI9Og”
      // }

      var d = "FvOOk6hMixJ2o9zt4PCfan_UW7i4aOEnzj76ZaCI9Og";
      var x = "11XvRWy1I2S0EyJlyf_bWfw_TQ5CJJNLw78bHXNxcgw";
      var y = "eZXwxvO1hvCY0KucrPfKo7yAyMT6Ajc3N7OkAB6VYy8";

      var PublicKey = ECDsa.Create(new ECParameters
      {
        Curve = ECCurve.NamedCurves.nistP256,
        Q = new ECPoint
        {
          X = Base64UrlEncoder.DecodeBytes(x),
          Y = Base64UrlEncoder.DecodeBytes(y)
        }
      });

      var PrivateKey = ECDsa.Create(new ECParameters
      {
        Curve = ECCurve.NamedCurves.nistP256,
        D = Base64UrlEncoder.DecodeBytes(d),
        Q = new ECPoint
        {
          X = Base64UrlEncoder.DecodeBytes(x),
          Y = Base64UrlEncoder.DecodeBytes(y)
        }
      });

      string SmartHealthCardJwsToken = string.Empty;
      try
      {
        //Get the Smart Health Card JWS Token 
        SmartHealthCardJwsToken = await SmartHealthCardEncoder.GetTokenAsyncFromKeys(PublicKey, PrivateKey, SmartHealthCard);
      }
      catch (SmartHealthCardEncoderException EncoderException)
      {
        Console.WriteLine("The SMART Health Card Encoder has found an error, please see message below:");
        Console.WriteLine(EncoderException.Message);
      }
      catch (Exception Exception)
      {
        Console.WriteLine("Oops, there is an unexpected development exception");
        Console.WriteLine(Exception.Message);
      }

      //Instantiate the Smart Health Card QR Code Factory
      SmartHealthCardQRCodeEncoder SmartHealthCardQRCodeEncoder = new SmartHealthCardQRCodeEncoder();

      //Get list of SMART Health Card QR Codes images
      //Note: If the SMART Health Card JWS payload is large then it will be split up into multiple QR Code images.
      //SMART Health Card QR Code scanners can scan each image in any order to obtain the whole SMART Health Card  
      List<Bitmap> QRCodeImageList = SmartHealthCardQRCodeEncoder.GetQRCodeList(SmartHealthCardJwsToken);

      var jws = SmartHealthCardQRCodeEncoder.GetQRCodeRawDataList(SmartHealthCardJwsToken);

      //Write to file the SMART Health Card QR Codes images      
      for (int i = 0; i < QRCodeImageList.Count; i++)
      {
        QRCodeImageList[i].Save(@$"/Users/mleners/Developer/SmartHealthCard/QRCode-{i}.png", System.Drawing.Imaging.ImageFormat.Png);
      }
    }
  }
}

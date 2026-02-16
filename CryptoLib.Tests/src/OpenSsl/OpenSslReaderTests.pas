{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit OpenSslReaderTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  Rtti,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpPemObjects,
  ClpIPemObjects,
  ClpIPemWriter,
  ClpPemWriter,
  ClpIOpenSslPemWriter,
  ClpOpenSslPemWriter,
  ClpIOpenSslPemReader,
  ClpOpenSslPemReader,
  ClpIAsymmetricCipherKeyPair,
  ClpAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpBigInteger,
  ClpRsaGenerators,
  ClpIRsaGenerators,
  ClpIRsaParameters,
  ClpRsaParameters,
  ClpIKeyGenerationParameters,
  ClpKeyGenerationParameters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpDsaParameters,
  ClpIDsaParameters,
  ClpDsaGenerators,
  ClpIDsaGenerators,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpICmsAsn1Objects,
  ClpCmsAsn1Objects,
  ClpCmsObjectIdentifiers,
  ClpIAsn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TOpenSslReaderTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    const
      (* PKCS7 ContentInfo with contentType id-envelopedData (from bc-reference openssl/pkcs7.pem). *)
      Pkcs7Pem =
        '-----BEGIN PKCS7-----' + sLineBreak +
        'MIIJogYJKoZIhvcNAQcDoIIJkzCCCY8CAQAxgfgwgfUCAQAwXjBZMQswCQYDVQQG' + sLineBreak +
        'EwJHQjESMBAGA1UECBMJQmVya3NoaXJlMRAwDgYDVQQHEwdOZXdidXJ5MRcwFQYD' + sLineBreak +
        'VQQKEw5NeSBDb21wYW55IEx0ZDELMAkGA1UEAxMCWFgCAQAwDQYJKoZIhvcNAQEB' + sLineBreak +
        'BQAEgYAikb9cD39oDYpMHzLuqA4BonNpPx+jYtqlUIaJv30V03nUz1MLm7IH7TFt' + sLineBreak +
        'ZhL6BXAbdC2iwk62KVS66ZCLBKdsqtD3w9N2HtxTEW6AdaNHKNUb6z83yarNQGzB' + sLineBreak +
        '67llZjeCLeipP7RWIvBZcV0OoqCgLcpZkpZqzrmz5MjxTCmB/DCCCI0GCSqGSIb3' + sLineBreak +
        'DQEHATAUBggqhkiG9w0DBwQIja9nGhuQE1GAgghocswhe5MZRov9Zo1gnB25S0P8' + sLineBreak +
        'Mw3463VaOcb+ljX1mXkT3fivkBv0plLlmVT+m+CRgczup9p21+t1OqsdaITNIyrG' + sLineBreak +
        'hYSVETWyFA/Yn7dQupK+cdCaVLKC3lT8f13iPrU40wnbeo4ZKi2vbv/X3uU4fRMZ' + sLineBreak +
        'wSlyczFozcviUYURtA5MZaS2e6/2r1eLZcUlcZ0BDcuD+FNdryGbKztSWa2ye0Ym' + sLineBreak +
        'Uilu+GAZr5CQi3IxpRxDqrS+RUQZNllcg8nGZ2UP5W8FjH+Z568NJ7djoziCX0EH' + sLineBreak +
        'yd4vp+g0LRG2dkhGXIff4ufO2U3QOAgCIOuZmG5YSpRN2U7F6T8W/FwShFO1u+QH' + sLineBreak +
        'YduA3pA/5K+IDfCbEZDMWznd13lTEZQlLSXV7dLNCqpR30JWpGg956rJR0k2bT7G' + sLineBreak +
        'KFTXhSUK/Puac5y6IVmJwPxqAkjH+xjXpE32/AcRHi77La3nKp1aQEKo5uHg7HEg' + sLineBreak +
        'w160S1LUenJSqcmOuk5XWvM1wdsUJl5Qk4m9a0VyovLPm/RrnulMtUjRugxJLfZK' + sLineBreak +
        '27NivOrLl9h/Wm6BXYq4PohM5d+5zPYqupn5ipKHsA68Ps7rnDEGS3VzOQ32hqu4' + sLineBreak +
        'kdm6xI2zLWK0+6mQnusBPO0IAxtja6BPz8vTMlWjZtWZgEIMppQMhQJKBEQG6HTV' + sLineBreak +
        'z+/gkFds2pFO0v8pLcMBy9+8nqhzwGacymnupXJzB6l3gon2t/e2zJjAPKUSCbHI' + sLineBreak +
        'QhCjW2JK9tGKTbF40uYMUGMIPhxr7j1u4LKNEhKCNhlUz82NSsdJ00YNQdwuDMWN' + sLineBreak +
        'CTAE9/STmRGF3ZHT9KWmz5MQECp/pGORD7LtOQslbUYiMH5oCYP1jD8eM+KxCljv' + sLineBreak +
        '1pFPf+sZdpboAkdaXKcZVnKqOuPBP3Y1jBkLCZykgnXkVbEYM7gSdvsCGK52GcxH' + sLineBreak +
        'yi/gOhfOIgywmFB3B4Yk4mDtU84WpK5sVlrZ2vZuTaAmOHaTIkVMvkq30F/jpVy3' + sLineBreak +
        'OF4v9/EbEAJGv6rqHMhKmuIHP530CKtWkUUfGv7qQilZ1Qi6NyFJJTfb1bhyENJt' + sLineBreak +
        'j8A1QQFIYHDzMolmUoQgqOXJ/6xc9AtCv0fU2LijLUNFjB4rapJggo5UnZE98+Iq' + sLineBreak +
        'UAT7tWalpbFisOdX5Dy582hhvcFn/1DDpISXpF0kgE8TV/swkJ7zuu+hO/Yj1HNd' + sLineBreak +
        'cwG6NC9+wUCjaRqAobBtvPQyK666I8C12pnW0AeuqtznnZve2B0/a83ECS0tUmxC' + sLineBreak +
        'PO9zv9RNwcakynklrupw7B4PcXEaEbxpvHE+/zNLgfrPRggoFdqSIRFS9xQRPE9T' + sLineBreak +
        'uO7jEh+tyh70eLqce2jqKpRwxItZst3ABT5XarJ6vfGxxcs55sJG7xjv52xuMikY' + sLineBreak +
        'gOagSKpETRdkeE1aAmKwpa/vEFu2J4Oq1Aiv+D2Gc7G04cOsdc+6P+N9EEv70v0R' + sLineBreak +
        '3NA4vg3gTBcO3wxwnJZAS7GwUJOcrqC1cAaQkc5NR0lUx0lMzgWWDDS5qKX+YwIU' + sLineBreak +
        '7KEQiyhqQ74rkf6hxQyfesaBxqxCZZkikbwBHlDZwoPfwnfrV4X4/xyo3cqCqbhf' + sLineBreak +
        'FFlHOAXissz14wsTPh4XQumj5RZSnwj8gGK2xou9H9wMrwuZ2eAT/3L3OtbIr/Sz' + sLineBreak +
        'Cbp8Y95Tz8FgmrJXvygMVO1xv77PA1DzE9SLiLyB6TL8lsxFQ1ZF2D8JhpDeIPpj' + sLineBreak +
        'L0k2vTrmCgENJ+tCc0ngZO55ZgRbo1fbB/RUfkTRgEKF9WmJYnlXUVoh77kZ0cc9' + sLineBreak +
        'Y+KsueEZp1woSTywJb3tc/jXeRGSmcaWe6pa0DcfM50coV0y4lw1ednEV3zkA1r4' + sLineBreak +
        'zVtUBw8Xvr9GKcNfWdmqgIJKsQraq6WCeIxCPPJw708+/RERQBoUobXI4+Jatw/z' + sLineBreak +
        'XiV9SjrjK9nJ4H1YKyOjyz3SAbeYrgdgrTGvkETCPAALb+4Rg1FHymSMfDquwOsB' + sLineBreak +
        '63Mdl63DIkJpicA6CY6yk/LgOADQzEipjcdKqzQOjlb4hsQZxN83kzGJiWB0qZOL' + sLineBreak +
        'XVLrGXP4xRYS2bUFB0T8pon0K5qsZ9oKKf+HZaHMYkni43Ef9IRA0qeDl4FfAupA' + sLineBreak +
        'kL0lLnBjgGRHc6rMBy4qL18xRjTtR9hsn4Z/pYhIgqMm3QEVkK/aOgTOlwXHdIwu' + sLineBreak +
        '+Hvzx0Y/BgMdCZSlrspPbQBDgrlWzr+PjcjEvDf3LYj9whtRJP5cXVxiYqi/SpCk' + sLineBreak +
        'Ghy47RfNYfkkJs/gbojlO/lDvM8oo+XPi22zAN6yFLuxr65lJZK7QIvabHvTkEIN' + sLineBreak +
        'wmpnWcRH+MwcFZO3yKt6lxY7nJWuW5hh8O7k4/oN0pNdGtv1/2XgXFOCREQ4CcPn' + sLineBreak +
        'Zm/vXULLCCh7oP+RyklnwyedvfeSfY4lpldwyHCIsYyYmfZHMw32zqH5jCnSxZA4' + sLineBreak +
        'fHBrblr4Mj/5jyHLUF5xGsJdm5RtDfwJWe6NelO/kJMs35UjA6dhSOfHEkw73M5P' + sLineBreak +
        'jcRo1OtYZGu19x2QguhILpZxuAvNtLpOt88z3PtsxA6Fc0BGpQXPJTYwtXiPf1lj' + sLineBreak +
        'fUd5KFsPohPJOIEJAaFHL3GTwmWFtK1dHofPQukiOTb6pC6yKlM/zGWLOyzTM4qP' + sLineBreak +
        'UvuUSwg1UY8GplCeqhCJNTieNmyY70vzG2CWcotAwRPeVbpa4MEWRXHf9ft4Mawb' + sLineBreak +
        'qn2J48iW4Zgh82vFHNYcGRjKRJqLzp4VBn/qpRaX+aWEsdXq4shRgFOAOKyQNMex' + sLineBreak +
        'GZyd9amkblqjEOOEzzxPUdmt8k+QEm+JC80NR2sv1mw80PqU/his5zUJ1Aj4tzkF' + sLineBreak +
        'fi4jy2nPNvVSpjWiAI6cpZsbdhdh9iayij4YdQg3HB20+1K9VcFnTmBqLKiBbG2o' + sLineBreak +
        '4oX2oNPE9Vr3H9Y8YaVoeUU+Kiqo5g==' + sLineBreak +
        '-----END PKCS7-----';
      (* Unencrypted DSA private key (from bc-reference openssl/dsa/openssl_dsa_unencrypted.pem). *)
      DsaUnencryptedPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'MIIDPgIBAAKCAQEAyKItMopMK218pcmy6PkrMVXAv5dt07TdGBuNhVWpQ52ldK9X' + sLineBreak +
        'mL7CPKpo4Dy85EZRPvRNyOnhe+LRJZ+ReKntpEkEiar/ZsKVkUthPsiUMpoM5S79' + sLineBreak +
        'JK8iT8F9HdFjIFKaXGySBZ4xcrj8HQ/v75iolYCso+66Ybgjs9/nsWS0UQyGE6rc' + sLineBreak +
        'ibx7xPAtcbaGZUBaBtdkNER7+P2ueJwej89aNZxj+AKuvrWrArq6/5zOIhGR12wQ' + sLineBreak +
        'EQQjj7FQ66ZFivJ/AYsv1yXDS7mZBNp5eMuxk8Kmis/++HKcP7tdbVRnlfTGdBuN' + sLineBreak +
        'BMyOcBTIsE11jwikcI+KIbr9cEZoaikkm4KyuwIVAP4DZEC+/JZJ0PHSEtJTt6uz' + sLineBreak +
        'yn1hAoIBAHhLbqDib7zqaFBrNnbaBSNiltY3GxWM6uQT88NH9YWz3wXRb6i4KJFH' + sLineBreak +
        '9NtLbK0RF7MoQVprJY6LuGQHZ/e61Fs2EabDwT4vB2HT619fVUvDndbuSW6qfUR4' + sLineBreak +
        'y9kbG7zLkE4Mnym/ikmUwLABLA67cZUS9yjtcRXGpOkiTAQfCGBeUH6nWOFEaWjI' + sLineBreak +
        'fGNMQ5awKvZhIvGyN4Zvd+mE+199s/kAsCKFux2Sq9tYw3qS0Tw2IEebHsHvX7A3' + sLineBreak +
        'bvxV6p7czVxlO9+O0w7bBTekPpw1BnCYmPyy0H36g/7aF2V70UCWzER8zT1Pfh7d' + sLineBreak +
        '3P0hLqHYzX375l/7oxuDawtcDAV++iwCggEASajPdllHVQ8JvKdPH6qDkjC5XJTZ' + sLineBreak +
        'RK46mYm1cCu8Q9Dy9ZfL67CcJBpwKVHNC3sXmk4XPfs91AZf/t01qbMJvCrR8NHs' + sLineBreak +
        'jRyJkNIaMyDeWcFmO0KmMi374BQpFyIDQ6mK1y9BilneZ6gHDdfHMsKniLFW+SQf' + sLineBreak +
        '9hlwlArIPYuELu7riJhNcuRUTJEfybDHwM4/ht0IFbyUIFl00mMdTrozk+e/esEs' + sLineBreak +
        'QdWbx2UBjNs8meZPivFbT2HpQF1I0qZhtn3e7jcR5YatBQ3e4abnu1RrDc73q7d4' + sLineBreak +
        'g2SYQK3PmIWwxiFhJQTzeiQtl5rKzEn76knAydOtPVRgjXWzHUoW6Az0qwIVAMvw' + sLineBreak +
        'thRrEZxNdxELdnwW3rpYBm6B' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';
      (* Unencrypted RSA private key (from bc-reference openssl/rsa/openssl_rsa_unencrypted.pem). *)
      RsaUnencryptedPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'MIIEpAIBAAKCAQEAyGOvloI+jKnRHWKuhYB+cTIEwZhagKJ0f3rIY8WNgujB7Plp' + sLineBreak +
        'gpjUg4pNjYGViGjg7zhfbjhCtlNGXyRBti3GcaHiBIIP5nyCNn+Ay8tSWGo5v5Zc' + sLineBreak +
        '8BQcwHf0ZHLN6sD9m2uVSp/6UqjS5ZyhzF5FzvvUo3xw8fecdnStXQfHhkBnLpTj' + sLineBreak +
        'HE5t7iu1JVjTuE0pcBvah2dWqDNxiIOQtXyKW8Sag1YxaunxQGqRNykSFiEJindx' + sLineBreak +
        'OSAnAxK6q/wGqcZ3zvFBTcVVkji1u2QH4rOMP3PPxAIMkB8ONkdHTco1DmbE6BfD' + sLineBreak +
        'HArDqUYxqJUlPGlMqrKb3fCFiT3eXehwR7nlzQIDAQABAoIBAFd6vTKVVT0O/U04' + sLineBreak +
        'wTtiptA/p7fkDM5PHVBxh32Wxno5pj8PerIaiduKyuRVh7PvJRMJpw903BrAK95o' + sLineBreak +
        '847WWOVOaF7TcKGMBURJUS6maiJS7TboK1ZbUVnsg/I99ArhiVUKGDhlsl/Xd4np' + sLineBreak +
        'YPDYztzXLzLXpm7bS6CiuvP762x9dfVu8K+afP8cjH8pfXLq55ghZOUKidRQaYz1' + sLineBreak +
        'mNOTQyAQlCQdLRgKlYgqcRHlj0pb28XBJaln3W7Z7GFMWFPojkxx6LaCp8+Jyx2C' + sLineBreak +
        'tv54zIZQhMjF37tQyTnfK4Ocl3sCRb+jYV4FkrUnsQE9W2dey0Tms1XB31gfUJlx' + sLineBreak +
        'dRZu7zkCgYEA/nWcTwzot2OIAhXoJ2fnqTcpdmj05LHhGcayKjyix7BsVH2I0KpF' + sLineBreak +
        '9kXX066tr3+LxZTergl4UpWSl3yx/4kPBQM6np4VVRytn7+cQdEhOczZnBw6x7IZ' + sLineBreak +
        'fv81DSNruQDBRAlTtklW4KBY74JKLhaJSvF1F3x32+H+99i1MmCNJRMCgYEAyZpF' + sLineBreak +
        'h4c3pM9z+YlmgLdUh/G2abdoamugcQOFbzHbZowsRAxEzdEW9wj2McN6mt8Rn1tc' + sLineBreak +
        'tY/+PcYuIK+vcmk9k23GuzxRlJlkaDicHwlAebgVIulFcrStfTlSkXjpuOuusfD9' + sLineBreak +
        '2DuHMcUiPx3qElNB0dZJF/axpq7BjTIFENefhZ8CgYACn+vw1M1BtwEcJGW0olm9' + sLineBreak +
        'YRhIZGTCRyNvRKFp1h5HuQYlCPZ0UI1QMQA86rxX5xTmANcbLHXVRD2y2lJrtFo3' + sLineBreak +
        'TwU3xaGqsxUHZM6TzzhshDRqa9AfZzLkIHXHoOnnip5zuTTn2HHQ91ZzggCJ4Smh' + sLineBreak +
        'YEQ47cu+tOIQZGfaESzjiQKBgQCCfnZlDJRq/NFwA40y4fg4arANa+eNgw7+OC5F' + sLineBreak +
        '1HrUvQTmIx7iLmZ0Dvv1KDgTSTLJ+MRgzczexYoUJEQnhZGS/Wq2xYt06XlBsOr1' + sLineBreak +
        'd/KhFxOvXllSrzrhJJqaiS6YQQ36JijZr2aKQ7UwL7fUlsmy/safWVKStumX8Hmw' + sLineBreak +
        '9jFOtwKBgQDmtirdNQ8aKolokD/3bDHPcDsNcybEpiCu8BIltxZAs/LsN1IIxfcp' + sLineBreak +
        'mGP2AFt3mbblKbsRM8hDW/X9taeG9s2KGe5wlKOE5lV8YAo4hFoJYN2/0d8Y0K9X' + sLineBreak +
        'QAAYU3iPG1zL+a/7TFLJ0u/biqsBg9hnNbMnN/tOeSuKnH2Rx9F1rg==' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';
  strict private
    function CreatePemReader(AStream: TStringStream): IOpenSslPemReader;
    function CreatePemWriter(AStream: TStringStream): IOpenSslPemWriter;
    procedure KeyPairTest(const AName: string; const APair: IAsymmetricCipherKeyPair);
    procedure DoOpenSslTestData(const APemData: string; AExpectDsa: Boolean);
  published
    procedure TestPkcs7EnvelopedData;
    procedure TestKeyPairRsaRoundTrip;
    procedure TestKeyPairDsaRoundTrip;
    procedure TestPkcs7RoundTrip;
    procedure TestOpenSslDsaUnencrypted;
    procedure TestOpenSslRsaUnencrypted;
  end;

implementation

{ TOpenSslReaderTest }

function TOpenSslReaderTest.CreatePemReader(AStream: TStringStream): IOpenSslPemReader;
begin
  AStream.Position := 0;
  Result := TOpenSslPemReader.Create(AStream);
end;

function TOpenSslReaderTest.CreatePemWriter(AStream: TStringStream): IOpenSslPemWriter;
begin
  Result := TOpenSslPemWriter.Create(AStream);
end;

procedure TOpenSslReaderTest.KeyPairTest(const AName: string;
  const APair: IAsymmetricCipherKeyPair);
var
  LWriteStream: TStringStream;
  LReadStream: TStringStream;
  LWriter: IOpenSslPemWriter;
  LReader: IOpenSslPemReader;
  LReadVal: TValue;
  LPubK: IAsymmetricKeyParameter;
  LReadPair: IAsymmetricCipherKeyPair;
begin
  LWriteStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := CreatePemWriter(LWriteStream);
    LWriter.WriteObject(TValue.From<IAsymmetricKeyParameter>(APair.Public));

    LReadStream := TStringStream.Create(LWriteStream.DataString, TEncoding.ASCII);
    try
      LReader := CreatePemReader(LReadStream);
      LReadVal := LReader.ReadObject();
      Check(not LReadVal.IsEmpty, 'Public key should read back');
      Check(LReadVal.TryAsType<IAsymmetricKeyParameter>(LPubK), 'Should be public key');
      Check(LPubK.Equals(APair.Public), 'Failed public key read: ' + AName);
    finally
      LReadStream.Free;
    end;
  finally
    LWriteStream.Free;
  end;

  LWriteStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := CreatePemWriter(LWriteStream);
    LWriter.WriteObject(TValue.From<IAsymmetricKeyParameter>(APair.Private));

    LReadStream := TStringStream.Create(LWriteStream.DataString, TEncoding.ASCII);
    try
      LReader := CreatePemReader(LReadStream);
      LReadVal := LReader.ReadObject();
      Check(LReadVal.TryAsType<IAsymmetricCipherKeyPair>(LReadPair), 'Should be key pair');
      Check(LReadPair.Private.Equals(APair.Private), 'Failed private key read: ' + AName);
      Check(LReadPair.Public.Equals(APair.Public), 'Failed private key public read: ' + AName);
    finally
      LReadStream.Free;
    end;
  finally
    LWriteStream.Free;
  end;
end;

procedure TOpenSslReaderTest.DoOpenSslTestData(const APemData: string;
  AExpectDsa: Boolean);
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LKp: IAsymmetricCipherKeyPair;
  LDummy: IInterface;
begin
  LStream := TStringStream.Create(APemData, TEncoding.ASCII);
  try
    LReader := CreatePemReader(LStream);
    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'ReadObject should return key');
    Check(LVal.TryAsType<IAsymmetricCipherKeyPair>(LKp), 'Should be key pair');
    Check(LKp <> nil, 'Didn''t find OpenSSL key');
    if AExpectDsa then
      Check(Supports(LKp.Private, IDsaPrivateKeyParameters, LDummy), 'Returned key not DSA private')
    else
      Check(Supports(LKp.Private, IRsaPrivateCrtKeyParameters, LDummy), 'Returned key not RSA private');
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.TestPkcs7EnvelopedData;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LCmsContent: ICmsContentInfo;
begin
  LStream := TStringStream.Create(Pkcs7Pem, TEncoding.ASCII);
  try
    LReader := CreatePemReader(LStream);
    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'ReadObject should return PKCS7');
    Check(LVal.TryAsType<ICmsContentInfo>(LCmsContent), 'Should be CmsContentInfo');
    Check(LCmsContent <> nil, 'ContentInfo should not be nil');
    Check(LCmsContent.ContentType.Equals(TCmsObjectIdentifiers.EnvelopedData),
      'ContentType should be EnvelopedData');
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.TestKeyPairRsaRoundTrip;
var
  LGen: IAsymmetricCipherKeyPairGenerator;
  LPair: IAsymmetricCipherKeyPair;
  LSecRandom: ISecureRandom;
begin
  LSecRandom := TSecureRandom.Create();
  LGen := TRsaKeyPairGenerator.Create();
  LGen.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf($10001),
    LSecRandom, 768, 25) as IKeyGenerationParameters);
  LPair := LGen.GenerateKeyPair();
  KeyPairTest('RSA', LPair);
end;

procedure TOpenSslReaderTest.TestKeyPairDsaRoundTrip;
var
  LGen: IAsymmetricCipherKeyPairGenerator;
  LDsaParamsGen: IDsaParametersGenerator;
  LDsaParams: IDsaParameters;
  LDsaKeyParams: IKeyGenerationParameters;
  LPair: IAsymmetricCipherKeyPair;
  LSecRandom: ISecureRandom;
begin
  LSecRandom := TSecureRandom.Create();
  LDsaParamsGen := TDsaParametersGenerator.Create();
  LDsaParamsGen.Init(512, 80, LSecRandom);
  LDsaParams := LDsaParamsGen.GenerateParameters();
  LDsaKeyParams := TDsaKeyGenerationParameters.Create(LSecRandom, LDsaParams) as IKeyGenerationParameters;
  LGen := TDsaKeyPairGenerator.Create();
  LGen.Init(LDsaKeyParams);
  LPair := LGen.GenerateKeyPair();
  KeyPairTest('DSA', LPair);
end;

procedure TOpenSslReaderTest.TestPkcs7RoundTrip;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LCmsContent: ICmsContentInfo;
  LWriter: IOpenSslPemWriter;
  LOutStream: TStringStream;
  LReader2: IOpenSslPemReader;
  LVal2: TValue;
  LCmsContent2: ICmsContentInfo;
begin
  LStream := TStringStream.Create(Pkcs7Pem, TEncoding.ASCII);
  try
    LReader := CreatePemReader(LStream);
    LVal := LReader.ReadObject();
    Check(LVal.TryAsType<ICmsContentInfo>(LCmsContent), 'Should be CmsContentInfo');
    Check(LCmsContent <> nil, 'ContentInfo should not be nil');

    LOutStream := TStringStream.Create('', TEncoding.ASCII);
    try
      LWriter := CreatePemWriter(LOutStream);
      LWriter.WriteObject(TValue.From<ICmsContentInfo>(LCmsContent));
      LReader2 := CreatePemReader(LOutStream);
      LVal2 := LReader2.ReadObject();
      Check(LVal2.TryAsType<ICmsContentInfo>(LCmsContent2), 'Read back should be CmsContentInfo');
      Check(LCmsContent2.ContentType.Equals(TCmsObjectIdentifiers.EnvelopedData),
        'failed envelopedData recode check');
    finally
      LOutStream.Free;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.TestOpenSslDsaUnencrypted;
begin
  DoOpenSslTestData(DsaUnencryptedPem, True);
end;

procedure TOpenSslReaderTest.TestOpenSslRsaUnencrypted;
begin
  DoOpenSslTestData(RsaUnencryptedPem, False);
end;

initialization

{$IFDEF FPC}
RegisterTest(TOpenSslReaderTest);
{$ELSE}
RegisterTest(TOpenSslReaderTest.Suite);
{$ENDIF FPC}

end.

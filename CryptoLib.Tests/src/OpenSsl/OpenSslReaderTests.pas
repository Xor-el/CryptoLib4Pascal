{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
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
  ClpValueHelper,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIOpenSslPemWriter,
  ClpOpenSslPemWriter,
  ClpConverters,
  ClpIOpenSslPemReader,
  ClpOpenSslPemReader,
  ClpIOpenSslPasswordFinder,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpBigInteger,
  ClpRsaGenerators,
  ClpIRsaParameters,
  ClpRsaParameters,
  ClpIKeyGenerationParameters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpDsaParameters,
  ClpIDsaParameters,
  ClpDsaGenerators,
  ClpIDsaGenerators,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpPkcsAsn1Objects,
  ClpICmsAsn1Objects,
  ClpCmsObjectIdentifiers,
  ClpIAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpX9ObjectIdentifiers,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestOpenSslPassword = class(TInterfacedObject, IOpenSslPasswordFinder)
  strict private
    FPassword: TCryptoLibCharArray;
  public
    constructor Create(const APassword: String);
    function GetPassword(): TCryptoLibCharArray;
  end;

  TOpenSslReaderTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    const
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

      EcParametersWithPrivateKeyPem =
        '-----BEGIN EC PARAMETERS-----' + sLineBreak +
        'BggqhkjOPQMBBw==' + sLineBreak +
        '-----END EC PARAMETERS-----' + sLineBreak +
        '-----BEGIN EC PRIVATE KEY-----' + sLineBreak +
        'MHcCAQEEIA+81An0qk7oztXp+tagHCSaZumqwn9CtutCv4OTS+M9oAoGCCqGSM49' + sLineBreak +
        'AwEHoUQDQgAEkzJDRhblkCRl1m4hchBjV2o6cqqOT2k3IdUU0/LhYLuzV+gvlgDD' + sLineBreak +
        'BwPl8QSucQXgPoLdj3yhX9Audpcoe+WkvA==' + sLineBreak +
        '-----END EC PRIVATE KEY-----';

      DsaAes128CbcPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-128-CBC,3D7028A746BE6B09694E16A222C543CB' + sLineBreak +
        '' + sLineBreak +
        'RkTEJRJjGfaMfNc876Tx1hD92cblJRj7TvUafRKnH0J3Zv7l67MSG/6rY5HD91HP' + sLineBreak +
        's9i9Se+H8Sjn/HaUl3QTZv04egloNlL3MPSkI5fusR6maZGPVLRJBLfVKYQZVDja' + sLineBreak +
        '9YRe+ZhXMS8jTe/IhYMcTlQLBnnwmmgZC09Y9Wm39idu7lytOl3JBMgz0aUNA+P6' + sLineBreak +
        'lN2MtaQyIBXHbaqfNDGFn/r7+MH4CGw6MtrPzGqRJgGMHhV6T5o/x0nEU+loQVOK' + sLineBreak +
        'mPkSZTxBbn7xUb4JvFPnLTbsI4Cnre3QmfmDwkCAklQXqAIT9Ex1Slq8qaCc6TEf' + sLineBreak +
        'mWJQCYPUkpQOqyinR8o1VbYm3DFFvE5F+CktJrppqkQvAct0dQNjMTBFxUjCkZum' + sLineBreak +
        'qGfAslGPBREmmnsExm5GThYqA5LN+qo2prBtvt6Eso0i2jNiXA8bi5OfDzDr24R5' + sLineBreak +
        '/RKUdFPf7keaAjg9jSArwp6EfM3y3sj2riibwZlty2ckPJw3SwxIe6QSMwKRbKlh' + sLineBreak +
        'GJoi05/cO0NxQYhMmlwVN9v5+YpvWmT3CsFvCA+Zb5rXPx2AZpFv8YoHdQb0qyEs' + sLineBreak +
        'b5YuVoavL58+BWIPQpeYy/jttR5pEPpgM+C/6/1o4Cae4lwppP2OYFl1fsqyqbKh' + sLineBreak +
        'iadErB6QRaJCnfnhG6511CxY+vZtQE5EM36blOl/op+6G+36ApuqDtfA0C074daV' + sLineBreak +
        'uHfcqA/g5dODEJP+ps6yoWtM5lbd5bZZVidWhrU6Skbt0faF9w5ECF0qkYDGqF85' + sLineBreak +
        'qqFcaoimq+NP7EtUEFSneOee72zYALXyzjoEU9InktzDi0Oufojzc1gjhh7LbObw' + sLineBreak +
        'UBANPHTsbaL6FPTEs4a3JYSyat9m/R5GAaT0EBynHxvdQRGNhtEWFPkpGYUrAz9W' + sLineBreak +
        '0A9mNX1as8Jsxkh9wqjgOR6Xpbqh0aFHNnkodwV72H5ROga5EN8/bbuCBxInNzy8' + sLineBreak +
        'o9z19AnajR7vCW/p42QwsGfSolQgE3KBdqWsle81LcCPVQPQshXzcjgBHZbH9/mY' + sLineBreak +
        'M4bX4iEsC9yeNgoMcHtIagOKipsqd4nuPskutf07Mh71OXFuxsVyGcOBVhhdZCb0' + sLineBreak +
        '3ZYzVi+nzORPRZ93nPXipy3+NmoARk7mhXDgX9p1bPI=' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes128CfbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-128-CFB,C0CCB782DF620FA388D9A356F8B7C346' + sLineBreak +
        '' + sLineBreak +
        'DftIvr+HZuCHBanw4n8P5ZajHAw1ldQkSgLxtxY0ZYhhVDLEqEqh6z+4ySjZz5SR' + sLineBreak +
        'KY7kYFo6yJnURurg3DAGvJ55s6jgyrRHQZkhiO1fBxhyarOfcBjJauJKDT4uhFtC' + sLineBreak +
        'LWZ7dqft3PlcHi09mFKjK+BYjULe1QkdrKQlV5FBpCj7ENuHqtfx//bV+IWWVnbu' + sLineBreak +
        'QRx4ec2nNCiS2qiI9Qg7fgMdXWrpJlr8Zvfmn0Mta3Dn9SWR9hK5J4d3xiBtaF0F' + sLineBreak +
        '+BNuszy9poxnsRaORZYAsBh2vdLaQyn1gGdehlsWG4J2Zb5RHApYczJcp2AoPX4K' + sLineBreak +
        'j9wAzlfLRSZ4Lt5edShd1zf/iDxegBKQFFHTfPA6uu+fe38qckdxVyBdGaCCBvUz' + sLineBreak +
        'Quu2DjjXdCWWo8To5C28LVoVyAy+qJaX86vn7yw03/6n0y2dkydiB3u6wnucsom2' + sLineBreak +
        'HfLX+pdyarFoNvtCeSW3Y/1Eqd54dDhz3GrSTh6c7G+wiRziKpTduEmoZ+l+CIrl' + sLineBreak +
        'tWxmh59YTSeX4mi48+fxTA8xaVwD/j3VuA/jTOQWDW+DXU2z6OcAQ9rlOnT6Jad6' + sLineBreak +
        'P2El+vgLrIFbC4eJs2ry6bszqFJ4wieBVnazPCUADLSsXVwbFuO9oB4129y3Yg+U' + sLineBreak +
        'dE+lN24KV0kC/YIdO7c2PghaFY98CVrBX/oocHy4j122fHfboiPNh7S7n6cqJHh2' + sLineBreak +
        'JKKQK1qTdfULAN5ypecl27gWeM2i3ib2C5jJiOFUlwiAkZWLRJlsiJOk+b/rI5FD' + sLineBreak +
        'tM7yFanhEtcYumRRoSzKII3tF0h+z2AwzPdsyJDdASCzo/DmhB0fg0O8G0q/isNi' + sLineBreak +
        'VV2zL+w7mNmf79QsrGVA39Y+G/uKS2QPf3bGFthzYZwKH1M9hTN/do8wCCJJv7MR' + sLineBreak +
        'Ejnd32srumBOvGXnYtGuHnT3qRA1mj82B00bdfwCd09GGUr6mEQwfvsDOR3q4OfH' + sLineBreak +
        'eGCn9NkWKYvf/QAxCG9Vh7u62sUlXKS08hJcVAgBOzN10wFISTIOAvedt/q5GMvm' + sLineBreak +
        'nRuF/ixs6f6LNy/VgyztHoQ4vN4HBf8teDsbWSMDvlLkU6tQZjyuu8JkTjeDaqMv' + sLineBreak +
        'GbCzrRBldS3zMXX2OaWpZohi' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes128EcbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-128-ECB,174C8C70B397BCF00CAECA7AAF7A0A73' + sLineBreak +
        '' + sLineBreak +
        'wzs0bJqGg+Scn00TgtgXyV6hopQKVWMEFnMpu6R/Sp1tbPVlr+m5+SppJFVyW3WJ' + sLineBreak +
        'YeFSwXzuVAsnbD9qIZpAlco1ZYpmRXaY6IfXJKYf58v2IrqkxVd6AwjGN2FloSNp' + sLineBreak +
        'b/DinJXJe807tNAkuBLQ/7QlkCv/BmZMeYBl60XYIH8LDF/T/ON2hREl49zr/GLY' + sLineBreak +
        'bwmVzgRpfl3c8QIt6Yl9uKOqCFJmMHD3YS+dT2RwuQwqY+U3DNzVoCci6Zjd+gL3' + sLineBreak +
        'eb/S6VstodSR55qF8Fkwt+sy5yL6XmhQaGWEgCwDwArN40MWIEpx4NaBxCcqHF7g' + sLineBreak +
        'o26bg6CZwY7Rv42RTHKHNPETegZneAMK+e1lNassSijak+A3ng9bxiBquWSKHe0i' + sLineBreak +
        's265Rptr/GvQX0hLxmfjEjvL98dKVDZpvdBaWRqV2lS26jDPiFAHtVsXvF8uo25J' + sLineBreak +
        '1aS8FDHaD2DghC5aXTQRaVy1jlMTm2YZeVfiU6+7HVXBkLsVbShqEHxKylxgtB/1' + sLineBreak +
        'OAui+st60+o8lvRmn5dT2xnxLn81Bt4qron4pz0LdzC2xl0DqjhXyRsf7kdxr44h' + sLineBreak +
        'YN1YzmdU3fYFzQw+VmE8xECIjPukp+0HSb4n7BTGsWvqzntFIrzWGeRmNhjtMcwy' + sLineBreak +
        'YJoWGnz+WbxP3DJqSGNdFME7mNI/kaybIkOpbHLLlmgD7XWpeyGYtsU/rzrh5NXN' + sLineBreak +
        'YRj6Nf3TWI1zwS2xx95+/5vc5Df+sb1+/33J4hbGOx9KdfqoVlJZ16puvdTq97dF' + sLineBreak +
        'x8TVYxk2PfBJpvpChCsFlYBOB29F+kY2qoBKPbrvmFPsPCgI2q4gFuJ9pq1qyDbK' + sLineBreak +
        'pq9d1oewOOxR22VMQNGG7tL0tMmtXJ/z0n3Y1UE3aYiSG7apOhooBAQ8grpuwqbn' + sLineBreak +
        'mGTz6sYB8fHdCnedcxEUxxuFjXupmBcT2ulUjFZgFrG0SEMElgTDjtG21eurqPKh' + sLineBreak +
        'ZgxfkW+tM251WTi6sqjiQO8WYHlU7+XyO3BKfH5v3kz4qXxsmvKfh4UOfRy5f9YT' + sLineBreak +
        'Ft5oi1bos0soTvms0d8ckLt9Tph2wgoz3Sc++4DRcF53Ks9N6iUgtTpkEtmd/Uc2' + sLineBreak +
        '5+xewYmlfYO2qfiqiF/6dSVfDPjJYR/YLx8KBZ40/e0=' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes128OfbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-128-OFB,B32C602DACAACE3A4C55B4600D974E5F' + sLineBreak +
        '' + sLineBreak +
        'w1+kMXURdxpREW3giZg+PooayvatT1Pf1bY/h0Wcm8z0w7zRtQOyjCOdEPNxsdd5' + sLineBreak +
        'ZYn3qEIOO+wkw0v0PdK1AaegJfYMbMpSp/iEyFXU/LHS0FpO7o8zmUiAvdeEKAFt' + sLineBreak +
        'Qk90gFBiyQyvWEWsp32KQH1/eDSeSLeQbfRfDbh70DkB4nUjYMW/eFL9E/cHCmdw' + sLineBreak +
        '0LKUpEycc4s8i/mWCYJF+cQd4J8RHK+Ose2+5z86kHTrbFSlTBEZEXPDRHl8ZsZE' + sLineBreak +
        '477A6/Ndy0Mq3+NgMLSl8xacs2v3itdza3AJREVOzvnRmV+NmWtYQ4MQrJrLg2yv' + sLineBreak +
        'wfAf4b2r+k8Igbpzn3NCEYolecGfyEWftzTsqTutlFO7RfeW8go4v2MvEsmHTphQ' + sLineBreak +
        'k2qaQkdSTFaA7a2O4PKezJap4RRCJhq1d5bw7RwkCpbRshsvrKQqGdTGJxEZZfGY' + sLineBreak +
        '6pOt/qRL9LVCGUVdTTdje7fx9okx0LvKo62eKcUBh/AwZGE+ue28g6/77iABuVtQ' + sLineBreak +
        '6kgJ3lQK3AQwKislF5cBC9MAkiIomsoVOKiP6+yX74XIa7T+3aWXlsY1oX13+kMW' + sLineBreak +
        'zijwOrc114Sus2eS3xSCOWLYN+0GECMrh2NDGDW6tx7i3R20BuEF/IwHob1qjbkz' + sLineBreak +
        'hnS8KrRY+174avQDeF1lMSBz4Wfi0O1IDuxWRDRT2z31E4E8EIoJh+73NZr7w6JA' + sLineBreak +
        '8usK8RkiJ4ypoOPtRegXX6GBG5UYgI5bn1Ms2X5xSUGIXgG8IwjHDbAAd5xLSWp+' + sLineBreak +
        '01HzUsR+6wA3MxYiybTU4eOKNMviM1G4gGsKeuGrDsNnidrHfSzVyOGVVHr51xRI' + sLineBreak +
        '9Xie4FX/VX8/7Q5RMsA8Y2eN/yeVwXup65JRhDD5LjILVMy7aA90KX7y/s8KIYae' + sLineBreak +
        'n6lB7PtcpRWwhdYSYtnlrJmYmrl55d6ZQtJm2/xjnOBd+igY4YKNjh11xBL8YNo3' + sLineBreak +
        'wBjW4/lgrlvC7kbLxO6JIWipPr/6F3bjvmeLclTAZxjM1NU5HhTScGaEA8A4bq4+' + sLineBreak +
        '6Jiw9ZUw+TDCOmntkgEublcCMjcAxrawWYO/5EWuOAOkyBsa7BbfsUv3pgPugz70' + sLineBreak +
        'qa/CEkshP5e/1VZgFq/BNFtb' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes192CbcPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-192-CBC,7FA13403627D9E1FA02FF88F6D594679' + sLineBreak +
        '' + sLineBreak +
        'hZYB09uY4gjQFEHX8KGI33EzcJijYhBMNJCR9v8UK8IcQIITOfZxYV2BmrfQhuVh' + sLineBreak +
        'Kcar1JrQdnc4S7+UDFIjlLV9ErBCvIUQEflP2ByDhxl892EtVcoMKB3BJ2Rgi9mk' + sLineBreak +
        '32KhayXo5V2bu2kOv2nTAjp91LebDz/ylmhhJhI86BL0DLjnjTEl99v9OHQsMtb9' + sLineBreak +
        'cXZb51mwIynmqU7Wf+PchH83Yw0WOKs4MOrCtsqO9lL7Mf/MiSSiE+S/rpKLPXY0' + sLineBreak +
        '4aBxP6fw+HG57gPlNAvv/qKtJu8YgZDqVXhIKNDZRTSRX+B9R1Yo1tgmJVPhk/7x' + sLineBreak +
        'mmYUxIb7w9nqa5OrxzFHyNvo1U5dJcXyCEhvUZ3ImR1DZt/oGJYgrPd/8YcYbsNP' + sLineBreak +
        'LKmTLUKI5CARZ5KcOjfM8vpKqlfpCg3Yl1FaNIjM0eAhD6XrepLj3faAJW4/YEoZ' + sLineBreak +
        'SGMO5atbM0ERT9sNDJTG0iMW6xGL5l/6pzfsTKI/2yMaAeWAyvg1PySNoSH7s6CC' + sLineBreak +
        'CfqF0w0VpQEiOPb+qjtmjBDB/VW5kNrRiBQqZAgpO6mED0jAdg9o31tyuuaFDWzX' + sLineBreak +
        '41C2viVvxTx5A/xOtPvaDo9EMecc+7MpPLM2VhWhPDiDBYb8PCKqBOEwIyH119MN' + sLineBreak +
        'gQEC0IN/itc/J9ybHLCjrF1Rp83T3/XhAaXNVU9msBBpKNjawnwsUUj8gI0JRbx/' + sLineBreak +
        '5ehO32sQm8wkMyP/8iKDAqBRkDT3RIEmLi8ms+ZZRmLwGBkSZZzvOK3A5Dder4bp' + sLineBreak +
        'dIhOOetvoN6Bs9l1i6Dds64pwsy8IcnLLeNmOag+Qh8+pVUBNZ1zUV3KSizRKh5U' + sLineBreak +
        'dyT6VMILd2EAUJYLXs9HNFTtHZglRb96jQ3rkHGmAepeIVnJlNGKByvDUsJQDGl/' + sLineBreak +
        'bGNk5Ejz93ylY8JzR1GaYyFVIUU0qY8khbo7bSn/o6II+KjyTTyTkV28jTSD5dYe' + sLineBreak +
        'upGHOzmqpGi3Pzaz3DXpbLcMzwYrMP9FuXuqkVWToDs87DCfGqskKtko+zlTV7/P' + sLineBreak +
        'eBILwUawtXMJfYntkV247FffKgS3/BNkgEE+iNthOsFMSoqX/3ESBKJdJDfKRH0J' + sLineBreak +
        'BkYL8O0I7OwYzfU3gCWVZ8AvAhd+nSqp4H3QUK0QM2w=' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes192CfbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-192-CFB,3E445502677C77AC6ED115F8EFD9BBB7' + sLineBreak +
        '' + sLineBreak +
        'fJXVVcgxhZJXZANfEWDbVmz75ocICvntATRNVgt92sHgl1B2c4cgQC4Xmu7WM/Bc' + sLineBreak +
        'ocUlcSpWnoHtWRDumw2cwB+fDb5k3e9qb+aL2juzHkK+kYd2mkRjW8KSG6D8HIwq' + sLineBreak +
        'fpvV6NQmVrxI5+n+uabwfil8Ecg9V7GD6ta0QSgt0lc8clp01se+VDacX1uCB7zG' + sLineBreak +
        'NtJsr1wUM0SQbEWPEcpLUoYfK0qSO0h8fpnagKrNQLfzFbk85arkpD9XBzxpNO2p' + sLineBreak +
        '2fYsc3xZ0RkFauSZGt6ehu0jh1TZNPYDURvSn3uVrseLyR0Gt8LWp+hjIUp9Kpo2' + sLineBreak +
        'fLUVaH/7wxpdCAYzo4Ub/gHPfbxo2E5qYmE1oTJyAHplaDqSg8pbwJofiXl12gMM' + sLineBreak +
        'IyIC3SCHZJph7xqbKa+W/X4ChxYuN23ZMZ72cmqH4tH/j9IpKrpWEeqjxaj0EwDs' + sLineBreak +
        'R06Sz/qAqs9iDMKTkuFTMxGhc09DV9sN4NYczEIEas7gploOdryJGMCM96RtMDS1' + sLineBreak +
        'gjW21w0wyfqa7ogsDJJ2/HqKL73Zfn7l0jzmqya7YwcToEfKOSP+a2Q/y3Exr4KO' + sLineBreak +
        'FY5PLwKvpBaFcFzJoYhAaPphUzzAQuQFgXj34f4JU9bAXbf7ol7Swcv9JP9tN/mF' + sLineBreak +
        'n7z55BbPfC1EiyGyDjeUDWw4XIYF6LtRK3lnvn4uSZFXLmYMJJthwwC/yS+D65LW' + sLineBreak +
        'vsW9uuQ2qEfEC3hVbMPP+1KMgRkb9CVbSXBH+B7UoaUkGsJYzdSDeHZHbwiHgxqH' + sLineBreak +
        'jb6WcjtUjh7W2VO/MnHBrLg8dnC77OnR4IiqJq/6TenuSu0N/4mm73SH7BtYAugu' + sLineBreak +
        'ok/2H7GYfGfWjOnd+QvG/Vjsb+l9gtB6SXYFiWuThjB/sU4kHH8LUUOmGRlC3NDz' + sLineBreak +
        'w4pv+cR3tS1zX+evPL0BsZ3ynDSGRbMpss7xVooxIPacFwDN8kHUnWvIBpQKAizq' + sLineBreak +
        'blt1owc97vidf9OnZxUMpzw28/PZ+y/vRYSPQrde3kH8mJmu1FC6tLZnqzuCSsgR' + sLineBreak +
        'SJSr3/8qqSj3XrAW+nj0Y2P8lItNdFXex7j/RuX3eV5QIyK7uY+z8ZP4gf5q9w54' + sLineBreak +
        'p+dQi7Vx8acRjbsU+r85+MRR' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes192EcbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-192-ECB,C625A2E97BCB192B31A8E33CB0CD857C' + sLineBreak +
        '' + sLineBreak +
        'jM0PVjU2r063OACSZgLkaS9ppOj4idZ9hgkdMi58Oi+C5bfhZavbjROyxCG0EMGz' + sLineBreak +
        'HnAIRJ4pkJeZTnGElmOEFbaNPb42NAvcrYXAP4XNu5FbZ2SqGKwRnjjN8z7s8+Ip' + sLineBreak +
        'MrCyJsWycYy2BNaksJRaDNgazjKgqQxGFlQPJ+j99E4dk5QaduOCrf6YQ2G+1Q+m' + sLineBreak +
        '2/uqVujTwmverPnHDNhQI0ZYMY+l8+oVcPHIY3TR3ufecvrGkjFgKH0B+/L7gWSd' + sLineBreak +
        'ASvldEnWuFtPMiYnqCPtLgJNKSXO2nlumLc4Gz2ruvYKI1qGPXsVLIGnxISVLUzT' + sLineBreak +
        'VQz7NrRYwlvSLWdQNqbrEPvEu4q1KstqIkiPRoC98vG4+VRkf9AXAGqxA+vKYktP' + sLineBreak +
        '2Ui/SLhoC/seh9pxYXLsmqP+8bxcNM3VsJQoUUFM2PtfyvzBtuQ7mJQTSFSXgBym' + sLineBreak +
        'qXvzx749S4xOot+H6r/bCh8753MMEsgsM39jBsRm1zbaBjaNFG0UBdfFigHWh1zx' + sLineBreak +
        '4I44pIHu1AQDexjnfaUVrZFbys0CtM/Wy/3y0I3+mar1Wg3Rc1XL1PJzwDqBoZst' + sLineBreak +
        'vg1h0L5OPV1c4CekFnAEx+VI6ImxENoYtZCpbpt90kz3GxRY/eS8roS/SRJ7KizC' + sLineBreak +
        'p9bWEsUMwJ4Jl+xvV/VtVG96nKzlU13gkI6lMATYzImK4Fh7hH/LBy/UhNVL8X76' + sLineBreak +
        '3fo64CCwE3YkrWEmBDdxt/K8Knj4MUPjBgy/ETVRC7ziG0rUwRSd7zLOoEALMHig' + sLineBreak +
        'AtNX+juPvPU7yARw317Q9lZXeytf1AmGiFGjYZR/mduAa9M415uWm6zutIJEz+q8' + sLineBreak +
        'KV93bm18JUaQSrX4D6m8IgNhX0EfmRYAIFnB3rv+1rsb61q+4USk0L/1vKT/fGGm' + sLineBreak +
        'yvXMCA10N50wGS4wovMYQIl/giMEU8e88f+gqImU1kporgESIOUYUm9tOZ80w4R6' + sLineBreak +
        'ITlKCzRuoptMQBGZeJIWfWNLxwYq7NXKpvjNeSOeOqQ4fxhkzEetFERG/2hnszmM' + sLineBreak +
        'pqwoZBZQ8bb+T6cmJD1GuxoO3ev258WIUkEZTkFYK2Q/+QKymPZO4ATSAO4N2UqQ' + sLineBreak +
        '4TXRqUs4i+1f/BJU0ahnSgmzrynGmskUonKxt6T87lE=' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes192OfbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-192-OFB,7E4DC037A44E5DEE4E005CED36B18C16' + sLineBreak +
        '' + sLineBreak +
        'hvLtWTLg0+cMFDo3jN0yZc8S7fE6cDdZcBK0aRy+Eg+9kWlnmR/VYqG4xaich3VQ' + sLineBreak +
        'wkyhNpBSAoUHY8OKkB8hYsqbGkuKxQ6Db4IJlahCTFgb0yO2C7pUrtGDTvmXVq2n' + sLineBreak +
        'qJ4c+4CILeyzIp5yfy0dE8CAsZZcLEdSpPvaNK0VPZEPhelm4WdqqLozYVibR0KS' + sLineBreak +
        '2BbVO+E7yHGC/G3xtdbduuYpID1pLwyaebUCNgblggn6FJ0G2+Iu7lndmMU4B1Wr' + sLineBreak +
        'phvb+Fd1kL5421u8OOKRVLS2yMtlzbK2Mz7NclEzEs1m6K/xJUzztxImAxElBiiB' + sLineBreak +
        'YfOw5WLy278DuD1GCBkSuAKB4XWUtlq0+tJnCzAG0yrdMloKH1m+XF3MXFiRTXgE' + sLineBreak +
        'k08PcZchoNgGP51Rcg77skATP9OMamcjnkMx1B8YxTx9O5Vv/oSIjGQrr+t2np2t' + sLineBreak +
        'JU1dHTr9QrCeadSz+My0sjlZrL3ZisAwBbu6C0Zta1P1eB+i8ORZvm9HvmadcyyE' + sLineBreak +
        'y5oQWv7XwSfAQup/4uuAJ8bQBunIH/ajMF1WmD8rzLcUjG8W0rnBWUtjaxxBdkWv' + sLineBreak +
        'xBzgMPm7Q+L/5yhL/TMH3dkUBq+Cg5VQSe9EspNRGKBUgfKYk67Y343Mv91xKtX8' + sLineBreak +
        '8Tmh/WlnYXDv8QBnFJZXVnf8HeSFHsHDzfTgAmWHdhisTNwmgSFvBK5ghvhvkbXI' + sLineBreak +
        'UIPi+FgeB7P3ccFYnmoMq5qgK0Ki4lU6v57soDrjRl/NttfXdQEhLfWO1zXNANLk' + sLineBreak +
        'lqEhJSvBPZY4/FiOW4kNaZg2oRswz/+Bmp3amsK5TwBcI72rnH6SW5ADqPCcTP+h' + sLineBreak +
        'IrH4L9wnhOXw7QLk/h58JwiEc8suj5n0PJPQeHKajizd/EpUzVAuRTAl4GMvxLCY' + sLineBreak +
        'rALxeRaEXfJH5i/0UQydEvdU3ZP/LTibAqStXyVlSBZmKOg0GNQ+aAiHZyBnI3oq' + sLineBreak +
        'QuD0KuJi84ETMLU2baRydTbVlQDr8O0vxnCNlPkFFOqVpWyOyBgMctUfFJiM5c0l' + sLineBreak +
        '1UT6dc2F7NF5WOuoDCVw+Jp974CJuBSRGpdQKGms1Dvjwrtnf0ycstswXHvp2ZhV' + sLineBreak +
        'IVeCbT4WWh4f9bp6STkdquSc' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes256CbcPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-256-CBC,307CEE18F79CA333A38CA90E75B248C5' + sLineBreak +
        '' + sLineBreak +
        'qyg9Q1cX/FGOoP0NFzrCRLwmR6bai7JzDiCLFCthciYkMIWLIVzvyTg850YD3dw3' + sLineBreak +
        'Wusli8EQJig8DEpFSM0WBc1Rne8U4168nKuRnFUaP+VWuD4UpNDt66cT6dMoqATD' + sLineBreak +
        'kZGdd+p8ReO9TK9gO/ZZU4R+q3OUpjxX44szxj/EIVSgphi8R0rRSxl/yFRnGHyO' + sLineBreak +
        'xfpM9NxgMvBYlyxl5w1Lp/ictuF3D505nF/uuhzGL5a+WWhSnssMFHF9vxXTu21/' + sLineBreak +
        '3Cy0C3Qah9eV/C2oyAU7GGsXHIfqFqsgMjQN+cTFqMyFeg6g0J7hytDAgZVBXIFw' + sLineBreak +
        'UuzMbxUUZU9VHcZzwqstkg5BmUI3sgW6gibBUzuJrmo7uLrCvHyj9oehSMqeuPUC' + sLineBreak +
        'EXFqhw6Nb+jZMkvW9J9qFYG9eg3PQsDErIdVK8aWdLrLyc+O4gycOdMbR8aq/3Z4' + sLineBreak +
        'TlV7Ye650EvQ13bwZghZyKel6Rjt4P1MagGriNqCcLVVsyrRXAiqjq8cyJgYtoXF' + sLineBreak +
        '1VMBZz8ob2FH9+kvk2sb4+T22sTYwiqAVaLnCsuJ4dmS5wdBrhfF4oyHYV2KOVgG' + sLineBreak +
        '64GqxiF9/whvbAWSM4cU+KslKnWGZwz53LKleafrgeFJ2P1ldqnl0on5EQ/m9bzt' + sLineBreak +
        '+GSGwzZGRmhf5NoyhaH+OCkq/h1UP+LZ5kDJCqH/l1JZbvJQkGNKzt1OroW17GnQ' + sLineBreak +
        'EgihXAmhy/xOAIZkz1XKa3bNvgS1F9yreAxJAvBHB0QzZ1HrablsaTKsZOtY1Qvq' + sLineBreak +
        'e2OdpJFm+SrI7RUtbp787Yl9pH2cLEdto+WH8gtgXloS+b11Q7broE42w9MIJrno' + sLineBreak +
        'kzs6eDWafSExTvpi+29OJEtK4PNezmhOxzTUIsG0/8d9Vd2WYqrLD34ze68X8qUa' + sLineBreak +
        'CoIXYP8VsQLoXVzX7VnMBYTQ+YOR0Ntq6pRj07RbJrNiOt8qcWGslzE17ERuCr0+' + sLineBreak +
        'ZFTGy77KOksKjLksvRj4oshQjRhVYZscPNnwKODFDvOPsGFjDoU2Sg+W8kcfE6Bc' + sLineBreak +
        '1RQwk4N0cjkC2JXXk61QQjh+efWRBqPN6va+ixUcsZSxndCIoBk4qtqtsyTFEcC7' + sLineBreak +
        'LdfCC96RGnXlvroiPHvrmJYN69JAyyRrnhiYfaaC98s=' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes256CfbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-256-CFB,337D3978222A1367F5CFE08611416E9C' + sLineBreak +
        '' + sLineBreak +
        'GVmy9WG3oR1Vpfxnfpv1hFvXGzBgE+c4jplSw2BAlKnbznCPbZLc3WF/ZMv2851O' + sLineBreak +
        'iE/8sdcetzoAlm3jGPoDi6Y/FqMFmcbqtro7vUz/SVgi1HDI0FXjOTPtFe6xfzhv' + sLineBreak +
        '84qt5lz5VAUueTKFXEZHqM9tV7lHt1FX86VutNObn8pE7nAWVX/Xvq+qWUsEx0ik' + sLineBreak +
        'YjZjLY696pyz61hnxZE4jKZLRx/9a6vWYaVfzsEi2FLw9qAsw6ILp+xDaAeKa+Il' + sLineBreak +
        'YVkgDPi62NPr7cRX1WCiw+/feNYPgUfGiBNkd2mOnAr1yOXFM+YALw5V+q8I6ZKN' + sLineBreak +
        'k8R7skAzRZkwTJ9WaaFGD/UypYmhe2b9Jp2n0BMEn5RpW4o1DTIHmfMSUmUPp5w3' + sLineBreak +
        'HjbtdDUWIiuplrz7mUE2sez/3bMbcoiO2Ym9SInJKBrMFSvyasg403u4QESYQhC2' + sLineBreak +
        'Lwcocb5ixXoczHjef3CogL6BhL2oZwXCl3OBqpMOJJJKXUPRhN8bvgV41UIsiGtN' + sLineBreak +
        'TFUXqYdpbmMkxJNMGiD3mKWpSm2MMdQYnRlxNh0wXLi5sHckD/WS4yFrNsCIMVDT' + sLineBreak +
        'W094liK/Z7BmplY4TyqKhsRlFVQ4VOo/W0WNh7Ayp0siIfo8vHDyoQsnUkn/EUER' + sLineBreak +
        'UZG1lIy6/y1RSg15GWpdi1bvT9URjElh/U944LSYD28K2VU8aPKaRBokk+K3AyR6' + sLineBreak +
        'YhZRCBr6uIVZ8HDkBL5OW0eP69/jdbyc4MnWRa6C0d0boA7N639j+NQz9erYT6wu' + sLineBreak +
        'RkInmBbVfxQD6HLkMwiuU23qLP+QQTLkH7rQJmnRPSwAKEE8RiXWi4/TnYW7d0AC' + sLineBreak +
        'Bj8oaK6DO+J9t1pdj0IGluf52iUwAOf2Pxwvu44ovaF+yb2n3P7S5maDGLTV/xBW' + sLineBreak +
        'D6nEAct9cYj22/aRDTLdpOfG0L242vjQLnjrgezBLraa9eTy29hR5FU5ACH5sB72' + sLineBreak +
        'rxUSwoCHCJuNFSxC27QwZqeCFw51epwXxLv1CjqsQi2So12qH+vFVtL/1YrFBct0' + sLineBreak +
        'dzwbdNk0S6UyPRqfiOE/+Iszzahmb/GgskPJdfT5Y03FnpDWfOotpaAebrY4t6kz' + sLineBreak +
        '/gs8pxupvdKw4eWsxVCL9KOP' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes256EcbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-256-ECB,267E98B92F05ECECABF28790E81DCFA0' + sLineBreak +
        '' + sLineBreak +
        'MkVFB5/gKxAksBI/g96MmN+ujdt0XFXC+7MI+0/OJ/H0LXlHlLpwfGlx/Je73Imt' + sLineBreak +
        'rOZveXf4I8sBCF1Z0Fhzb3TTTDxcastJGKWAVKaPzKkWdxNeUjx0kinbrkM7Spfa' + sLineBreak +
        'yG+wW+Srtfyi6LzEsbCduDK7hzfDnLbgKymdDeP0TVeJzEdXgXcV09a01GA+CEVX' + sLineBreak +
        'aHesQLNHyYm9nxFxK0fAnKo5r1I2JsozSWNTG3VNbiItxtfoJdXTn25I16qXjKzn' + sLineBreak +
        'MOn/A+RBpO+P01j4uk0q0SPJMlIYIX+RjgAoPiI5R5vSeucsdUJo1sWnSfqLc4yP' + sLineBreak +
        'vUG5wD/+lYrxsXiW61KdwIg3vy/ty5+GqwNgNvN0FZM8DvK+NQ9K/IpoW5RE4ioS' + sLineBreak +
        'ZNm1JpeGJiywsBf3Pi9mwR44tTVY0Jwa/TTQp1kEYGjhYXMIEvf+LUHwG5KO2wmD' + sLineBreak +
        'kDediMDUPaUx9K34eSpgIUln5d+1viMpC2VcDIg4tYjAODtGRxzgDUr3mbuoVl8f' + sLineBreak +
        'GqusTAdsNoIyilY44XxA2odHa4S8yXsx1f54P8fRYbA4Xo179LY1Nh7PwQPm+rI2' + sLineBreak +
        'mERkCsvns9jP1zJRuS1lYW1Dqjtxxq8Nt5RAsEwKQYLO4DfsuMZPblEXPAwSGb/N' + sLineBreak +
        '69xNs8ZFHm3KT1r7FdUrVpHk2vmqsetNa/g2wRTEuBmRCgrtTtEDWgdBNtDoHlBR' + sLineBreak +
        'pDIWgwNvt7oJIU0EbQkUgW8bmg1p7jxXN8Bk2QKZoOytxA4TB3fR1p92VkXzrkxn' + sLineBreak +
        'l+Z815BNfqnNCU5nNzLwk3jLgksZrDnLu4sXykIBC/bpP5fubnT7iJYh9h6ZGFeY' + sLineBreak +
        'QLUP//ssuZM2auNjTVykWUtAiglROzxnFZjMXEbujOKbm70Uj3YvAHjoKalkti9x' + sLineBreak +
        'MTj/vpR0xBv/iDtTFl12HIg+IEGL1PfX4xy2avvJO+XGFD4zcnrLfTMwtUJQjdQH' + sLineBreak +
        'dUMWP8VI266u+B6wGfcrhdCYqtvuLVUvbISU3YD/tP+esXh5' + sLineBreak +
        '63kPnXd2UuaS3ErE' + sLineBreak +
        '/7Y/hzyUkDjJ2g37Hq3M4wbaEg/a6osDtfg73thDMadsbTLIDjHKgAgBv4umNtA8' + sLineBreak +
        '+EaP0stzRH3ayHL/f4I5bHC8bMIAumKM6zap6tBiork=' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaAes256OfbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-256-OFB,A2D4D65382905DF6EEE7A315B10CF2D9' + sLineBreak +
        '' + sLineBreak +
        'CpLeywQMv8uZGrgJYM8rZ01awWHJWH/ZKkNi1rpQhaI1BAShQbIUvpY1IsMLa0/E' + sLineBreak +
        'g2+oj+Aa1UE4UDsAlzcfsKG9QHS8nOYWuLpU7VAyjC6wUPn0yI0sxxKRd4dmPIgW' + sLineBreak +
        'w3r0xO187yqLAjIZCj4y+3ANCjw+rLpZ5Zq8KAN4j6H1NEmzNoNVQbwY0hpsyxwE' + sLineBreak +
        'Tg7TkI5IyNKQSQC48EuZh16cJR48l36gzFOmZKr47gzS0zivvED4Vxdaey+WZkoF' + sLineBreak +
        '1XW4VbQGHRnLEn/I8rziic9E5pvvcZt6K2NwvzXrkS53ufFYZcgxNRxrdM4yLz+r' + sLineBreak +
        '20Unn2F2KqumB1RAliKo/PtudO7XfsPNc7rbF/stGhlxDWTyPU2HMX9tw3JkWDfG' + sLineBreak +
        'rRsG4RJOQgsx0Q73/7XPhgu1J2Wp39a/QI/IHwZ+rWIerdUPhs/MRRPoduAfSSZo' + sLineBreak +
        'r2z8OPJAlMWLwAjmmKDGhpTp/21n9xLo8tbvqmy8Frz+kAxAHXeHCTWUbxA+URKb' + sLineBreak +
        's5NKQALX3wYHT9Xq0A27A/Zrqs5elqc/IQL58nU/Da3a3OfPB4+MNWeWU781ohhi' + sLineBreak +
        'VkBgMRbnQNCC8OPoeMd/At9GDEEj1rDxx49pJdMMwxXS04P43LiuNSmndCei2cQh' + sLineBreak +
        '/7cho8YTbdgjKF2kVCZvYXBVsu7Nn834kJw7eMH6slU+VM45jTkOTr2uLzKWrBL6' + sLineBreak +
        'YONiK2xdD9NlDcTsX4YRkt+dByJEcDAuvprVdnLKpFXAOWDLW6e0o0siuFIGBtgX' + sLineBreak +
        'NR5vA5llpOkladJk+j+dxX4u5Ql9KFPtD9uM05ik5VQCZN8pxy6On3GUeSdoAE9i' + sLineBreak +
        'i+rtgZofs39mZOTxhYr+Djnq3WiWntV91GImwhqiXxUBI/fs91+yy+FWphpGORaT' + sLineBreak +
        '+Rab+cyvauBsdTAoSjjd5cNXXsztfDxEhLnZ1yWMQZxVgV7tcLevVo7e75pSZrN0' + sLineBreak +
        '/gMQAH1Fcxtbrdzg1fehLiqTEWp14lFyDCkqAqQ5C9niCqwyf8+6Axaukk4ImmP5' + sLineBreak +
        'n9eIykRezLizjA+GCe2oC1jXpVEEYVzOJpbBAwZqk/jlyNd0m01URxvhOaW1/M41' + sLineBreak +
        'uWDeQp7ljJrtiyMqD5P3STGR' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaBlowfishCbcPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: BF-CBC,B23E9DCDF6361CCB' + sLineBreak +
        '' + sLineBreak +
        'BTPCHNUVRgsKo1up9Ktshx00vDANb05S4S0LPU/wzG8sj60db3bX7Uzr0PPy7ShH' + sLineBreak +
        '1zPv0PECYla1dh9nVBPOS4EQE3uHyzuDMTg0AsiR8TpysuI+a4y8XJeAhkU1DTD6' + sLineBreak +
        'YzmaodjbCrhautYUCzvcui/sWWXTUSWH/yrFOxaaxLpccacCssGlPc3Tmr5brPmO' + sLineBreak +
        'xaZvO32ii6z7WAP/WmyRoYH+BSqmUBhObolifBD5kg1ilPfCk3xMtz4lbJRWANsS' + sLineBreak +
        'r6YWPwo+qh1TIQWw40Kz4oQOteVNiwh/dvYGxMkd9Gs4J9nY5deKYExoWlYcci6N' + sLineBreak +
        'VOrGA6HBWzfFx/QWWGK77xE8yQ8HeeZUgkWwYoSyAmxjPWgCj+BT5gbYV3W9E6UR' + sLineBreak +
        'T3lsKGtI/lMW9N0DVcLdur0lLIBFiVbzxoUAL1SteLJ0mbu/Vnk4VhI5z5mOmSxo' + sLineBreak +
        'bU/HElXdjIhk7hdTU5PMNSKiAsxNh03NiPsTpEASMhz+oP8BuJZh6Zi/K3qMYH3u' + sLineBreak +
        '6BYmA+Ua23fFYd/kz2TclVwiQ1HQjO3+9l0aSgLhHFb3t0spYbx1Ld5+bAb8b30Q' + sLineBreak +
        '9w/fNab1mB6hFgaqruPErfI0K8BZ845oAiakZBfKnTRQxAlKNY5gWvSiPDWlkfIb' + sLineBreak +
        'uSBW6csh62iQM1/bcW0voR21NGS+WdQ3eg16vv0HMhmEXmEvtAuCGb6ZMqY117s/' + sLineBreak +
        'VciBymZzwdLKFjCqrLn6enYrT7uneOoq/8PaXD1rdMuKGL4W2LqGH+Q0RU+1hyBJ' + sLineBreak +
        '7ipTQqystqi6HUU2R1/PI4K73X0MMTB0Jfkd81S6GmjkMYCFCHmHXCdNULjbjzT4' + sLineBreak +
        'gppgVW5joIbLKNPHJ78lw4BuMxcAgptmtQBADnWZQNF/pBnIVAY/pdHgreIBTQ7R' + sLineBreak +
        'KL1/ATp3+gtGd37FOGZilhq8C4ML+w18M0iTUUfGg5svUvmtw+NpNWMijTJpu3Uo' + sLineBreak +
        'KqjMj3NbwCwu2b9qxwalC3qWOgAJf4Z784+i2GOvACk2Mw2QyXoZV8Qm520M+idR' + sLineBreak +
        'rj6DIfzEf/86TWH9IrGukDbJNB74QHgdXd9upyt4sL6uHMxPwz4nnhBB7I8B/Q59' + sLineBreak +
        'oB+3CBpYIANihDscUbiNSsw5/AXNtMuA' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaBlowfishCfbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: BF-CFB,A39496D20CA5F694' + sLineBreak +
        '' + sLineBreak +
        'A9ZO/WPm319cQ3hoxaEsmuGVDkMVhCuRzFfSWC4hVBsxKHd3FIw8xZpGSkEI7+aL' + sLineBreak +
        'cMtcyxTQn4jVV71Sw3vyb4N1+2i+DAd+63l8LztpTBQi1o2gTBqmqL9esV3shqWB' + sLineBreak +
        'JV7uyOi94olPea0Rf5PMRXx1bAZs9U0TV+5XHAQxM04lXRJajxiN9LBZ1OMRiUVu' + sLineBreak +
        'SdoHdXh077ylUQmgDaGQktWYuVH6leq7Yc9CF3nre6njFiUrpk61iPki7+/FgWzq' + sLineBreak +
        'vToqiYaWffy+1lB7sXcL88BtFaMWAOV5A48Mv05miTb00VbJqdKL+SDmu6j2Soxi' + sLineBreak +
        'Qk3k6Le0heXFHqqkURMKOrr6tepqKEjmy8WTELwMnuT5vNngMqDKpNyhdsIEJW69' + sLineBreak +
        '+L0imi4fWIelCd7PMI1bbPAp2QsB8Rndjlfj3irVm0AtubL/rbep3JT0ezukoScd' + sLineBreak +
        'wLYNTlDdaLfEggry/1kYvPBMolU4xqDxg7C0quwYxLuycEFzU2QmWNtRn0xkfx+j' + sLineBreak +
        'ruApr4getT6q2fJznW7coiW+OE9Ik7JgtYUGEZuWFUeydDHa9PiJ34w9t/aw50Sk' + sLineBreak +
        'arATzKH66zM//g1zgzg31SmziKeE375skyQr2+1S9RajmdZzEUDL5ajsdrbALflf' + sLineBreak +
        'UPQNr0YEF92DRHsI4O39L/+k5fesiiU38u0NoKv5DDRb5T1lQeesDZCZBowQP5KP' + sLineBreak +
        '+6o6lnj8kCeccpGX/eUukPXFl6mdddAJ/vLptHC1zaRp2dlKPRfedZkRm4Wduplh' + sLineBreak +
        'vQ+6oGqkjep0Q/LSRcVP69m91CZot86lAn9Ct0jfJu8o7Ua7KBeOB2k/rx1nUaZG' + sLineBreak +
        'BOjHQRaSvPA7FVKCP1UlT0GR2hTb/VcW3UQJ7fCY8E4hc1kPfoa/T+mf0JrHtlMm' + sLineBreak +
        '364YQh6KLgcsgVjsPBXnTN1+POH0Qy0xp/0VwQIQFWKwU7gsXprfs/uYx0uD2Ev1' + sLineBreak +
        'w9kIWLovIGmBh6HKptqTnjtdwhqueez5kb3MkrCMi3kqVmV1TEQoklz6eBbloXbX' + sLineBreak +
        'SyR5jivLmuaoCJOA3oQ/A+75bwcvUP4iULZbdTpM2rnURyljKNU9Hwxim0neZ0Zv' + sLineBreak +
        '4kiOZuhQKkGfj0gv5bRkDAZC' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaBlowfishEcbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: BF-ECB,6105920EB281329C' + sLineBreak +
        '' + sLineBreak +
        'ungL+71R1VG+DP1CKuROEP1pESqlLeGoX/vupWbGTWR9VoK4v/9e1Bh96r+hEobm' + sLineBreak +
        'LvgsV1xhWrnyRMMw+W5bSJCfBH627SxqHltgxPhyKCNAf76cTIAdxxXgLZAxjtJi' + sLineBreak +
        'mjuBDTNHdJ8NiAxJKLL6dr/hh+Vt1Lk9Gr/x7UdocQnhxG+IZLDSOFdXnFb8EBtK' + sLineBreak +
        'kmAXXyOL14Rerywi6pmbxaculi/CihuFm4u6GXvunFjtP33eObzKLRub5ktbCtol' + sLineBreak +
        '97rbDoAAUsPPm4efu6Fs/3CE/BfvjUf+cmOYu6pIKQil9VHtxXloXwkeykI9Kl92' + sLineBreak +
        'uZVT+e9WEn6oZslAzCnjT/r69+V0Bf06AP0zkdTK7lRNBhmcR9fAgHpxz52GC2Bt' + sLineBreak +
        'xsqEzU7d+adCy1M73tT+bA2RBUnbA6BoCDHkvtmZTGV4mkAv11tVxU9Zqeglvi/w' + sLineBreak +
        '6QVDQYo/b9U8GVkQFo0oh4xNaAUNdT/i1OIy7d+6UR8k1S9+r6SGVwS3er20trWN' + sLineBreak +
        '8mAJ3dWiy3yLreggSqEvwHSpwrUQP8uxdTZOlFAy+xmwuEb3AgT4/sHQN7sJjAN9' + sLineBreak +
        'ISdzp+B5tBbM3kQgvEXUZckVykM7jgyv7SJ9DoDaYXvlfOVFo1oM3aWf57DcB8KH' + sLineBreak +
        'WIV94r4USVElJERYHH9sR61YtTi2lIi1zuAQZKCf3ShJcgU+vh2ZZ3vRPQhAMXjZ' + sLineBreak +
        '0Doi5uxi7HK/MVenO1CzNmsc6XQtyTtONqlJVmBoSq3Il8phMkMXnaOeNrQsT/1X' + sLineBreak +
        'PzbQ6MpWEr2WkKsQn5hNA9b8BIZ+cwk9zeFbhwLH5ewjO25BWJkFra4gGFJl+HZf' + sLineBreak +
        'vMNFjlnxuMjqM+Fjn3YH/O08P3nF/3ZGezqTCV8OJigB4Cdfbf9OrNtJSvCVsH1q' + sLineBreak +
        'YB/3+KOO5mKObH0Y+k1pvwZsXMkj7exAEHh+nFLldjo7tBAycqUHK0RaZ29TOjqH' + sLineBreak +
        'J6/4SSzMTJL5PF9Ayjtx0Vai4sFrjRGgnvdd8tddA/bWq6JC5i0yWIWjCEu0+b1q' + sLineBreak +
        'q8EHdE39+gbANJn2lKsEAOOt242bsjKR+bblijaaEgZXHZyALOThcEXxn1RaFFgC' + sLineBreak +
        '4Iv+DftZrU8lOiEvN8w00K6GDy9gbByG' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      DsaBlowfishOfbPem =
        '-----BEGIN DSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: BF-OFB,56A8F965C6533468' + sLineBreak +
        '' + sLineBreak +
        '91TyUkVkBxdl1ZXkXezMngH3YsE2cuXhiEFySx+dWZqFWcOQ3S6izXXqvk9B5sZg' + sLineBreak +
        'O95SFlZ917dU+SFACzB8dqwYo0QmxvH0zaAIMBguuYib6YZVCd8/ElX0vyEEo68O' + sLineBreak +
        '9V856HAks6w5WZk4zTC/75skb3tdLRWgG42oBlXHW7GsL6y29Dy3xvaWHJ3vpKXF' + sLineBreak +
        'HygbvR/TiSzhWj/jJB6V4kCQAAm99yyMxpmo3e4Wis5AwGgf9XyHJx0gUCeyNqez' + sLineBreak +
        'i6UJMGnYsHl1H67ltpN13trIXRcXTUDhFTadRz/suaR1R8IEefkpsnBEPnJwBuPY' + sLineBreak +
        'tUQzlolPKuwbPXFukpJrhi7It7dLsDsw5DUYvyOnHkDXJ4vFAIplCKdG0+KLaYKJ' + sLineBreak +
        'pXI8FH6X4M1YbIPTF+k1dhCAz7Cz+cEBA5hfJfSA4p7L6f9NBPWso3DDsyAbdPx9' + sLineBreak +
        'JJkVPtu0ofZHzYuD9nIhRsXjK9zaQXU0szLBdtGw7rfmPp3ftXeBcXDnO2ZdXL+j' + sLineBreak +
        'PK6CJm0ktjnUMKY8gpWahUUfImwebQ8+uQYv+NNn61rtfCaGQWMStXaNYgq54YLs' + sLineBreak +
        'D5ImRdvWm936tNUCeoik0yhPVlriNC4gKswRSUxD/nNIetsPl4FB4DIS/W5fvWZf' + sLineBreak +
        'WYKwW1UlpC/HagbUVIuZcOrAMFTG+zLYS617lzZh7Y7K87GJH+jVwgbYSbHHFWCp' + sLineBreak +
        'V215NLfofwlV5pFwq8djbeEnBhKi9SbGlZUyaZKKyDoIIEnwaxg8BoModBEWHyWp' + sLineBreak +
        'OUmw/v81TQu6RwJYxl1C1U9n5w4yjtXr5oowgu6WRYXwWXZtevtLkHrhcuWt21ud' + sLineBreak +
        'Cq42ojFrb0GqIcYWDXF3Wjp4nLZ4pIqg5kadpJpcFYx+fcL++Jnxs9l8Ohqwn1br' + sLineBreak +
        '/UvY+gTmTwnICapIwovVjN6p6cT6MAok82oemWPZNPYXVwVkGewCH3DWqfeRYsdg' + sLineBreak +
        '6gDWeIwyk2Eqn4bxFz40NrNZaLqcmQPaJVRReCV7Y0jQuQWqSYKkBHgFodf2GPMg' + sLineBreak +
        'DRqs7doN2MW7Is6qjyc8CDDzPcSuaqUz0gzohupDfD1vAtuoC0X6U+m/8NM3yuE5' + sLineBreak +
        'CKE8rofcKcxmFAr52CUUsJBL' + sLineBreak +
        '-----END DSA PRIVATE KEY-----';

      RsaAes128CbcPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-128-CBC,8DA91D5A71988E3D4431D9C2C009F249' + sLineBreak +
        '' + sLineBreak +
        'ZUo4tso7YF0+ayrQpLsgM4TN2H31b5g5ryj//QqqVG/WmvYgl56Vu7fDbYXytgnb' + sLineBreak +
        'PQoJLo+8iUI1d51nirw3RrtAx7Z9lrBu6mX+JBE7nwCVsjBVVlAx1B6d6Jwc20wj' + sLineBreak +
        '935VaUkwT3n0zZ1dwb9HLjEGUp82TIbiZ3KjWKnfER2AhFXJl3SzswA5Fvwe0AYm' + sLineBreak +
        'KTAEYaaxigTTPgltiEQDIvA/Pnh9ZHjh6rbM816Fa2hdk30wjU4U/KkTYbg4hdoV' + sLineBreak +
        'vLeQpYnMT2uICCuvNXq0cXXetfbgdMFsLTxvVElUZrjyMTsw1QtjijeM+gj1dbDj' + sLineBreak +
        'HGzR0k97Xj3q+84m+SoNW29zPLZzSaFDX4KdKKG2cHs9BTYJmzb0h7qP4pCXjGgF' + sLineBreak +
        '8V2iUDMs7BQlgNnOa9gwT7x7DN4HM6J0MIlNIiYQZnupqqYQTDR0rd+fhdIsXHkA' + sLineBreak +
        'qNZKI/4ep7voVIufSS8ZyoISES3f7dvs5nnM2C+QAtL+l/yaaqRdfUyn9BL1djaP' + sLineBreak +
        'akSRPXmHrmed8s8YamuhLHyf+GPL2uYpd4i1voA2KKYSx4PnfjH/F/8fXPZr3dNh' + sLineBreak +
        'sDtcjhgXHTNAEVVek9VOaHtlUNZEY0UcbP5uqBZta+wP2rBTC94DxIbN+k8A2SlP' + sLineBreak +
        'cKGkaRltjnPJAXWmwKMRm1J7vXngXYq0r5VUvnGPiUhFlQwAW5TUml4+1SMEUirZ' + sLineBreak +
        'y/Oh3AjhOus67uiAXAQoqlr9KykueXobFrhZjLCgRf7iDmP/t1eK40UyV83w85yz' + sLineBreak +
        'cORi8FNfqvCARz05qXwfhf2NBMTRbLNzKCGjS4iY0dLNk+QYNgJGoM4nFVkHYgbM' + sLineBreak +
        'pTThzpYgtRnxQf1mYTZFtqr8hRJqiRfexzCyk2JC3rDtEO8WUmNdvdKNN0KwCd4+' + sLineBreak +
        'dcVS8KzNov9fYMqiiol0dL89WBN1RN+hs7HnOJkNZZgaNVspOLCT4+SN5fLgtbJI' + sLineBreak +
        'BzbAgTK1ILrSom5fyzZcRkYwzIqNc97YhRYnxDp7vJFlgsBqySJgtdGUkTPrrzAO' + sLineBreak +
        'CCYyi/ukSVphPe+qRsvj9L4syZgpLRgDdZaW+BR0pbTUg2WQvZuKL5iMhfB8cbAC' + sLineBreak +
        '+FjoKeSlxI68jukrAYHBNcco+qaAYrUaHsJFUsbf7j85DzHxnaA3M+P0i+LWJwOI' + sLineBreak +
        '3G751QR2CrjgK+QD7XUtUjBMrsVGlJmfaQsEm7+rtuPynXq+ArJrvgha4lc0GRD6' + sLineBreak +
        'yNDCTTMafuBnJ72wop1UEE8zGOsqERsgvOAL10J1s5KCcPHGwrDhjhr3/x1GI6/e' + sLineBreak +
        'H80zp/E9mPgzYQMfhl06s9SwyvsxFCIZAfrKIhq7lVqeEDiusYbe15kCLmTVNZ6C' + sLineBreak +
        'c/BhDc76vwek05AOLaZLGbdpMRwevbOn4WvUHV0o5Yr1h1IGZKx9BQYwFS65SDCg' + sLineBreak +
        'uxfM+dKulE6MWD2hPUP9s47+R812cBnHu5BVV+Cq52YygAiAP1+nfFw7TBKzqczo' + sLineBreak +
        'fnIsoL69JthqtkZiwl36uMmcoWwZM621ZqYFJI53WO57uhW0uuoyidQj8HoNG/re' + sLineBreak +
        'o3OyAgVO6sTFsw/Dwxo4WX2AKuIt9W2IJMFNC7aS7lH0iPrtiVC3FFXvuY5agipH' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes128CfbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-128-CFB,2F7AF90B0C0A420FFD62214EBEFC4CD5' + sLineBreak +
        '' + sLineBreak +
        'hciElffC9lqjzOx+aBT3DYY0/oZrI0Q34xfQg7IOTUPUAxrrT/UjHlToX56VIbRm' + sLineBreak +
        'PH2M5yoF88Ji7BI2V/Y2QRAjAYRFVjZvPO9ke4IGYI8xfnKRivfxLtW/YfaiKnqc' + sLineBreak +
        '7VyyO2UI2tYGm27+JJbGLR+GdaHmcnLmencGdS4Hn3KDQ9IK4eLLXrBPWyzGnxEZ' + sLineBreak +
        'qA2OWdzqodjppFCjlx892YJUsq+w3BXu5lkPoooTEoxB5RywZfngUY9Y+raN60S6' + sLineBreak +
        'zhjkaaJTEqAfnAsdVMUvzpkYpoH5LCO1vl4+XpKdeUu3wJ5p3D9TVc4kt6/V/MeL' + sLineBreak +
        'rHJVN8FKJKYddTlaP7xOmh4bivrJao6LzRUdnyxGL6SkVQ4ipitgWcSwFGgRQc1m' + sLineBreak +
        '/MzFmTATtC8tocSqXMY8nblp0/sabGhUSTGG+uBGddDr16D/8J5rb8cMCfR0KLPF' + sLineBreak +
        '3uwV89PbbqpS73IUKkolRjxslO74TPDT5ds0i+UV+J+AJM+9CnyY7WI3FgMlVvRn' + sLineBreak +
        'KwYJuihDzFjozJfe386XWYs2Joa3Eo0vbaVvp4hbHq5Gh7S2iiBpqy2uN0xxuZA9' + sLineBreak +
        'QB1XpLd+rOC0y5l1usuVc9kBlGsTiFVyBoZo/pWVlTU3z8Hzgv8p1TAJN6jgqVH7' + sLineBreak +
        'oMVgubXsz1XPHrrjjgZEEpxqzXtKJw3DKchGDfAn4VLTSrOINwMC5sR8l30OZVtD' + sLineBreak +
        'IdlmftUBhv2AeVUqkLsSMKGdeagfwoqOlfL4FKvSt4n8Vq+Hn9lY/S7n3cjM17YE' + sLineBreak +
        'YAgpBjX4PJqXsp8K5KmBHPQMB08jW+NQFABOprdes5bwflrERogdLZmQH4vxqUvs' + sLineBreak +
        'DFhHVJxo1wxeRDOftVgtxnmHzU+SaB9MgdWWhC/4pxx5uzqYi0Q2kSOZ27EXZNdh' + sLineBreak +
        'MgVX16W6jLUw9zaR1wJIJZU7SmhJOL1fxvt85RytaD28+JvPTNs2ffDpjPu0sXh9' + sLineBreak +
        'n0gYiWztuBNUv1m+LMpi1SPtHvtoZLhc++9g4BXoZevtgNl+FqvHs2Ob9w3yXqkT' + sLineBreak +
        'lyJQbqju674MaKXDoQ+3+tnXad8MRGCvIgmIUzmMZj3O7QcrBbDY/pbcxoEDOaKI' + sLineBreak +
        'SygvYvKfrBIKq6PuGsN1KHSMrjc2A4+wuTYy75xsai9YtwwT1tyIIeCv5NXbbtJq' + sLineBreak +
        'vW+nbSNYW+khIicBc+Ye+GFfUh2MXj+iC1lK+5i+1leKo4zLNFDmnXKgZ4jOOPMa' + sLineBreak +
        'FMYPZkwANQ6//tyP/qzLWGyBucIC/Ym9hUvi0HlYjjU3Z+Zv92vM+2+li4mtMy7M' + sLineBreak +
        'tdcm72bqsT3+1rtJKKRaYG/FiQizOGTDyhgV+JX9MEVwJPa+61V9jwkIPPR6iBrl' + sLineBreak +
        'u7NoFfSp666XbD+LurRh82vlS7KYOB2zimHFxI6nOHBsypJynqtgIzLg5N1+LhVz' + sLineBreak +
        't+cxucW9eFvkEEXmjZwofqlxq9BDso587kKY+EpOkXrlnG/ha9XeZcyUipn+jQ0Q' + sLineBreak +
        '64Cb7LfvcU5UEXTcMh6BKkoeNP07O1ecpD1LXMGYFn2HsfYHigwwcZ7sm9oCCC9q' + sLineBreak +
        'vF/rjXg/oIMagmc6MZOjRE2eT9tpLRAaMynLiln7XS5u+Q8O3RexEw==' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes128EcbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-128-ECB,3E3ACDA483AAD613760CC55C7DBFE582' + sLineBreak +
        '' + sLineBreak +
        'PJupElZP0QC92uiYotAm/CG6i8ypU5SXxc3zmrk7sBdxVU9JQXsIE/oIUK40AlFW' + sLineBreak +
        'cGuHWxxYkdYNtTpuwG/CVlsrq20YfpxQrl525f4pz8ETWt/P5+aLQ0TemEKr+LVE' + sLineBreak +
        '921o6LNstZpftQJbe3yMz0cFTjSfsxsHbadfUZUQzobr1XcbazPyhr5rrSntgIMy' + sLineBreak +
        'rJ5M4G6QrOEAIHfVVZ1oizlFnd4vjGOKk1i6APgEEqJTIyFWoCXEzDtaMcl97GEI' + sLineBreak +
        'EWGusd8DJrqpJKnohVoTZdOzLrnerJXEUEJ0cz+UjvljAYg2MBSJk5v6HCp8aWcc' + sLineBreak +
        'CCoWUbJp2933n4nLBq7EXTVmJ1pwbB4cjNM1oL2BznW/pdznrSRcw8qut35ikEKW' + sLineBreak +
        'mB97+IMVr03orl0uFjHBIch6cPLYkXKi5w7CO4vvJeqqPK+mCtckzgIlzsdTL7Pp' + sLineBreak +
        'tp+wrMBtG2Ibh2HeJuvvlFCgoYBY482aPu/4NMei2eqfs0p5g0bf67R/BiG2Sxxr' + sLineBreak +
        '4o8hmR14v+dzLsQeoKrr3RnMqfmrbqgdkUfgBomlsunHUu9u7jB70TuYsZk/COPn' + sLineBreak +
        'SgMM0T1pxEuHdXfyZPSS9u2SFGEhbW4zIuVz79Lo7h3sKdYJqmwmgOk1P3IL/nra' + sLineBreak +
        'YpcacWzmV0g/GK8O+2CSGvEh1+m0ffQac1Pd2Abjzg9jghshsBTVTpkcFI0UfkIm' + sLineBreak +
        'gpP/hwLONl5a1KJn7u/ltFPdZkJ5CWPe0ZQ1mqjhDaPnc8j7iuFzUilsWITLRof0' + sLineBreak +
        'KHUDsAZSV7gZ5G/Lh6DGZdlwfkD4b+2GOPayQ44mr4p2hdOque6Z/LEXtOv+UvvF' + sLineBreak +
        'kR9azOu2RXVTiDLL4c/ntltS6laT/nCg0goMs5NAis+3cxKd7Uk/yXBAulwR6wmy' + sLineBreak +
        'MIZuSM4gk2pqbt6TJWIfxl4ZtPwp+jYIpMZc47XQ7w5m7YSquJzjilaj+IDVPkhF' + sLineBreak +
        'TWTMf+Ucb4duBD39HZjBWAoLkF487M8KDtcxL60uHuhVJsKyYsb8b20ukA++c6aH' + sLineBreak +
        '0VqU3NB8VXH7De3pA08G51P+XLurlLUUr118STaEd4r7GR8FddFmSh5x+PSuVXut' + sLineBreak +
        'D2p2W7pfvS8OTuaMF0PZo0KkUq/TbTpvMcTax+G0DgGJqFFhqxNur6WoJyYbQE0M' + sLineBreak +
        'nX8USnuJhS+BRNPEXc5i14dWmZEeE8i2KGm8RlL3KZfyrpBk2zwnGs+WM8xAlBSY' + sLineBreak +
        'KnGO6bLvRaUl+8IT1nKfY30HLr2tX+F0fEM9Tn443VgsXkYnMoaPDU0aW6+J0lLE' + sLineBreak +
        'lTeqJn8MPVRbU0Ss/0Q2PQLpayHrR+ly6yxJPOY6Nc1eLkhXoB1DwiGh5Mp7J6+V' + sLineBreak +
        'R5UL4nRr40hZy+35sH1lf/+1mY95Rb1hAYP9r5K9dAvqkdUMSPz8rtzb/4gevLi2' + sLineBreak +
        'rxB5XyOHM/qZL9ySpJWjFPBwOtJ/EJioRTvnG+/8jdxXWBiGKdkGLKV8k1z7gOee' + sLineBreak +
        'ewq2/8n4HnzMm5YKdTesy6LuaO5TaOAUe89Eo/CxPgdM5YnxSxRsxunrPR8JMLYI' + sLineBreak +
        'V6xyNRRHLOy2ffGdJZ3nqbSOxCNiHW+Glh5I2jyrKG5Bs0S1jbt3l0hZKWSU8k5k' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes128OfbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-128-OFB,271025C313E6EFC0403320C73382F15B' + sLineBreak +
        '' + sLineBreak +
        '/L1xK2Hx7pYQBTuhHX1P/mkXqLAlbSSz58hL1E4oxsDJODiVH+ueTSKajA8+tbxG' + sLineBreak +
        'eBK4p0s5j1fp7SJ9m4QXBwvhCnis992H9kQws6U9gGFrofrYAniRFhX6yzvm86ee' + sLineBreak +
        'deQ2Pfcv+evGRPigkoeRSQGxSa40fJ+5cBs4G22cfrKabaEKxnLtQpqPG17JQ4/f' + sLineBreak +
        'LdrHz64IyJTgvV6LCzJxShO7vxwIXaA82HNR6Qp09WUXxLB1/pfQ8oQfZbTUkvWi' + sLineBreak +
        'CBdXWT42VZklPl7StNiAN9U85K/USIYkKG47CpJvWMYbWJ3Dt1EFiEFi/wmYTinv' + sLineBreak +
        'b2K0xUrVUKxAMfmVtr1wGSJA9P9AT0/sBO2vTn5ibXVVHibtAET+vGXLtpGqf89/' + sLineBreak +
        'RmcqNEFYxvLzoTyR2FONtVluAC2yk10cKHY/pzZwQyVfjcgMlbnrZz9Pp1Y6ntR5' + sLineBreak +
        'AfXpVR/qyYOaQ8BeMCXkfR79GPyCPV6txy3KE2mbajwamvL7eR0+0R3Q0lhVcWGp' + sLineBreak +
        'g91D1nbgVFkHGOugO+2yb8vLq9k7K84Za+TY9NCqCG6g0S46yAgZD2rqrAAO4UIf' + sLineBreak +
        '6+nno8TS41W5wmsdEarbRoIg7iIKaPKzEmRRurSdlj/s7MKHgQFoet/OdZuAQkV6' + sLineBreak +
        'FumyDmqekmPAgIIJEO2NdrWo87RWKCzc61Yl52qmWsqrJIHrPORMGdjdlLVxXXIE' + sLineBreak +
        'XZQot33Rx7/f0VZktYB5fWk08kjWQ0sKTDiHEp8Xobq/RDyMTm9TFIkeFm4rLkl6' + sLineBreak +
        'Zt2bzp7ssoKeYuJgpoRzUmGP83wgl+AaJZpupARdz5MlqXd5knuPTETFPaFIf98d' + sLineBreak +
        'r/sl/V4E1nh0x83HNOBrLlpKbeWocVV4zv22q4zemALPCOQKUPWulINQWAYiTPDA' + sLineBreak +
        'lBQhFRnJXSZYFUqFWpxjp3yIWCvTZd4wgX5IQpaJvG+ehRn0H4FR0hJukMG7Pn5y' + sLineBreak +
        'ye0M0XlvVYWfxhLRDK23iNkRzVIbIxZfxqaInpGvatcTHyb2vnVFateSGlXIk0wU' + sLineBreak +
        'GxgytnTGW2fZtCDOqeQxCL66nIkpqKhB2hJKaD5WIG7SUikjBblvVcN+gkj9IWML' + sLineBreak +
        '7LB7xjE+4cyt27Rt9QHuLchdgSScPnPTZhdX0iK1LVELlJQFx8WPZpfXwpQR/xz8' + sLineBreak +
        'tqAKOfyhOX2XxYYOoaNN+ffQ3mEnsVFx2uQOp7PvNjL06XdYP4p/AruzVnbqsDsG' + sLineBreak +
        'BIo+oo7PfepNw1jRxcmeoaMotIZ8Feq8H8QEARqQSnzRWAJZhV5D9ztmUtaeqyy4' + sLineBreak +
        'QDbgxBxdV0nLAWG7e54FMn5yJfjqq2pkBl69ZvR3N+F+L5/eWlEpalIoq2l8AffY' + sLineBreak +
        'gDxlGgp030MAyFYSLJNYj+UUwq8k5INaC0QKjARbBMblf0HOX4U6RBqrpzn2xyvU' + sLineBreak +
        'mlM6pTiO+mOpG9WLgQS9XTUk2te8n0vAVUTk4Camj94Vdl8JWFNsfJIgwE59hprg' + sLineBreak +
        'a3Pz4FosIcBbj1pYtlA9Lz3kIGe9U3z9rHeQHNxJ8agW8NKGvlzY/YBdb115UhnM' + sLineBreak +
        'WOVp5TkpF2MyE+TGWqXzwNo3GutaNVs5YO5nX3Mtx4ClRrsmQYVTMg==' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes192CbcPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-192-CBC,51C73DF9487965B976234C88321E3F30' + sLineBreak +
        '' + sLineBreak +
        '6yLkX7C2XTX5AE6KqWsB2Lmt+TMGsoHIH5BDl+o7Yjx7aBSzB9X9KPTsVoPmTCOg' + sLineBreak +
        '+yhhV6am/yBImCdyuY8d9Q0A1kPIJTEkshgk5vc2KpW08blLCHSCjokEVbQ4TJDH' + sLineBreak +
        'bMtrEBVMU1g9KBTMuBpbu6MLVaFth2GTsqExX2gu7FB5EAKvEGhkmLudo1jKkgvR' + sLineBreak +
        'aiiyMd2CH2MTdatZtw5PrJmkhV/6RMZRKP8r9wkez8NN14ehmk5QDY2s/hj5uaEf' + sLineBreak +
        'xK0GXY6OcwoRo85PsOYhmOeFDqHKGRo9a0pPBy5ZaV4udj0QZekE1fziOxiPf6K8' + sLineBreak +
        '0BL50UUzQBW+3n0dIZbzlOiJQScQkjoxi0kc088FHXHf74VBoJUo6pckAu4OwpXW' + sLineBreak +
        'L4XLIGAr2Kv4OMiFSJOcaihyawE312B2URcAzVCO7skhTYHaC0fMYDJCGTc2D9rR' + sLineBreak +
        '+V5tVfT1dG4xdB+p/b9TQyAu8PE10jT+tVNJqGsZRI8I3iOtyWsBcn4sQInpYFYU' + sLineBreak +
        'R/v2tgG4hDdq1beEY5N/ZaLsoSyFYZmwbzB+BVhPg0W/9s91/nYAQgOL6XrExQjF' + sLineBreak +
        'lZxS28ujAq1LDNzg0NDA2KsDGJF2TuST2stnxyvf23h8+KV2nZLOZXjhlVl/Nr5O' + sLineBreak +
        'WPm3gCmuPf8F6FPqM+zI4YBBRtvLRkXafUNuvc7PYVNiaPyuMh7I7U1EUUzTpkqi' + sLineBreak +
        'OI/YD4xv6DpDand/WEtLHaYfVYU6PAapLV0T28BoFITp/qxHYYnXVfhn4htSgiwW' + sLineBreak +
        'R1btcxWyNjsIedjb1LJ2EwEfuXqZmzDz51uDLBq3XQ/dbvDkDzfZR3O1KGaACxAT' + sLineBreak +
        'tAeAdnTnAVliWYQiJ7BHn4LTJZ0ERGL/R1xpQs4quki4WHtEBRRzP6BbmUYYhigO' + sLineBreak +
        'QwvTK9darP1Ev7miF5BkRnrzWqCQHNTlDB3i/RzIfIDChQbSZtrpZH/V/quPuPlO' + sLineBreak +
        '1353Q6D221UiChhw0+8GmIszbLwBkDq+Zr7/poUBAqHmTaA3LeiahACM55ATbg1+' + sLineBreak +
        'FKf0nvUL0SaEBAqFxSdQ1mnW83VCMlCE7Luh49BDl4/nufCdF+iv3cYRW2SDHPrU' + sLineBreak +
        'HELYYLz+b4QLl+XO2SgUYEkU9s1Z+eCKcVUXGzz6vZUsA8UwvYIy8b/1cz4Y5sZ4' + sLineBreak +
        'MLpEXnQRMwAjArh4fvmosAG+diC18H2asLWpUS5HBBrSb8lAqKPLl+n72SlZkFjE' + sLineBreak +
        'WP+qq3koz3EyJsjwH2qbpx5BLhTPcEVHl3DZ1eOQmCXcpSm/cqKp2MKQFubCC4rr' + sLineBreak +
        'nphTD8uYKCP3mJXB8vqIIO9ho7+GVlCHJdZGu+3bw1L89O6ZG6WClbY56eGz2xUn' + sLineBreak +
        'DBmikb9sppeYSs0eX+yQ9kjQRf/BGnRab2dSTGtDT7jp6cL+zWUUOawLHWS72XtN' + sLineBreak +
        '3XYSEvvAWPygwbBuAuw17pwPPmTXduRiJosR1lRk28FGsMwzbj4byXm77IO3vD80' + sLineBreak +
        'cyrAQ/bmSpvlmYEHvmRn9N7QT7SFANY4a03aBK2iuqZQUz/zeo3eyrJudBXIiwUz' + sLineBreak +
        '/ZRteBa6SQagqDsmfeuGCjgTFGVnutCokh9lajm9BZ1pZtCmHEDd7yz4Odx5CmxG' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes192CfbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-192-CFB,58F8574921C585278A50F7A2EA529595' + sLineBreak +
        '' + sLineBreak +
        'RQtPMTKDNttPq1R+DiwHrEK33FOfxK1Cst5x1jrDhXe5MObLhqbz4Ft2idjtG/vC' + sLineBreak +
        'pemznnZqQYKsuJl/Th6Ydsthkg7HH1pYLRstc/tWQTESa0RseHDtdw3e/Wxhm6DH' + sLineBreak +
        'pSqymOfRq8R7PQKPxboj9fjxeooWlA+RQxGdyRJ6gki6PljOD29C2hxZV4HuL2II' + sLineBreak +
        'tUn/cdzaGu6bCvpFDvDuFja3TRtIrHSbCq01uZg6XrFui7BuwJxxR5lERsauJ6RX' + sLineBreak +
        '+lAvhwXqN4nsEQefvZc/GeTFzklsoJ+c3HJy7pN15nyfwNzmmH5EK7C4CdBJQymv' + sLineBreak +
        'MRwe9hY/LGXB5IFEgXvop9bh2qYk9tb/zb8aAHcLS9rwFsGOo+5+Yib3ds4GC5fx' + sLineBreak +
        'ILKH234g+hkhutao530kmWXFf7qup8lvTlBZueAWcIFdmBCsWjm8ejxQUZaPCqEY' + sLineBreak +
        'sZ1UMDw1HPX7/4TXdVNZWrxHisv0VWnhwJNflEcI/k/GR0/qUgkHnUPycWTtg0W2' + sLineBreak +
        '7ivs7D0EkIJy2OyFj5swWs+eqhsSDmd0BgGL0VduLB0voi1eU908Af3PllsTwf4D' + sLineBreak +
        'UaLFvOkllIbul+YweImT9TinmkWIFMZuNDR/PHjpbLN/39YkvSub6oS4LOgKEu1Y' + sLineBreak +
        'Xr779QOZHMcIP+PXoaxqOWls9hgI6M3PAH+gAjwF77OWIQIh8JZCibR6HWYcr/qo' + sLineBreak +
        'iFTzJGNN7P06s3IOek+YoHG1c0GoPsNungPOzthNnaAUcRyvZ1Yg8cy/nhrA8Eeo' + sLineBreak +
        'A4G/I241jr/Ex5jooykpeotV1/AMIF7qxFeTARQgObRi/fiR0r9rjaSMbOt4PlRv' + sLineBreak +
        'Ln0ZBqedtkkRBPRGO0VViSbUAUOq0oSb98FWqPFpcFl8tXRyqe9m/W2zACczZplz' + sLineBreak +
        'OySvRuASdKYpGk4DmMlQtS8wjzMYTesBx68OiZfw9W2nkH+Xapc4cH8hyb3+aXXb' + sLineBreak +
        'b53nbp59+mx4UwPOcrdzVHdKhDT3BjYrJTv9kHAY8yA4Nr08ZsO5tOeI7vF+bUKx' + sLineBreak +
        'kWu4AIEccB030iu87/xHXUEOBzsV6HzzT1TrZ5GKSh43vhRwoasYON2xlO6RuKCD' + sLineBreak +
        'Yv6GbcPd4lv2mv4lAaDXk5IThABHUL8yhqfwru4L43av5AwdslRKIvBM7UWrlXFe' + sLineBreak +
        'A/Hipy6jjcusGiOyH7WfWBFV2/f6NtX6lGuna03F/yMZcHI/HEK5RyhqOYOmcxfw' + sLineBreak +
        'A1eGKSqOnq9IJ6vXnF8PuRYKB9i8Ha0z5JmWkh/dX5dhTzwH6wOz4+bLgkgXBdhY' + sLineBreak +
        'jptSs5zsvrxGiLCbENPTjArsBbT5NISh+VTrrUtmA5BLPWx6d4NNJ5eBXTnpOIJr' + sLineBreak +
        'rxA0halZtFYKj0mp1ZgnVylHC45QDiwzDnhXra83RVrcgQjcX4npjKOaYZRQ5cKR' + sLineBreak +
        '2F1QdvoLvE9YqhjH0QFQWMWfvmLHGIDIDkSB6EyFsgzWdv6kIaiYsmdir5FzE8c5' + sLineBreak +
        'SvHvu28j1X4OL62AquOFKMXQVns1/jLp0KERx1EhrQChHUxpA/cbqNJbhjHoRQK6' + sLineBreak +
        '0zXWP9gNlyrSIKY4egyQmjcTDvNXVcSDu2o7EfnprNCYirFgsAbw5A==' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes192EcbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-192-ECB,A3A4C4B92548B906A635B84B3D67591E' + sLineBreak +
        '' + sLineBreak +
        'E4I7KvCs0qknDw8D9ISQev5oQCNiHskfB/SvuKJ/qJoJP52qk+ajN9pNMp+011R+' + sLineBreak +
        'MRaMlK7tANTrQ0L/Yc6QNUZW2aHyiex0aoC4ien4ojgvqHfaP12dMxFhOoLctN+N' + sLineBreak +
        'zrAPSuQg2OEBiWxEoDqpgA7FTUbxPiJ3QdtwwOXS5kqAKIEIoNnCPCL+45uKBrP8' + sLineBreak +
        'encSI+nrZIXLFqGEukKZuFH9qzdF2leOKSmEW1kmwxMOfQLMVQMJyVzd19cCxU/1' + sLineBreak +
        'FZtPRRIzFlx4PlNYLKDpypSUavgo5V/o3UHk6vbP/Wd+Wy1ERwNliV7CTCCpOrBH' + sLineBreak +
        'qJezvhkbktiHQQ7+5zU0jsTzTlZcxATdm2ktyfEa5GKrCNfrmUYNwNSi8DC2Dn1x' + sLineBreak +
        '4z9r6OfKV3dKcSkgmFS3ZI97ZhrnMqpvo0h1kg8tuiboI9pPWp8OsLIvw5+jz707' + sLineBreak +
        'GLsl6hI0EX61YFc7bqeetnObgiaJMJxQJXHi0U+Z01GjZ+qgGb6USmQ1D8r34nuj' + sLineBreak +
        '4l88VYW4jBhxa/IFpzUoxIioKG58xQT+OK2Fi7BF/OJLQpj+3RA3YLqry0D+AOT+' + sLineBreak +
        'f+nDJepwrQ/CZtoQl53ssct+mDY0D1IU6u7ah9WdIuuptV7+WxutFfDpXsmErKcZ' + sLineBreak +
        'eILXaH5zK9iNVnVNQDmnVacjQt0x0Rm28wrjI5N7M8jGWKWi9PMLElx3BTo9EbON' + sLineBreak +
        'pJ6x6xshjmdCR3gOLo86CZGkoUM1eNGhJuihrl6HelcZxeFnuiNYnLb5hIaqDd1v' + sLineBreak +
        'NpFUQBRC6Q3jz85zIvVsiN2vIyak2OGDRs7r5dqb1x9QVz5tMjxuKe3t+rfX1FN1' + sLineBreak +
        'vCusACQQzOl6NdTgmm5Of+pMniOL/kRF78e7zva8vM1Qf31/z8wtq3gemt+pZstW' + sLineBreak +
        'WV/kRhIvY/p2Nm41TtltlctThbYquFTEy8gxhB/Cot2k7Z494+8UBVIn7SjsdDpU' + sLineBreak +
        'X+N24itXM9/sd1LHrXBSbBT5PzSBJFC5MS4Nt6qpvSKIRbyWINjUoTvbbUwoCo6g' + sLineBreak +
        'soYBPJR9KeAcQ8YdBOEXtFScq7c5ZPOGCj/+3p++Pk7yMmlxNPvs6HLjdHchjAYz' + sLineBreak +
        'jycK/uWYNLOwKS/AMxwi4R3i45pPgIRuwGdRyi17Z8kOKATdyQwScbPOShW9/066' + sLineBreak +
        'OA0rEORx3C9gMoKa9QYo3O9YLjA7NS1ERSY9c3X9anSgR7eSs+DLRwFiB3EHoCba' + sLineBreak +
        'ULqd3n7qBKgkQpVF60p34yKb3K8o5s0cIE7oAm3VdoI/O/RSs87rDmUbpuYzAA24' + sLineBreak +
        'mXRwBvPpwEhke5PoPeFIYmcWa4wUZOJWuF78U/tZw047vcLKgr60Z1s+DlQJvFXI' + sLineBreak +
        'tXkV3qS45f9UDaWQ15YNev9fq+x/1JDO1LjQ9AHANBjRQSzE9K6YpyIw/SZlbo1O' + sLineBreak +
        'xuFrE077EL3hrRNh00O2rtcrK53mAOKMX9D5xifIcN4/uD9AdwU24YvC44gij47m' + sLineBreak +
        'hSg5wz0RokMNGLKTXaJxJGs4+ZK8JWQs/Kf/V9j6j/i4iDWuy5Ra7+/dIU/Qy1ZW' + sLineBreak +
        'cc8Uo2ji4i2z+QyzbpbR/jBqO++lcV2byEVDy8Xp/0X2G9mY0ymIbm7ATTlzE2/b' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes192OfbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-192-OFB,9797077D8AC3052C37DE4D719CA8FC00' + sLineBreak +
        '' + sLineBreak +
        'SU3g1XmkcVhlJpQSWXdeHcHI8IQCQBg0oenT/35NKgWnFBlysqwGwl/pwgdDBmm4' + sLineBreak +
        'jLsPaE5Vanm4aqWv9DNhItOQokIbIkxF6qKeV3wNSNbTsSaG2LNphwMiLs9rw4G9' + sLineBreak +
        '3aFV+0THPLAy3BDTsB3NPuRqlOSVcwVrfaeMXQGhCOPGmsGDeczai1xH7eq1C1no' + sLineBreak +
        'KUqNMGdf8g1NuCmQnvswuTF9BCi6rIO0JRqLPTxoz/1emKfHhJFefpSj88zg3ucm' + sLineBreak +
        'cz6ZOAlsmWm1MQrktXd+odzpmjHtd1vNsgr4GSYUeVxxWQX4o8pVFqWqiQXii+HS' + sLineBreak +
        'ubtMARXAuFIGoM1RCMN8o7sJG00RbG7zNxfhHqe4wSkKgx3qEuusUDewXkDeYhHJ' + sLineBreak +
        'HGQCD1epByGHCZkLwBntccOqbCQoSNB0/PcFU6vJrtgVFl8N4VsNMRuLj2ZJ7uuL' + sLineBreak +
        '/EZ3qkLTk/Ek68++m2dtAdyj2KF1O4z2SFROSh7MCqWl2rYh4zZcBtGEfmQe5Pwz' + sLineBreak +
        '+kPycc76ayzHO8Bjg6rl/16Ua5Wx7d6vy4Hg7JYb5eDmj2UGJ8p/z83KBdQnb1ku' + sLineBreak +
        '84ZjpYgmtjZ1vY8Z5iZqfZro9JBjWM4wFZIKNXcBniC7kBV9fRC5nzpjs6qWTPRb' + sLineBreak +
        'bd7PLMuyRZz9PO6cRuhqYlP5tYSGYYVhAMVutIqSrQVRDV8AnmblfPiOtT5lHC48' + sLineBreak +
        'GR/xPTIFxxVqsDmeyBzyXn9gzAJKgjTVCXNksXojM/ZMfDDvAF6m/Ntz/izp2CbI' + sLineBreak +
        'f2lcHgsm7SwVn2fvHikAugA9B6ixMCXygO0L5OEUDJW1e1fB7FMasjrwRorDsxsj' + sLineBreak +
        'JUNDW0KhUXWt/U8lNyfRm3oNUjQQU3x1iEymjQZV10ZO9DTn28fZOF70moUWnl0y' + sLineBreak +
        'ffELY1vLtLNP7Y5tcGNtJARSGnMUW99P7OKpLNXkhL8zE3DGEL1N+gDS1n81kzTH' + sLineBreak +
        '7hPjM6yR6gJQVsQrQmXrEpIlHQeGA99LYchzyVog14qMhvQItDlCsr5UIPwVwhMP' + sLineBreak +
        'LTA2LITZOYieRAqrv3vn+yFHYG4k9/C/xHwKHE/4pDw8bLn1o8thGv5ZW4yDsHGx' + sLineBreak +
        'n6F6vqJrkPW6vXkmwcgO5jK8JBbEpyzAPc6aSsibH3JF0ufsfs2hQ4bwb96OmU6v' + sLineBreak +
        'mukMLjQoi3BJC70Op1bpe7wtCELJw1oFvbZDoXLYsa3c06HK1M4rmzJQTIEBjqxd' + sLineBreak +
        'vs3g4L4CQ4RHAzlkjLrCF+wcBHt33586bDrt03qBEA7GSyAUu1NSM3UKjjM0OydG' + sLineBreak +
        'u8echgFIz6XetqDICHdN0r3ZWyICM/FgnVQhs39fCgafVJsy9C4p5jByUuDPvebP' + sLineBreak +
        '+gvvVqkb+DGwfkKT3RUFAcYiNHdtIob3kmp8OJKTFk/nwdUwqUTEu3VFCmWog9ps' + sLineBreak +
        'oe/0KOL7j1Kn1xEFkOt5MdSFCcpbsYjQNi7F1gWAr1vMXDDPsSizsniGSvXZIYBt' + sLineBreak +
        'Pk5AH4MflqbHFofWClhGczSLi0FRiVPqWyudoU7LOesQhhN74Dn5IzkeAGtDL8r6' + sLineBreak +
        '4vC+G61PZdFXhLXQfOEL99hgJ2mjQP4rVqwdz143YE4/CUHmpq6d8g==' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes256CbcPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-256-CBC,1876F5A50C9046D504D47B2BF8951875' + sLineBreak +
        '' + sLineBreak +
        'BAPOppBjFxMrMU+NI00PbmXXutKdPAiP+If8JqX5xGQDB9bSt5Q9R2QkaMx8Z94f' + sLineBreak +
        'trVbp82iERyPYnwcnA1Av+pcZhKi/mYFgDBPP+dDLp8qKRFAWil0zc0U2jkfo0U7' + sLineBreak +
        'v8cpO5+oipkJ9RtjaTg3/XmrwCUFZH4KA6G+SUFc4Oxj8/dzQ5YUDtJ5iyArRlnr' + sLineBreak +
        'v4nsvP4OvsI5UFYwp/T97ks0KSmo6YLMpJwUBwcleX2vOhX8fd3thk9I+EbVVt/f' + sLineBreak +
        '+JztCTwr4EsLxWe4XVmit9AKfLU0AhmcA20j2YXE1VFvRJdyr+gOGPD2SDoRgiZH' + sLineBreak +
        'rRBhfi7cou3QmZ5d43jFYoYCBc98blEV07umH0DXMTL8XSrfWNIjZf8uQR3+ZbHt' + sLineBreak +
        'W60jVdhOCEb40KoRTHQAMBQdgVVkrbXCFyc9NeVzzhPqyKXElGxLBjRB9u0h15DV' + sLineBreak +
        'WCJUdc9UGuHzFpVFzpEaehdm/7vl+SZXUzAOgAQDtL+ATsvZglyMx5y2UA+5L1eZ' + sLineBreak +
        'grA6e3tQFdBcv8w+WgYW37oAY2VkHKjoHs1TnR8z1t+OpVovnpcklawybh9Avv5J' + sLineBreak +
        'kXyZGc+lbbb2gvUw33VeYR8yIE4zBoePuhTFM3K4NfkBbKavBBXMjQlsdRzlt48r' + sLineBreak +
        'RqdFnpYc1XB4ZLP2VparhG+Q1UueVML8uBcd5F6X/0u9n78LfIITwRUpVoaLXRzs' + sLineBreak +
        '94Us0pbzWFDxqxtqKPZHLAVJOYvEOwZD5Haw/bwho73EHEx38MY7mk9T5PonsBko' + sLineBreak +
        '7Op6aEmKK1qfpJ1aPvy74UmIlVDHu5WEMkYx7nQL67gnFXHY0yKjmP6dc2y3+nfR' + sLineBreak +
        'qNK95RTaS9VbACRS+re+P9+Z3aAsQGvj3MA+4Q+qlscUmb8uk+M7tg9ADk0VSe1u' + sLineBreak +
        'Ts2x7UZroI61c+WzgsQzMAwm2QLPoKQcvv2b+iGD82enAtleTTHL9rkoS+KmNNU6' + sLineBreak +
        'hWL+AJ7HP9s/5+FJ7/4CD84pcLECXQ+f185vvE42TfdZmoq6NgSKrGVZPLxYnyjO' + sLineBreak +
        'qa2sTRzImZrXPtsnFEL9OBflWA+ZHaAGo4HJNxZW4Z90HJlAZN3isSZnE3jPToKP' + sLineBreak +
        'YFdHsPv5m/KpNa5luh4L3K41QWzLmPlRR0aygWM7/0fYkgxI8PnBeCp4OjoK6qHx' + sLineBreak +
        'VYTWMKJQTLyji3YwMr4CufFAVty3InUZzm+ALMFHqEORB6JqPTR9mtnR145FHtxE' + sLineBreak +
        '1z0LnEoDFEdGuLjtC57yR+lYS/vgMbtj4EqQ2zK93JaXvI2HxxOiZCZEDww262Bx' + sLineBreak +
        'QZo0vBoAd5vkMKmz5eAMpRVkguF1wN1RPvao7I2auJIHp/3zoaUowpZgtbmDHZFA' + sLineBreak +
        'Kddfc927GQRxtUH3QQVe1R6FFAa7JBHNeJsBvZu3bj3l/7BATzcne5OPhjZ/t8Sl' + sLineBreak +
        'hMqEBZuo0svrEc0w+e8dpbPEjuj8UwBmHYZWlALby5N+YJ1NEtLYmyHe2PFNXwK0' + sLineBreak +
        '2fo45CCSyl7YJrHD1ONJ0M804ML4nMwmYq6fOAaV9ufQBFqQQj/hyyE93blB8f2E' + sLineBreak +
        'I8LMN/SUKN06YU0nErN0PRdm7CkrS+kutn/Pz2H4oSbUZ67z4Ee1tpnVQjoDYdQU' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes256CfbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-256-CFB,37639E4753C0E4CD43EEDEEA18AA66D7' + sLineBreak +
        '' + sLineBreak +
        'HKuYoKfUqTRf4sW12EzTuIFK5J1FkeJAD+ajYnKeKYneNiDbmDlQv0kIk12qBv6l' + sLineBreak +
        'LA0oBH62QKjUDKi/sg8NAO5CqYkN2ZB0gQurTgGT/jrvMkkkkwE0x1n69bGNScCN' + sLineBreak +
        'mkqMnAnjQqbo1xERzwqX5OWNTTb4iDLiPyjiUlQDONl14pe4x6zGpVziCVCQh8Q6' + sLineBreak +
        'rAPDryZBg/wQtPXNhNpk8MiTiSwe03wq10QP6W5TmUIKp3kD4OVfBxpW1N4znyIu' + sLineBreak +
        'unJDVcRdBf6XA+aL7plAsETL6F9Tx3Mxm5GaeaJcSOWWzKMvqYhAcEYwM01lx0w8' + sLineBreak +
        'LMMRUogny67ZqaLywXZWH6FCJGCnJK5oaJE+jlnKZ6xhbwAxMyxWRCZC9pF22ocI' + sLineBreak +
        '3IY602+shDOWZQDoihhddwPJejh+o3mVFEglco3YEByL7Cy6GvqxhctEEH7uKvlQ' + sLineBreak +
        'gXGb7srmOpeHHfP76N9afF2hn0mqyToakdZqgnlgT2jm4UDHJ1vQ+onIksV56I07' + sLineBreak +
        'tVMEmPhXQCIHhfKdzEgI/v8CiLL3W/g8r+20/5qyKCL5vPBLAxmRudYKbGkhm5pq' + sLineBreak +
        'GkzaSp1cKe4ipUfVc5OEUikOMCuadal0TUQZ+h658aBCxLWHNPdZCzNdY/bZLN9z' + sLineBreak +
        'XPhAzml/H6VOZyIxb9hm+FNESvqNKdlU2NaE7HW0ILKaDif7gsZhvogP4qNDp2P9' + sLineBreak +
        'xPANQh9UxpA16AUTUNOqk78t9aQVpbjZfAeGmcw6AxJ77uK649JgkEnKqcuxcDSi' + sLineBreak +
        'zn/8NGeaKow/bTW6jJJj7b4cMys32uxRjeeeClC0moQiy28OIJpRRCRJIs7Muka+' + sLineBreak +
        'dMBoNyftBnCONH+oqj+F5au3QPMwKH4v/4VpO3hcByXcqxegH+BPEZzzYJ1OnI3u' + sLineBreak +
        'dh9VlpTdC/CD+Gn3ZRqYbguSaqow1ZF+nlpD0xcs0IQjNEe2BVR7CULUFVXIgF44' + sLineBreak +
        'pTv96/LvbG1J9b0VuBr+iIp30FG9azd2xyn4O3lW2xk1uzvo/Wf1vDGvT6AYyXNG' + sLineBreak +
        'DQS1dGtIm3+sy975sNTlba5gWgh0YNHjeiQq19I6ZzLFhkvLKfh7zpx+R53YcqSY' + sLineBreak +
        'lXj62N0u2s4KUygqg14oiIUoEnNr+n7Pq0es/gYs34mY/KvlqA8Prax91BaoqqLW' + sLineBreak +
        'qHN5bEv90KdKaJlvdWsCUjA3wReeaQa+U737GMXaON9/oOJ02bWC8/OIzUPgfGRH' + sLineBreak +
        'v/8YL7kMnTd+Col0f+XxnebWSfJsAzT7mjfly+An9EjccTeiOon8submd+L8WySK' + sLineBreak +
        'lVvWzBD3l4HKjQkr/3/YtmpuymVZyeTzngVuSdw+iXWPmOOuXHyjyD2Htn5iNWch' + sLineBreak +
        'Zlw37a5sHhiFtpNZtOnhpmDbX9sgt68KJMB/E9Mh3JuWCaKZZ3Cv/22KA4KQRlNB' + sLineBreak +
        'FSvDDKJBrM1m599A6GPJisR+iC7g7asJQ8hI1OqaY69v8nP0Fo+Qk8+Ac1L/n/Vm' + sLineBreak +
        'RjksignkKjvqgWENNn5Bf9A9+zZrLLu9wJJLae7wIiw4UgsNob68sGjWdLyg+tab' + sLineBreak +
        'QTxd15H5VUIuD6pkeAI2qC+0sSw9V6LKm6pmEIIbp188CzApcsGBXA==' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes256EcbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-256-ECB,C5DF56EE3F83A1F8C1AC805EA73D4D24' + sLineBreak +
        '' + sLineBreak +
        'ac22chm8+bxXpppAKfsrFJwCY0S4VPnXmFRqlAPZRuqBH9ylFcG+F8TuHdIsLeof' + sLineBreak +
        'q6s8yxkXa8y+/3hyqIZeMwN5Ai1Cas4P1iMwEtMUCMeaip5t0nf+yeCyx433hDSW' + sLineBreak +
        'dVnsdeuiFCiBUPUXfp6dCGO9kOLUEwu4wM4lIJkJ4QVyauO0/DwObQ6s6xEMFvQH' + sLineBreak +
        'GF1AFFTfW39CpZuS1rguG4hTxW6aNxjEaSKHJnzWu+kduMLJEaLUiL5+i/tUw937' + sLineBreak +
        'V8DhGdWU//1Q6KKLMr+5w0k9i/FhVxAGJZoZ5j79ToYORGr4jpkDPOvHaCydM6Iv' + sLineBreak +
        'JH0epC0wfG8L/dArNGLEftTpVVlvqHMpAlc0Rgvn+LtqstfyWFXqbQ90NBxC5Fs5' + sLineBreak +
        'xiGxKFGpkX4stoKIaOvFVw/hoCI/oxs8Eihz8u4QjBsl/3TdYQ6AUyfBGEWImy/y' + sLineBreak +
        'hh+QKCVOfzAmVGcffXYf7fvZETVgpo6tynxKVlSRXO9ZuzANJCC8jkUEOjc7jSKl' + sLineBreak +
        'jyMKQMNnQxyplgaFxnWIfs/snvlLQW8DlpMPH8xSkHkUgLKMWrSLB9Cisv0N7V5t' + sLineBreak +
        'Zl7Xxm3tOteLG73JxJKJkSZ9djlhkPvlvS///mvLQc6jse8EzY8peQMI1pYQu87U' + sLineBreak +
        'CvHVDOYn56SFVJmo2koER8FG8a1910NqdCKpNkzjqTl1Qbz7Z2VwghTslM7sUA2L' + sLineBreak +
        'AJP6PgdCkiGbi3oU8moPy3Nyg908j/17Bj9VyCXiegMAOxI6Kefim5Nn/sq+2/7Z' + sLineBreak +
        'MHIucQX6ka8KjEp9jvf7jvNC5WYxJkKIl+yzwAzqRQ395Lp1sun6jPfngnPQmkXY' + sLineBreak +
        'toeOeFvKlxaQu3QgNY7Hq9wwGbK/uo+rLK+Jbnt/75w7x5aGHQF3kf36epr3O/0l' + sLineBreak +
        'MyZPPx6sLblYcNQhBV8rnSey1WeO6105h61xTXdKV6To/m+RDZYvt+qs4z5SNQlj' + sLineBreak +
        'oKTezoQUh4J4QMg0EPhghyCS+/+cPMdnVnwX6Ds6nD2feX2CpN27xieGEp5ZhioG' + sLineBreak +
        'qWi6/59B38kBW2e60eQyL5f53bhWvywBg3HeUsXCD0ujtXBqPMuNnO6FU+/5Ohg5' + sLineBreak +
        'BAJ/bXaWiOkobmppBeaViidGv3NytL48ZIuQ1PZsYQajFb/k1SkyLebmeC2NYdO8' + sLineBreak +
        'VBWxAz5glgIKP11K9DJMD3n6PVl+ZyvlYZUGXjfUhOxHKVmNDHv2o5Pv8jf3WEhs' + sLineBreak +
        'yuWEoRECvfNlkDrmda0MxMhEYjeTysbxeX6fvwD2InzuFKhfzwh49p5LdZLurEm8' + sLineBreak +
        'DI8KBIXUx8g3svArJRvbVLyW0deMlXBY7h8Yc/2y7c5qBwfYrYhgazxVBfRqS3lt' + sLineBreak +
        'EsO2sa0V0GaGhPh7LUt+n1qDDYmaOfxOdpZoSLm/surciEQIQVNXt264YuFJS+ot' + sLineBreak +
        'vHWWVHzS1AZIgizu7NHRVeUmu4XEgT8vRsJYeogyG9o3U27L/lF1L5ysvYQjtvkd' + sLineBreak +
        'q5idZxCnY5RctE2wa5gjxPjmgbt1sUN23KOiPyz2cmXGBh/dwqEhIV6j7+WeS4/r' + sLineBreak +
        'SFBZBeGRHi8tACblT/6G9UB6FcycyD3hf317Zb3jXZLve17ozwRZRQ8aBkz07+iy' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaAes256OfbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: AES-256-OFB,E6AB8D4FECB44185E26505049A97B0D6' + sLineBreak +
        '' + sLineBreak +
        'Fg8Nq9CxyVZmBNEiN9vBI+gsZL4lvWqCPaR5E+Po7acLxYGos4zIcmLCBa2X8lvM' + sLineBreak +
        'UInn087k98OAClm+0PvhZ64/AdDE952UclD/xiNvQCH25HGQy7wk/BxuOM5/FT0S' + sLineBreak +
        'rlV6RGMibelHpnv+yploYoHD8CSo77N4RHdEuepPwod2fGTKu5Cbbt1FBGU5LXWJ' + sLineBreak +
        'BrDMOlSN8P/rD5ePADhDsYnh86g4cBVHTb3MkrteLa0m1Szt47E6d3s+Ued8Cg5S' + sLineBreak +
        '7tiJOTFnXkmG87LsLZ0HDp6yML3g2gpTL/1Zhn9zS9lZc3cnkBfRJmttLBPjVCiB' + sLineBreak +
        'mStjlXnuJTDBdgQhJPJ4+2xJiR/ucFbCnUF/VICsl0hdz2Hd0PCOdhzj6U3jbRk4' + sLineBreak +
        'uI2sv5TV/E+e/Ppvdh2W8LISSBdIwp9CJf3se8RFz1dUXwTMGM50LKr/dpvy3T4m' + sLineBreak +
        'NMO/Cf/LyA7HBFJxjqf++wi5LPDXzROm1QHncvXNUjypNPND3RhP53pMeQ/Ffd04' + sLineBreak +
        'dw29zrmbyQKQOOac5Ss9Lj33Q/WzBgw5UxxxMxwRVDyfFpdz6JRfMrnj2c97auLI' + sLineBreak +
        'RI3euI9A9yRNxneBKTobS0EjYyqAiU6b5MbNwrybqvavbA/+ZMEg9Ylg7vtBOXpW' + sLineBreak +
        'YLLYFYPhWNEambOfNJi4tHcX8znGACxO/W7v3Ir+QFhw2IzSvntcMODKGaNKMGys' + sLineBreak +
        'HJ6mqKbmYidjhtKen1qHB5u2bukaGWUj2kjkv7jjuDK3ExsvB2PjEV5d0foPEwW7' + sLineBreak +
        '9QQeKc5pY4tOxFVA4qCq1tTzUhWr0mBkPhnFjc7XOLbu0sHYdr6ArZ3SadaNT12w' + sLineBreak +
        'LG2yg5r8BgmaUVTTQAzIiHhAQYZoCHAq+ohNocIikIh7lPE58DL2GPpEdXZsgzTi' + sLineBreak +
        'T+EUSkSw4VtIMmnWw5GNE3zCOxvx5qzhKiXVcnB+2+IF3nlHkQqFXcYNGhezZjnJ' + sLineBreak +
        '4FlR4FPzumRmMj1x0zmdbp7eTFpipUpKqJtC8iuea29pEl8opXDNhvmpmrT4/429' + sLineBreak +
        '7x8eJOjZhm8WL1dVpV2/Ikc9boEsYzHcBkY7kuaTqT8I9tdQ08ODo8UE5aReaFuZ' + sLineBreak +
        'vlBY4J+A4lltQ7qQ+sAk6gUMvlY8h/9L9gZiGbLe438Ndizskuwy+jAZAEx0f0cK' + sLineBreak +
        'YnTsZxBHPkWQXgBHMhe3BAAA+CZaXPps0SjD0yMQs7lkAgag6zBXW2vqttoJLU9R' + sLineBreak +
        'f6uP+BLwZCFDF1NtkROLV1oROnaGvMbHWcar2tw5qNe3BAsPQqGk8XnqwILz4IwX' + sLineBreak +
        'MN6QrjzbBC2jcL5jsxPZ/Tis9+wfI3t1Ke0EljYqA9RVWuC2KtRK+X3xOK6tWEK+' + sLineBreak +
        'QlagHRDI0Z0u0slCLjpB/ev9Ajqwlr0h25T5ucdsLd3FFEKZbzspdfsJuOXPM5la' + sLineBreak +
        'Uv9gpYIcuFrKcVbvuBPzt6NX/rp9gozZv7ZOnujjor6RDorHsfbgbEfcerydvJGu' + sLineBreak +
        'PRk788TkAB0LOE2wD2J2UO8+Ufp1qK9GWmtr0WFCazqFfeiorTh71iS7pwUt08so' + sLineBreak +
        '0BRkqfrfP6pXEcnh4p+LKh+dnbgIBD+KH0qHsyc0ci43byoOSDDHnQ==' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaBlowfishCbcPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: BF-CBC,E59962EBB3DD3C74' + sLineBreak +
        '' + sLineBreak +
        '1FpslA4+P9E8HcUUGpkIMWeZYV2XxCgOiSgCe2NAUiutcRkVAg9nPbzwnsQTbckx' + sLineBreak +
        'd5uOE/w53BURpxPkz3nNcike0sr3fa/MzaoRUDo0P4MU5bmAihjnZqhRllqvw4Zt' + sLineBreak +
        'BsyxjHVn54RaqZC4RNQUqwIHYZwJmHUi7Zk3+Sw7fivMZBr/AWqa66I2hk20+obB' + sLineBreak +
        'y5ubRjtjw6uaciPLIoMZksxoEwi5xv4KnQHAQnaihQ558RPpUwweqHXyOZPEC1Kx' + sLineBreak +
        'gNQPrTGc4Zm+CKqR4CceACSYzcYtechZpSQqn61emmtyhowDqXpqqjG2nimNihcI' + sLineBreak +
        'hbp5O+O3fKZFkJllB20xuaj0rK1NFF4aLiS3BK6aWeCZ6aXFawSvbQb6vGx+pQmP' + sLineBreak +
        'eQemfllRXXkT43CHUmMTaf6gKnz5DaxDBqdVP73dBa6UoWnxTrZcUNKiPUCvB3g1' + sLineBreak +
        'ciJePjBnsijb2Bh6jIwr7yghIbS65AYE/0V+5Duw360Fa1OqJkMuz5pKeJIUcYEZ' + sLineBreak +
        '3yuI22CZeorkvymKhrt1hUn5xLIKRZkWg7UbXG1WXCrGtPdJ+CxnwupHMdL8iMLi' + sLineBreak +
        '1haNeJ3E/PeMjehQRzSEEFwDljn/b1JtoWsEwnQPTPKY3505OWIhYRwRXLEo5n1y' + sLineBreak +
        'QEfktZ9UtIsJcIpfi7hMvbpp/7Njlu2MJKZ/1ZtvwVLoaXFTSivqcAkDdP7u5enb' + sLineBreak +
        'OJ4EaDWrRXS3Zj31fpYTV5p0fRaejFPevRNnYvMLRiSoFobd5MUrKjxpxPRCLiW7' + sLineBreak +
        '24BF9QY7C2Nso9yR7gNkzLw5x/725lGxa2ZD16nJmiECOaEB8ORVlilmjX2OQi66' + sLineBreak +
        'hpGVtjHMaoGr5IvBrtc7Q9aM0bdoFZD5I2mOm0hniNHG9es2IMByHWRAQFzOOLGH' + sLineBreak +
        'IFoIyW3OIuzK3cz8lMLsh/Hlbzo/3bpX0rbrn1XZULWAJ1oNzRJRi6a3Sw2YoIMh' + sLineBreak +
        '656IJB/fGRbG9CMVMl0T7onDUhZYLA/mV+xy2CjkQdPBjFpQUTn5YHu6zMU7gejo' + sLineBreak +
        'YSV/4esuUfhogLiqw7sPuCDqLL2UftN29xloQDTY6MlrkFb9jCciAwn02DAmsN4h' + sLineBreak +
        '7Utus3Z2N7gJnxt1dRecqr2o/agIINm3tMh0LK3/CydmlthZQNpsxMD7IqaWFfQR' + sLineBreak +
        'Uq7zQUfYZi0l2J6iy6FUHUokskqwgiNhMP2Z+uZ1xHUnoP7E0IZMHnVWEKBIQZ0d' + sLineBreak +
        'ddDucux1jOBlMwLqom3jYPjPkxoeSU2E0ozVNSOqsPnoKkz2qKnEHhea2sAPg4eX' + sLineBreak +
        'lsZ9ENQyQMZVapjic41BU/32pbrE/+JkK2Cc+dcLlrnHo+JpFeTdbleJhZ2JgXHW' + sLineBreak +
        '8r04vZHA7tQOc0KNR522Niu7dvOW302lwmfp7D5xfon62/AxVhos1DSZuNpVClm3' + sLineBreak +
        'V59lqeCBDm1yJwdM/946Eq45YJiTNTzYsPPFl25KNv+3+GKkhZ20GuLiaqprel3S' + sLineBreak +
        'MC5XbMJg4nc0LiAfDT/q1jO/EKZ5LzRRtkVvx1D8To6DAptyFoJSMKyFu79tQdfN' + sLineBreak +
        '371+sXEX1VjpEGxO2t/DUmuERIBdc9X7rPNOXSl31QxsXy4s73zcAhI94X8xrqYZ' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaBlowfishCfbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: BF-CFB,A6C793D28C38F56A' + sLineBreak +
        '' + sLineBreak +
        'sjmmZGwl3qF65MFuXEtiTkltbaXuionUsMtzc/XzyPPaIxcdl/03iR5Fix0hTY2Y' + sLineBreak +
        '/W9BntQGcycH7uNcoYwOUScTRr2BJncyoDXZaUx/WOQ6cDHuhRWWwpLpmitfsn1B' + sLineBreak +
        'SRvLdKddL1GE2nfG2xhCdN4N7pVPUwIahHye1AkaSJ4gur8tU0++mJQTjDo63xKB' + sLineBreak +
        'oTh3mZB0OCnelXtoYFKGFXNh5ouAPZgcE84breDJBoGReH6f4elkigtSx/J2QhgN' + sLineBreak +
        'vXERboYz/HHhHSRCtMSp0qLEQo+uLcFxZcSMQE12eglOOucht877V5n5RMLFT/3c' + sLineBreak +
        'DeZdg6D1b52UzaSjTvLm/jJCdkYqZf4SFuBgLHF/rEALQ1vBqDiKQ7QxuWz5ApPm' + sLineBreak +
        'P0ntscETngWuJ2g2M1EoxGehwNiJJEslYE/CB0Aky1XeUmUAUm++Q3QVfUA3G3C7' + sLineBreak +
        'pP7whQSr1Y7gL44EmttFCX+dX8GWXuZDXa399wijphVw+6bl0gp/hWRWriTern1D' + sLineBreak +
        '+/4S78ddrci4slA+/Kkq423wjLNGZtOoy9cXRmFdbQlMfVaeu5U7LmrTQRrgGVM6' + sLineBreak +
        'GQjgNanXYhkCNubQ+v2Q6FflAdri8Ac8ZvFXxSIGZ3JG14cm072vOdp0/rCNkzSb' + sLineBreak +
        'fmtyzXUGgNgKzfp/GFvIXD04lLfeipzlUhNvDK8AKUNIctrMHZegpbfSm6HD6BiV' + sLineBreak +
        'rUFNLvr58WDK0eLeRxg4pFTCf9QXr9Q1v4MWehkn+LOTconhJtRictdlj+G2ymOQ' + sLineBreak +
        'LYgSRPPdXVNxlBI6u5WRtMxzZM6G3N8jkEvFfFsyeMtE+R0OsXiIwvGzdksnI/1F' + sLineBreak +
        'deQJzav9uMBj4A0bJuMQ3Ls8ydZNFU2RDofSU84bP/g6TzU8MpT7QXQXPD2jKdLp' + sLineBreak +
        'JouxtbRw+YY+9p0sk5PFYxti+T17jZN//pqiBrZUzvspwr5sWoa8BbA3bWE2gnXT' + sLineBreak +
        'cmx98wREJ3wWRx+t0k44084kD5/cvVH7MsAQ75XxGa0ofVj3crMCL29c+/QaUnhR' + sLineBreak +
        'GrdJ0sVJeIthiOQZZ5zBqG+IhJfG/jkKpweA9fkQ5gm+FoasTfDnAdSJjah7WfoO' + sLineBreak +
        'C6LKzNBB1FaOHqy4X6LUN5wraEOP+0OI3hKPdOB47yUzPF6FGneGk4BajDHG4RyT' + sLineBreak +
        'F2ZnG1aa+FRfakQ6l7ok4j+VPtDlCPY2jnT7muj2F78G69abNOS7ASXg5+PJzso0' + sLineBreak +
        'liaWo1d8TDfEazlDQvglDAKpzYw2mSbpJVmmbPSaVZxUARcIIaBqxu6xWepfdN8v' + sLineBreak +
        'qZGrOp7vTOuGu8f2YmWKd3+lcNm2CwwGYIPpuTFjtUuF7guKEdTffyj5tpOdo942' + sLineBreak +
        'RAy/F3tCy5zfZrI8SkSkx+wfZAnkUnI3xQNdKKVLCXcpBtQWht2UGO1G9W84OmFy' + sLineBreak +
        'eg21zeITIwPJZfUif9WHihdINSlfm0CiS+gDRzXukS4HgniPfS3NPo6HAepc2Gzr' + sLineBreak +
        'QUGF/ENern3v85DCEE/AebRaQN7liM+6Z55UZ4GOT3Tj64+Nth7MNQXqBYEmCS8P' + sLineBreak +
        'ndWvlalOs+vlj2Rl13IcSUOK8OOr6S7jeZhoutej1b4lbw8RwYBXGg==' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaBlowfishEcbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: BF-ECB,1E15270A7DD42BA2' + sLineBreak +
        '' + sLineBreak +
        'zz3p7Ml80hSdlJsI5RyvOScQlsGC1GLg3AK0dC/Hh0IKPTDF7a2OITL6H/y/3txz' + sLineBreak +
        'LJ6jAcobjRfVMWGAJUwFaSlE5QF5W1+RauV+M8oMmv+Mf2K/Urha6m63EauLEVWu' + sLineBreak +
        'IDtxj74qfQgyd//qWHU+XmWhhNEGk5MrH163VITZqpG3Qe9dYHdalh4TB/ILJqfN' + sLineBreak +
        'URKLjdz8L4YbL48dwK6UxargixQ3tfrvIdTr4mkMiquNlayTk9g5qXWnEXy+I1DB' + sLineBreak +
        'HweXveJeSUHhYRXdx37y2I8Bz8HcuZF5wODEDJJuYXy7a8Q+Ar0Ll/uQ4NXE3iI0' + sLineBreak +
        'NA8RA0caAlc+Du/xfzKdUgIPQaLt/sjhM4gPBDLlASUmO+PJfb1VYgDIbNbXiR9x' + sLineBreak +
        '92ePzennPnbhKsPcuZzXoc/jH2BiQwwRT2gLscZ86n9O1FNoaPAnYERlyNIVrQoC' + sLineBreak +
        '0Ll6NnGBM9Ls5k1royQQtZU2x5Yu5Q7DGcNqX2yI14AZrI4e9/Y0nEa+17WRD6eO' + sLineBreak +
        'fdaIC5dVrv8HZxlfzwFs33FpufovP2vlINWM3IqDjMf4FIQsoLdnmTsgoLRYm4JK' + sLineBreak +
        'zfcyiImXPt2iUrcybZHKa0EXYjrcoIVBS8YP1UTcG8WHnj3ploMxXOw0AmpXcznf' + sLineBreak +
        'sbLsaehbs4ugM5G358PMeWFXTv8K2YXRtArXHtkIYzA45zqWzpta5E7LiTQJfBRL' + sLineBreak +
        'VNtLja40a0gaajvROCekEzWhezZc7bu6RQ/XZXxBYHx9m7nhzKRkDlBrrJVpWSW7' + sLineBreak +
        'QmS0ptXblyt2tbaUtNLsi2SP7gP9ggTlc5hCpwygT+lxrcr6j18CiPgMYOgDmFY7' + sLineBreak +
        'gZ3jZ+HHd2+8GnimOai+r8wh1aW06/tLfIZxpIn4T9yGh/EMW/R1RTJjN0xe6oqw' + sLineBreak +
        'wC+TPUM2bMvDtAvdn8bYh3pVVLXnFa6LjhhgNvnx6wBoiBCJ4E9R1Ec0QA4jF/97' + sLineBreak +
        'B4e8TEv7PAFB+VGhIPnQqfsAqRfM88FwgZqSfZrBXKMVWA7I4fBeVD0cJQq8TwCz' + sLineBreak +
        'TY9Fi1YnomqTfacH1hf9KiX3j8OkfrhIM3+w26nE553/wOcO42YJ55NgnNXlQL2e' + sLineBreak +
        'e1s4uJ9lroATY2WqvgLy5Th8n5y6kVkjuODb/8hk3KXqiLqbUOmZCYLuT4ZHZ+Rk' + sLineBreak +
        'xtWuFpmFiuWgbg6Nr2t2KYXwD39pjGBRmmwMX1mBxmUD9NK28yO4HEgiPVzfn7sU' + sLineBreak +
        '1PWC7HpgPf797M2/N1gyUfrBbfw4OXWpycvmtJLXHEJi/p/H1bz0MuMJvPtNhzUO' + sLineBreak +
        'CP4jq0xbu9nT5eW9rD7kgvv10W+aUf314RcWKaLkOxkk2dTENjbviASce5X3ZU4l' + sLineBreak +
        'eGG2wtoHvCvHnNVj2ImKf0jbAL7dymVJlA1XwsLANAmk+9RGyVJgHn7ZkOfRVJmW' + sLineBreak +
        'VMfZ6AVeFY5BeJ0LCq1uE6QMClVx8fLN2iBEqamBNekcZ62Qz3b1R7ZbN2tlPKee' + sLineBreak +
        'JnLSooju6Mu8U9twVI2tr63OTh/a0XAjtlO0OAXuVcOmYOHT9fSjPdAAt3Rp50Sj' + sLineBreak +
        'PDvgN8s+qSkQKpx7C2OA9Wisrr71UrBrCfBhCOmN5gyWFg24PwwRKUnc1a8mT5Zx' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      RsaBlowfishOfbPem =
        '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak +
        'Proc-Type: 4,ENCRYPTED' + sLineBreak +
        'DEK-Info: BF-OFB,B9F95E282FEAA06D' + sLineBreak +
        '' + sLineBreak +
        'StEkcUPp3txNaJlYBP+eVabWYcEzAkX64aj8vaDX64i7bVl4ospAs2stac7uXtXG' + sLineBreak +
        'IZLTqNNACoqC0jWWTDJca9vTEoqjDRKjN9yjXYfrovj5oKi79wfsSU29oH1dcKG8' + sLineBreak +
        'G4y8qNsA9TexRQDWTBxYO6EiQFVie9O3oXzjhO1hYwxldSWOV5ZRWoVmg16vAOxX' + sLineBreak +
        'Gx2W1twtjQXG/hp0HxosPkZteUDdhMZLWonYuqEw1oBC4iDG1Tjp0p5uSnb1gaIr' + sLineBreak +
        'pzZScikP0Z4/8CxiKV9/C1VNE70EHdAUYKjUx2PAbPaMFyO/sAXOy1INI7Wis7jh' + sLineBreak +
        'U2wKeXgCMRxmca4OMITcjDp6OGmKf41uWyTFwjO1scMvjSJsOZxNjAjcrZW1PPRA' + sLineBreak +
        'tvnhRpU9h1G9BOH2rM7VUI6zJ2FSNKG9R6M0WOQqxRegJzvK+YNLhw5lUzrbWOR0' + sLineBreak +
        'RdkKL15gfnuXqLTDTMuLX+aCDS1Mu/ZRmDqLWkJH4W1HJ4l2rBojX5fcbamueMyf' + sLineBreak +
        'Sbd1S7QtmF/B9LaGDEPMT12kOQHZkRBUYpyolK6BoMuRPYnGS0RkUwvIuPZA8uJU' + sLineBreak +
        'vHHuYRZsOA45YFEipyB/sek61bvqYy+8TaPxzpfj0fkh7AUSQmbk3qQRkQbltzqq' + sLineBreak +
        '/MkFShIzS7SUkyiowOet8fVjXDJPsw2bS3uOHC4zy2QQmhVKzCYWd4yCFl+WtJnZ' + sLineBreak +
        'eEkrZH2BpoCDEzKlex/NQlH9KBLOor221nJEVd5tkdWWZt71eGld20eFL3ewtDqV' + sLineBreak +
        'GJX8jFmR51vQL6NZ2Ehp/5zhearuBJ8VKJfFxIKSrbPjyCbEwUgYOyVHHyvYyMR/' + sLineBreak +
        '6hcflrUu1IFFwFhryg2bucAkdX9AhsO1dimxSgZKEFlZbihPBysCdUw3WRea57iS' + sLineBreak +
        'n/zqLrOm786KiWh0ndBgJ973g1x+OeuUvbNl/0yiO4Vjny6PkXcBOORu+ILEflzf' + sLineBreak +
        'UiEKyG8+cYzoYZjeiCFBxsA2+gZMdgjxVYF/lKzTqFkfpwYV+tF2K5N8W51cL8Is' + sLineBreak +
        'yhz5OHiENobjx3QeFCZ4LWDEXg1H8cA34i9oELbXtyG7W+hkZp0B9tRDrXcDwVWk' + sLineBreak +
        '4oYqWLNCQXqr1lL6cCuctKLdXbc1ibLt1nYGpJrPkPCbOshsI+iCMmulT23s+jqW' + sLineBreak +
        'TMW0RNb3wFjR5z9A1YTWfiqMKEcyzRhP6bEM/+WNmHE5LRefx+dnvZrVJzGZA/3k' + sLineBreak +
        'JAOpsxEPKv7YNR8N9yoAopRfFEOH4HYtLbsAA2sZfD6iVAXAAeiZ2Ehn+Bvek5lV' + sLineBreak +
        '5zIOtsXswRgzXvxXCPy0V5GWqMglbkUS2HGsWaHpxDSMbvBJuaSi2blZ16p3IICM' + sLineBreak +
        '7YcCLolKUaWqpXjhb3UypoYRwJs+40EiXid7aJ8rKoeId1SeETOwVWkz95NMiVK9' + sLineBreak +
        '5K37/OMvxOAdjAUxtmz/+v+twKfrUhYqP3Qkapy6FgA+qxnzpCFZZXrMKjpr99Pc' + sLineBreak +
        'QVNcvM/SKWB34jZGTo+Styc7d+iXDC1BUS/43Pvbka/Aa2IV/LPQA2pD44aP5l3V' + sLineBreak +
        '/tOfQFQWI0wCqpBPV8aXqGuqZU2ES0yc9DJ974a8NvS1cNWfsMcvNg==' + sLineBreak +
        '-----END RSA PRIVATE KEY-----';

      EncKeyPem =
        '-----BEGIN ENCRYPTED PRIVATE KEY-----' + sLineBreak +
        'MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIpII67Pp5Vs8CAggA' + sLineBreak +
        'MB0GCWCGSAFlAwQBKgQQBpkbyKLxdtlBlp6tm6lZoASCBND/h43o5NNNmTXWHN2+' + sLineBreak +
        'N9ncoFknxohgShAc8WHKMHt0SCEJab8E2IAxVkYFMOMpvi1KVldcveLlg7hcMIDm' + sLineBreak +
        '74pJmvXOW6b0bENvPMOxFadzr9NjO7j5ZT81dwNLz2pBLyiUMYElWl0LVnxKThQF' + sLineBreak +
        'qijJTDPcmTpFwDiUyTxzHxMx4DsoFYQulRBsZbRCAjsFpPM+OrOekSAyQHKMSbHU' + sLineBreak +
        'LvcdWCrSDRtKOyCeCPbBA4OzPJFyzep6trhbQii6rkddf9o54/oJut+LMuUblrHE' + sLineBreak +
        '2yMStfW0G5ZyI7AeOxAy1gKG/CQrvFHn/yhtyjkvPa0sYVGtR4pGew+cs9iIsdFk' + sLineBreak +
        'nXOf9frJMA2agQZKc4+rf66NPv+dxVecm40HIR3omk7EnxR8s6msXOOn4qnY7qae' + sLineBreak +
        'aq1M7pKNqCu6eW5560mW6buLpOkpm/kDbr4v9rfCX41b5rIRzOdfAt71FSJcHp6K' + sLineBreak +
        'FNojK86YsNJWYh9pnfDbjEk7346cCIeJVgICGTmL8Tg6TUy9wIB6eKUXmIG3fKjI' + sLineBreak +
        'Ep8OzYAU3/ae8vdmZqD12l3v75muRPs4bP1RdjaVrux5Xlq8TkzU21ixWG6Odj7I' + sLineBreak +
        '1jusSUjz16iR29XhLP/HI80GKYQMc2yHWcYQ1YVXyLzhnHYydrqjW5OTKZW01rbe' + sLineBreak +
        '9BC8XlRzKZJ4IOQMfSiZxcdERtImO86Kprl4du7gvWaTUGTyiQ721Q08GfFdVuAn' + sLineBreak +
        'OO/J8stTLv2Ee7ugTeAFA2+qpz2vAo5JIPOmqjNqI2ytPjLRb80B3tSVXT41OodT' + sLineBreak +
        'D4v5YbNpySMDpw2F052Wx37hl2wNxIP98U6aw3ZjJdM/YfLdGOJhdoRTBDAvygRU' + sLineBreak +
        'Di6F56sDvX8bdXDUZURMg+iMx3Noc5G3TB3JpYunm3BL9lwGWesrkDzg3Vs1J/6c' + sLineBreak +
        '4AMhAsw9+5tzvyGEDHnGZRg07K0eyWskDK0/Qb+vjSLOj8+QphM+EPCmugNnXRNo' + sLineBreak +
        'AdslIFoVfrcKruS1/DeSIesXvMd7sj2RH/xYDcAIGzmwbc+Ki4JTPuoZlF3pGMYE' + sLineBreak +
        'YkkYj2KHjJeX7CeUjCmU9Y7/jHp+fzlKsQAMQLVm8bRjDpvLA84RDJRoCPav333F' + sLineBreak +
        'YqRciZzMjfx2f6AJTCT+/8nv+DBiWcRtab1u6f+p1iDUa8bVt0Y8PB71gwAyonmY' + sLineBreak +
        'gp4A3fSilIlKEGsP2Hb4aU9V5vy1EZT0K0PuAY4yxGPmhedLCKdBqOuwQBxsLDP2' + sLineBreak +
        'YmXR5wQOsI0dVE8zogpgOGOEE9RXNAf7QV7pBOPNu4HQLNuZi22dKi+wkyMLsIR5' + sLineBreak +
        'dGEz7uDIaGQMvlprtOA02RON3gBnQTJAp7E/YMd7OldSBShRRGeIDw7yTrLoHwLI' + sLineBreak +
        'YnA5+ZwFLBPnOrnBC47CwgB2X/+ooL8/+yigoajZIIE5RvzuKRQGjC/ZgSHXSHrt' + sLineBreak +
        'mJKGerOR/3+OYYCTctTa3wTPVRc/vB1hZac9OPmnKpeywCJ4Q+jX+ZOhHOM671H6' + sLineBreak +
        'h9fLPd0tSE75gIkSuJqBuLV2TB1cp7BTnrZxLywCxC779lZBTVLctXu60kiIoW46' + sLineBreak +
        'zgEz1dyf22vfMN5ss0ybvBVCl8ROmrVr8ZWObzkj1MUyifDM8Tayd3uZ3SdHPo8L' + sLineBreak +
        '2G24+4bjyVdFjUvrBdzB5dNzAQ==' + sLineBreak +
        '-----END ENCRYPTED PRIVATE KEY-----';

      Pkcs8UnencryptedPem =
        '-----BEGIN PRIVATE KEY-----' + sLineBreak +
        'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBvYyk4LsBVS3S' + sLineBreak +
        '34GZc8uuddHq7cUJx1lZaxWK7C6nnTNKJmJEhxW80VIukpo2RODL1hPFlgCJY3ch' + sLineBreak +
        '/4437UoG8ZNAE1BfuVMIkS1AX/l/KAyqUIX/bsXgvZch0Joo92KaPfDB7QA8VCGd' + sLineBreak +
        'NCcRaOnusDdsFDdF4/Mrd7/x+Ipkd56FXVEk14QGizFc86aNJrzXjy9ent34PTcS' + sLineBreak +
        'uGPXUX7pbiZj8gK9f77pDuH+JymqXdfBKz/x0T54i8N4QFfVp2LbGzeRnduaX4Ff' + sLineBreak +
        '79ikdo/XQYTPOYoDwgdiAR+n0+mvDNkI5rbukSLcz+xbWdkJ1ReHW/QQAiqQWK37' + sLineBreak +
        '4D1fFNrZAgMBAAECggEAGbH+GVAE/WRCs5kZIzUMapMNyE7It0dNPmLJdKdmeKyM' + sLineBreak +
        'xOTaW6Re6bAJakvfUBtKhT5bWPVQFOiwQD4Yqqo6Czm3AeSN4GQ/8v7uNX+FI6w4' + sLineBreak +
        'Ic6UNxCGBgyfIsj76TsGRNa6O74nLdkqrCLim5iCjjmo4Bi+S/Kzqaw0NO91y2Um' + sLineBreak +
        '9XyCzM7Oh4LukmF94pd5gZBQjjVEkEsw3+oQlOznm3rCNIhYSjfStnFZT5stvcIw' + sLineBreak +
        'BscQg386Wo+UvXV8zDI0qrAi0pNepVGsdpGGGUIHkogaF9HHElcSIAVBOQLhxvf5' + sLineBreak +
        'S27j3bvHBzWmmR/MgOsBH5+ZqQCTzVGJdzIzXkCRUQKBgQDkQIQNsRv0V44UriNr' + sLineBreak +
        'nageBkbjVFxczl5k2qN193qb0GalSOoeKcT9jsBO32mcaBd84vuueSNS69rGlj8+' + sLineBreak +
        '7rKyMsRAnjhbMJ0FCWv2muQjxZWEcTWV38wgXkbzos4fon19wQo3JPg0ikOjmGbK' + sLineBreak +
        'Z4EIJE0PIw6hjGrTXqc9wK4kgwKBgQDZSv2KVaTX80ZyLIOlbs5+CTAzlEde8+u+' + sLineBreak +
        '7LcFOvrrzeo86i6+65yvu395Dlm6PAhz0KocaUECeEDakdQHEDfvEf29BsU+p7fU' + sLineBreak +
        'kfNPotacAD7kNo2WenzH0mIhtBWchSUz1P3cIbq4Rxm4XPlAzMEXcDtFRqf+4wVV' + sLineBreak +
        'd8Thcjl8cwKBgQCKVGczfRC6Bo3/DoI86DFI8PjpMOlA/XjLmo3SIofWAnkS1pu8' + sLineBreak +
        'aAgQuwDlTBTPS25gq5doZ9X2nSXbkJcH5tW5lXbGypzQ9ydSNCGQNNLqswYoXAvj' + sLineBreak +
        'ptwpCbnqUdKl7W4sVl+AiBE8lkbj0KsLI6tZadahw9dMJLNhIk4s6KchTQKBgB4f' + sLineBreak +
        'PCh6GODq04AuVY2QX8WvBmSQEJjEHZEZBYIPHAumPut010gWJ2FhD5m7eIrNmapc' + sLineBreak +
        'aciIer+Z5fumrYrRH7/fcZpLnvpBi8VG+kC25SM5EX7XZSdQEY4txva/HSPWfULD' + sLineBreak +
        'KvHiJx02lgUttkvaVoYmQ8Elu1IlLG8drEhIalmrAoGAKLjcIIAcAhuE0QkstS/z' + sLineBreak +
        'ZiFhp7tCCrH5sVvXPJfxuKtEC3iTfgOoMywaX3SQGkOP5kVngziGemv1b493Vmek' + sLineBreak +
        'T8JLbnNbkooCvPsbMlMgcqZcb/5ckymabMaJBTqhYP4w/uRETNyjmb0uxX2CqXk0' + sLineBreak +
        'RoIdgWsw0IiLCNMn16z5O5w=' + sLineBreak +
        '-----END PRIVATE KEY-----';

      Pkcs8Aes256EncryptedPem =
        '-----BEGIN ENCRYPTED PRIVATE KEY-----' + sLineBreak +
        'MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIGQp1RhqLV50CAggA' + sLineBreak +
        'MB0GCWCGSAFlAwQBAgQQhMfC5lWjUndHWVmSgLGLMgSCBNBZEZlGvXV9XjzWo0di' + sLineBreak +
        'IJof42XSh+mrOdRvUPUS0uPzctmnXZjhKdu42v5jrbyNdruqZsMXTnnQC/UW7Fox' + sLineBreak +
        'fp3JzOM5w7wEmgrJybOZgA5spNkiWDdlnmqKme34wEPKv+GPEuHj7w+Z4hc7MSdg' + sLineBreak +
        'T6Q3CJFLJDCEvfK70Gyxp6X90HN1riQQVxFOTSg9TJsnsvkOJ9Ju3VCTOqt3jlW0' + sLineBreak +
        'FEzrC3lV4AcxfWZct7tkqOTXygWMGinz7OqLxIcmlrF3oc0bLxEQzQuGCJIzrhKo' + sLineBreak +
        '3Lb73Xto/kC/uqbCdU+v1zafdKLI/0Uj3/GOGLUu/PeMo7VaHbAj/AOX63Yvj3zm' + sLineBreak +
        'WOgJwnOis5iP5rqL3lfdeJrkmE1w7xTLn9fUWXXr+qcVBLeZY30TE9wW9gRCDCka' + sLineBreak +
        '09ZVw9MnrodTgvWVSI3xHxjYin8GcxQ+VZTxQMQFHA2cyR60yMG+eGm5t3TZNHVW' + sLineBreak +
        'h3uqVxjbN7tMYbjUo1NdbINntOQZhqMje39ai3mWIhGPO09yfsw7ZRX9hhKlrIYo' + sLineBreak +
        'UQ4LcEgMZsZDDtAY+Mol7pYB7KpM2iftBT8KSkBLSlqpndl4PJHLUaNBgbNDP6py' + sLineBreak +
        'PB8FjPO49qPybeVCIgg3AswxJwGE9bXtO9SLcf/p6S0IWvVcWn+VV5sX+9Bav0eZ' + sLineBreak +
        'nCO0WJYrWcjUBzYJLWIDcPviYkoMkFrsFGUP0DA7OneLlW84YUh3AeqqJppb/qve' + sLineBreak +
        'UeUXZipLEHf+Z/ToGW+RzPQmFTVDqIx0FdQCi3EefBr3CbN/KtLdRjbP4kyeRGlw' + sLineBreak +
        'CUS+BWQ+W/NtVUfVmBvsSLtVfW1pevemt4FE9rP9qUa8KeRpOJIzF4kHUmHyDfp6' + sLineBreak +
        'rvQTSS6d3a+N1GyJA5/N4UM6g7FbVnbngPvM1hMNfK6xbIcxQJudBQa/bHqf8DXu' + sLineBreak +
        '61npKQYir+TmgDXlc9iD23M+TH2VgeunrFKuVMNVl4igH3+mcHyXpZ/EGM0KyIhq' + sLineBreak +
        'PJjPRKD0qcCvs4mPRiOx1wJbCYMdYfEF7sIlkQgKjbQZQyRlDKLkLl4pGWXxaqUm' + sLineBreak +
        'iyo6VpK2phKcA/hPYz10isRfy1WrKdNHW0B5DPyreko2H0akapfqMjROE0JHtVGs' + sLineBreak +
        'gKg0FrbZXUP+QuKm0V91ShA7c3mRfN2XNbxEc9JFzkDJs4JBxj2H7MxvPQyRrWE3' + sLineBreak +
        'sKsQWtr5AFpFb5p5kqCtyyu7ag9pGicqlaFuLda/PR0ykMrhMU4RBO0OulOGl8ZP' + sLineBreak +
        '9RC1GCArbSSUYH9xvwthGdaDylONVmHwunFMHs8pblTyo6FiKn1q7lIVXYO3AJ/5' + sLineBreak +
        'NfKgryp50SXq0p41i8Dtu+4R6CKx4xTMilPYKYDiDPCRtnwvckI/PshGMA/CHLzr' + sLineBreak +
        'LLZUlRt1iup5SDjqRIjquw/aDRe+Wy4AXXniHOnlSrNynHcJRWz+pnLT3Bi6Z2nQ' + sLineBreak +
        'ERY4pCIQ/ZdhAHHldFZ7WJ2wrwhf4MQ7sF20HLgXeUN3qj4xYcwR3CykU8f7dfI7' + sLineBreak +
        'TIo26asqsVDsVL02tr4dUrtm4J8yQsH8jD0nCpvGwJ9gswUBPmo9YreN82Kt/LSy' + sLineBreak +
        'YZISyo2BnoowEcAEGnZBf+PLwBeePeXC2/vrxHlMl7JPkPesEHtTuET034woXELi' + sLineBreak +
        'wO/DuStXmiIydT29G1n81zmdVw==' + sLineBreak +
        '-----END ENCRYPTED PRIVATE KEY-----';

  strict private
    function CreatePemReader(AStream: TStringStream): IOpenSslPemReader;
    function CreatePemWriter(AStream: TStringStream): IOpenSslPemWriter;
    procedure KeyPairTest(const AName: string; const APair: IAsymmetricCipherKeyPair);
    procedure DoOpenSslTestData(const APemData: string; AExpectDsa: Boolean);
    procedure DoOpenSslEncryptedTestData(const APemData, APassword: string; AExpectDsa: Boolean);
    procedure DoOpenSslDsaModesTest(const ABaseName: string);
    procedure DoOpenSslRsaModesTest(const ABaseName: string);
    procedure DoOpenSslTests(const ABaseName: string);
  published
    procedure TestPkcs7EnvelopedData;
    procedure TestKeyPairRsaRoundTrip;
    procedure TestKeyPairDsaRoundTrip;
    procedure TestPkcs7RoundTrip;
    procedure TestEcParametersRoundTrip;
    procedure TestOpenSslDsaUnencrypted;
    procedure TestOpenSslRsaUnencrypted;
    procedure TestOpenSslAes128;
    procedure TestOpenSslAes192;
    procedure TestOpenSslAes256;
    procedure TestOpenSslBlowfish;
    procedure TestEncryptedPrivateKey;
    procedure TestPkcs8;
  end;

implementation

{ TTestOpenSslPassword }

constructor TTestOpenSslPassword.Create(const APassword: String);
begin
  inherited Create();
  FPassword := TConverters.ConvertStringToCharArray(APassword);
end;

function TTestOpenSslPassword.GetPassword(): TCryptoLibCharArray;
begin
  Result := System.Copy(FPassword);
end;

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
      Check(LReadVal.TryGetAsType<IAsymmetricKeyParameter>(LPubK), 'Should be public key');
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
      Check(LReadVal.TryGetAsType<IAsymmetricCipherKeyPair>(LReadPair), 'Should be key pair');
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
    Check(LVal.TryGetAsType<IAsymmetricCipherKeyPair>(LKp), 'Should be key pair');
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
    Check(LVal.TryGetAsType<ICmsContentInfo>(LCmsContent), 'Should be CmsContentInfo');
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
    Check(LVal.TryGetAsType<ICmsContentInfo>(LCmsContent), 'Should be CmsContentInfo');
    Check(LCmsContent <> nil, 'ContentInfo should not be nil');

    LOutStream := TStringStream.Create('', TEncoding.ASCII);
    try
      LWriter := CreatePemWriter(LOutStream);
      LWriter.WriteObject(TValue.From<ICmsContentInfo>(LCmsContent));
      LReader2 := CreatePemReader(LOutStream);
      LVal2 := LReader2.ReadObject();
      Check(LVal2.TryGetAsType<ICmsContentInfo>(LCmsContent2), 'Read back should be CmsContentInfo');
      Check(LCmsContent2.ContentType.Equals(TCmsObjectIdentifiers.EnvelopedData),
        'failed envelopedData recode check');
    finally
      LOutStream.Free;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.TestEcParametersRoundTrip;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LX962Params: IX962Parameters;
  LOid: IDerObjectIdentifier;
  LVal2: TValue;
  LKp: IAsymmetricCipherKeyPair;
  LWriter: IOpenSslPemWriter;
  LOutStream: TStringStream;
  LInStream: TStringStream;
  LReader2: IOpenSslPemReader;
  LVal3: TValue;
  LX962Params2: IX962Parameters;
  LOid2: IDerObjectIdentifier;
  LVal4: TValue;
  LKp2: IAsymmetricCipherKeyPair;
begin
  LStream := TStringStream.Create(EcParametersWithPrivateKeyPem, TEncoding.ASCII);
  try
    LReader := CreatePemReader(LStream);

    // First object: EC PARAMETERS
    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'First ReadObject should return EC PARAMETERS');
    Check(LVal.TryGetAsType<IX962Parameters>(LX962Params), 'First should be IX962Parameters');
    Check(LX962Params <> nil, 'EC PARAMETERS (X962Parameters) should not be nil');
    Check(LX962Params.IsNamedCurve, 'EC PARAMETERS should be a named curve');
    LOid := LX962Params.Parameters as IDerObjectIdentifier;
    Check(LOid.Equals(TX9ObjectIdentifiers.Prime256v1), 'EC PARAMETERS should be prime256v1');

    // Second object: EC PRIVATE KEY
    LVal2 := LReader.ReadObject();
    Check(not LVal2.IsEmpty, 'Second ReadObject should return EC PRIVATE KEY');
    Check(LVal2.TryGetAsType<IAsymmetricCipherKeyPair>(LKp), 'Second should be IAsymmetricCipherKeyPair');
    Check(LKp <> nil, 'EC key pair should not be nil');

    // Write roundtrip
    LOutStream := TStringStream.Create('', TEncoding.ASCII);
    try
      LWriter := CreatePemWriter(LOutStream);
      LWriter.WriteObject(TValue.From<IX962Parameters>(LX962Params));
      LWriter.WriteObject(TValue.From<IAsymmetricCipherKeyPair>(LKp));

      // Read back
      LInStream := TStringStream.Create(LOutStream.DataString, TEncoding.ASCII);
      try
        LReader2 := CreatePemReader(LInStream);

        LVal3 := LReader2.ReadObject();
        Check(not LVal3.IsEmpty, 'Roundtrip first ReadObject should return EC PARAMETERS');
        Check(LVal3.TryGetAsType<IX962Parameters>(LX962Params2), 'Roundtrip first should be IX962Parameters');
        Check(LX962Params2.IsNamedCurve, 'Roundtrip EC PARAMETERS should be a named curve');
        LOid2 := LX962Params2.Parameters as IDerObjectIdentifier;
        Check(LOid2.Equals(TX9ObjectIdentifiers.Prime256v1), 'Roundtrip EC PARAMETERS should be prime256v1');

        LVal4 := LReader2.ReadObject();
        Check(not LVal4.IsEmpty, 'Roundtrip second ReadObject should return EC PRIVATE KEY');
        Check(LVal4.TryGetAsType<IAsymmetricCipherKeyPair>(LKp2), 'Roundtrip second should be IAsymmetricCipherKeyPair');
        Check(LKp2.Private.Equals(LKp.Private), 'Roundtrip EC private key should match');
        Check(LKp2.Public.Equals(LKp.Public), 'Roundtrip EC public key should match');
      finally
        LInStream.Free;
      end;
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

procedure TOpenSslReaderTest.DoOpenSslEncryptedTestData(const APemData, APassword: string;
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
    LReader := TOpenSslPemReader.Create(LStream, TTestOpenSslPassword.Create(APassword) as IOpenSslPasswordFinder);
    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'ReadObject should return key');
    Check(LVal.TryGetAsType<IAsymmetricCipherKeyPair>(LKp), 'Should be key pair');
    Check(LKp <> nil, 'Didn''t find OpenSSL key');
    if AExpectDsa then
      Check(Supports(LKp.Private, IDsaPrivateKeyParameters, LDummy), 'Returned key not DSA private')
    else
      Check(Supports(LKp.Private, IRsaPrivateCrtKeyParameters, LDummy), 'Returned key not RSA private');
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.DoOpenSslDsaModesTest(const ABaseName: string);
var
  LDsaPems: array[0..3] of string;
begin
  if ABaseName = 'aes128' then
  begin
    LDsaPems[0] := DsaAes128CbcPem;
    LDsaPems[1] := DsaAes128CfbPem;
    LDsaPems[2] := DsaAes128EcbPem;
    LDsaPems[3] := DsaAes128OfbPem;
  end
  else if ABaseName = 'aes192' then
  begin
    LDsaPems[0] := DsaAes192CbcPem;
    LDsaPems[1] := DsaAes192CfbPem;
    LDsaPems[2] := DsaAes192EcbPem;
    LDsaPems[3] := DsaAes192OfbPem;
  end
  else if ABaseName = 'aes256' then
  begin
    LDsaPems[0] := DsaAes256CbcPem;
    LDsaPems[1] := DsaAes256CfbPem;
    LDsaPems[2] := DsaAes256EcbPem;
    LDsaPems[3] := DsaAes256OfbPem;
  end
  else if ABaseName = 'blowfish' then
  begin
    LDsaPems[0] := DsaBlowfishCbcPem;
    LDsaPems[1] := DsaBlowfishCfbPem;
    LDsaPems[2] := DsaBlowfishEcbPem;
    LDsaPems[3] := DsaBlowfishOfbPem;
  end;

  DoOpenSslEncryptedTestData(LDsaPems[0], 'changeit', True);
  DoOpenSslEncryptedTestData(LDsaPems[1], 'changeit', True);
  DoOpenSslEncryptedTestData(LDsaPems[2], 'changeit', True);
  DoOpenSslEncryptedTestData(LDsaPems[3], 'changeit', True);
end;

procedure TOpenSslReaderTest.DoOpenSslRsaModesTest(const ABaseName: string);
var
  LRsaPems: array[0..3] of string;
begin
  if ABaseName = 'aes128' then
  begin
    LRsaPems[0] := RsaAes128CbcPem;
    LRsaPems[1] := RsaAes128CfbPem;
    LRsaPems[2] := RsaAes128EcbPem;
    LRsaPems[3] := RsaAes128OfbPem;
  end
  else if ABaseName = 'aes192' then
  begin
    LRsaPems[0] := RsaAes192CbcPem;
    LRsaPems[1] := RsaAes192CfbPem;
    LRsaPems[2] := RsaAes192EcbPem;
    LRsaPems[3] := RsaAes192OfbPem;
  end
  else if ABaseName = 'aes256' then
  begin
    LRsaPems[0] := RsaAes256CbcPem;
    LRsaPems[1] := RsaAes256CfbPem;
    LRsaPems[2] := RsaAes256EcbPem;
    LRsaPems[3] := RsaAes256OfbPem;
  end
  else if ABaseName = 'blowfish' then
  begin
    LRsaPems[0] := RsaBlowfishCbcPem;
    LRsaPems[1] := RsaBlowfishCfbPem;
    LRsaPems[2] := RsaBlowfishEcbPem;
    LRsaPems[3] := RsaBlowfishOfbPem;
  end;

  DoOpenSslEncryptedTestData(LRsaPems[0], 'changeit', False);
  DoOpenSslEncryptedTestData(LRsaPems[1], 'changeit', False);
  DoOpenSslEncryptedTestData(LRsaPems[2], 'changeit', False);
  DoOpenSslEncryptedTestData(LRsaPems[3], 'changeit', False);
end;

procedure TOpenSslReaderTest.DoOpenSslTests(const ABaseName: string);
begin
  DoOpenSslDsaModesTest(ABaseName);
  DoOpenSslRsaModesTest(ABaseName);
end;

procedure TOpenSslReaderTest.TestOpenSslAes128;
begin
  DoOpenSslTests('aes128');
end;

procedure TOpenSslReaderTest.TestOpenSslAes192;
begin
  DoOpenSslTests('aes192');
end;

procedure TOpenSslReaderTest.TestOpenSslAes256;
begin
  DoOpenSslTests('aes256');
end;

procedure TOpenSslReaderTest.TestOpenSslBlowfish;
begin
  DoOpenSslTests('blowfish');
end;

procedure TOpenSslReaderTest.TestEncryptedPrivateKey;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LPrivKey: IAsymmetricKeyParameter;
  LRsaKey: IRsaPrivateCrtKeyParameters;
begin
  LStream := TStringStream.Create(EncKeyPem, TEncoding.ASCII);
  try
    LReader := TOpenSslPemReader.Create(LStream, TTestOpenSslPassword.Create('password') as IOpenSslPasswordFinder);
    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'ReadObject should return key');
    Check(LVal.TryGetAsType<IAsymmetricKeyParameter>(LPrivKey), 'Should be IAsymmetricKeyParameter');
    Check(Supports(LPrivKey, IRsaPrivateCrtKeyParameters, LRsaKey),
      'Should be RSA private CRT key');
    Check(LRsaKey.PublicExponent.Equals(TBigInteger.Create('10001', 16)),
      'decryption of private key data check failed');
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.TestPkcs8;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LPrivKey: IAsymmetricKeyParameter;
  LRsaKey: IRsaPrivateCrtKeyParameters;
  LPemData: string;
begin
  LPemData := Pkcs8UnencryptedPem + sLineBreak + Pkcs8Aes256EncryptedPem;
  LStream := TStringStream.Create(LPemData, TEncoding.ASCII);
  try
    LReader := TOpenSslPemReader.Create(LStream, TTestOpenSslPassword.Create('password') as IOpenSslPasswordFinder);

    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'First ReadObject should return key');
    Check(LVal.TryGetAsType<IAsymmetricKeyParameter>(LPrivKey), 'First should be IAsymmetricKeyParameter');
    Check(Supports(LPrivKey, IRsaPrivateCrtKeyParameters, LRsaKey),
      'First should be RSA private CRT key');
    Check(LRsaKey.PublicExponent.Equals(TBigInteger.Create('10001', 16)),
      'First key decryption check failed');

    LPrivKey := nil;

    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'Second ReadObject should return key');
    Check(LVal.TryGetAsType<IAsymmetricKeyParameter>(LPrivKey), 'Second should be IAsymmetricKeyParameter');
    Check(Supports(LPrivKey, IRsaPrivateCrtKeyParameters, LRsaKey),
      'Second should be RSA private CRT key');
    Check(LRsaKey.PublicExponent.Equals(TBigInteger.Create('10001', 16)),
      'Second key decryption check failed');
  finally
    LStream.Free;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TOpenSslReaderTest);
{$ELSE}
RegisterTest(TOpenSslReaderTest.Suite);
{$ENDIF FPC}

end.

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

unit ClpParameterUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpIDerObjectIdentifier,
  ClpNistObjectIdentifiers,
  ClpCryptoLibTypes;

resourcestring
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SAlgorithmNotRecognised = 'Algorithm "%s" not Recognised.';

type

  TParameterUtilities = class sealed(TObject)

  strict private
    class var

      Falgorithms: TDictionary<String, String>;

    class procedure AddAlgorithm(const canonicalName: String;
      aliases: array of String); static;

    class constructor CreateParameterUtilities();
    class destructor DestroyParameterUtilities();

  public
    class function GetCanonicalAlgorithmName(const algorithm: String): String;
      static; inline;
    class function CreateKeyParameter(const algOid: IDerObjectIdentifier;
      keyBytes: TCryptoLibByteArray): IKeyParameter; overload; static; inline;

    class function CreateKeyParameter(const algorithm: String;
      keyBytes: TCryptoLibByteArray): IKeyParameter; overload; static; inline;

    class function CreateKeyParameter(const algOid: IDerObjectIdentifier;
      keyBytes: TCryptoLibByteArray; offset, length: Int32): IKeyParameter;
      overload; static; inline;

    class function CreateKeyParameter(const algorithm: String;
      keyBytes: TCryptoLibByteArray; offset, length: Int32): IKeyParameter;
      overload; static;

    class procedure Boot(); static;

  end;

implementation

{ TParameterUtilities }

class procedure TParameterUtilities.AddAlgorithm(const canonicalName: String;
  aliases: array of String);
var
  alias: string;
begin
  Falgorithms.Add(canonicalName, canonicalName);
  for alias in aliases do
  begin
    Falgorithms.Add(alias, canonicalName);
  end;

end;

class procedure TParameterUtilities.Boot;
begin
  Falgorithms := TDictionary<String, String>.Create();

  TNistObjectIdentifiers.Boot;

  AddAlgorithm('AES', []);

  AddAlgorithm('AES128', ['2.16.840.1.101.3.4.2',
    TNistObjectIdentifiers.IdAes128Cbc.ID]);

  AddAlgorithm('AES192', ['2.16.840.1.101.3.4.22',
    TNistObjectIdentifiers.IdAes192Cbc.ID]);

  AddAlgorithm('AES256', ['2.16.840.1.101.3.4.42',
    TNistObjectIdentifiers.IdAes256Cbc.ID]);

end;

class function TParameterUtilities.GetCanonicalAlgorithmName(const algorithm
  : String): String;
begin
  Falgorithms.TryGetValue(UpperCase(algorithm), result);
end;

class function TParameterUtilities.CreateKeyParameter(const algorithm: String;
  keyBytes: TCryptoLibByteArray): IKeyParameter;
begin
  result := CreateKeyParameter(algorithm, keyBytes, 0, System.length(keyBytes));
end;

class function TParameterUtilities.CreateKeyParameter
  (const algOid: IDerObjectIdentifier; keyBytes: TCryptoLibByteArray)
  : IKeyParameter;
begin
  result := CreateKeyParameter(algOid.ID, keyBytes, 0, System.length(keyBytes));
end;

class function TParameterUtilities.CreateKeyParameter(const algorithm: String;
  keyBytes: TCryptoLibByteArray; offset, length: Int32): IKeyParameter;
var
  canonical: string;
begin

  if (algorithm = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  end;

  canonical := GetCanonicalAlgorithmName(algorithm);

  if (canonical = '') then
  begin
    raise ESecurityUtilityCryptoLibException.CreateResFmt
      (@SAlgorithmNotRecognised, [algorithm]);
  end;
  result := TKeyParameter.Create(keyBytes, offset, length) as IKeyParameter;
end;

class function TParameterUtilities.CreateKeyParameter
  (const algOid: IDerObjectIdentifier; keyBytes: TCryptoLibByteArray;
  offset, length: Int32): IKeyParameter;
begin
  result := CreateKeyParameter(algOid.ID, keyBytes, offset, length);
end;

class constructor TParameterUtilities.CreateParameterUtilities;
begin
  TParameterUtilities.Boot;
end;

class destructor TParameterUtilities.DestroyParameterUtilities;
begin
  Falgorithms.Free;
end;

end.

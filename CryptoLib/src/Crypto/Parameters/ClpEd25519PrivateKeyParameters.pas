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

unit ClpEd25519PrivateKeyParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpEd25519,
  ClpIEd25519,
  ClpISecureRandom,
  ClpAsymmetricKeyParameter,
  ClpIEd25519PrivateKeyParameters,
  ClpIEd25519PublicKeyParameters,
  ClpEd25519PublicKeyParameters,
  ClpArrayUtils,
  ClpAsn1Objects,
  ClpCryptoLibTypes;

resourcestring
  SEOFInPrivateKey = 'EOF encountered in middle of %s private key';
  SUnsupportedAlgorithm = 'Unsupported Algorithm';
  SCtxNotNil = 'Ctx must be Nil for %s Algorithm';
  SMsgLen = 'MsgLen must be Equal to "PreHashSize" for %sph Algorithm';

type
  TEd25519PrivateKeyParameters = class sealed(TAsymmetricKeyParameter,
    IEd25519PrivateKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;
    FEd25519Instance: IEd25519;

  public

    const
    KeySize = Int32(TEd25519.SecretKeySize);
    SignatureSize = Int32(TEd25519.SignatureSize);

    constructor Create(const Ed25519Instance: IEd25519;
      const random: ISecureRandom); overload;
    constructor Create(const Ed25519Instance: IEd25519;
      const buf: TCryptoLibByteArray; off: Int32); overload;
    constructor Create(const Ed25519Instance: IEd25519;
      input: TStream); overload;

    procedure Encode(const buf: TCryptoLibByteArray; off: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;
    function GeneratePublicKey(): IEd25519PublicKeyParameters; inline;

    procedure Sign(algorithm: TEd25519.TEd25519Algorithm;
      const publicKey: IEd25519PublicKeyParameters;
      const ctx, msg: TCryptoLibByteArray; msgOff, msgLen: Int32;
      const sig: TCryptoLibByteArray; sigOff: Int32);

    function Equals(const other: IEd25519PrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

implementation

{ TEd25519PrivateKeyParameters }

function TEd25519PrivateKeyParameters.GeneratePublicKey
  : IEd25519PublicKeyParameters;
var
  publicKey: TCryptoLibByteArray;
begin
  System.SetLength(publicKey, TEd25519.PublicKeySize);
  FEd25519Instance.GeneratePublicKey(FData, 0, publicKey, 0);
  result := TEd25519PublicKeyParameters.Create(publicKey, 0);
end;

function TEd25519PrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  result := System.Copy(FData);
end;

constructor TEd25519PrivateKeyParameters.Create(const Ed25519Instance: IEd25519;
  const random: ISecureRandom);
begin
  Inherited Create(true);
  System.SetLength(FData, KeySize);
  FEd25519Instance := Ed25519Instance;
  FEd25519Instance.GeneratePrivateKey(random, FData);
end;

constructor TEd25519PrivateKeyParameters.Create(const Ed25519Instance: IEd25519;
  const buf: TCryptoLibByteArray; off: Int32);
begin
  Inherited Create(true);
  System.SetLength(FData, KeySize);
  FEd25519Instance := Ed25519Instance;
  System.Move(buf[off], FData[0], KeySize * System.SizeOf(Byte));
end;

constructor TEd25519PrivateKeyParameters.Create(const Ed25519Instance: IEd25519;
  input: TStream);
begin
  Inherited Create(true);
  System.SetLength(FData, KeySize);
  FEd25519Instance := Ed25519Instance;
  if (KeySize <> TStreamUtils.ReadFully(input, FData)) then
  begin
    raise EEndOfStreamCryptoLibException.CreateResFmt(@SEOFInPrivateKey,
      [FEd25519Instance.AlgorithmName]);
  end;
end;

procedure TEd25519PrivateKeyParameters.Encode(const buf: TCryptoLibByteArray;
  off: Int32);
begin
  System.Move(FData[0], buf[off], KeySize * System.SizeOf(Byte));
end;

function TEd25519PrivateKeyParameters.Equals(const other
  : IEd25519PrivateKeyParameters): Boolean;
begin
  if (other = Self as IEd25519PrivateKeyParameters) then
  begin
    result := true;
    Exit;
  end;

  if (other = Nil) then
  begin
    result := false;
    Exit;
  end;
  result := TArrayUtils.ConstantTimeAreEqual(FData, other.GetEncoded())
end;

function TEd25519PrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := TArrayUtils.GetArrayHashCode(FData);
end;

procedure TEd25519PrivateKeyParameters.Sign
  (algorithm: TEd25519.TEd25519Algorithm;
  const publicKey: IEd25519PublicKeyParameters;
  const ctx, msg: TCryptoLibByteArray; msgOff, msgLen: Int32;
  const sig: TCryptoLibByteArray; sigOff: Int32);
var
  pk: TCryptoLibByteArray;
begin
  System.SetLength(pk, TEd25519.PublicKeySize);

  if (publicKey = Nil) then
  begin
    FEd25519Instance.GeneratePublicKey(FData, 0, pk, 0);
  end
  else
  begin
    publicKey.Encode(pk, 0);
  end;

  case algorithm of
    TEd25519.TEd25519Algorithm.Ed25519:
      begin
        if (ctx <> Nil) then
        begin
          raise EArgumentCryptoLibException.CreateResFmt(@SCtxNotNil,
            [FEd25519Instance.AlgorithmName]);
        end;

        FEd25519Instance.Sign(FData, 0, pk, 0, msg, msgOff, msgLen,
          sig, sigOff);
      end;

    TEd25519.TEd25519Algorithm.Ed25519ctx:
      begin
        FEd25519Instance.Sign(FData, 0, pk, 0, ctx, msg, msgOff, msgLen,
          sig, sigOff);
      end;

    TEd25519.TEd25519Algorithm.Ed25519ph:
      begin
        if (TEd25519.PreHashSize <> msgLen) then
        begin
          raise EArgumentCryptoLibException.CreateResFmt(@SMsgLen,
            [FEd25519Instance.AlgorithmName]);
        end;

        FEd25519Instance.SignPrehash(FData, 0, pk, 0, ctx, msg, msgOff,
          sig, sigOff);
      end
  else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnsupportedAlgorithm);
    end;

  end;
end;

end.

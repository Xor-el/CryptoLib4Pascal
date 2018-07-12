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

unit ClpECSchnorrSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  ClpIDigest,
  ClpISigner,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpICipherParameters,
  ClpISchnorr,
  ClpIECSchnorrSigner,
  ClpIParametersWithRandom,
  ClpDerSequence,
  ClpDerInteger,
  ClpIDerInteger,
  ClpAsn1Object,
  ClpIAsn1Sequence,
  ClpBigInteger,
  ClpBigIntegers,
  ClpIECKeyParameters,
  ClpIECPublicKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpCryptoLibTypes;

resourcestring
  SECPublicKeyNotFound = 'EC Public Key Required for Verification';
  SECPrivateKeyNotFound = 'EC Private Key Required for Signing';
  SCurveNil = 'Key has no Curve';

type
  TECSchnorrSigner = class(TInterfacedObject, ISigner, IECSchnorrSigner)

  strict private

  var
    FDigest: IDigest;
    FRandom: ISecureRandom;
    FSigner: ISchnorr;
    FforSigning: Boolean;
    Fkey: IECKeyParameters;
    FBuffer: TMemoryStream;

    function Aggregate: TCryptoLibByteArray; inline;

  public

    function Do_Sign(const pv_key: IECPrivateKeyParameters;
      const k: TBigInteger): TCryptoLibByteArray;

    function Do_Verify(const pu_key: IECPublicKeyParameters;
      sig: TCryptoLibByteArray): Boolean;

    class function Encode_Sig(const r, s: TBigInteger)
      : TCryptoLibByteArray; static;

    class function Decode_Sig(sig: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>; static;


    // ECSchnorr signer implementation according to:
    //
    // - `BSI:TR03111 <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_pdf.html>`_
    // - `ISO/IEC:14888-3 <http://www.iso.org/iso/iso_catalogue/catalogue_ics/catalogue_detail_ics.htm?csnumber=43656>`_
    // - `bitcoin-core:libsecp256k1 <https://github.com/bitcoin-core/secp256k1/blob/master/src/modules/schnorr/schnorr_impl.h>`_
    //
    //
    //
    // *Signature*:
    //
    // - "BSI": compute r,s according to to BSI :
    // 1. k = RNG(1:n-1)
    // 2. Q = [k]G
    // 3. r = H(M ||Qx)
    // If r = 0 mod n, goto 1.
    // 4. s = k - r.d mod n
    // If s = 0 goto 1.
    // 5. Output (r, s)
    // - "ISO": compute r,s according to ISO :
    // 1. k = RNG(1:n-1)
    // 2. Q = [k]G
    // If r = 0 mod n, goto 1.
    // 3. r = H(Qx||Qy||M).
    // 4. s = (k + r.d) mod n
    // If s = 0 goto 1.
    // 5. Output (r, s)
    // - "ISOX": compute r,s according to optimized ISO variant:
    // 1. k = RNG(1:n-1)
    // 2. Q = [k]G
    // If r = 0 mod n, goto 1.
    // 3. r = H(Qx||Qy||M).
    // 4. s = (k + r.d) mod n
    // If s = 0 goto 1.
    // 5. Output (r, s)
    // - "LIBSECP": compute r,s according to bitcoin lib:
    // 1. k = RNG(1:n-1)
    // 2. Q = [k]G
    // if Qy is odd, negate k and goto 2
    // 3. r = Qx % n
    // 4. h = H(r || m).
    // if h == 0 or h >= order goto 1
    // 5. s = k - h.d.
    // 6. Output (r, s)
    //
    // *Verification*
    //
    // - "BSI": verify r,s according to to BSI :
    // 1. Verify that r in {0, . . . , 2**t - 1} and s in {1, 2, . . . , n - 1}.
    // If the check fails, output False and terminate.
    // 2. Q = [s]G + [r]W
    // If Q = 0, output Error and terminate.
    // 3. v = H(M||Qx)
    // 4. Output True if v = r, and False otherwise.
    // - "ISO": verify r,s according to ISO :
    // 1. check...
    // 2. Q = [s]G - [r]W
    // If Q = 0, output Error and terminate.
    // 3. v = H(Qx||Qy||M).
    // 4. Output True if v = r, and False otherwise.
    // - "ISOX": verify r,s according to optimized ISO variant:
    // 1. check...
    // 2. Q = [s]G - [r]W
    // If Q = 0, output Error and terminate.
    // 3. v = H(Qx||M).
    // 4. Output True if v = r, and False otherwise.
    // - "LIBSECP":
    // 1. Signature is invalid if s >= order.
    // Signature is invalid if r >= p.
    // 2. h = H(r || m).
    // Signature is invalid if h == 0 or h >= order.
    // 3. R = [h]Q + [s]G.
    // Signature is invalid if R is infinity or R's y coordinate is odd.
    // 4. Signature is valid if the serialization of R's x coordinate equals r.

    /// <param name="signer">
    /// instance of one of "BSI","ISO","ISOX","LIBSECP"
    /// </param>
    /// <param name="digest">
    /// initialized "IDigest" instance.
    /// </param>
    constructor Create(const signer: ISchnorr; const digest: IDigest);
    destructor Destroy(); override;

    function GetAlgorithmName: String;
    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(forSigning: Boolean; const parameters: ICipherParameters);

    /// <summary>
    /// update the internal digest with the byte b
    /// </summary>
    procedure Update(input: Byte);

    /// <summary>
    /// update the internal digest with the byte array in
    /// </summary>
    procedure BlockUpdate(input: TCryptoLibByteArray; inOff, length: Int32);

    /// <summary>
    /// Generate a signature for the message we've been loaded with using the
    /// key we were initialised with.
    /// </summary>
    function GenerateSignature(): TCryptoLibByteArray;

    /// <returns>
    /// true if the internal state represents the signature described in the
    /// passed in array.
    /// </returns>
    function VerifySignature(signature: TCryptoLibByteArray): Boolean;

    /// <summary>
    /// Reset the internal state
    /// </summary>
    procedure Reset();
  end;

implementation

{ TECSchnorrSigner }

class function TECSchnorrSigner.Encode_Sig(const r, s: TBigInteger)
  : TCryptoLibByteArray;
begin
  Result := TDerSequence.Create([TDerInteger.Create(r) as IDerInteger,
    TDerInteger.Create(s) as IDerInteger]).GetDerEncoded();
end;

class function TECSchnorrSigner.Decode_Sig(sig: TCryptoLibByteArray)
  : TCryptoLibGenericArray<TBigInteger>;
var
  s: IAsn1Sequence;
begin
  s := TAsn1Object.FromByteArray(sig) as IAsn1Sequence;
  Result := TCryptoLibGenericArray<TBigInteger>.Create
    ((s[0] as IDerInteger).value, (s[1] as IDerInteger).value);
end;

function TECSchnorrSigner.Aggregate: TCryptoLibByteArray;
begin
  FBuffer.Position := 0;
  System.SetLength(Result, FBuffer.Size);
  FBuffer.Read(Result[0], FBuffer.Size);
end;

procedure TECSchnorrSigner.BlockUpdate(input: TCryptoLibByteArray;
  inOff, length: Int32);
begin
  FBuffer.Write(input[inOff], length);
end;

constructor TECSchnorrSigner.Create(const signer: ISchnorr;
  const digest: IDigest);
begin
  inherited Create();
  FDigest := digest;
  FSigner := signer;
  FBuffer := TMemoryStream.Create();
end;

destructor TECSchnorrSigner.Destroy;
begin
  FBuffer.Free;
  inherited Destroy;
end;

function TECSchnorrSigner.Do_Sign(const pv_key: IECPrivateKeyParameters;
  const k: TBigInteger): TCryptoLibByteArray;
begin

  if (pv_key.parameters.curve = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SCurveNil)
  end;

  Result := FSigner.Do_Sign(Aggregate(), FDigest, pv_key, k);
end;

function TECSchnorrSigner.Do_Verify(const pu_key: IECPublicKeyParameters;
  sig: TCryptoLibByteArray): Boolean;
begin

  if (pu_key.parameters.curve = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SCurveNil)
  end;

  Result := FSigner.Do_Verify(Aggregate(), FDigest, pu_key, sig);
end;

function TECSchnorrSigner.GenerateSignature: TCryptoLibByteArray;
var
  order, k, orderMinusOne: TBigInteger;
  pv_key_params: IECPrivateKeyParameters;
begin

  pv_key_params := Fkey as IECPrivateKeyParameters;
  order := pv_key_params.parameters.curve.order;
  orderMinusOne := order.Subtract(TBigInteger.One);

  repeat
    // k := [1, q - 1]
    k := TBigIntegers.CreateRandomInRange(TBigInteger.One,
      orderMinusOne, FRandom);

    Result := Do_Sign(pv_key_params, k);
  until (Result <> Nil);

end;

function TECSchnorrSigner.GetAlgorithmName: String;
begin
  Result := FDigest.AlgorithmName + 'with' + 'ECSCHNORR' +
    FSigner.AlgorithmName;
end;

procedure TECSchnorrSigner.Init(forSigning: Boolean;
  const parameters: ICipherParameters);
var
  rParam: IParametersWithRandom;
  Lparameters: ICipherParameters;
begin

  FforSigning := forSigning;
  Lparameters := parameters;

  if (forSigning) then
  begin

    if (Supports(Lparameters, IParametersWithRandom, rParam)) then
    begin
      FRandom := rParam.Random;
      Lparameters := rParam.parameters;
    end
    else
    begin
      FRandom := TSecureRandom.Create();
    end;

    if (not(Supports(Lparameters, IECPrivateKeyParameters))) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SECPrivateKeyNotFound);
    end;

    Fkey := Lparameters as IECPrivateKeyParameters;
  end
  else
  begin
    if (not(Supports(Lparameters, IECPublicKeyParameters))) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SECPublicKeyNotFound);
    end;

    Fkey := Lparameters as IECPublicKeyParameters;
  end;
  Reset();
end;

procedure TECSchnorrSigner.Reset;
begin
  FDigest.Reset;
  FBuffer.Clear;
  FBuffer.SetSize(0);
end;

procedure TECSchnorrSigner.Update(input: Byte);
begin
  FBuffer.Write(TCryptoLibByteArray.Create(input)[0], 1);
end;

function TECSchnorrSigner.VerifySignature
  (signature: TCryptoLibByteArray): Boolean;
var
  pu_key_params: IECPublicKeyParameters;
begin

  pu_key_params := Fkey as IECPublicKeyParameters;

  Result := Do_Verify(pu_key_params, signature);

end;

end.

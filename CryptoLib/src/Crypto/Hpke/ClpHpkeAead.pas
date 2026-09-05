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

unit ClpHpkeAead;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpPack,
  ClpByteUtilities,
  ClpArrayUtilities,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpIAeadCipher,
  ClpIBlockCipher,
  ClpAesEngine,
  ClpGcmBlockCipher,
  ClpChaCha20Poly1305,
  ClpHpkeTypes,
  ClpIHpkeAead,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SExportOnlyCannotSealOpen =
    'Export only mode, cannot be used to seal/open';
  SMessageLimitReached = 'HPKE message limit reached';
  SUnexpectedOutputSize = 'AEAD produced an unexpected output size';

type
  /// <summary>
  /// RFC 9180 sec. 5.2 single-key AEAD context. The 64-bit sequence number is
  /// folded into the low 8 bytes of the 12-byte base nonce per message and only
  /// advances after a successful operation.
  /// </summary>
  THpkeAead = class sealed(TInterfacedObject, IHpkeAead)

  strict private
  const
    NonceSize = Int32(12);
    MacSizeBits = Int32(128);

  var
    FAeadId: THpkeAeadId;
    FKey, FBaseNonce: TCryptoLibByteArray;
    FSeq: UInt64;
    FCipher: IAeadCipher;

    function ComputeNonce(): TCryptoLibByteArray;
    procedure IncrementSeq();
    function Process(AForEncryption: Boolean;
      const AAad, ABuf: TCryptoLibByteArray; AOff, ALen: Int32)
      : TCryptoLibByteArray;

  public
    constructor Create(AAeadId: THpkeAeadId;
      const AKey, ABaseNonce: TCryptoLibByteArray);

    destructor Destroy(); override;

    function Seal(const AAad, APt: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function Seal(const AAad, APt: TCryptoLibByteArray; APtOff, APtLen: Int32)
      : TCryptoLibByteArray; overload;

    function Open(const AAad, ACt: TCryptoLibByteArray)
      : TCryptoLibByteArray; overload;
    function Open(const AAad, ACt: TCryptoLibByteArray; ACtOff, ACtLen: Int32)
      : TCryptoLibByteArray; overload;
  end;

implementation

{ THpkeAead }

constructor THpkeAead.Create(AAeadId: THpkeAeadId;
  const AKey, ABaseNonce: TCryptoLibByteArray);
begin
  inherited Create();
  FAeadId := AAeadId;
  FKey := System.Copy(AKey);
  FBaseNonce := System.Copy(ABaseNonce);
  FSeq := 0;

  case AAeadId of
    THpkeAeadId.AesGcm128, THpkeAeadId.AesGcm256:
      FCipher := TGcmBlockCipher.Create(TAesEngine.Create() as IBlockCipher);
    THpkeAeadId.ChaCha20Poly1305:
      FCipher := TChaCha20Poly1305.Create();
    THpkeAeadId.ExportOnly:
      FCipher := nil;
  end;
end;

destructor THpkeAead.Destroy;
begin
  // wipe the derived key material held for the context lifetime
  TArrayUtilities.Fill(FKey, 0, System.Length(FKey), Byte(0));
  TArrayUtilities.Fill(FBaseNonce, 0, System.Length(FBaseNonce), Byte(0));
  inherited Destroy();
end;

function THpkeAead.ComputeNonce: TCryptoLibByteArray;
var
  LSeqBytes: TCryptoLibByteArray;
begin
  LSeqBytes := TPack.UInt64_To_BE(FSeq);
  Result := System.Copy(FBaseNonce);
  // XOR the 8 sequence bytes into the low 8 bytes of the nonce.
  TByteUtilities.XorTo(8, LSeqBytes, 0, Result, System.Length(Result) - 8);
end;

procedure THpkeAead.IncrementSeq;
begin
  // 64-bit counter; High(UInt64) is the last usable value. Wrapping would
  // repeat a nonce under the same key, so the message limit is reported.
  if FSeq = High(UInt64) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SMessageLimitReached);
  end;
  System.Inc(FSeq);
end;

function THpkeAead.Process(AForEncryption: Boolean;
  const AAad, ABuf: TCryptoLibByteArray; AOff, ALen: Int32)
  : TCryptoLibByteArray;
var
  LParams: IAeadParameters;
  LPos: Int32;
begin
  if FCipher = nil then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SExportOnlyCannotSealOpen);
  end;

  LParams := TAeadParameters.Create(TKeyParameter.Create(FKey) as IKeyParameter,
    MacSizeBits, ComputeNonce());

  FCipher.Init(AForEncryption, LParams);
  FCipher.ProcessAadBytes(AAad, 0, System.Length(AAad));

  System.SetLength(Result, FCipher.GetOutputSize(ALen));
  LPos := FCipher.ProcessBytes(ABuf, AOff, ALen, Result, 0);
  LPos := LPos + FCipher.DoFinal(Result, LPos);

  // The standard AEAD modes report an exact GetOutputSize; a mismatch is an
  // internal invariant violation, so fail closed rather than emit a truncated
  // result (and before advancing the sequence number).
  if LPos <> System.Length(Result) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SUnexpectedOutputSize);
  end;

  // RFC 9180 sec. 5.2: advance only after a successful operation, so a rejected
  // ciphertext never desynchronises the receiver from the sender.
  IncrementSeq();
end;

function THpkeAead.Seal(const AAad, APt: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := Seal(AAad, APt, 0, System.Length(APt));
end;

function THpkeAead.Seal(const AAad, APt: TCryptoLibByteArray;
  APtOff, APtLen: Int32): TCryptoLibByteArray;
begin
  TArrayUtilities.ValidateSegment(APt, APtOff, APtLen);
  Result := Process(True, AAad, APt, APtOff, APtLen);
end;

function THpkeAead.Open(const AAad, ACt: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  Result := Open(AAad, ACt, 0, System.Length(ACt));
end;

function THpkeAead.Open(const AAad, ACt: TCryptoLibByteArray;
  ACtOff, ACtLen: Int32): TCryptoLibByteArray;
begin
  TArrayUtilities.ValidateSegment(ACt, ACtOff, ACtLen);
  Result := Process(False, AAad, ACt, ACtOff, ACtLen);
end;

end.

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

unit ClpCipherModeParameterUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpIAeadParameters,
  ClpIParametersWithIV,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Parsed view of an AEAD init parameter block. Produced by
  /// TCipherModeParameterUtilities.TryResolveAeadOrIv so that each AEAD
  /// mode's Init can keep its algorithm-specific validation (mac-size
  /// bounds, key-length / nonce-length checks, nonce-reuse detection)
  /// while delegating the mechanical IAeadParameters / IParametersWithIV
  /// unwrapping to a single place.
  /// </summary>
  TCipherAeadChoice = record
    /// <summary>True when the source implemented IAeadParameters;
    /// False when it implemented IParametersWithIV.</summary>
    IsAead: Boolean;
    /// <summary>
    /// AEAD branch: the cipher key / parameter bundle nested inside
    /// IAeadParameters (may be nil). IV branch: IParametersWithIV.Parameters.
    /// Preserves the original "may be nil / may not be an IKeyParameter"
    /// semantics required by CCM / EAX which pass this value straight to a
    /// CBC-MAC / CTR init without re-typing it.
    /// </summary>
    CipherKey: ICipherParameters;
    /// <summary>IKeyParameter view of CipherKey when CipherKey implements
    /// that interface; otherwise nil. OCB, GCM-SIV and ChaCha20-Poly1305
    /// consume this directly.</summary>
    KeyParameter: IKeyParameter;
    /// <summary>Nonce / IV bytes as reported by the source interface.</summary>
    Nonce: TCryptoLibByteArray;
    /// <summary>IAeadParameters.GetAssociatedText in the AEAD branch;
    /// nil in the IV branch (callers document the default behaviour).</summary>
    AssociatedText: TCryptoLibByteArray;
    /// <summary>IAeadParameters.MacSize (bits) in the AEAD branch;
    /// 0 in the IV branch. Callers apply their own default when 0.</summary>
    MacSizeBits: Int32;
  end;

  /// <summary>
  /// Shared parameter-unwrapping helpers for block-cipher mode implementations.
  /// Centralises the repeated "if Supports(IParametersWithIV) ..." ladder
  /// (used by the non-AEAD modes) and the three-branch
  /// IAeadParameters / IParametersWithIV / raise ladder (used by every
  /// AEAD mode Init). Left as a sealed stateless class so the call surface
  /// looks identical to TBlockCipherBulkUtilities and there is exactly one
  /// place to audit for parameter-handling changes.
  /// </summary>
  TCipherModeParameterUtilities = class sealed(TObject)
  public
    /// <summary>
    /// If AParameters implements IParametersWithIV, copy the nested IV into
    /// the caller-pre-sized AIvTarget buffer (right-aligned, left-pad with
    /// zero bytes when the nested IV is shorter than AIvTarget), expose the
    /// inner IParametersWithIV.Parameters through AInnerParameters and
    /// return True. Otherwise leave AIvTarget untouched, set AInnerParameters
    /// := AParameters and return False. AIvTarget must be non-nil and
    /// pre-sized to the mode's target IV length.
    /// </summary>
    class function TryUnwrapIv(const AParameters: ICipherParameters;
      const AIvTarget: TCryptoLibByteArray;
      out AInnerParameters: ICipherParameters): Boolean; static;

    /// <summary>
    /// Populate AChoice from AParameters, trying IAeadParameters first and
    /// falling back to IParametersWithIV. Returns True on success; returns
    /// False when neither interface is available, in which case callers
    /// should raise their mode-specific "invalid parameters" exception
    /// (the helper deliberately does not raise so every mode keeps its
    /// existing error text / class).
    /// </summary>
    class function TryResolveAeadOrIv(const AParameters: ICipherParameters;
      out AChoice: TCipherAeadChoice): Boolean; static;
  end;

implementation

{ TCipherModeParameterUtilities }

class function TCipherModeParameterUtilities.TryUnwrapIv(
  const AParameters: ICipherParameters;
  const AIvTarget: TCryptoLibByteArray;
  out AInnerParameters: ICipherParameters): Boolean;
var
  LIvParam: IParametersWithIV;
  LIv: TCryptoLibByteArray;
  LPrefix: Int32;
begin
  if Supports(AParameters, IParametersWithIV, LIvParam) then
  begin
    LIv := LIvParam.GetIV();
    if System.Length(LIv) < System.Length(AIvTarget) then
    begin
      // Right-align the supplied IV so the high bytes of AIvTarget hold the
      // caller-supplied material (matching the original per-mode loops that
      // zeroed the leading bytes and copied the tail).
      LPrefix := System.Length(AIvTarget) - System.Length(LIv);
      System.Move(LIv[0], AIvTarget[LPrefix],
        System.Length(LIv) * System.SizeOf(Byte));
      TArrayUtilities.Fill<Byte>(AIvTarget, 0, LPrefix, Byte(0));
    end
    else
    begin
      System.Move(LIv[0], AIvTarget[0],
        System.Length(AIvTarget) * System.SizeOf(Byte));
    end;
    AInnerParameters := LIvParam.Parameters;
    Result := True;
  end
  else
  begin
    AInnerParameters := AParameters;
    Result := False;
  end;
end;

class function TCipherModeParameterUtilities.TryResolveAeadOrIv(
  const AParameters: ICipherParameters;
  out AChoice: TCipherAeadChoice): Boolean;
var
  LAeadParameters: IAeadParameters;
  LParametersWithIV: IParametersWithIV;
begin
  AChoice.IsAead := False;
  AChoice.CipherKey := nil;
  AChoice.KeyParameter := nil;
  AChoice.Nonce := nil;
  AChoice.AssociatedText := nil;
  AChoice.MacSizeBits := 0;

  if Supports(AParameters, IAeadParameters, LAeadParameters) then
  begin
    AChoice.IsAead := True;
    AChoice.CipherKey := LAeadParameters.Key;
    Supports(AChoice.CipherKey, IKeyParameter, AChoice.KeyParameter);
    AChoice.Nonce := LAeadParameters.GetNonce();
    AChoice.AssociatedText := LAeadParameters.GetAssociatedText();
    AChoice.MacSizeBits := LAeadParameters.MacSize;
    Result := True;
  end
  else if Supports(AParameters, IParametersWithIV, LParametersWithIV) then
  begin
    AChoice.CipherKey := LParametersWithIV.Parameters;
    Supports(AChoice.CipherKey, IKeyParameter, AChoice.KeyParameter);
    AChoice.Nonce := LParametersWithIV.GetIV();
    Result := True;
  end
  else
    Result := False;
end;

end.

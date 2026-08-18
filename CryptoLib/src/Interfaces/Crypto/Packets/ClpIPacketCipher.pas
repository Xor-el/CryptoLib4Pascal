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

unit ClpIPacketCipher;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// One-shot, reusable packet cipher (the small-message hot path). A single call
  /// performs the whole seal/open (init + process + finalize) so it avoids the
  /// streaming API's per-message parameter-object churn and buffered-wrapper
  /// layering. Instances are reusable across messages under the same or different
  /// keys; a per-instance key cache means repeated same-key calls skip the key
  /// schedule (and, for AEAD modes, the MAC subkey derivation).
  ///
  /// This is the family-neutral base: the parameter-object <c>ProcessPacket</c>
  /// is polymorphic through <c>ICipherParameters</c>, so AEAD and plain
  /// block-mode ciphers share it. The AEAD raw-span entry points live on
  /// <see cref="IAeadPacketCipher"/>. Not thread-safe: use one instance per thread.
  /// </summary>
  IPacketCipher = interface(IInterface)
    ['{2D3A9874-FAEC-43B6-816F-BAB6D9C654A5}']

    /// <summary>
    /// Parameter-object entry point. Extracts the mode's parameters from
    /// <c>AParameters</c> and performs the whole seal/open. Returns the number of
    /// output bytes written at <c>AOutOff</c>.
    /// </summary>
    function ProcessPacket(AForEncryption: Boolean;
      const AParameters: ICipherParameters; const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload;
  end;

implementation

end.

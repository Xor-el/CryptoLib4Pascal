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

unit ClpIEphemeralECDHAgreement;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpICipherParameters;

type
  /// <summary>
  /// Single-use ECDH agreement for a freshly generated EPHEMERAL private key
  /// (e.g. a TLS 1.3 ECDHE key share). It multiplies the peer point by the private
  /// scalar with a dedicated constant-time multiplier whose scalar-blind width is
  /// chosen for one-shot use (minimal blind, or deterministic fixed-length), never
  /// the curve's shared fully-blinded default. The private key is released after a
  /// single CalculateAgreement, and a second call is refused. NOT for long-term or
  /// reused (static) keys - those must use the fully-blinded default agreement.
  /// </summary>
  IEphemeralECDHAgreement = interface(IInterface)
    ['{6F2A1C34-8E5B-4D71-9A2C-3B7E1F5D8A46}']

    function CalculateAgreement(const APubKey: ICipherParameters): TBigInteger;
  end;

implementation

end.

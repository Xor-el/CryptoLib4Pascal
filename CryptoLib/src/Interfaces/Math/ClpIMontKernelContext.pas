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

unit ClpIMontKernelContext;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type

  /// <summary>
  /// A reusable Montgomery kernel context over an odd modulus, in 64-bit little-endian
  /// limbs: the context layout (<c>[-n0', N64, modulus-limbs]</c>), the Newton derivation
  /// of <c>n0'</c>, the precomputed <c>R^2 mod n</c> used to enter Montgomery form, and
  /// the N64+2 CIOS accumulator discipline.
  ///
  /// Immutable once built, so one instance is safe to share across threads (and across
  /// every signature on a key). The scratch is caller-owned - each thread / operation
  /// supplies its own - which lets concurrent signatures run against one shared context
  /// without contending.
  /// </summary>
  IMontKernelContext = interface(IInterface)
    ['{4A1D9C7E-6B23-4F58-9E1A-2C7D5B0F8A34}']
    function GetN64: Int32;
    function GetEngaged: Boolean;
    /// <summary>True when <c>AModulusLimbs</c> (N64 little-endian limbs) is the modulus
    /// this context was built over - lets a caller that adopts a cached context prove it
    /// matches the operand before trusting the result.</summary>
    function MatchesModulus(const AModulusLimbs: TCryptoLibUInt64Array): Boolean;
    /// <summary><c>ADst[0..N64-1] := AX*AY*R^-1 mod n</c>. <c>AScratch</c> must hold at
    /// least N64+2 limbs and must not alias AX/AY; ADst may alias AX/AY.</summary>
    procedure Mul(const AScratch, AX, AY, ADst: TCryptoLibUInt64Array);
    /// <summary><c>ADst := AX^2*R^-1 mod n</c>, via the dedicated square kernel where
    /// available, otherwise <c>Mul(AX, AX)</c>.</summary>
    procedure Sqr(const AScratch, AX, ADst: TCryptoLibUInt64Array);
    /// <summary>Enter Montgomery form: <c>ADst := ABase*R mod n</c>, computed as
    /// <c>MontMul(ABase, R^2)</c> - no division. Requires <c>ABase &lt; n</c>.</summary>
    procedure ToMontgomery(const AScratch, ABase, ADst: TCryptoLibUInt64Array);
    property N64: Int32 read GetN64;
    property Engaged: Boolean read GetEngaged;
  end;

implementation

end.

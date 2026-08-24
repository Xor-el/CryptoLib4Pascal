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

unit ClpIAffineCombPreCompInfo;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPreCompInfo,
  ClpCTFieldValue,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Precomputed fixed-base table for the affine (no-doubling) comb multiplier,
  /// cached on the base point. The flat table holds, per Booth window i and
  /// magnitude j (1..2^(w-1)), the affine Montgomery-domain point
  /// (j * 2^(w*i)) * G at index i*EntriesPerWindow + (j-1); the doublings are
  /// baked in, so the online phase is windows-many mixed additions and no
  /// doublings. Contents are public - only the online window index is secret.
  /// </summary>
  IAffineCombPreCompInfo = interface(IPreCompInfo)
    ['{7F2A9C41-6B3E-4D18-9A2C-1E5F8D0B7C63}']

    function GetWindow: Int32;
    function GetNumWindows: Int32;
    function GetEntriesPerWindow: Int32;
    function GetTable: TCryptoLibGenericArray<TFeAffine>;

    property Window: Int32 read GetWindow;
    property NumWindows: Int32 read GetNumWindows;
    property EntriesPerWindow: Int32 read GetEntriesPerWindow;
    property Table: TCryptoLibGenericArray<TFeAffine> read GetTable;
  end;

implementation

end.

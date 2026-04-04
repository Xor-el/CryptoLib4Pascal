{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIPemHeader;

{$I ..\..\Include\CryptoLib.inc}

interface

type
  /// <summary>
  /// Interface for PEM header objects.
  /// </summary>
  IPemHeader = interface(IInterface)
    ['{ED7A5DF3-5307-427B-8B47-63820438FEF1}']

    function GetName: String;
    function GetValue: String;

    /// <summary>
    /// Get the header name.
    /// </summary>
    property Name: String read GetName;
    /// <summary>
    /// Get the header value.
    /// </summary>
    property Value: String read GetValue;

    /// <summary>
    /// Get hash code for this header.
    /// </summary>
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
    /// <summary>
    /// Check if this header equals another object.
    /// </summary>
    function Equals(const AObj: IPemHeader): Boolean;
    /// <summary>
    /// Get string representation of this header.
    /// </summary>
    function ToString(): String;
  end;

implementation

end.

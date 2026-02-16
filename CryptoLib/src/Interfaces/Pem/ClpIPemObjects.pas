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

unit ClpIPemObjects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes;

type
  IPemHeader = interface;
  IPemObject = interface;
  IPemObjectGenerator = interface;

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

  /// <summary>
  /// Interface for PEM object generator.
  /// </summary>
  IPemObjectGenerator = interface(IInterface)
    ['{B2C3D4E5-F6A7-8901-BCDE-F23456789012}']

    /// <summary>
    /// Generate a PEM object.
    /// </summary>
    /// <returns>A PEM object</returns>
    function Generate(): IPemObject;
  end;

  /// <summary>
  /// Interface for PEM objects.
  /// </summary>
  IPemObject = interface(IPemObjectGenerator)
    ['{9D65BB7D-721A-48B4-963B-13DBA970705A}']

    function GetType: String;
    function GetHeaders: TCryptoLibGenericArray<IPemHeader>;
    function GetContent: TCryptoLibByteArray;

    /// <summary>
    /// Get the PEM object type.
    /// </summary>
    property &Type: String read GetType;
    /// <summary>
    /// Get the PEM headers.
    /// </summary>
    property Headers: TCryptoLibGenericArray<IPemHeader> read GetHeaders;
    /// <summary>
    /// Get the PEM content (decoded from base64).
    /// </summary>
    property Content: TCryptoLibByteArray read GetContent;
  end;

implementation

end.

